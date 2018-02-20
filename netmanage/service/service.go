package service

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/dedis/cothority/cosi/protocol"
	cosisign "github.com/dedis/cothority/cosi/service"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/netmanage"
	"golang.org/x/crypto/openpgp"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"strings"
	"sync"

	//for test

	"encoding/hex"
	"encoding/json"
	"golang.org/x/crypto/openpgp/armor"
	"gopkg.in/dedis/onet.v1/simul/monitor"
	"io/ioutil"
	"os"
	"strconv"
)

const (
	ErrorGenesisPolicy = 4100 + iota

	ErrorNewPolicy

	ErrorSignPolicy

	ErrorGetPolicy

	ErrorVerifyPolicy
)

//ServiceName is used for registration on the onet.
const ServiceName = "NetManage"

var netManageID onet.ServiceID

func init() {
	var err error
	netManageID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessage(&Storage{})
}

// NetManage service
type Service struct {
	*onet.ServiceProcessor
	Storage *Storage

	//just for using the skipchain api functions
	skipchainClient *skipchain.Client
	cosiClient      *cosisign.Client
}

//this is where to store the policy chain
type Storage struct {
	// the first block of policy chain
	GenesisPolicy *skipchain.SkipBlock

	// the latest block of policy chain
	LatestPolicy *skipchain.SkipBlock

	genesisMutex sync.Mutex
	latestMutex  sync.Mutex
}

// storageID reflects the data we're storing - we could store more
// than one structure.
const storageID = "main"

func (s *Service) GenesisPolicyRequest(req *netmanage.GenesisPolicyRequest) (*netmanage.GenesisPolicyResponse, onet.ClientError) {
	//if s.Storage.LatestPolicy == nil {
	//	fmt.Printf("service GenesisPolicyRequest 00000 s.Storage.LatestPolicy is nil\n")
	//}

	//prepare the input for StoreSkipBlock
	el := req.Roster
	baseH := req.BaseH
	maxH := req.MaxH
	if el == nil {
		return nil, onet.NewClientErrorCode(ErrorGenesisPolicy, "The Genesis policy request has no Roster")
	}
	if baseH == 0 {
		return nil, onet.NewClientErrorCode(ErrorGenesisPolicy, "The Genesis policy request has no base height")
	}
	if baseH == 0 {
		return nil, onet.NewClientErrorCode(ErrorGenesisPolicy, "The Genesis policy request has no max height")
	}

	//fmt.Printf("GenesisPolicyRequest00000000000\n")
	//check if the admins' signatures have reached the threshold. If no enough approvers, return nil and error directly

	genesisApprovalCheck := monitor.NewTimeMeasure("genesisApprovalCheck")
	isApproved, err := s.ApprovalCheck(req.PolicyData, req.Signatures)
	genesisApprovalCheck.Record()

	if isApproved != true {
		return nil, onet.NewClientError(err)
	}
	//cosign the PolicyData into CosiPolicy as the data part of the policy block

	genesisCoSign := monitor.NewTimeMeasure("genesisCoSign")
	cosiPolicy, err := s.SignPolicyData(el, req.PolicyData)
	genesisCoSign.Record()
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
	}

	genesisCreateBlock := monitor.NewTimeMeasure("genesisCreateBlock")
	genesis, err := s.skipchainClient.CreateGenesis(el, baseH, maxH, skipchain.VerificationNone, cosiPolicy, nil)
	genesisCreateBlock.Record()
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	s.Storage.genesisMutex.Lock()
	s.Storage.GenesisPolicy = genesis
	s.Storage.genesisMutex.Unlock()

	s.Storage.latestMutex.Lock()
	s.Storage.LatestPolicy = genesis
	s.Storage.latestMutex.Unlock()

	//fmt.Printf("!!!!!service GenesisPolicyRequest data is %s\n",string(s.Storage.LatestPolicy.SkipBlockFix.Data))
	resp := &netmanage.GenesisPolicyResponse{BlockID: genesis.Hash, GenesisBlock: genesis}
	//fmt.Printf("GenesisPolicyRequest genesis hash hex = %s\n", hex.EncodeToString(genesis.Hash))
	//fmt.Printf("GenesisPolicyRequest genesis hash = %s\n",string(genesis.Hash[:]))

	if s.Storage.LatestPolicy == nil {
		fmt.Printf("service GenesisPolicyRequest 11111 s.Storage.LatestPolicy is nil\n\n")
	}

	return resp, nil
}

//ignore this first: validate the PolicyData, if it is validated with threshold sigs of admins
//cosign Data, PolicyData -> CosiPolicy, save CosiPolicy into a block, append the block to the chain, and return the block
//roster in request cannot be nil, since we need the roster to find the corresponding skipchain client
func (s *Service) NewPolicyRequest(req *netmanage.NewPolicyRequest) (*netmanage.NewPolicyResponse, onet.ClientError) {
	//prepare the input for StoreSkipBlock
	if s.Storage.LatestPolicy == nil {
		fmt.Printf("service NewPolicyRequest 00000 s.Storage.LatestPolicy is nil\n")
	}

	latestID := req.ParentBlockID
	if latestID == nil {
		return nil, onet.NewClientErrorCode(ErrorNewPolicy, "The new policy request has no parent block hash")
	}

	el := req.Roster
	if el == nil {
		return nil, onet.NewClientErrorCode(ErrorNewPolicy, "The new policy request has no roster")
	}

	//check if the admins' signatures have reached the threshold. If no enough approvers, return nil and error directly
	newApprovalCheck := monitor.NewTimeMeasure("newApprovalCheck")
	isApproved, err := s.ApprovalCheck(req.PolicyData, req.Signatures)
	newApprovalCheck.Record()
	if isApproved != true {
		return nil, onet.NewClientError(err)
	}

	//cosign the PolicyData into CosiPolicy as the data part of the policy block
	newCoSign := monitor.NewTimeMeasure("newCoSign")
	cosiPolicy, err := s.SignPolicyData(el, req.PolicyData)
	newCoSign.Record()

	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
	}
	//create a newBlock with cosiPolicy as the data part

	newCreateBlock := monitor.NewTimeMeasure("newCreateBlock")
	newBlock := skipchain.NewSkipBlock()
	newCreateBlock.Record()

	buf, err := network.Marshal(cosiPolicy)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
	}
	//fmt.Printf("NewPolicyRequest buf = %s\n", string(buf[:]))

	newBlock.SkipBlockFix.Data = buf
	newBlock.SkipBlockFix.Roster = el

	newStoreSkipBlock := monitor.NewTimeMeasure("newStoreSkipBlock")
	skiprep, err := s.skipchainClient.StoreSkipBlock(latestID, newBlock)
	newStoreSkipBlock.Record()

	if err != nil {
		return nil, onet.NewClientError(err)
	}

	s.Storage.latestMutex.Lock()
	s.Storage.LatestPolicy = skiprep.Latest
	s.Storage.latestMutex.Unlock()

	//fmt.Printf("!!!!!service NewPolicyRequest data is %s\n",string(s.Storage.LatestPolicy.Data))
	resp := &netmanage.NewPolicyResponse{BlockID: skiprep.Latest.Hash, LatestBlock: skiprep.Latest}

	if s.Storage.LatestPolicy == nil {
		fmt.Printf("service NewPolicyRequest 11111 s.Storage.LatestPolicy is nil\n\n")
	}

	return resp, nil
}

//check if enough admins ÃÂ¯ÃÂ¼ÃÂ>= threshold) have signed on the Policy
func (s *Service) ApprovalCheck(policyData *netmanage.PolicyData, signatures []string) (bool, error) {
	var (
		admins    openpgp.EntityList         // List of all admins whose public keys are in the conf in the new policy Request
		approvers map[string]*openpgp.Entity // Map of admins who provided a valid signature. Indexed by public key id (openpgp.PrimaryKey.KeyIdString)
		err       error
	)

	approvers = make(map[string]*openpgp.Entity)

	// Creating openpgp entitylist from list of public keys in the conf
	admins = make(openpgp.EntityList, 0)
	for _, pubkey := range policyData.Conf.PubKeys {
		keybuf, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pubkey))
		if err != nil {
			log.Error("Could not decode armored public key", err)
		}
		for _, entity := range keybuf {
			admins = append(admins, entity)
		}
	}

	// Verifying every signature in the list and counting valid ones

	//transform policy into bytes
	//fmt.Printf("approveCheck1111111111111111\n")
	signedBuf, err := network.Marshal(policyData.Policy)
	if err != nil {
		log.Error(err)
		return false, err
	}

	for _, signature := range signatures {
		result, err := openpgp.CheckArmoredDetachedSignature(admins, bytes.NewReader(signedBuf), strings.NewReader(signature))
		if err != nil {
			log.Lvl1("The signature is invalid or cannot be verified due to", err)
		} else {
			if approvers[result.PrimaryKey.KeyIdString()] == nil { // We need to check that this is a unique signature
				approvers[result.PrimaryKey.KeyIdString()] = result
				log.Lvl4("Approver: %+v", result.Identities)
			}
		}
	}

	log.Lvl3("Is release approved? ", len(approvers) >= policyData.Conf.Threshold)

	//fmt.Printf("approvers = %d threshold = %d approval is %t\n",len(approvers),policyData.Conf.Threshold, (len(approvers) >= policyData.Conf.Threshold))

	return len(approvers) >= policyData.Conf.Threshold, err
}

func (s *Service) cosiSign(r *onet.Roster, msg []byte) (*cosisign.SignatureResponse, error) {
	//client := cosisign.NewClient()
	cosiSig, err := s.cosiClient.SignatureRequest(r, msg)

	if err != nil {
		log.Error(err)
		return nil, err
	}
	return cosiSig, nil
}

func (s *Service) cosiVerify(r *onet.Roster, msg []byte, cosiSig *cosisign.SignatureResponse) error {
	err := cosi.VerifySignature(network.Suite, r.Publics(), msg, cosiSig.Signature)
	return err
}

//Cosi PolicyData, return CosiPolicy
//TO DO: first verify the threshold ...................
//marshal PolicyData struct into byte, then cosi the buf, and save the sig into one CosiPolicy with the PolicyData
func (s *Service) SignPolicyData(r *onet.Roster, policyData *netmanage.PolicyData) (*netmanage.CosiPolicy, onet.ClientError) {
	//validate the policyData, check all if the signatures reach the threshold

	//sign this policyData to cosiPolicy
	buf, err := network.Marshal(policyData)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientErrorCode(ErrorSignPolicy, err.Error())
	}

	coSignature, err := s.cosiSign(r, buf)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientErrorCode(ErrorSignPolicy, err.Error())
	}
	cosiPolicy := &netmanage.CosiPolicy{PolicyData: policyData, CoSignature: coSignature}
	return cosiPolicy, nil
}

//given the latest known blockID, return data in the latest Policy block
func (s *Service) GetPolicyRequest(req *netmanage.GetPolicyRequest) (*netmanage.GetPolicyResponse, onet.ClientError) {
	if s.Storage.LatestPolicy == nil {
		fmt.Printf("service GetPolicyRequest 00000 s.Storage.LatestPolicy is nil\n")
	}

	_, msg, merr := network.Unmarshal(s.Storage.LatestPolicy.Data)
	if merr != nil {
		log.ErrFatal(merr)
		return nil, onet.NewClientErrorCode(ErrorGetPolicy, merr.Error())
	}
	data := msg.(*netmanage.CosiPolicy)
	return &netmanage.GetPolicyResponse{data}, nil
}

//Verify CosiPolicy
//given a CosiPolicy struct, verify if the cosig in it is the correct one for its PolicyData
func (s *Service) VerifyPolicyRequest(req *netmanage.VerifyPolicyRequest) (*netmanage.VerifyPolicyResponse, onet.ClientError) {
	buf, err := network.Marshal(req.Policy.PolicyData)
	if err != nil {
		log.Error(err)
		return &netmanage.VerifyPolicyResponse{false}, onet.NewClientErrorCode(ErrorVerifyPolicy, err.Error())
	}
	verr := s.cosiVerify(req.Roster, buf, req.Policy.CoSignature)
	if verr != nil {
		return &netmanage.VerifyPolicyResponse{false}, onet.NewClientErrorCode(ErrorVerifyPolicy, verr.Error())
	}
	return &netmanage.VerifyPolicyResponse{true}, nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) onet.Service {
	//fmt.Printf("!!!!! newService\n\n")
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		skipchainClient:  skipchain.NewClient(),
		cosiClient:       cosisign.NewClient(),
		Storage: &Storage{
			GenesisPolicy: skipchain.NewSkipBlock(),
			LatestPolicy:  skipchain.NewSkipBlock(),
		},
	}
	if err := s.RegisterHandlers(s.GenesisPolicyRequest, s.NewPolicyRequest, s.GetPolicyRequest, s.VerifyPolicyRequest); err != nil {
		log.ErrFatal(err, "Couldn't register messages")
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
	}

	return s
}

// Tries to load the configuration and updates the data in the service
// if it finds a valid config-file.
func (s *Service) tryLoad() error {
	s.Storage = &Storage{}
	if !s.DataAvailable(storageID) {
		return nil
	}
	msg, err := s.Load(storageID)
	if err != nil {
		return err
	}
	var ok bool
	s.Storage, ok = msg.(*Storage)
	if !ok {
		return errors.New("Data of wrong type")
	}
	return nil
}

//==========================================================just for service test=================================

//for test, write the policy into a file
func (s *Service) WritePolicyFile(policy *netmanage.CosiPolicy, pullPolicyFile string) error {
	//transform policy into JSON and write into file pullPolicyFile
	buf, err := json.Marshal(policy.PolicyData.Policy)
	if err != nil {
		fmt.Println("error:", err)
		return err
	}
	pubwr := new(bytes.Buffer)
	_, err = pubwr.Write(buf)
	if err := ioutil.WriteFile(pullPolicyFile, pubwr.Bytes(), 0660); err != nil {
		return err
	}
	pubwr.Reset()

	return nil
}

func (s *Service) WriteLatestID(hashFile string) error {
	//write the BlockID into a file for further test
	pubwr := new(bytes.Buffer)
	_, err := pubwr.WriteString("blockID = ")
	_, err = pubwr.WriteString("\"")
	hash := s.Storage.LatestPolicy.Hash
	//_, err = pubwr.Write(s.Storage.LatestPolicy.Hash)
	_, err = pubwr.WriteString(hex.EncodeToString(hash))
	_, err = pubwr.WriteString("\"")
	//fmt.Printf("WriteLatestID s.Storage.LatestPolicy.Hash = %s\n",string(s.Storage.LatestPolicy.Hash[:]))
	//fmt.Printf("WriteLatestID hex hash = %s\n",hex.EncodeToString(hash))
	if err := ioutil.WriteFile(hashFile, pubwr.Bytes(), 0660); err != nil {
		log.Errorf("Could not write BlockID to the file:", err)
	}
	pubwr.Reset()
	return err
}

func GenerateAmdinFiles(policyFile, signaturesFile, configFile, privFile string, adminNum int) error {
	//read the Policy json file, get a policy struct and turn it into bytes using network.Marshal, then we get the buf to be signed
	policy, err := NetPolicyScanner(policyFile)
	if err != nil {
		fmt.Printf("NetPolicyScanner err \n")
		log.Error(err)
		return err
	}
	for _, msg := range []interface{}{
		netmanage.Policy{},
	} {
		network.RegisterMessage(msg)
	}
	text, err := network.Marshal(policy)
	if err != nil {
		log.Error(err)
		return err
	}
	var developers openpgp.EntityList

	for i := 0; i < adminNum; i++ {
		entity, err := openpgp.NewEntity(strconv.Itoa(i), "", "", nil)
		developers = append(developers, entity)
		if err != nil {
			log.Errorf("PGP entity %+v has not been created %+v", i, err)
			return err
		}
	}
	// Writing threshold to a policy file
	pubwr := new(bytes.Buffer)
	_, err = pubwr.WriteString("threshold = ")
	_, err = pubwr.WriteString(strconv.Itoa(adminNum))
	_, err = pubwr.WriteString("\n\npublicKeys = [\n")
	if err := ioutil.WriteFile(configFile, pubwr.Bytes(), 0660); err != nil {
		log.Errorf("Could not write thresold value to the file:", err)
		return err
	}
	pubwr.Reset()

	fpub, _ := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0660)
	defer fpub.Close()
	fpriv, _ := os.OpenFile(privFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0660)
	defer fpriv.Close()
	fpriv.WriteString("Entities = [\n")
	//ÃÂ¥ÃÂ¾ÃÂªÃÂ§ÃÂÃÂ¯ÃÂ§ÃÂÃÂÃÂ¦ÃÂÃÂÃÂ¦ÃÂ¯ÃÂÃÂ¤ÃÂ¸ÃÂªdeveloperÃÂ§ÃÂÃÂÃÂ¥ÃÂÃÂ¬ÃÂ©ÃÂÃÂ¥ÃÂ¥ÃÂÃÂÃÂ¥ÃÂÃÂ¥fpub, ÃÂ§ÃÂÃÂÃÂ¦ÃÂÃÂÃÂ§ÃÂ§ÃÂÃÂ©ÃÂÃÂ¥ÃÂ¥ÃÂÃÂÃÂ¨ÃÂ¿ÃÂfpriv,
	for i, entity := range developers {
		// Saving private and public keys
		privwr := new(bytes.Buffer)
		privarmor, _ := armor.Encode(privwr, openpgp.PrivateKeyType, nil)
		pubarmor, _ := armor.Encode(pubwr, openpgp.PublicKeyType, nil)
		if err := entity.SerializePrivate(privarmor, nil); err != nil {
			log.Errorf("Problem with serializing private key:", err)
			return err
		}
		if err := entity.Serialize(pubarmor); err != nil {
			log.Error("Problem with serializing public key:", err)
			return err
		}
		privarmor.Close()
		pubarmor.Close()

		fpriv.WriteString("\"\"\"")
		fpub.WriteString("\"\"\"")
		if i != len(developers)-1 {
			pubwr.Write([]byte("\n\"\"\",\n"))
			privwr.Write([]byte("\n\"\"\",\n"))
		} else {
			pubwr.Write([]byte("\n\"\"\"]"))
			privwr.Write([]byte("\n\"\"\"]"))
		}

		if _, err := fpriv.Write(privwr.Bytes()); err != nil {
			log.Error("Could not write privates key to a file:", err)
			return err
		}
		if _, err := fpub.Write(pubwr.Bytes()); err != nil {
			log.Error("Could not write a public key to policy file:", err)
			return err
		}
		privwr.Reset()
		pubwr.Reset()
	}
	for _, entity := range developers {
		//ÃÂ§ÃÂÃÂ¨ÃÂ¥ÃÂ®ÃÂÃÂ¤ÃÂ½ÃÂentityÃÂ§ÃÂÃÂÃÂ§ÃÂ§ÃÂÃÂ©ÃÂÃÂ¥sign textÃÂ¯ÃÂ¼ÃÂÃÂ¥ÃÂ­ÃÂÃÂ¥ÃÂÃÂ¨pubwrÃÂ©ÃÂÃÂÃÂ¯ÃÂ¼ÃÂÃÂ§ÃÂÃÂÃÂ¦ÃÂÃÂsignatures.txtÃÂ¦ÃÂÃÂÃÂ¤ÃÂ»ÃÂ¶
		openpgp.ArmoredDetachSign(pubwr, entity, bytes.NewReader(text), nil)
		pubwr.WriteByte(byte('\n'))
	}

	err = ioutil.WriteFile(signaturesFile, pubwr.Bytes(), 0660)
	if err != nil {
		log.Error("Could not write to a signatures file", err)
		return err
	}

	return nil
}

//create a partial GenesisPolicyRequest struct from the files
func GenerateGenesisPolicy(policyFile, signaturesFile, configFile string) (*netmanage.PolicyData, []string, error) {
	//policyFile and configFile for policyData {Policy, Conf}
	policy, err := NetPolicyScanner(policyFile)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}

	conf, err := ConfScanner(configFile)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}

	//signaturesFile for Signatures []string
	signatures, err := SigScanner(signaturesFile)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	//fmt.Printf("GenerateGenesisPolicy policy%v\n",policy)
	//fmt.Printf("GenerateGenesisPolicy conf pub0 = %s\n",conf.PubKeys[0])
	//fmt.Printf("GenerateGenesisPolicy signatures%v\n",signatures)
	return &netmanage.PolicyData{Policy: policy, Conf: conf}, signatures, nil
}

//create a partial NewPolicyRequest struct from the files
func GenerateNewPolicy(policyFile, signaturesFile, configFile, HashFile string) (*netmanage.PolicyData, []string, skipchain.SkipBlockID, error) {
	//policyFile and configFile for policyData {Policy, Conf}
	policy, err := NetPolicyScanner(policyFile)
	if err != nil {
		log.Error(err)
		return nil, nil, nil, err
	}

	conf, err := ConfScanner(configFile)
	if err != nil {
		log.Error(err)
		return nil, nil, nil, err
	}

	//signaturesFile for Signatures []string
	signatures, err := SigScanner(signaturesFile)
	if err != nil {
		log.Error(err)
		return nil, nil, nil, err
	}
	//fmt.Printf("GenerateGenesisPolicy policy%v\n",policy)
	//fmt.Printf("GenerateGenesisPolicy conf pub0 = %s\n",conf.PubKeys[0])
	//fmt.Printf("GenerateGenesisPolicy signatures%v\n",signatures)

	//parentIDFile for ParentBlockID skipchain.SkipBlockID
	parentBlockID, err := HashScanner(HashFile)
	if err != nil {
		log.Error(err)
		return nil, nil, nil, err
	}
	//fmt.Printf("NewPolicyRequest parentBlockID %s\n", string(parentBlockID[:]))
	return &netmanage.PolicyData{Policy: policy, Conf: conf}, signatures, parentBlockID, nil
}
