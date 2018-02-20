package netmanage

/*
The api.go defines the methods that can be called from the outside. Most
of the methods will take a roster so that the service knows which nodes
it should work with.

This part of the service runs on the client or the app.
*/

import (
	"github.com/dedis/cothority/skipchain"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	//"github.com/dedis/netmanage/parsers"
	//"gopkg.in/dedis/onet.v1/network"
	"io/ioutil"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"bytes"
)

const ServiceName = "NetManage"

// Client is a structure to communicate with the CoSi
// service
type Client struct {
	*onet.Client
}

// NewClient instantiates a new netmanage.Client
func NewClient() *Client {
	return &Client{Client: onet.NewClient(ServiceName)}
}

func (c *Client) GenesisPolicyFromFiles(r *onet.Roster, policyFile, signaturesFile, configFile, outputHashFile string, baseH, maxH int) (*GenesisPolicyResponse, onet.ClientError) {
	//policyFile and configFile for policyData {Policy, Conf} 
	policy, err := NetPolicyScanner(policyFile)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
		//return nil, onet.NewClientErrorCode(ErrorSignPolicy, err.Error())
	}
	
	conf, err := ConfScanner(configFile)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
	}
	
	//signaturesFile for Signatures []string
	signatures, err := SigScanner(signaturesFile)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
	}
	//fmt.Printf("GenerateGenesisPolicy policy%v\n",policy)
	//fmt.Printf("GenerateGenesisPolicy conf pub0 = %s\n",conf.PubKeys[0])
	//fmt.Printf("GenerateGenesisPolicy signatures%v\n",signatures)
	policyData := &PolicyData{Policy: policy, Conf: conf}
	
	genesisResponse, cerr := c.GenesisPolicyRequest(r, policyData, signatures, baseH, maxH)
	if cerr != nil {
		return nil, cerr
	}
	
	//write the BlockID (hash) into outputHashFile
	pubwr := new(bytes.Buffer)
	_, err = pubwr.WriteString("blockID = ")
	_, err = pubwr.WriteString("\"")
	hash := genesisResponse.BlockID
	//_, err = pubwr.Write(s.storage.LatestPolicy.Hash)
	_, err = pubwr.WriteString(hex.EncodeToString(hash))
	_, err = pubwr.WriteString("\"")
	//fmt.Printf("WriteLatestID s.storage.LatestPolicy.Hash = %s\n",string(s.storage.LatestPolicy.Hash[:]))
	//fmt.Printf("WriteLatestID hex hash = %s\n",hex.EncodeToString(hash))
	if err := ioutil.WriteFile(outputHashFile, pubwr.Bytes(), 0660); err != nil {
		fmt.Printf("Could not write BlockID to the file: %s\n", err.Error())
	}
	pubwr.Reset()
	
	return genesisResponse, nil
}

func (c *Client) GenesisPolicyRequest(r *onet.Roster, data *PolicyData, signatures []string, baseH, maxH int) (*GenesisPolicyResponse, onet.ClientError) {
	//dst := r.RandomServerIdentity()
	dst := r.Get(0)
	log.Lvl4("Sending GenesisPolicyRequest message to", dst)
	reply := &GenesisPolicyResponse{}
	err := c.SendProtobuf(dst, &GenesisPolicyRequest{Roster: r, PolicyData: data, BaseH: baseH, MaxH: maxH, Signatures:signatures}, reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) NewPolicyFromFiles(r *onet.Roster, policyFile, signaturesFile, configFile, parentHashFile, outputHashFile string) (*NewPolicyResponse, onet.ClientError) {
	//policyFile and configFile for policyData {Policy, Conf} 
	policy, err := NetPolicyScanner(policyFile)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
	}
	
	conf, err := ConfScanner(configFile)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
	}
	
	//signaturesFile for Signatures []string
	signatures, err := SigScanner(signaturesFile)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
	}
	
	parentBlockID, err := HashScanner(parentHashFile)
	if err != nil {
		log.Error(err)
		return nil, onet.NewClientError(err)
	}
	//fmt.Printf("GenerateGenesisPolicy policy%v\n",policy)
	//fmt.Printf("GenerateGenesisPolicy conf pub0 = %s\n",conf.PubKeys[0])
	//fmt.Printf("GenerateGenesisPolicy signatures%v\n",signatures)
	policyData := &PolicyData{Policy: policy, Conf: conf}
	
	newPolicyResponse, cerr := c.NewPolicyRequest(r, policyData, signatures, parentBlockID)
	if cerr != nil {
		return nil, cerr
	}
	
	//write the BlockID (hash) into outputHashFile
	pubwr := new(bytes.Buffer)
	_, err = pubwr.WriteString("blockID = ")
	_, err = pubwr.WriteString("\"")
	hash := newPolicyResponse.BlockID
	//_, err = pubwr.Write(s.storage.LatestPolicy.Hash)
	_, err = pubwr.WriteString(hex.EncodeToString(hash))
	_, err = pubwr.WriteString("\"")
	//fmt.Printf("WriteLatestID s.storage.LatestPolicy.Hash = %s\n",string(s.storage.LatestPolicy.Hash[:]))
	//fmt.Printf("WriteLatestID hex hash = %s\n",hex.EncodeToString(hash))
	if err := ioutil.WriteFile(outputHashFile, pubwr.Bytes(), 0660); err != nil {
		fmt.Printf("Could not write BlockID to the file: %s\n", err.Error())
	}
	pubwr.Reset()
	
	return newPolicyResponse, nil
}

func (c *Client) NewPolicyRequest(r *onet.Roster, data *PolicyData, signatures []string, parentBlockID skipchain.SkipBlockID) (*NewPolicyResponse, onet.ClientError) {
	//dst := r.RandomServerIdentity()
	dst := r.Get(0)
	log.Lvl4("Sending NewPolicyRequest message to", dst)
	reply := &NewPolicyResponse{}
	err := c.SendProtobuf(dst, &NewPolicyRequest{Roster: r, PolicyData: data, Signatures:signatures, ParentBlockID: parentBlockID}, reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

//===================================below are for follower routers=============================
//get the latest block from roster R
func (c *Client) GetPolicyRequest(r *onet.Roster) (*CosiPolicy, onet.ClientError) {
	//dst := r.RandomServerIdentity()
	dst := r.Get(0)
	
	log.Lvl4("Sending GetPolicyRequest message to", dst)
	reply := &GetPolicyResponse{}
	//fmt.Printf("client GetPolicyRequest 0000000000000\n")
	err := c.SendProtobuf(dst, &GetPolicyRequest{}, reply)
	if err != nil {
		fmt.Printf("client GetPolicyRequest SendProtobuf err \n")
		return nil, err
	}
	
	/*
	_, msg, merr := network.Unmarshal(reply.BytesCosiPolicy)
	fmt.Printf("client 22222222222\n")
	if merr != nil {
		fmt.Printf("client 333333333333\n")
		log.ErrFatal(merr)
		return nil, onet.NewClientError(merr)
	}
	fmt.Printf("client 44444444444\n")
	data := msg.(*CosiPolicy)
	return data, nil
	*/
	
	return reply.CosiPolicy, nil
}

//only if nil, nil, the policy is valid
func (c *Client) VerifyPolicyRequest(r *onet.Roster, policy *CosiPolicy) (*VerifyPolicyResponse, onet.ClientError){
	//dst := r.RandomServerIdentity()
	dst := r.Get(0)
	//dst := r.List[0]
	
	log.Lvl4("Sending VerifyPolicyRequest message to", dst)
	reply := &VerifyPolicyResponse{}
	//fmt.Printf("api VerifyPolicyRequest 111111111111 \n")
	req := VerifyPolicyRequest{Roster: r, Policy: policy}
	err := c.SendProtobuf(dst, &req, reply)
	//fmt.Printf("api VerifyPolicyRequest 22222222222 \n")
	if err != nil {
	fmt.Printf("api VerifyPolicyRequest 33333333333 \n")
		return nil, err
	}
	//fmt.Printf("api VerifyPolicyRequest &&&&&&&&&&&&&&&&&\n")
	return reply, nil
}

//write one policy to file
func WritePolicyFile(policy *CosiPolicy, pullPolicyFile string) error {
	//transform policy into JSON and write into file pullPolicyFile
	buf, err := json.Marshal(policy.PolicyData.Policy)
	if err != nil {
		//fmt.Println("error:", err)
		return err
	}
	pubwr := new(bytes.Buffer)
	_, err = pubwr.Write(buf)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(pullPolicyFile, pubwr.Bytes(), 0660); err != nil {
		return err
	}
	pubwr.Reset()
	
	return nil
}
