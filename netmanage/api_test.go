package netmanage_test

import (
	"testing"
	"os"
	"github.com/stretchr/testify/assert"
	"fmt"
	"bytes"
	"io/ioutil"
	"strconv"
	
	// We need to include the service so it is started.
	_ "github.com/dedis/netmanage/service"
	"github.com/dedis/netmanage"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestClient_All(t *testing.T) {
	nbr := 5
	local := onet.NewTCPTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, roster, _ := local.GenTree(nbr, true)
	defer local.CloseAll()
	
	policyFile1 := "netPolicy1.json"
	signaturesFile1 := "signatures.txt"
	configFile1 := "config.toml"
	privFile1 := "privatering.txt"
	outHashFile1 := "blockID1.toml"
	
	policyFile2 := "netPolicy2.json"
	signaturesFile2 := "signatures2.txt"
	configFile2 := "config2.toml"
	privFile2 := "privatering2.txt"
	outHashFile2 := "blockID2.toml"
	
	pullLatestPolicy := "latest_policy.json"
		
	adminNum := 5
	baseH := 2
	maxH := 2
	
	//===============================admins: request to append new policy to the chain=========================
	//admin behaviors simulation: make files
	GenerateAmdinFiles(policyFile1, signaturesFile1, configFile1, privFile1, adminNum)
	GenerateAmdinFiles(policyFile2, signaturesFile2, configFile2, privFile2, adminNum)
	
	//admin send request
	
	c := netmanage.NewClient()
	//GenesisPolicyFromFiles Test
	genesisResponse, err := c.GenesisPolicyFromFiles(roster, policyFile1,signaturesFile1,configFile1, outHashFile1, baseH, maxH)
	log.ErrFatal(err)
	_, msg, merr := network.Unmarshal(genesisResponse.GenesisBlock.SkipBlockFix.Data)
	log.ErrFatal(merr)
	rst := msg.(*netmanage.CosiPolicy)
	assert.Equal(t, rst.PolicyData.Policy.Num, 4)
	assert.Equal(t, genesisResponse.BlockID, genesisResponse.GenesisBlock.Hash)		
	fmt.Printf("11111111111 TestClient GenesisPolicyFromFiles end\n\n")		
	
	//NewPolicyFromFiles Test
	newPolicyResponse, err := c.NewPolicyFromFiles(roster, policyFile2, signaturesFile2, configFile2, outHashFile1, outHashFile2)
	log.ErrFatal(err)
	_, msgn, merrn := network.Unmarshal(newPolicyResponse.LatestBlock.SkipBlockFix.Data)
	log.ErrFatal(merrn)
	rstn := msgn.(*netmanage.CosiPolicy)
	//assert.Equal(t, rstn.PolicyData.Policy.Num, newdata.Policy.Num)
	assert.Equal(t, rstn.PolicyData.Policy.Num, 5)
	assert.Equal(t, newPolicyResponse.BlockID, newPolicyResponse.LatestBlock.Hash)
	fmt.Printf("22222222222 TestClient NewPolicyRequest end\n\n")
	
	
	//GetPolicyRequest Test
	latest, err := c.GetPolicyRequest(roster)
	//fmt.Printf("##########################\n")
	log.ErrFatal(err)
	//fmt.Printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$\n")
	//rstg := latest.CosiPolicy
	//fmt.Printf("***********************\n")
	//assert.Equal(t, latest.PolicyData.Policy.Num, newdata.Policy.Num)
	assert.Equal(t, latest.PolicyData.Policy.Num, 5)
	//fmt.Printf("latest is %s\n", latest.PolicyData.Policy.Rules[0].Match.Dports)
	fmt.Printf("333333333333 TestClient GetPolicyRequest end\n\n")
	
	//VerifyPolicyRequest Test
	//cosiPolicy := rstn
	respv, err := c.VerifyPolicyRequest(roster, latest)
	log.ErrFatal(err)
	assert.Equal(t,respv.IsValid, true)
	fmt.Printf("444444444444 TestClient VerifyPolicyRequest end\n\n")
	
	//WritePolicyFile Test
	werr := netmanage.WritePolicyFile(latest, pullLatestPolicy)
	assert.Equal(t, werr, nil)
	fmt.Printf("5555555555555 TestClient WritePolicyFile end\n")
}


//simulate admin behaviors: give policy json file and amdin numbers, make sig and conf file
func GenerateAmdinFiles(policyFile, signaturesFile, configFile, privFile string, adminNum int) {
	//read the Policy json file, get a policy struct and turn it into bytes using network.Marshal, then we get the buf to be signed
	policy, err := netmanage.NetPolicyScanner(policyFile)
	if err != nil {
		log.Error(err)
	}
	
	for _, msg := range []interface{}{
		netmanage.Policy{}, 
	} {
		network.RegisterMessage(msg)
	}
		
	text, err := network.Marshal(policy)
	if err != nil {
		log.Error(err)
	}

	var developers openpgp.EntityList

	for i := 0; i < adminNum; i++ {
		entity, err := openpgp.NewEntity(strconv.Itoa(i), "", "", nil)
		developers = append(developers, entity)
		if err != nil {
			log.Errorf("PGP entity %+v has not been created %+v", i, err)
		}
	}

	// Writing threshold to a policy file
	pubwr := new(bytes.Buffer)
	_, err = pubwr.WriteString("threshold = ")
	_, err = pubwr.WriteString(strconv.Itoa(adminNum))
	_, err = pubwr.WriteString("\n\npublicKeys = [\n")
	if err := ioutil.WriteFile(configFile, pubwr.Bytes(), 0660); err != nil {
		log.Errorf("Could not write thresold value to the file:", err)
	}
	pubwr.Reset()

	fpub, _ := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0660)
	defer fpub.Close()
	fpriv, _ := os.OpenFile(privFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0660)
	defer fpriv.Close()
	fpriv.WriteString("Entities = [\n")

	//generate each developer's public keys and write into fpub, generate private keys and write into fpriv
	for i, entity := range developers {
		// Saving private and public keys
		privwr := new(bytes.Buffer)
		privarmor, _ := armor.Encode(privwr, openpgp.PrivateKeyType, nil)
		pubarmor, _ := armor.Encode(pubwr, openpgp.PublicKeyType, nil)
		if err := entity.SerializePrivate(privarmor, nil); err != nil {
			log.Errorf("Problem with serializing private key:", err)
		}
		if err := entity.Serialize(pubarmor); err != nil {
			log.Error("Problem with serializing public key:", err)
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
		}
		if _, err := fpub.Write(pubwr.Bytes()); err != nil {
			log.Error("Could not write a public key to policy file:", err)
		}
		privwr.Reset()
		pubwr.Reset()
	}

	for _, entity := range developers {
		openpgp.ArmoredDetachSign(pubwr, entity, bytes.NewReader(text), nil)
		pubwr.WriteByte(byte('\n'))
	}

	err = ioutil.WriteFile(signaturesFile, pubwr.Bytes(), 0660)
	if err != nil {
		log.Error("Could not write to a signatures file", err)
	}
	
}