package service

import (
	"testing"

	"fmt"
	//"github.com/dedis/cothority/skipchain"
	//cosi "github.com/dedis/cothority/cosi/service"
	"github.com/dedis/netmanage"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	//"encoding/hex"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestService_All(t *testing.T) {
	local := onet.NewTCPTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	policyFile := "net_policy_1.json"
	signaturesFile := "signatures.txt"
	configFile := "config.toml"
	privFile := "privatering.txt"

	hashFile1 := "blockID1.toml"

	policyFile2 := "net_policy_2.json"
	signaturesFile2 := "signatures2.txt"
	configFile2 := "config2.toml"
	privFile2 := "privatering2.txt"

	adminNum := 500

	//admin app, simulate admins make policy files, conf files  and sign policy files into signaturesFile
	GenerateAmdinFiles(policyFile, signaturesFile, configFile, privFile, adminNum)
	GenerateAmdinFiles(policyFile2, signaturesFile2, configFile2, privFile2, adminNum)

	//from here, it belongs to the client api. Given the 3 files, send a policy request

	//åapi.goéï¼ç¶åå¨api_testéæµè¯
	//å¥½ååºè¯¥å¨clientéåä¸ä¸ªGenesiså½æ°ï¼è¾å¥æ¯è¿ä¸ä¸ªæä»¶åï¼åä¸ä¸ªè¿åçhashæä»¶åï¼æhashåå°æä»¶é
	//ååä¸ä¸ªnewpolicyå½æ°ï¼è¾å¥æ¯è¿ä¸ä¸ªæä»¶å+ä¸ä¸ªparentHashæä»¶åï¼å¦å¤ä¸ä¸ªè¿åçhashæä»¶å
	gdata, gsigs, err := GenerateGenesisPolicy(policyFile, signaturesFile, configFile)

	//TestAdminæçææä»¶çè¿ç¨åå°api_testéï¼ä½ä¸åå«å¨clientéï¼åªæ¯testéçè¾å©å½æ°ï¼ç¨æ¥æ¨¡æadminçè¡ä¸º

	//apiè¿åºè¯¥ægetPolicy, verifyPolicyè¿ä¸¤ä¸ªå½æ°ï¼ç¶åå¨testé
	services := local.GetServices(hosts, netManageID)
	log.ErrFatal(err)

	s := services[0]
	log.Lvl2("Sending request to", s)
	resp, err := s.(*Service).GenesisPolicyRequest(
		&netmanage.GenesisPolicyRequest{Roster: roster, PolicyData: gdata, BaseH: 2, MaxH: 2, Signatures: gsigs})
	log.ErrFatal(err)
	_, msg, merr := network.Unmarshal(resp.GenesisBlock.SkipBlockFix.Data)
	log.ErrFatal(merr)
	rst := msg.(*netmanage.CosiPolicy)
	assert.Equal(t, rst.PolicyData.Policy.Num, 4)
	assert.Equal(t, resp.BlockID, resp.GenesisBlock.Hash)
	fmt.Printf("00000000 TestService_GenesisPolicyRequest end\n")

	s.(*Service).WriteLatestID(hashFile1)

	newdata, newsigs, parentID, err := GenerateNewPolicy(policyFile2, signaturesFile2, configFile2, hashFile1)
	//fmt.Printf("22222222222 parentID %s\n", hex.EncodeToString(parentID))
	respn, errn := s.(*Service).NewPolicyRequest(
		&netmanage.NewPolicyRequest{Roster: roster, PolicyData: newdata, Signatures: newsigs, ParentBlockID: parentID})
	log.ErrFatal(errn)
	_, msgn, merrn := network.Unmarshal(respn.LatestBlock.SkipBlockFix.Data)
	log.ErrFatal(merrn)
	rstn := msgn.(*netmanage.CosiPolicy)
	assert.Equal(t, rstn.PolicyData.Policy.Num, newdata.Policy.Num)
	assert.Equal(t, rstn.PolicyData.Policy.Num, 5)
	assert.Equal(t, respn.BlockID, respn.LatestBlock.Hash)
	fmt.Printf("1111111111 TestService_NewPolicyRequest end\n")

	latest, err := s.(*Service).GetPolicyRequest(
		&netmanage.GetPolicyRequest{})
	log.ErrFatal(err)
	rstg := latest.CosiPolicy
	assert.Equal(t, rstg.PolicyData.Policy.Num, newdata.Policy.Num)
	assert.Equal(t, rstg.PolicyData.Policy.Num, 5)

	fmt.Printf("22222222222 TestService_GetPolicyRequest end\n")

	respv, err := s.(*Service).VerifyPolicyRequest(&netmanage.VerifyPolicyRequest{Roster: roster, Policy: rstg})
	log.ErrFatal(err)
	assert.Equal(t, respv.IsValid, true)

	fmt.Printf("3333333333 TestService_VerifyPolicy end\n")

	pullPolicyFile := "latest_policy.json"
	err = s.(*Service).WritePolicyFile(rstg, pullPolicyFile)
	assert.Equal(t, err, nil)
}

/*
func TestService_GenesisPolicyRequest(t *testing.T) {
	local := onet.NewTCPTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	policyFile := "net_policy_1.json"
	signaturesFile := "signatures.txt"
	configFile := "config.toml"
	privFile := "privatering.txt"
	adminNum := 5

	GenerateAmdinFiles(policyFile, signaturesFile, configFile, privFile, adminNum)
	policyData, sigs, err := GenerateGenesisPolicy(policyFile,signaturesFile,configFile)

	services := local.GetServices(hosts, netManageID)

	s := services[0]
		assert.Equal(t, err, nil)
		log.Lvl2("Sending request to", s)
		resp, err := s.(*Service).GenesisPolicyRequest(
			&netmanage.GenesisPolicyRequest{Roster: roster, PolicyData: policyData, BaseH: 2, MaxH: 2, Signatures: sigs})
		log.ErrFatal(err)
		_, msg, merr := network.Unmarshal(resp.GenesisBlock.SkipBlockFix.Data)
		log.ErrFatal(merr)
		rst := msg.(*netmanage.CosiPolicy)
		assert.Equal(t, rst.PolicyData.Policy.Num, 4)
		assert.Equal(t, resp.BlockID, resp.GenesisBlock.Hash)

	fmt.Printf("00000000 TestService_GenesisPolicyRequest end\n")
}


func TestService_NewPolicyRequest(t *testing.T) {
	local := onet.NewTCPTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	policyFile := "net_policy_1.json"
	signaturesFile := "signatures.txt"
	configFile := "config.toml"
	privFile := "privatering.txt"

	hashFile1 := "blockID1.toml"

	policyFile2 := "net_policy_2.json"
	signaturesFile2 := "signatures2.txt"
	configFile2 := "config2.toml"
	privFile2 := "privatering2.txt"

	adminNum := 5

	GenerateAmdinFiles(policyFile, signaturesFile, configFile, privFile, adminNum)
	GenerateAmdinFiles(policyFile2, signaturesFile2, configFile2, privFile2, adminNum)

	gdata, gsigs, err := GenerateGenesisPolicy(policyFile,signaturesFile,configFile)

	services := local.GetServices(hosts, netManageID)
	log.ErrFatal(err)

	//for _, s := range services {
		s := services[0]
		log.Lvl2("Sending request to", s)
		s.(*Service).GenesisPolicyRequest(
			&netmanage.GenesisPolicyRequest{Roster: roster, PolicyData: gdata, BaseH: 2, MaxH: 2, Signatures: gsigs})
		s.(*Service).WriteLatestID(hashFile1)
		newdata, newsigs, parentID, err := GenerateNewPolicy(policyFile2,signaturesFile2, configFile2, hashFile1)
		fmt.Printf("22222222222 parentID %s\n", hex.EncodeToString(parentID))
		resp, err := s.(*Service).NewPolicyRequest(
			&netmanage.NewPolicyRequest{Roster: roster, PolicyData: newdata, Signatures: newsigs, ParentBlockID:parentID})
		log.ErrFatal(err)
		_, msg, merr := network.Unmarshal(resp.LatestBlock.SkipBlockFix.Data)
		log.ErrFatal(merr)
		rst := msg.(*netmanage.CosiPolicy)
		assert.Equal(t, rst.PolicyData.Policy.Num, newdata.Policy.Num)
		assert.Equal(t, rst.PolicyData.Policy.Num, 5)
		assert.Equal(t, resp.BlockID, resp.LatestBlock.Hash)
	//}
	fmt.Printf("1111111111 TestService_NewPolicyRequest end\n")
}

func TestService_VerifyPolicy(t *testing.T) {
	local := onet.NewTCPTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	policyFile := "net_policy_1.json"
	signaturesFile := "signatures.txt"
	configFile := "config.toml"
	privFile := "privatering.txt"

	hashFile1 := "blockID1.toml"

	policyFile2 := "net_policy_2.json"
	signaturesFile2 := "signatures2.txt"
	configFile2 := "config2.toml"
	privFile2 := "privatering2.txt"

	adminNum := 5

	GenerateAmdinFiles(policyFile, signaturesFile, configFile, privFile, adminNum)
	GenerateAmdinFiles(policyFile2, signaturesFile2, configFile2, privFile2, adminNum)

	gdata, gsigs, err := GenerateGenesisPolicy(policyFile,signaturesFile,configFile)

	services := local.GetServices(hosts, netManageID)
	log.ErrFatal(err)

		s := services[0]
		log.Lvl2("Sending request to", s)
		s.(*Service).GenesisPolicyRequest(
			&netmanage.GenesisPolicyRequest{Roster: roster, PolicyData: gdata, BaseH: 2, MaxH: 2, Signatures: gsigs})
		s.(*Service).WriteLatestID(hashFile1)
		newdata, newsigs, parentID, err := GenerateNewPolicy(policyFile2,signaturesFile2, configFile2, hashFile1)
		fmt.Printf("22222222222 parentID %s\n", hex.EncodeToString(parentID))
		s.(*Service).NewPolicyRequest(
			&netmanage.NewPolicyRequest{Roster: roster, PolicyData: newdata, Signatures: newsigs, ParentBlockID:parentID})
		log.ErrFatal(err)

		latest, err := s.(*Service).GetPolicyRequest(
			&netmanage.GetPolicyRequest{})
		log.ErrFatal(err)

		rst := latest.CosiPolicy

		cosiPolicy2 := latest.CosiPolicy

		assert.Equal(t, cosiPolicy2.PolicyData.Policy.Num, 5)
		assert.Equal(t, cosiPolicy2.PolicyData.Policy.Rules[0].Match.Dports, "999,1000")

		verr := s.(*Service).VerifyPolicy(roster, cosiPolicy2)
		assert.Equal(t,verr, nil)


		cosifake := &netmanage.CosiPolicy{PolicyData: b1data, CoSignature: cosiPolicy2.CoSignature}
		verr2 := s.(*Service).VerifyPolicy(roster, cosifake)
		fmt.Println(verr2.Error())


		cositest := &netmanage.CosiPolicy{PolicyData: cosiPolicy2.PolicyData, CoSignature: cosiPolicy2.CoSignature}
		verr3 := s.(*Service).VerifyPolicy(roster, cositest)
		assert.Equal(t,verr3, nil)

		cosiPolicy1 := s.(*Service).SignPolicyData(roster, b1data)
		cositt := &netmanage.CosiPolicy{cosiPolicy1.PolicyData, cosiPolicy2.CoSignature}
		verr4 := s.(*Service).VerifyPolicy(roster, cositt)
		fmt.Println(verr4.Error())
	}
}

/*
func TestService_cosi(t *testing.T) {
	local := onet.NewTCPTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()
	testData := []byte("Test data")

	services := local.GetServices(hosts, netManageID)

	for _, s := range services {
		log.Lvl2("Sending request to", s)
		resp := s.(*Service).cosiSign(roster, testData)
		terr := s.(*Service).cosiVerify(roster, testData, resp)
		assert.Equal(t, terr, nil)
	}
}
*/
