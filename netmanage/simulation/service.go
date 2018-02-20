package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/netmanage"
	netservice "github.com/dedis/netmanage/service"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/simul/monitor"
	"fmt"
)

/*
 * Defines the simulation for the service-netmanage
 */

func init() {
	onet.SimulationRegister("NetManageService", NewSimulationService)
}

// SimulationService only holds the BFTree simulation
type SimulationService struct {
	onet.SimulationBFTree
	BaseHeight             int
	MaxHeight              int
	AdminNum			   int
}

// NewSimulationService returns the new simulation, where all fields are
// initialised using the config-file
func NewSimulationService(config string) (onet.Simulation, error) {
	//fmt.Printf("00000000 NewSimulationService\n")
	es := &SimulationService{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
// This has to initialise all necessary files and copy them to the
// 'dir'-directory. This directory will be accessible to all simulated hosts.
func (s *SimulationService) Setup(dir string, hosts []string) (
	*onet.SimulationConfig, error) {
	//fmt.Printf("11111111111 Setup dir =%s\n",dir)
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	
	//在这里准备数据，该有的文件，就是Policy的吧。。应该是生成config、sig File后面用吧
	err = app.Copy(dir, "netPolicy1.json")
	if err != nil {
		return nil, err
	}
	err = app.Copy(dir, "netPolicy2.json")
	if err != nil {
		return nil, err
	}
	
	return sc, nil
}

// Node can be used to initialize each node before it will be run
// by the server. Here we call the 'Node'-method of the
// SimulationBFTree structure which will load the roster- and the
// tree-structure to speed up the first round.
func (s *SimulationService) Node(config *onet.SimulationConfig) error {
	//fmt.Printf("222222222222 Node\n")
	index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

// Run is used on the destination machines and runs a number of
// rounds
func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	//fmt.Printf("33333333333333 Run\n")
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", s.Rounds)
	
	// check if the service is running and get an handle to it
	service, ok := config.GetService(netservice.ServiceName).(*netservice.Service)
	if service == nil || !ok {
		fmt.Printf("33333333333333 Run generate service not OK 000000000000\n")
		log.Fatal("Didn't find service", netservice.ServiceName)
	}
	//measure genesisPolicy, newPolicy, getPolicy, verify time
	//prepare data and file
	policyFile := "netPolicy1.json"
	signaturesFile := "signatures1.txt"
	configFile := "config1.toml"
	privFile := "privatering1.txt"


	hashFile1 := "blockID1.toml"

	policyFile2 := "netPolicy2.json"
	signaturesFile2 := "signatures2.txt"
	configFile2 := "config2.toml"
	privFile2 := "privatering2.txt"
	
	//simulate admins make policy files, conf files  and sign policy files into signaturesFile
	err := netservice.GenerateAmdinFiles(policyFile, signaturesFile, configFile, privFile, s.AdminNum)
	if err != nil {
		fmt.Printf("run GenerateAmdinFiles fail\n") 
		return err
	}
	err = netservice.GenerateAmdinFiles(policyFile2, signaturesFile2, configFile2, privFile2, s.AdminNum)
	if err != nil {
		fmt.Printf("run GenerateAmdinFiles fail\n") 
		return err
	}
	
	gdata, gsigs, err := netservice.GenerateGenesisPolicy(policyFile,signaturesFile,configFile)
	
	for round := 0; round < s.Rounds; round++ {
		log.Lvl1("Starting round", round)
		roundGenesis := monitor.NewTimeMeasure("GenesisPolicyRequest")
		ioGenesis := monitor.NewCounterIOMeasure("GenesisPolicyRequest",config.Server)
		log.Lvl2("Sending GenerateGenesisPolicy request to", service)
		_, err = service.GenesisPolicyRequest(&netmanage.GenesisPolicyRequest{Roster: config.Roster, PolicyData: gdata, BaseH: s.BaseHeight, MaxH: s.MaxHeight, Signatures: gsigs})
		log.ErrFatal(err)			
		roundGenesis.Record()
		ioGenesis.Record()
		
		service.WriteLatestID(hashFile1)
		newdata, newsigs, parentID, err := netservice.GenerateNewPolicy(policyFile2, signaturesFile2, configFile2, hashFile1)
		
		roundNewPolicy := monitor.NewTimeMeasure("NewPolicyRequest")
		ioNewPolicy := monitor.NewCounterIOMeasure("NewPolicyRequest",config.Server)
		_, err = service.NewPolicyRequest(
		&netmanage.NewPolicyRequest{Roster: config.Roster, PolicyData: newdata, Signatures: newsigs, ParentBlockID:parentID})
		log.ErrFatal(err)
		roundNewPolicy.Record()
		ioNewPolicy.Record()
		
		roundGetPolicy := monitor.NewTimeMeasure("GetPolicyRequest")
		ioGetPolicy := monitor.NewCounterIOMeasure("GetPolicyRequest",config.Server)
		latest, err := service.GetPolicyRequest(&netmanage.GetPolicyRequest{})
		log.ErrFatal(err)
		roundGetPolicy.Record()
		ioGetPolicy.Record()
		
		roundVerifyPolicy := monitor.NewTimeMeasure("VerifyPolicyRequest")
		ioVerifyPolicy := monitor.NewCounterIOMeasure("VerifyPolicyRequest",config.Server)
		_, err = service.VerifyPolicyRequest(&netmanage.VerifyPolicyRequest{Roster: config.Roster, Policy: latest.CosiPolicy})
		log.ErrFatal(err)
		roundVerifyPolicy.Record()	
		ioVerifyPolicy.Record()
	}
	return nil	
}
