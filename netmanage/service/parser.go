package service

import (
	"bufio"
	"os"
	"strings"
	"fmt"

	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v1/log"
	
	"github.com/dedis/netmanage"
	"io/ioutil"
	"encoding/json"
	"github.com/dedis/cothority/skipchain"
	"encoding/hex"
)

// Scanner for a file containing signatures, return sig array
func SigScanner(filename string) ([]string, error) {
	var blocks []string
	head := "-----BEGIN PGP SIGNATURE-----"
	log.Lvl2("Reading file", filename)

	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		log.Errorf("Couldn't open file", file, err)
		return nil, err
	}

	scanner := bufio.NewScanner(file)
	var block []string
	for scanner.Scan() {
		text := scanner.Text()
		log.Lvl4("Decoding", text)
		// end of the first part
		if text == head {
			log.Lvl4("Found header")
			if len(block) > 0 {
				blocks = append(blocks, strings.Join(block, "\n"))
				block = make([]string, 0)
			}
		}
		block = append(block, text)
	}
	blocks = append(blocks, strings.Join(block, "\n"))
	return blocks, nil
}

// Scanner for a configuration file containing threshold and public keys
func ConfScanner(filename string) (*netmanage.Conf, error) {
	type confToml struct {
		Threshold  int
		PublicKeys []string
	}
	var c confToml
	//fmt.Printf("ConfScanner@@@@@@@@@@@@\n")
	log.Lvl3("Reading file", filename)
	meta, err := toml.DecodeFile(filename, &c)
	if err != nil {
		log.Fatal(err)
	}
	
	log.Lvlf4("Fields of the configuration are %+v", meta.Keys())
	
	conf := &netmanage.Conf{Threshold: c.Threshold, PubKeys:c.PublicKeys}
	//fmt.Printf("ConfScanner conf threshold = %d\n",conf.Threshold)
	//fmt.Printf("ConfScanner conf pub0 = %s\n",conf.PubKeys[0])
	return conf, err
}

// Scanner for a file containing a network policy (the policy file is made manually)
//return a Policydata struct and its bytes to be signed
func NetPolicyScanner(filename string) (*netmanage.Policy, error) {
//read the Policy json file, get a policy struct and turn it into bytes using network.Marshal, then we get the buf to be signed	
	raw, err := ioutil.ReadFile(filename)
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
	var policy netmanage.Policy
	err = json.Unmarshal(raw, &policy)
	if err != nil {
		fmt.Println("error:", err)
		log.Fatal(err)
	}
	//fmt.Printf(policy.Rules[0].Match.Dports+"\n")
	//fmt.Printf(policy.Rules[2].Match.Sports+"\n")
	return &policy, err
}


func HashScanner(filename string) (skipchain.SkipBlockID, error) {
	type hashToml struct {
		BlockID string
	}
	var hash hashToml

	log.Lvl3("Reading file", filename)
	_, err := toml.DecodeFile(filename, &hash)
	if err != nil {
		log.Lvlf1("Could not decode a toml release file", err)
	}
	//fmt.Printf("HashScanner  BlockID %s\n", hash.BlockID)
	parentID, err := hex.DecodeString(hash.BlockID)
	if err != nil {
		return nil, err
	}
	return parentID, nil
}