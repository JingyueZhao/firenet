package netmanage

import (
	"github.com/dedis/cothority/skipchain"
	cosisign "github.com/dedis/cothority/cosi/service"
	//"github.com/satori/go.uuid"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

func init() {
	for _, msg := range []interface{}{
		GenesisPolicyRequest{}, GenesisPolicyResponse{},
		NewPolicyRequest{}, NewPolicyResponse{},
		GetPolicyRequest{}, GetPolicyResponse{},
		VerifyPolicyRequest{}, VerifyPolicyResponse{},
		Policy{}, 
		PolicyData{},
		CosiPolicy{},
	} {
		network.RegisterMessage(msg)
	}
}


//Policy is a self-efficient policy containing several network rules
//policy should be just a string??????????????
type Policy struct {
	Description string
	//number of rules it contains
	Num int
	Rules []Rule
}

//network rule
type Rule struct {
	Match *Match
	Action string
}

type Match struct {
	Chain string
	Protocol string
	Src string
	Sports string
	Dest string
	Dports string
}

//confFile contains the public keys of admins & signature threshold
type Conf struct {
	Threshold  int
	PubKeys    []string
}

type PolicyData struct {
	Policy *Policy
	Conf *Conf
	
	//just the hash of last policy, is it necessary??
	//lastPolicyHash string	
	
	//the merkle root of Policy, Conf and ParentHash,
	//hash but should be calculated when need to be signed, the admin (users) only need to provide the above 3 items
	//Merkleroot []byte
}

type CosiPolicy struct {
	PolicyData *PolicyData

	//cosi signature of the PolicyData's merkle root
	CoSignature *cosisign.SignatureResponse
}


type GenesisPolicyRequest struct {
	Roster *onet.Roster
	PolicyData   *PolicyData
	BaseH  int
	MaxH   int
	
	//admins' signatures of the PolicyData's merkle root
	Signatures []string
}

type GenesisPolicyResponse struct {
	GenesisBlock *skipchain.SkipBlock
	BlockID skipchain.SkipBlockID
}

//ignore this first: validate the PolicyData, if it is validated with threshold sigs of admins
//cosign Data, PolicyData -> CosiPolicy, save CosiPolicy into a block, append the block to the chain, and return the block
type NewPolicyRequest struct {
	Roster      *onet.Roster
	PolicyData        *PolicyData //data expected to be stored in a new block after validate and cosi
	
	//admins' signatures of the PolicyData's merkle root
	Signatures []string
	
	//which one is better? I think ParentBlockID is better. This is expected to be the latest block in the chain.
	ParentBlockID skipchain.SkipBlockID
	//LatestBlock *skipchain.SkipBlock
}

//return this new Policy block hash with CosiPolicy as its Data part
type NewPolicyResponse struct {
	BlockID skipchain.SkipBlockID
	LatestBlock *skipchain.SkipBlock
}

type GetPolicyRequest struct {
	//Roster *onet.Roster
	//KnownLatestID skipchain.SkipBlockID
}


type GetPolicyResponse struct {
	CosiPolicy *CosiPolicy
}

/*
type GetPolicyResponse struct {
	BytesCosiPolicy []byte
}*/

type VerifyPolicyRequest struct {
	Roster *onet.Roster
	Policy *CosiPolicy
}

type VerifyPolicyResponse struct {
	IsValid bool
}
