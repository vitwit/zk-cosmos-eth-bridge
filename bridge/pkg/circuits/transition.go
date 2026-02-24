package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/circuits/ed25519"
)

// TransitionCircuit verifies that the old validator set has signed a new validator set hash.
type TransitionCircuit struct {
	// Public Inputs
	PackedOldValidatorsHash [4]frontend.Variable `gnark:",public"`
	PackedNewValidatorsHash [4]frontend.Variable `gnark:",public"`

	// Private Inputs (The Old Validator Set)
	VotingPowers []frontend.Variable
	PublicKeys   []ed25519.PublicKey
	TotalPower   frontend.Variable

	// Private Inputs (Anchor metadata for New Set)
	PackedNewBlockHash [4]frontend.Variable
	PackedNewDataHash  [4]frontend.Variable
	NewHeight          frontend.Variable

	// Private Inputs (The Signatures from the Old Set)
	Signatures []ed25519.Signature
	Signed     []frontend.Variable
}

func (c *TransitionCircuit) Define(api frontend.API) error {
	// 1. Setup EdDSA API
	eddsa, err := ed25519.NewEdDSA(api)
	if err != nil {
		return err
	}

	// Unpack OldValidatorsHash
	oldVhBytes := c.unpack(api, c.PackedOldValidatorsHash)
	u8Api, _ := uints.NewBytes(api)

	// Verify Old Set Hash
	sha, _ := sha2.New(api)
	for i := 0; i < MaxValidators; i++ {
		// Serialize PK (32-byte compressed format)
		pkBytes := eddsa.SerializePoint(c.PublicKeys[i].A)
		sha.Write(pkBytes[:])

		powerBits := api.ToBinary(c.VotingPowers[i], 64)
		sha.Write(bitsToU8(api, u8Api, powerBits))
	}

	actualOldHash := sha.Sum()
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(actualOldHash[i].Val, oldVhBytes[i].Val)
	}

	// 2. Verify that OldSet signed NewBlockHash
	newBhBytes := c.unpack(api, c.PackedNewBlockHash)

	// 2a. Link NewBlockHash to NewValidatorsHash (Simplified Anchor)
	// This ensures the message signed by OldSet actually commits to the NewSet.
	newVhBytes := c.unpack(api, c.PackedNewValidatorsHash)
	newDhBytes := c.unpack(api, c.PackedNewDataHash)
	headerSha, _ := sha2.New(api)
	headerSha.Write(newVhBytes)
	headerSha.Write(newDhBytes)
	heightBits := api.ToBinary(c.NewHeight, 64)
	headerSha.Write(bitsToU8(api, u8Api, heightBits))
	computedNewBH := headerSha.Sum()
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedNewBH[i].Val, newBhBytes[i].Val)
	}

	var signedPower frontend.Variable = 0
	var totalPowerCalculated frontend.Variable = 0

	for i := 0; i < MaxValidators; i++ {
		// Verify signature against NewBlockHash (conditionally)
		err = eddsa.Verify(c.Signatures[i], newBhBytes, c.PublicKeys[i], c.Signed[i])
		if err != nil {
			return err
		}

		api.AssertIsBoolean(c.Signed[i])
		totalPowerCalculated = api.Add(totalPowerCalculated, c.VotingPowers[i])
		signedPower = api.Add(signedPower, api.Select(c.Signed[i], c.VotingPowers[i], 0))
	}

	api.AssertIsEqual(totalPowerCalculated, c.TotalPower)

	// signedPower * 3 > totalPower * 2 (Strict majority)
	lhs := api.Mul(signedPower, 3)
	rhs := api.Mul(c.TotalPower, 2)
	comparator := cmp.NewBoundedComparator(api, big.NewInt(0).Lsh(big.NewInt(1), 128), false)
	api.AssertIsEqual(comparator.IsLess(rhs, lhs), 1)

	return nil
}

// unpack converts 4 x uint64 variables into 32 byte-sized variables.
func (c *TransitionCircuit) unpack(api frontend.API, packed [4]frontend.Variable) []uints.U8 {
	var res []uints.U8
	for i := 0; i < 4; i++ {
		bits := api.ToBinary(packed[i], 64)
		for j := 7; j >= 0; j-- {
			start := j * 8
			byteValue := api.FromBinary(bits[start : start+8]...)
			res = append(res, uints.U8{Val: byteValue})
		}
	}
	return res
}

// AllocateSlices initializes the circuit slices with MaxValidators capacity.
func (c *TransitionCircuit) AllocateSlices() {
	if MaxValidators <= 0 {
		fmt.Printf("⚠️  WARNING: MaxValidators is %d, defaulting to 1 for safety\n", MaxValidators)
		MaxValidators = 1
	}
	c.VotingPowers = make([]frontend.Variable, MaxValidators)
	c.PublicKeys = make([]ed25519.PublicKey, MaxValidators)
	c.Signatures = make([]ed25519.Signature, MaxValidators)
	c.Signed = make([]frontend.Variable, MaxValidators)
}
