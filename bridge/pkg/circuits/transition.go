package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/circuits/ed25519"
)

// TransitionCircuit verifies that the old validator set has signed a new validator set hash.
type TransitionCircuit struct {
	// Public Inputs
	PackedOldValidatorsHash [4]frontend.Variable `gnark:",public"`
	PackedNewValidatorsHash [4]frontend.Variable `gnark:",public"`

	// Canonical Header Fields for the New Set (Leaves for the 14-field Merkle Tree)
	NewHeaderLeaves [14][32]uints.U8

	// Signing Metadata (matching the old set's commit to the new set)
	ChainID   []uints.U8
	BlockID   [32]uints.U8 // The New BlockID being signed
	Height    frontend.Variable
	Timestamp [12]uints.U8
	Round     frontend.Variable

	// SignBytes (Private Inputs for each validator's vote from the OLD set)
	SignBytes [][]uints.U8

	// Private Inputs (The Old Validator Set)
	VotingPowers       []frontend.Variable
	ProposerPriorities []frontend.Variable
	PublicKeys         []ed25519.PublicKey
	TotalPower         frontend.Variable
	ValidatorCount     frontend.Variable `gnark:",secret"`

	// Byte representations for bit-perfect ValidatorsHash reconstruction (of the OLD set)
	VotingPowerBytes      [][]uints.U8
	ProposerPriorityBytes [][]uints.U8

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

	// 1. Unpack OldValidatorsHash
	oldVhBytes := c.unpack(api, c.PackedOldValidatorsHash)
	comet := NewCometBFTGadget(api)

	// Verify Old Set Hash (Bit-Perfect)
	valHashes := make([][]uints.U8, MaxValidators)
	var prevAddr []uints.U8

	for i := 0; i < MaxValidators; i++ {
		// Serialize PK (Protobuf encoded)
		pkBytes := eddsa.SerializePoint(c.PublicKeys[i].A)
		protoPK := make([]uints.U8, 34)
		protoPK[0] = uints.U8{Val: 0x0a}
		protoPK[1] = uints.U8{Val: 0x20}
		for j := 0; j < 32; j++ {
			protoPK[2+j] = pkBytes[j]
		}

		// Address & Sorting
		addr := comet.ComputeAddress(pkBytes[:])
		if i > 0 {
			// Use VotingPower > 0 as a proxy for "part of the set"
			leftReal := api.IsZero(api.IsZero(c.VotingPowers[i-1]))
			rightReal := api.IsZero(api.IsZero(c.VotingPowers[i]))
			bothReal := api.And(leftReal, rightReal)

			checkSort := api.Select(bothReal, comet.IsLess(prevAddr, addr), 1)
			api.AssertIsEqual(checkSort, 1)
		}
		prevAddr = addr

		// 1. Decode Varint-encoded power and priority
		decodedPower, _ := comet.DecodeVarint(c.VotingPowerBytes[i])
		api.AssertIsEqual(decodedPower, c.VotingPowers[i])

		decodedPriority, _ := comet.DecodeVarint(c.ProposerPriorityBytes[i])
		api.AssertIsEqual(decodedPriority, c.ProposerPriorities[i])

		valHashes[i] = comet.HashValidator(addr, protoPK, c.VotingPowerBytes[i], c.ProposerPriorityBytes[i])
	}

	// 4. Verify the reconstructed OLD ValidatorsHash
	computedVH := comet.ValidatorsHash(valHashes, c.ValidatorCount)
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedVH[i].Val, oldVhBytes[i].Val)
	}

	// 2. Canonical Header Hash Verification for the NEW block
	var newLeaves [][]uints.U8
	for i := 0; i < 14; i++ {
		newLeaves = append(newLeaves, c.NewHeaderLeaves[i][:])
	}
	computedNewBH := comet.RFC6962TreeHash(newLeaves)

	// Ensure NewValidatorsHash public input corresponds to leaf 7 of the new header
	// newLeaves[7] = SHA256(0x00 || raw_new_ValidatorsHash), newVhBytes = raw_new_ValidatorsHash
	// So compute LeafHash(newVhBytes) in-circuit and compare to newLeaves[7]
	newVhBytes := c.unpack(api, c.PackedNewValidatorsHash)
	expectedNewVHLeaf := comet.LeafHash(newVhBytes)
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(expectedNewVHLeaf[i].Val, newLeaves[7][i].Val)
	}

	var signedPower frontend.Variable = 0
	var totalPowerCalculated frontend.Variable = 0

	var lastAddress []uints.U8
	for i := 0; i < MaxValidators; i++ {
		// 3. Verify that the SignBytes are canonical
		// The SignBytes (precommit from old set) must commit to the NEW block hash.
		comet.VerifyCanonicalVote(c.Signed[i], c.SignBytes[i], c.Height, c.Round, computedNewBH)

		// 3a. Verify Ed25519 Signature over the canonical SignBytes
		err = eddsa.Verify(c.Signatures[i], c.SignBytes[i], c.PublicKeys[i], c.Signed[i])
		if err != nil {
			return err
		}

		// 4. Validator Address and Sorting (of the old set)
		pkBytes := eddsa.SerializePoint(c.PublicKeys[i].A)
		addr := comet.ComputeAddress(pkBytes[:])

		if i > 0 {
			// Gate sorting check — dummy slots share the same generator key and wouldn't be sorted
			leftReal := api.IsZero(api.IsZero(c.VotingPowers[i-1]))
			rightReal := api.IsZero(api.IsZero(c.VotingPowers[i]))
			bothReal := api.And(leftReal, rightReal)
			checkSort := api.Select(bothReal, comet.IsLess(lastAddress, addr), 1)
			api.AssertIsEqual(checkSort, 1)
		}
		lastAddress = addr

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

	// 1. Initialize Public Inputs and Scalar Variables
	for i := 0; i < 4; i++ {
		c.PackedOldValidatorsHash[i] = 0
		c.PackedNewValidatorsHash[i] = 0
	}
	c.Height = 0
	c.TotalPower = 0
	c.Round = 0
	if c.ValidatorCount == nil {
		c.ValidatorCount = 1
	}

	// 2. Initialize Byte Arrays and Slices
	c.VotingPowers = make([]frontend.Variable, MaxValidators)
	c.ProposerPriorities = make([]frontend.Variable, MaxValidators)
	c.Signed = make([]frontend.Variable, MaxValidators)
	for i := 0; i < MaxValidators; i++ {
		c.VotingPowers[i] = 0
		c.ProposerPriorities[i] = 0
		c.Signed[i] = 0
	}

	// NEW Header Merkle Tree Leaves
	for i := 0; i < 14; i++ {
		for j := 0; j < 32; j++ {
			c.NewHeaderLeaves[i][j] = uints.U8{Val: 0}
		}
	}

	// Metadata
	for i := 0; i < 32; i++ {
		c.BlockID[i] = uints.U8{Val: 0}
	}
	for i := 0; i < 12; i++ {
		c.Timestamp[i] = uints.U8{Val: 0}
	}
	c.ChainID = make([]uints.U8, 32)
	for i := 0; i < 32; i++ {
		c.ChainID[i] = uints.U8{Val: 0}
	}

	// Signing Data
	c.SignBytes = make([][]uints.U8, MaxValidators)
	c.VotingPowerBytes = make([][]uints.U8, MaxValidators)
	c.ProposerPriorityBytes = make([][]uints.U8, MaxValidators)
	for i := 0; i < MaxValidators; i++ {
		c.SignBytes[i] = make([]uints.U8, 112)
		c.VotingPowerBytes[i] = make([]uints.U8, 10)
		c.ProposerPriorityBytes[i] = make([]uints.U8, 10)
		for j := 0; j < 112; j++ {
			c.SignBytes[i][j] = uints.U8{Val: 0}
		}
		for j := 0; j < 10; j++ {
			c.VotingPowerBytes[i][j] = uints.U8{Val: 0}
			c.ProposerPriorityBytes[i][j] = uints.U8{Val: 0}
		}
	}

	// Ed25519 Fields
	c.PublicKeys = make([]ed25519.PublicKey, MaxValidators)
	c.Signatures = make([]ed25519.Signature, MaxValidators)
}
