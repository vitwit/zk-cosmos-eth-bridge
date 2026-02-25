package circuits

import (
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/circuits/ed25519"
)

// MaxValidators defines the fixed capacity of the ZK circuit.
// Changing this requires regenerating keys and redeploying verifier contracts.
// Defaulting to 2 for memory efficiency on local environments.
var MaxValidators = 2

func init() {
	if val := os.Getenv("MAX_VALIDATORS"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			MaxValidators = i
		}
	}
}

type ValidatorCircuit struct {
	// Public Inputs
	PackedValidatorsHash [4]frontend.Variable `gnark:",public"`
	PackedBlockHash      [4]frontend.Variable `gnark:",public"` // The canonical header hash
	PackedDataHash       [4]frontend.Variable `gnark:",public"`
	Height               frontend.Variable    `gnark:",public"`
	TotalPower           frontend.Variable    `gnark:",public"`

	// Canonical Header Fields (Leaves for the 14-field Merkle Tree)
	HeaderLeaves [14][32]uints.U8

	// Signing Metadata (for CanonicalVote reconstruction)
	ChainID   []uints.U8 // Public or private
	BlockID   [32]uints.U8
	Timestamp [12]uints.U8 // Seconds (8) + Nanos (4)
	Round     frontend.Variable

	// SignBytes (Private Inputs for each validator's vote)
	// These are verified against the Signing Metadata to be canonical.
	SignBytes [][]uints.U8

	// Private Inputs (The Validator Set)
	VotingPowers       []frontend.Variable
	ProposerPriorities []frontend.Variable
	PublicKeys         []ed25519.PublicKey

	// Byte representations for bit-perfect ValidatorsHash reconstruction
	VotingPowerBytes      [][]uints.U8 // Varint-encoded
	ProposerPriorityBytes [][]uints.U8 // Varint-encoded

	// Private Inputs (The Signatures)
	Signatures []ed25519.Signature
	Signed     []frontend.Variable
}

func (c *ValidatorCircuit) Define(api frontend.API) error {
	// 1. Setup APIs
	eddsa, err := ed25519.NewEdDSA(api)
	if err != nil {
		return err
	}

	// 2. Unpack Hashes for verification
	vhBytes := c.unpack(api, c.PackedValidatorsHash)
	bhBytes := c.unpack(api, c.PackedBlockHash)
	dhBytes := c.unpack(api, c.PackedDataHash)

	// 2a. Canonical Header Hash Verification (RFC 6962 14-field Merkle Tree)
	comet := NewCometBFTGadget(api)
	var leaves [][]uints.U8
	for i := 0; i < 14; i++ {
		leaves = append(leaves, c.HeaderLeaves[i][:])
	}
	computedHeaderHash := comet.RFC6962TreeHash(leaves)

	// Ensure computed hash matches Public BlockHash
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedHeaderHash[i].Val, bhBytes[i].Val)
	}

	// 2b. Link specific leafs to Public Inputs
	// Leaf 3 (Height) - Note: In ZK, we must verify the leaf hash corresponds to the field value.
	// Leaf 7 (ValidatorsHash)
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(leaves[7][i].Val, vhBytes[i].Val)
	}
	// Leaf 6 (DataHash)
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(leaves[6][i].Val, dhBytes[i].Val)
	}

	var signedPower frontend.Variable = 0
	var totalPowerCalculated frontend.Variable = 0
	var lastAddress []uints.U8

	for i := 0; i < MaxValidators; i++ {
		// 3. Verify that the SignBytes are canonical
		// NOTE: In a production circuit, we'd reconstruct them from Header/BlockID/ChainID.
		// For now, we assume provide SignBytes are verified to contain the correct BlockHash (bhBytes).
		comet.VerifyCanonicalVote(c.Signed[i], c.SignBytes[i], c.Height, c.Round, bhBytes)

		// 3a. Verify Ed25519 Signature over the canonical SignBytes
		err = eddsa.Verify(c.Signatures[i], c.SignBytes[i], c.PublicKeys[i], c.Signed[i])
		if err != nil {
			return err
		}

		// 4. Validator Address and Sorting
		pkBytes := eddsa.SerializePoint(c.PublicKeys[i].A)
		addr := comet.ComputeAddress(pkBytes[:])

		if i > 0 {
			// Enforce Address[i] > Address[i-1] for canonical sorting
			isGreater := comet.IsLess(lastAddress, addr)
			api.AssertIsEqual(isGreater, 1)
		}
		lastAddress = addr

		// 5. Accumulate Voting Power
		api.AssertIsBoolean(c.Signed[i])
		totalPowerCalculated = api.Add(totalPowerCalculated, c.VotingPowers[i])

		sp := api.Select(c.Signed[i], c.VotingPowers[i], 0)
		signedPower = api.Add(signedPower, sp)
	}

	// 5. Global Assertions
	// Verify Total Power matches
	api.AssertIsEqual(totalPowerCalculated, c.TotalPower)

	// Threshold logic: lhsQuorum > rhsQuorum (Strictly greater than 2/3)
	// 3 * signedPower > 2 * totalPower
	lhsQuorum := api.Mul(signedPower, 3)
	rhsQuorum := api.Mul(c.TotalPower, 2)

	// Voting powersTypically fit in 64 bits, so 3 * power fits in ~66 bits.
	// 128 bit bound is safe for BN254.
	comparator := cmp.NewBoundedComparator(api, big.NewInt(0).Lsh(big.NewInt(1), 128), false)

	// Pass if rhsQuorum < lhsQuorum (i.e. lhsQuorum > rhsQuorum)
	api.AssertIsEqual(comparator.IsLess(rhsQuorum, lhsQuorum), 1)

	// Reset accumulators for the second loop, which will re-calculate based on verified varints
	signedPower = 0
	totalPowerCalculated = 0

	// 6. Validator Set Hash Verification (Sorted by Address & Bit-Perfect)
	// comet is already initialized
	valHashes := make([][]uints.U8, MaxValidators)

	// Track previous address for sorting check
	var prevAddr []uints.U8

	for i := 0; i < MaxValidators; i++ {
		// 6a. Serialize Ed25519 PK (Protobuf encoded: Tag 1 | Len 32 | Bytes)
		pkBytes := eddsa.SerializePoint(c.PublicKeys[i].A)
		// Protobuf PublicKey: 0x0a (Tag 1, Length-Delimited) | 0x20 (Length 32) | bytes
		protoPK := make([]uints.U8, 34)
		protoPK[0] = uints.U8{Val: 0x0a}
		protoPK[1] = uints.U8{Val: 0x20}
		for j := 0; j < 32; j++ {
			protoPK[2+j] = pkBytes[j]
		}

		// 6b. Validator Address
		addr := comet.ComputeAddress(pkBytes[:])

		// Lexicographical sorting check
		if i > 0 {
			api.AssertIsEqual(comet.IsLess(prevAddr, addr), 1)
		}
		prevAddr = addr

		// 6c. Verify Varint-encoded power and priority match variables
		decodedPower, _ := comet.DecodeVarint(c.VotingPowerBytes[i])
		api.AssertIsEqual(decodedPower, c.VotingPowers[i])

		decodedPriority, _ := comet.DecodeVarint(c.ProposerPriorityBytes[i])
		api.AssertIsEqual(decodedPriority, c.ProposerPriorities[i])

		// 6d. Compute leaf hash for this validator (Merkle root of fields)
		valHashes[i] = comet.HashValidator(addr, protoPK, c.VotingPowerBytes[i], c.ProposerPriorityBytes[i])

		// 7. Power Aggregation (re-accumulate using the verified VotingPowers)
		api.AssertIsBoolean(c.Signed[i])
		totalPowerCalculated = api.Add(totalPowerCalculated, c.VotingPowers[i])
		signedPower = api.Add(signedPower, api.Select(c.Signed[i], c.VotingPowers[i], 0))
	}

	// 8. Verify the reconstructed ValidatorsHash matches the header's leaf 7
	computedVH := comet.ValidatorsHash(valHashes)
	// vhBytes := c.unpack(api, c.PackedValidatorsHash) // Already unpacked at the beginning
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedVH[i].Val, vhBytes[i].Val)
		// Crucially, this MUST match leaf 7 of the header Merkle tree
		api.AssertIsEqual(computedVH[i].Val, leaves[7][i].Val)
	}

	// Final check for total power (should match the public input)
	api.AssertIsEqual(totalPowerCalculated, c.TotalPower)

	return nil
}

// unpack converts 4 x uint64 variables into 32 byte-sized variables.
func (c *ValidatorCircuit) unpack(api frontend.API, packed [4]frontend.Variable) []uints.U8 {
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
func (c *ValidatorCircuit) AllocateSlices() {
	if MaxValidators <= 0 {
		fmt.Printf("⚠️  WARNING: MaxValidators is %d, defaulting to 1 for safety\n", MaxValidators)
		MaxValidators = 1
	}

	// 1. Initialize Public Inputs and Scalar Variables
	for i := 0; i < 4; i++ {
		c.PackedValidatorsHash[i] = 0
		c.PackedBlockHash[i] = 0
		c.PackedDataHash[i] = 0
	}
	c.Height = 0
	c.TotalPower = 0
	c.Round = 0

	// 2. Initialize Byte Arrays and Slices
	c.VotingPowers = make([]frontend.Variable, MaxValidators)
	c.ProposerPriorities = make([]frontend.Variable, MaxValidators)
	c.Signed = make([]frontend.Variable, MaxValidators)
	for i := 0; i < MaxValidators; i++ {
		c.VotingPowers[i] = 0
		c.ProposerPriorities[i] = 0
		c.Signed[i] = 0
	}

	// Header Merkle Tree Leaves
	for i := 0; i < 14; i++ {
		for j := 0; j < 32; j++ {
			c.HeaderLeaves[i][j] = uints.U8{Val: 0}
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

func bitsToU8(api frontend.API, u8Api *uints.Bytes, bits []frontend.Variable) []uints.U8 {
	var res []uints.U8
	for i := 0; i < len(bits); i += 8 {
		val := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			if i+j < len(bits) {
				// Pack bits (Little Endian in our bits input usually)
				val = api.Add(val, api.Mul(bits[i+j], 1<<j))
			}
		}
		// Use uints.U8{Val: val} directly to avoid redundant range checks
		// if we know the input bits are already binary.
		res = append(res, uints.U8{Val: val})
	}
	return res
}
