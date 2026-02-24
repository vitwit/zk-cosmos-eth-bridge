package circuits

import (
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
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
	PackedBlockHash      [4]frontend.Variable `gnark:",public"` // The hash that validators actually sign
	PackedDataHash       [4]frontend.Variable `gnark:",public"` // The transaction root
	Height               frontend.Variable    `gnark:",public"`
	TotalPower           frontend.Variable    `gnark:",public"`

	// Private Inputs (The Validator Set)
	VotingPowers []frontend.Variable
	PublicKeys   []ed25519.PublicKey

	// Private Inputs (The Signatures)
	Signatures []ed25519.Signature
	Signed     []frontend.Variable // 0 or 1 indicating if validator signed this block
}

func (c *ValidatorCircuit) Define(api frontend.API) error {
	// 1. Setup EdDSA API
	eddsa, err := ed25519.NewEdDSA(api)
	if err != nil {
		return err
	}

	// 2. Unpack Hashes for verification
	vhBytes := c.unpack(api, c.PackedValidatorsHash)
	bhBytes := c.unpack(api, c.PackedBlockHash)
	dhBytes := c.unpack(api, c.PackedDataHash)

	// 2a. Verify Block Hash corresponds to Header (Linking VH, DH, and Height)
	// This prevents a relayer from providing valid signatures for a block with a different data root.
	headerSha, _ := sha2.New(api)
	u8Api, _ := uints.NewBytes(api)
	headerSha.Write(vhBytes)
	headerSha.Write(dhBytes)

	heightBits := api.ToBinary(c.Height, 64)
	headerSha.Write(bitsToU8(api, u8Api, heightBits))

	computedBlockHash := headerSha.Sum()
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedBlockHash[i].Val, bhBytes[i].Val)
	}

	var signedPower frontend.Variable = 0
	var totalPowerCalculated frontend.Variable = 0

	for i := 0; i < MaxValidators; i++ {
		// 3. Verify Ed25519 Signature (Conditional)
		err = eddsa.Verify(c.Signatures[i], bhBytes, c.PublicKeys[i], c.Signed[i])
		if err != nil {
			return err
		}

		// 4. Accumulate Voting Power
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

	// 6. Validator Set Hash Verification
	sha, err := sha2.New(api)
	if err != nil {
		return err
	}
	u8Api, _ = uints.NewBytes(api)

	for i := 0; i < MaxValidators; i++ {
		// Serialize Ed25519 PK (32-byte compressed format as used in Tendermint)
		pkBytes := eddsa.SerializePoint(c.PublicKeys[i].A)
		sha.Write(pkBytes[:])

		// Serialize Power (64 bits / 8 bytes)
		powerBits := api.ToBinary(c.VotingPowers[i], 64)
		powerBytes := bitsToU8(api, u8Api, powerBits)
		sha.Write(powerBytes)
	}

	actualHash := sha.Sum() // 32 bytes

	// 7. Verify Hash matches ValidatorsHash
	// Cosmos hashes are Big Endian. Match byte-by-byte.
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(actualHash[i].Val, vhBytes[i].Val)
	}

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
	c.VotingPowers = make([]frontend.Variable, MaxValidators)
	c.PublicKeys = make([]ed25519.PublicKey, MaxValidators)
	c.Signatures = make([]ed25519.Signature, MaxValidators)
	c.Signed = make([]frontend.Variable, MaxValidators)
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
