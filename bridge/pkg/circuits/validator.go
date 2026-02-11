package circuits

import (
	"math/big"
	"os"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// MaxValidators defines the fixed capacity of the ZK circuit.
// Changing this requires regenerating keys and redeploying verifier contracts.
var MaxValidators = 4

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
	PublicKeys   []ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]

	// Private Inputs (The Signatures)
	Signatures []ecdsa.Signature[emulated.Secp256k1Fr]
	Signed     []frontend.Variable // 0 or 1 indicating if validator signed this block
}

func (c *ValidatorCircuit) Define(api frontend.API) error {
	// 1. Setup Curve and Field APIs
	params := sw_emulated.GetSecp256k1Params()

	scalarApi, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return err
	}

	// baseApi, err := emulated.NewField[emulated.Secp256k1Fp](api)
	// if err != nil {
	// 	return err
	// }
	baseApi, _ := emulated.NewField[emulated.Secp256k1Fp](api)

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

	// 2b. Prepare Block Hash as emulated element for ECDSA
	// For ECDSA, we need the message as an element in the scalar field of secp256k1.
	var bhBits []frontend.Variable
	for i := 0; i < 32; i++ {
		byteBits := api.ToBinary(bhBytes[i].Val, 8)
		for j := 7; j >= 0; j-- {
			bhBits = append(bhBits, byteBits[j])
		}
	}
	msg := scalarApi.FromBits(bhBits...)

	var signedPower frontend.Variable = 0
	var totalPowerCalculated frontend.Variable = 0

	for i := 0; i < MaxValidators; i++ {
		// 3. Verify Signature (Conditional)
		// IsValid returns 1 if valid, 0 otherwise.
		isValid := c.PublicKeys[i].IsValid(api, params, msg, &c.Signatures[i])

		// Logic: If Signed[i] is 1, then isValid MUST be 1.
		// If Signed[i] is 0, isValid can be anything (ignored).
		// Constraint: Signed[i] * (1 - isValid) == 0
		api.AssertIsEqual(api.Mul(c.Signed[i], api.Sub(1, isValid)), 0)

		// 4. Accumulate Voting Power
		api.AssertIsBoolean(c.Signed[i])
		totalPowerCalculated = api.Add(totalPowerCalculated, c.VotingPowers[i])

		sp := api.Select(c.Signed[i], c.VotingPowers[i], 0)
		signedPower = api.Add(signedPower, sp)
	}

	// 5. Global Assertions
	// Verify Total Power matches
	api.AssertIsEqual(totalPowerCalculated, c.TotalPower)

	// Threshold logic: lhsQuorum >= rhsQuorum
	// or equivalently: NOT (lhsQuorum < rhsQuorum)
	// 3 * signedPower >= 2 * totalPower
	lhsQuorum := api.Mul(signedPower, 3)
	rhsQuorum := api.Mul(c.TotalPower, 2)

	// Voting powers typically fit in 64 bits, so 3 * power fits in ~66 bits.
	// 128 bit bound is safe for BN254.
	comparator := cmp.NewBoundedComparator(api, big.NewInt(0).Lsh(big.NewInt(1), 128), false)
	isLess := comparator.IsLess(lhsQuorum, rhsQuorum)
	api.AssertIsEqual(isLess, 0)

	// 6. Validator Set Hash Verification
	sha, err := sha2.New(api)
	if err != nil {
		return err
	}
	u8Api, _ = uints.NewBytes(api)

	for i := 0; i < MaxValidators; i++ {
		// Serialize PK (X, Y) - each 32 bytes
		xBits := baseApi.ToBits(&c.PublicKeys[i].X)
		yBits := baseApi.ToBits(&c.PublicKeys[i].Y)

		pkBytes := bitsToU8(api, u8Api, xBits)
		pkBytes = append(pkBytes, bitsToU8(api, u8Api, yBits)...)
		sha.Write(pkBytes)

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
	c.VotingPowers = make([]frontend.Variable, MaxValidators)
	c.PublicKeys = make([]ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], MaxValidators)
	c.Signatures = make([]ecdsa.Signature[emulated.Secp256k1Fr], MaxValidators)
	c.Signed = make([]frontend.Variable, MaxValidators)
}

func bitsToU8(api frontend.API, u8Api *uints.Bytes, bits []frontend.Variable) []uints.U8 {
	var res []uints.U8
	for i := 0; i < len(bits); i += 8 {
		val := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			if i+j < len(bits) {
				val = api.Add(val, api.Mul(bits[i+j], 1<<j))
			}
		}
		res = append(res, u8Api.ValueOf(val))
	}
	return res
}
