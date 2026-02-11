package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// TransitionCircuit verifies that the old validator set has signed a new validator set hash.
type TransitionCircuit struct {
	// Public Inputs
	PackedOldValidatorsHash [4]frontend.Variable `gnark:",public"`
	PackedNewValidatorsHash [4]frontend.Variable `gnark:",public"`

	// Private Inputs (The Old Validator Set)
	VotingPowers []frontend.Variable
	PublicKeys   []ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	TotalPower   frontend.Variable

	// Private Inputs (The Signatures from the Old Set)
	Signatures []ecdsa.Signature[emulated.Secp256k1Fr]
	Signed     []frontend.Variable
}

func (c *TransitionCircuit) Define(api frontend.API) error {
	// 1. Verify that the Private Old Set matches the Public OldValidatorsHash
	sha, err := sha2.New(api)
	if err != nil {
		return err
	}
	u8Api, _ := uints.NewBytes(api)
	baseApi, _ := emulated.NewField[emulated.Secp256k1Fp](api)

	// Unpack OldValidatorsHash
	oldVhBytes := c.unpack(api, c.PackedOldValidatorsHash)

	for i := 0; i < MaxValidators; i++ {
		xBits := baseApi.ToBits(&c.PublicKeys[i].X)
		yBits := baseApi.ToBits(&c.PublicKeys[i].Y)
		pkBytes := bitsToU8(api, u8Api, xBits)
		pkBytes = append(pkBytes, bitsToU8(api, u8Api, yBits)...)
		sha.Write(pkBytes)

		powerBits := api.ToBinary(c.VotingPowers[i], 64)
		sha.Write(bitsToU8(api, u8Api, powerBits))
	}

	actualOldHash := sha.Sum()

	// Match byte-by-byte
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(actualOldHash[i].Val, oldVhBytes[i].Val)
	}

	// 2. Verify that OldSet signed NewValidatorsHash
	params := sw_emulated.GetSecp256k1Params()
	scalarApi, _ := emulated.NewField[emulated.Secp256k1Fr](api)

	newVhBytes := c.unpack(api, c.PackedNewValidatorsHash)
	var newVhBits []frontend.Variable
	for i := 0; i < 32; i++ {
		byteBits := api.ToBinary(newVhBytes[i].Val, 8)
		for j := 7; j >= 0; j-- {
			newVhBits = append(newVhBits, byteBits[j])
		}
	}
	msg := scalarApi.FromBits(newVhBits...)

	var signedPower frontend.Variable = 0
	var totalPowerCalculated frontend.Variable = 0

	for i := 0; i < MaxValidators; i++ {
		isValid := c.PublicKeys[i].IsValid(api, params, msg, &c.Signatures[i])
		api.AssertIsEqual(api.Mul(c.Signed[i], api.Sub(1, isValid)), 0)

		api.AssertIsBoolean(c.Signed[i])
		totalPowerCalculated = api.Add(totalPowerCalculated, c.VotingPowers[i])
		signedPower = api.Add(signedPower, api.Select(c.Signed[i], c.VotingPowers[i], 0))
	}

	api.AssertIsEqual(totalPowerCalculated, c.TotalPower)

	// signedPower * 3 >= totalPower * 2
	lhs := api.Mul(signedPower, 3)
	rhs := api.Mul(c.TotalPower, 2)
	comparator := cmp.NewBoundedComparator(api, big.NewInt(0).Lsh(big.NewInt(1), 128), false)
	api.AssertIsEqual(comparator.IsLess(lhs, rhs), 0)

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
	c.VotingPowers = make([]frontend.Variable, MaxValidators)
	c.PublicKeys = make([]ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], MaxValidators)
	c.Signatures = make([]ecdsa.Signature[emulated.Secp256k1Fr], MaxValidators)
	c.Signed = make([]frontend.Variable, MaxValidators)
}
