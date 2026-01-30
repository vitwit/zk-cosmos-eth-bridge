package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

const MerkleDepth = 32 // Production-ready depth for Tendermint tx trees

// ZkBridgeCircuit proves that a transaction leaf hash is included
// in a Merkle tree with a specific root.
type ZkBridgeCircuit struct {
	// Public inputs (Visible to Ethereum)
	PackedRoot   [4]frontend.Variable `gnark:",public"`
	PackedTxHash [4]frontend.Variable `gnark:",public"`

	// Private inputs (Hidden from Ethereum)
	ProofPath   [MerkleDepth][32]frontend.Variable
	ProofHelper [MerkleDepth]frontend.Variable
	ActualDepth frontend.Variable `gnark:",secret"`
}

func (c *ZkBridgeCircuit) Define(api frontend.API) error {
	// 1. Unpack Root and TxHash into bytes
	rootBytes := c.unpack(api, c.PackedRoot)
	txHashBytes := c.unpack(api, c.PackedTxHash)

	// 2. Initialize currentHash with the leaf hash (unpacked TxHash)
	currentHash := make([]uints.U8, 32)
	for j := 0; j < 32; j++ {
		currentHash[j] = txHashBytes[j]
	}

	// 3. Reconstruct Merkle Root from path
	for i := 0; i < MerkleDepth; i++ {
		isActive := cmp.IsLess(api, i, c.ActualDepth)

		// Gating the SHA write to avoid padding constraint failures on dummy data
		sha, _ := sha2.New(api)

		prefix := api.Select(isActive, 1, 0)
		sha.Write([]uints.U8{{Val: prefix}})

		left := make([]uints.U8, 32)
		right := make([]uints.U8, 32)

		for j := 0; j < 32; j++ {
			pathByte := uints.U8{Val: c.ProofPath[i][j]}
			left[j].Val = api.Select(c.ProofHelper[i], pathByte.Val, currentHash[j].Val)
			right[j].Val = api.Select(c.ProofHelper[i], currentHash[j].Val, pathByte.Val)

			// Masking inputs to keep SHA state consistent
			left[j].Val = api.Select(isActive, left[j].Val, 0)
			right[j].Val = api.Select(isActive, right[j].Val, 0)
		}

		sha.Write(left)
		sha.Write(right)
		res := sha.Sum()

		// Update currentHash only if isActive is true
		for j := 0; j < 32; j++ {
			currentHash[j].Val = api.Select(isActive, res[j].Val, currentHash[j].Val)
		}
	}

	// 4. Assert correctness
	for j := 0; j < 32; j++ {
		api.AssertIsEqual(currentHash[j].Val, rootBytes[j].Val)
	}

	return nil
}

// unpack converts 4 x uint64 variables into 32 byte-sized variables.
func (c *ZkBridgeCircuit) unpack(api frontend.API, packed [4]frontend.Variable) []uints.U8 {
	var res []uints.U8
	for i := 0; i < 4; i++ {
		bits := api.ToBinary(packed[i], 64)
		// Bits are little-endian. We want to extract 8 bytes (big-endian order from bits)
		for j := 7; j >= 0; j-- {
			start := j * 8
			byteValue := api.FromBinary(bits[start : start+8]...)
			res = append(res, uints.U8{Val: byteValue})
		}
	}
	return res
}
