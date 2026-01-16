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
	// We pack 32 bytes into 4 x uint64 variables to save gas and avoid GNARK commitment complexity.
	PackedRoot   [4]frontend.Variable `gnark:",public"`
	PackedTxHash [4]frontend.Variable `gnark:",public"`

	// Private inputs (Hidden from Ethereum)
	ProofPath   [MerkleDepth][32]frontend.Variable
	ProofHelper [MerkleDepth]frontend.Variable
	ActualDepth frontend.Variable
}

func (c *ZkBridgeCircuit) Define(api frontend.API) error {
	uapi, _ := uints.NewBytes(api)

	// 1. Unpack Root and TxHash into bytes
	rootBytes := c.unpack(api, c.PackedRoot)
	txHashBytes := c.unpack(api, c.PackedTxHash)

	// 2. Initialize currentHash with the leaf hash (unpacked TxHash)
	currentHash := make([]uints.U8, 32)
	for j := 0; j < 32; j++ {
		currentHash[j] = txHashBytes[j]
	}

	// 3. Reconstruct Merkle Root from path using Tendermint InnerHash logic:
	// InnerHash(L, R) = SHA256(0x01 || L || R)
	//
	// SPECIAL CASE: If ActualDepth == 0 (single transaction in block),
	// then root == leaf, so we skip the Merkle hashing loop entirely.
	for i := 0; i < MerkleDepth; i++ {
		sha, _ := sha2.New(api)

		// Tendermint Inner Node Prefix: 0x01
		sha.Write([]uints.U8{uints.NewU8(1)})

		left := make([]uints.U8, 32)
		right := make([]uints.U8, 32)

		for j := 0; j < 32; j++ {
			pathByte := uints.U8{Val: c.ProofPath[i][j]}
			// ProofHelper[i] == 1 means currentHash is on the right
			left[j] = uapi.Select(c.ProofHelper[i], pathByte, currentHash[j])
			right[j] = uapi.Select(c.ProofHelper[i], currentHash[j], pathByte)
		}

		sha.Write(left)
		sha.Write(right)
		res := sha.Sum()

		// If i < ActualDepth, update currentHash.
		// This means when ActualDepth == 0, currentHash stays as the leaf (no hashing)
		isActive := cmp.IsLess(api, i, c.ActualDepth)
		for j := 0; j < 32; j++ {
			currentHash[j].Val = api.Select(isActive, res[j].Val, currentHash[j].Val)
		}
	}

	// 4. Assert the reconstructed root matches the public Root
	// When ActualDepth == 0: currentHash == txHashBytes == rootBytes (single tx case)
	// When ActualDepth > 0: currentHash == computed Merkle root
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
