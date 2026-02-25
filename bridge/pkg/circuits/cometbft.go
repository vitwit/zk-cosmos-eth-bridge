package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

// CometBFTGadget implements canonical Tendermint/CometBFT hashing logic
type CometBFTGadget struct {
	api frontend.API
}

func NewCometBFTGadget(api frontend.API) *CometBFTGadget {
	return &CometBFTGadget{api: api}
}

// RFC6962TreeHash implements the Merkle tree hashing used by CometBFT.
func (g *CometBFTGadget) RFC6962TreeHash(leaves [][]uints.U8) []uints.U8 {
	n := len(leaves)
	if n == 0 {
		return make([]uints.U8, 32)
	}
	if n == 1 {
		return leaves[0]
	}

	k := 1
	for k < n {
		k <<= 1
	}
	k >>= 1

	left := g.RFC6962TreeHash(leaves[:k])
	right := g.RFC6962TreeHash(leaves[k:])

	return g.InnerNodeHash(left, right)
}

func (g *CometBFTGadget) InnerNodeHash(left, right []uints.U8) []uints.U8 {
	sha, _ := sha2.New(g.api)
	sha.Write([]uints.U8{{Val: 1}})
	sha.Write(left)
	sha.Write(right)
	return sha.Sum()
}

func (g *CometBFTGadget) LeafHash(data []uints.U8) []uints.U8 {
	sha, _ := sha2.New(g.api)
	sha.Write([]uints.U8{{Val: 0}})
	sha.Write(data)
	return sha.Sum()
}

// VerifyCanonicalVote ensures the provided bytes match the expected fields.
// For CometBFT v0.38.19, CanonicalVote has fixed field order and deterministic offsets.
func (g *CometBFTGadget) VerifyCanonicalVote(enabled frontend.Variable, bytes []uints.U8, height frontend.Variable, round frontend.Variable, bhBytes []uints.U8) {
	// CanonicalVote Protobuf layout (deterministic):
	// Tag 1 (Type): 0x08 | 0x02 (Precommit)
	// Tag 2 (Height): 0x11 (sfixed64) | 8 bytes
	// Tag 3 (Round): 0x19 (sfixed64) | 8 bytes
	// Tag 4 (BlockID): 0x22 (message) | length | CanonicalBlockID
	// ... (Timestamp and ChainID follows)

	// Gate fixed byte checks
	g.api.AssertIsEqual(g.api.Select(enabled, bytes[0].Val, 0x08), 0x08)
	g.api.AssertIsEqual(g.api.Select(enabled, bytes[1].Val, 0x02), 0x02) // Precommit
	g.api.AssertIsEqual(g.api.Select(enabled, bytes[2].Val, 0x11), 0x11) // Tag 2

	// Verify Height (sfixed64 LE) - bytes[3:11]
	hBits := g.api.ToBinary(height, 64)
	for i := 0; i < 8; i++ {
		val := g.api.FromBinary(hBits[i*8 : (i+1)*8]...)
		g.api.AssertIsEqual(g.api.Select(enabled, bytes[3+i].Val, val), val)
	}

	// Index 11: 0x19 (Tag 3)
	g.api.AssertIsEqual(g.api.Select(enabled, bytes[11].Val, 0x19), 0x19)

	// Verify Round (sfixed64 LE) - bytes[12:20]
	rBits := g.api.ToBinary(round, 64)
	for i := 0; i < 8; i++ {
		val := g.api.FromBinary(rBits[i*8 : (i+1)*8]...)
		g.api.AssertIsEqual(g.api.Select(enabled, bytes[12+i].Val, val), val)
	}

	// Verify BlockID (Tag 4, Message)
	// Tag 0x22 | Len 34 | CanonicalBlockID
	// CanonicalBlockID: Tag 1 (0x0a) | Hash (32 bytes)
	g.api.AssertIsEqual(g.api.Select(enabled, bytes[20].Val, 0x22), 0x22)
	g.api.AssertIsEqual(g.api.Select(enabled, bytes[21].Val, 34), 34)     // Length of CanonicalBlockID
	g.api.AssertIsEqual(g.api.Select(enabled, bytes[22].Val, 0x0a), 0x0a) // Tag 1 (Hash)
	g.api.AssertIsEqual(g.api.Select(enabled, bytes[23].Val, 32), 32)     // Length 32
	for i := 0; i < 32; i++ {
		g.api.AssertIsEqual(g.api.Select(enabled, bytes[24+i].Val, bhBytes[i].Val), bhBytes[i].Val)
	}
}

// ComputeAddress calculates the Tendermint validator address: Truncate(SHA256(PK), 20)
func (g *CometBFTGadget) ComputeAddress(pkBytes []uints.U8) []uints.U8 {
	sha, _ := sha2.New(g.api)
	sha.Write(pkBytes)
	hash := sha.Sum()
	return hash[:20]
}

// CompareAddresses performs lexicographical comparison: (A < B)
func (g *CometBFTGadget) IsLess(a, b []uints.U8) frontend.Variable {
	// 20-byte comparison
	res := frontend.Variable(0)
	alreadyDiff := frontend.Variable(0)

	byteComp := cmp.NewBoundedComparator(g.api, big.NewInt(256), false)

	for i := 0; i < 20; i++ {
		lt := byteComp.IsLess(a[i].Val, b[i].Val)
		gt := byteComp.IsLess(b[i].Val, a[i].Val)

		res = g.api.Select(alreadyDiff, res, lt)
		alreadyDiff = g.api.Or(alreadyDiff, g.api.Or(lt, gt))
	}
	return res
}

// DecodeVarint decodes a Protobuf Varint (up to 64 bits) from a byte slice and returns (value, length).
func (g *CometBFTGadget) DecodeVarint(bytes []uints.U8) (frontend.Variable, frontend.Variable) {
	res := frontend.Variable(0)
	length := frontend.Variable(0)

	multiplier := big.NewInt(1)
	base := big.NewInt(128)
	stillActive := frontend.Variable(1)

	for i := 0; i < 10; i++ {
		bits := g.api.ToBinary(bytes[i].Val, 8)
		data := g.api.FromBinary(bits[:7]...)
		continuation := bits[7]

		// Value += data * multiplier (only if stillActive)
		increment := g.api.Mul(data, multiplier)
		res = g.api.Add(res, g.api.Mul(increment, stillActive))

		// Accumulate actual length
		length = g.api.Add(length, stillActive)

		// Update stillActive: it stays 1 as long as we keep seeing continuation bits.
		stillActive = g.api.Mul(stillActive, continuation)
		multiplier.Mul(multiplier, base)
	}
	return res, length
}

// LeafHashVarint hashes a Varint with its exact length (1-10 bytes).
func (g *CometBFTGadget) LeafHashVarint(data []uints.U8, length frontend.Variable) []uints.U8 {
	var results [10][]uints.U8
	for l := 1; l <= 10; l++ {
		sha, _ := sha2.New(g.api)
		sha.Write([]uints.U8{{Val: 0}})
		sha.Write(data[:l])
		results[l-1] = sha.Sum()
	}

	// Select the result based on length
	res := make([]uints.U8, 32)
	for j := 0; j < 32; j++ {
		current := results[0][j]
		for l := 2; l <= 10; l++ {
			isThisLen := g.api.IsZero(g.api.Sub(length, l))
			current.Val = g.api.Select(isThisLen, results[l-1][j].Val, current.Val)
		}
		res[j] = current
	}
	return res
}

// HashValidator computes the leaf hash for a single validator.
// In Tendermint v0.38, this is the root of a Merkle tree with 4 leaves:
// [Address, PubKey, VotingPower, ProposerPriority]
func (g *CometBFTGadget) HashValidator(addr []uints.U8, pubkey []uints.U8, powerBytes []uints.U8, priorityBytes []uints.U8) []uints.U8 {
	_, pLen := g.DecodeVarint(powerBytes)
	_, prLen := g.DecodeVarint(priorityBytes)

	leaves := make([][]uints.U8, 4)
	leaves[0] = g.LeafHash(addr)   // Fixed 20 bytes
	leaves[1] = g.LeafHash(pubkey) // Fixed 34 bytes
	leaves[2] = g.LeafHashVarint(powerBytes, pLen)
	leaves[3] = g.LeafHashVarint(priorityBytes, prLen)

	return g.RFC6962TreeHash(leaves)
}

func (g *CometBFTGadget) ValidatorsHash(valHashes [][]uints.U8) []uints.U8 {
	return g.RFC6962TreeHash(valHashes)
}
