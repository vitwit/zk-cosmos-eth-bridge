package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	MaxTxLen = 512 // Fixed max transaction length
	MaxDepth = 20  // Fixed max Merkle tree depth
)

// InclusionCircuit defines the ZK circuit for Merkle inclusion proof with fixed sizes
type InclusionCircuit struct {
	Root         [32]uints.U8        `gnark:",public"`
	TxHash       [32]uints.U8        `gnark:",public"`
	LockID       frontend.Variable   `gnark:",public"`
	Amount       frontend.Variable   `gnark:",public"`
	Destination  [20]uints.U8        `gnark:",public"`
	Proof        [][]uints.U8        // The Merkle proof nodes (fixed depth)
	PathSelector []frontend.Variable // 0 if proof node is right, 1 if left
	IsActive     []frontend.Variable // 1 if this level is part of the proof, 0 if padding
}

func NewInclusionCircuit(leafLen, proofDepth int) InclusionCircuit {
	proof := make([][]uints.U8, proofDepth)
	for i := range proof {
		proof[i] = make([]uints.U8, 32)
	}
	return InclusionCircuit{
		Proof:        proof,
		PathSelector: make([]frontend.Variable, proofDepth),
		IsActive:     make([]frontend.Variable, proofDepth),
	}
}

// Define declares the circuit constraints
func (c *InclusionCircuit) Define(api frontend.API) error {
	// 1. Boolean constraints for selectors
	for i := 0; i < len(c.PathSelector); i++ {
		api.AssertIsBoolean(c.PathSelector[i])
		api.AssertIsBoolean(c.IsActive[i])
		// Enforce that once a level is inactive, all higher levels are inactive
		if i < len(c.IsActive)-1 {
			api.AssertIsLessOrEqual(c.IsActive[i+1], c.IsActive[i])
		}
	}

	// 2. Compute Leaf Hash: SHA256(0x00 || TxHash || LockID || Amount || Destination)
	h, err := sha2.New(api)
	if err != nil {
		return err
	}
	h.Write([]uints.U8{uints.NewU8(0)}) // 0x00 prefix for leaf
	h.Write(c.TxHash[:])

	// Convert LockID to 32 bytes (Big Endian)
	lockIDBits := api.ToBinary(c.LockID, 64)
	lockIDBytes := make([]uints.U8, 32)
	// Pad with zeros for first 24 bytes
	for i := 0; i < 24; i++ {
		lockIDBytes[i] = uints.NewU8(0)
	}
	// Fill last 8 bytes
	for i := 0; i < 8; i++ {
		// Bits are little-endian from ToBinary, but we want Big Endian bytes?
		// Usually ToBinary returns little-endian bits of the value.
		// Let's assume we want standard Big Endian representation.
		// Byte 0 (MSB) is at the end of the bit array? No.
		// bits[0] is LSB.
		// So bits[0..8] is the last byte (LSB).
		// We want lockIDBytes[31] to be the LSB byte.
		start := (7 - i) * 8
		end := start + 8
		lockIDBytes[24+i] = uints.U8{Val: api.FromBinary(lockIDBits[start:end]...)}
	}
	h.Write(lockIDBytes)

	// Convert Amount to 32 bytes (Big Endian)
	amountBits := api.ToBinary(c.Amount, 256)
	amountBytes := make([]uints.U8, 32)
	for i := 0; i < 32; i++ {
		// bits[0] is LSB. We want amountBytes[31] to be LSB.
		// So amountBytes[31-i] comes from bits[i*8 : (i+1)*8]
		start := i * 8
		end := start + 8
		amountBytes[31-i] = uints.U8{Val: api.FromBinary(amountBits[start:end]...)}
	}
	h.Write(amountBytes)

	h.Write(c.Destination[:])
	currentHash := h.Sum()

	// 3. Iterate through proof
	for i := 0; i < len(c.Proof); i++ {
		h, err := sha2.New(api)
		if err != nil {
			return err
		}
		h.Write([]uints.U8{uints.NewU8(1)}) // 0x01 prefix for inner node

		// Select between currentHash and Proof[i]
		left := make([]uints.U8, 32)
		right := make([]uints.U8, 32)

		for j := 0; j < 32; j++ {
			left[j] = uints.U8{Val: api.Select(c.PathSelector[i], c.Proof[i][j].Val, currentHash[j].Val)}
			right[j] = uints.U8{Val: api.Select(c.PathSelector[i], currentHash[j].Val, c.Proof[i][j].Val)}
		}

		h.Write(left)
		h.Write(right)
		nextHash := h.Sum()

		// If IsActive[i] == 1, currentHash = nextHash
		// If IsActive[i] == 0, currentHash = currentHash
		for j := 0; j < 32; j++ {
			currentHash[j].Val = api.Select(c.IsActive[i], nextHash[j].Val, currentHash[j].Val)
		}
	}

	// 4. Verify against Root
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(currentHash[i].Val, c.Root[i].Val)
	}

	return nil
}
