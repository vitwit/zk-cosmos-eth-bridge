package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

const MaxDepth = 20

// InclusionCircuit defines the ZK circuit for Merkle inclusion proof
type InclusionCircuit struct {
	// -------- Public Inputs (8 field elements) --------
	RootHigh frontend.Variable `gnark:",public"` // inputs[0] - 16 bytes
	RootLow  frontend.Variable `gnark:",public"` // inputs[1] - 16 bytes
	TxHigh   frontend.Variable `gnark:",public"` // inputs[2] - 16 bytes
	TxLow    frontend.Variable `gnark:",public"` // inputs[3] - 16 bytes
	Dest     frontend.Variable `gnark:",public"` // inputs[4] - 20 bytes (Ethereum address)
	LockID   frontend.Variable `gnark:",public"` // inputs[5] - uint64
	AmtHigh  frontend.Variable `gnark:",public"` // inputs[6] - 16 bytes
	AmtLow   frontend.Variable `gnark:",public"` // inputs[7] - 16 bytes

	// -------- Private Inputs --------
	Proof        [MaxDepth][32]uints.U8      // Merkle proof siblings
	PathSelector [MaxDepth]frontend.Variable // Path direction (0=left, 1=right)
	IsActive     [MaxDepth]frontend.Variable // Whether this level is active (ADDED)
}

func (c *InclusionCircuit) Define(api frontend.API) error {
	// 1. Validate all path selectors and IsActive are boolean
	for i := 0; i < MaxDepth; i++ {
		api.AssertIsBoolean(c.PathSelector[i])
		api.AssertIsBoolean(c.IsActive[i])
	}

	// 2. Unpack public inputs to bytes for SHA256
	rootBytes := unpack32FromTwo16(api, c.RootHigh, c.RootLow)
	txBytes := unpack32FromTwo16(api, c.TxHigh, c.TxLow)
	amtBytes := unpack32FromTwo16(api, c.AmtHigh, c.AmtLow)
	destBytes := fieldToBytes20(api, c.Dest)

	// 3. Compute leaf hash: SHA256(0x00 || TxHash || LockID || Amount || Destination)
	h, err := sha2.New(api)
	if err != nil {
		return err
	}

	// Leaf prefix (0x00)
	h.Write([]uints.U8{uints.NewU8(0)})

	// TxHash (32 bytes)
	h.Write(txBytes)

	// LockID as 32 bytes (zero-padded, big-endian)
	lockBytes := make([]uints.U8, 32)
	lockBits := api.ToBinary(c.LockID, 64)

	// First 24 bytes are zero padding
	for i := 0; i < 24; i++ {
		lockBytes[i] = uints.NewU8(0)
	}

	// Last 8 bytes contain the uint64 in big-endian order
	for i := 0; i < 8; i++ {
		start := (7 - i) * 8
		end := start + 8
		lockBytes[24+i] = uints.U8{Val: api.FromBinary(lockBits[start:end]...)}
	}
	h.Write(lockBytes)

	// Amount (32 bytes)
	h.Write(amtBytes)

	// Destination (20 bytes)
	h.Write(destBytes)

	currentHash := h.Sum()

	// 4. Verify Merkle path (conditionally process based on IsActive)
	for i := 0; i < MaxDepth; i++ {
		h, err := sha2.New(api)
		if err != nil {
			return err
		}

		// Internal node prefix (0x01)
		h.Write([]uints.U8{uints.NewU8(1)})

		// Conditional swap based on path selector:
		// PathSelector[i] == 0: currentHash is left child, proof[i] is right sibling
		// PathSelector[i] == 1: proof[i] is left sibling, currentHash is right child
		left := make([]uints.U8, 32)
		right := make([]uints.U8, 32)

		for j := 0; j < 32; j++ {
			left[j] = uints.U8{Val: api.Select(c.PathSelector[i], c.Proof[i][j].Val, currentHash[j].Val)}
			right[j] = uints.U8{Val: api.Select(c.PathSelector[i], currentHash[j].Val, c.Proof[i][j].Val)}
		}

		h.Write(left[:])
		h.Write(right[:])
		newHash := h.Sum()

		// Use IsActive to conditionally update the hash
		// If active, use newHash; otherwise keep currentHash
		for j := 0; j < 32; j++ {
			currentHash[j] = uints.U8{Val: api.Select(c.IsActive[i], newHash[j].Val, currentHash[j].Val)}
		}
	}

	// 5. Assert final hash equals the public root
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(currentHash[i].Val, rootBytes[i].Val)
	}

	return nil
}

// ----------------------
// Helper Functions
// ----------------------

// unpack32FromTwo16 converts two 16-byte field elements into a 32-byte array
func unpack32FromTwo16(api frontend.API, high, low frontend.Variable) []uints.U8 {
	highBytes := fieldToBytes16(api, high)
	lowBytes := fieldToBytes16(api, low)

	result := make([]uints.U8, 32)
	copy(result[0:16], highBytes)
	copy(result[16:32], lowBytes)
	return result
}

// fieldToBytes16 converts a 128-bit field element to 16 bytes (big-endian)
func fieldToBytes16(api frontend.API, v frontend.Variable) []uints.U8 {
	bits := api.ToBinary(v, 128) // 16 bytes = 128 bits
	out := make([]uints.U8, 16)

	for i := 0; i < 16; i++ {
		// Extract bits for byte i (big-endian: MSB first)
		start := (15 - i) * 8
		end := start + 8
		out[i] = uints.U8{Val: api.FromBinary(bits[start:end]...)}
	}
	return out
}

// fieldToBytes20 converts a 160-bit field element to 20 bytes (for Ethereum address)
func fieldToBytes20(api frontend.API, v frontend.Variable) []uints.U8 {
	bits := api.ToBinary(v, 160) // 20 bytes = 160 bits
	out := make([]uints.U8, 20)

	for i := 0; i < 20; i++ {
		start := (19 - i) * 8
		end := start + 8
		out[i] = uints.U8{Val: api.FromBinary(bits[start:end]...)}
	}
	return out
}

// ----------------------
// Utility for Prover
// ----------------------

// PackBytesBE packs bytes in big-endian for witness creation
func PackBytesBE(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}
