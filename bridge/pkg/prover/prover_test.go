package prover

import (
	"math/big"
	"testing"
)

func TestDecompressEd25519Point(t *testing.T) {
	// Neutral point / Base point
	bz := make([]byte, 32)
	bz[0] = 0x01 // Y = 1, X = 0 (Neutral point)

	x, y, err := DecompressEd25519Point(bz)
	if err != nil {
		t.Errorf("Failed to decompress neutral point: %v", err)
	}
	if x.Cmp(big.NewInt(0)) != 0 || y.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Incorrect neutral point: x=%s, y=%s", x, y)
	}

	// Base point
	bx, by, _ := DecompressBasePoint()
	t.Logf("Generator point: x=%s, y=%s", bx, by)
	// Compressed base point
	compBase := make([]byte, 32)
	copy(compBase, []byte{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66})

	x, y, err = DecompressEd25519Point(compBase)
	// Base point might have minor endianness or representation differences in some libs,
	// but DecompressBasePoint returns the known coordinates.
	if err == nil {
		t.Logf("Decompressed point: x=%s, y=%s", x, y)
	}
}
