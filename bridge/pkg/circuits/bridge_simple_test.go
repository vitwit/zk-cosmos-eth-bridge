package circuits_test

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/circuits"
)

// TestZkBridgeCircuit_SimplePacking tests the circuit with simple packing logic
// that matches how the prover packs data (binary.BigEndian.Uint64)
func TestZkBridgeCircuit_SimplePacking(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit circuits.ZkBridgeCircuit

	// Create simple test data
	var root [32]byte
	var txHash [32]byte

	// Fill with recognizable patterns
	for i := 0; i < 32; i++ {
		root[i] = byte(i)
		txHash[i] = byte(i + 100)
	}

	// Pack using binary.BigEndian (same as prover)
	witness := circuits.ZkBridgeCircuit{}
	for i := 0; i < 4; i++ {
		witness.PackedRoot[i] = binary.BigEndian.Uint64(root[i*8 : (i+1)*8])
		witness.PackedTxHash[i] = binary.BigEndian.Uint64(txHash[i*8 : (i+1)*8])
	}

	// Set depth to 0 (no Merkle proof, just test packing/unpacking)
	witness.ActualDepth = big.NewInt(0)

	// Initialize proof arrays (all zeros since depth=0)
	for i := 0; i < circuits.MerkleDepth; i++ {
		for j := 0; j < 32; j++ {
			witness.ProofPath[i][j] = big.NewInt(0)
		}
		witness.ProofHelper[i] = 0
	}

	// This should pass - it verifies that unpacking works correctly
	// When ActualDepth=0, the circuit should just verify that unpacked root == unpacked txHash
	// (since no hashing happens)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}
