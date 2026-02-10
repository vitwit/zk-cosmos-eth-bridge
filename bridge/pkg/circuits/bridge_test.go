package circuits

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestZkBridgeCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit ZkBridgeCircuit

	// Create a dummy witness
	var witness ZkBridgeCircuit
	for i := 0; i < 4; i++ {
		witness.PackedRoot[i] = 0
		witness.PackedTxHash[i] = 0
	}
	witness.ActualDepth = 12

	for i := 0; i < MerkleDepth; i++ {
		witness.ProofHelper[i] = 0
		for j := 0; j < 32; j++ {
			witness.ProofPath[i][j] = 0
		}
	}

	// Primarily testing compilation and structure
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Merkle Circuit (Depth %d) constraints: %d", MerkleDepth, ccs.GetNbConstraints())

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254), test.NoTestEngine())
}
