package circuit

import (
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestInclusionCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	// Sample data
	txHash := make([]byte, 32)
	copy(txHash, []byte("tx_hash_placeholder"))
	maxTxLen := MaxTxLen
	maxDepth := MaxDepth

	// Compute leaf hash: SHA256(0x00 || txHash)
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(txHash)
	leafHash := h.Sum(nil)

	// Sample proof (1 level, but we need to pad to MaxDepth)
	siblingLeafHash := make([]byte, 32)
	copy(siblingLeafHash, []byte("sibling_hash_placeholder"))

	// Root: SHA256(0x01 || leafHash || siblingLeafHash)
	h = sha256.New()
	h.Write([]byte{0x01})
	h.Write(leafHash)
	h.Write(siblingLeafHash)
	root := h.Sum(nil)

	// Circuit
	circuit := NewInclusionCircuit(maxTxLen, maxDepth)

	// Witness
	witness := NewInclusionCircuit(maxTxLen, maxDepth)
	for i := 0; i < 32; i++ {
		witness.Root[i].Val = root[i]
		witness.TxHash[i].Val = txHash[i]
	}
	// Level 0 sibling
	for i := 0; i < 32; i++ {
		witness.Proof[0][i].Val = siblingLeafHash[i]
	}
	witness.PathSelector[0] = 0 // leaf is left, sibling is right
	witness.IsActive[0] = 1

	// Fill remaining levels with 0
	for i := 1; i < maxDepth; i++ {
		for j := 0; j < 32; j++ {
			witness.Proof[i][j].Val = 0
		}
		witness.PathSelector[i] = 0
		witness.IsActive[i] = 0
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
