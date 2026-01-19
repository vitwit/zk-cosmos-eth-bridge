package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestBasicCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit BasicCircuit
	var witness BasicCircuit
	witness.X = 1
	witness.Y = 1
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
