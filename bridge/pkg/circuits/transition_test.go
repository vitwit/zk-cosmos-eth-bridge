package circuits

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestTransitionCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit TransitionCircuit

	var witness TransitionCircuit
	witness.OldValidatorsHash = 0
	witness.NewValidatorsHash = 0
	witness.TotalPower = 100

	for i := 0; i < MaxValidators; i++ {
		witness.VotingPowers[i] = 0
		witness.Signed[i] = 0
		witness.PublicKeys[i].X = emulated.ValueOf[emulated.Secp256k1Fp](0)
		witness.PublicKeys[i].Y = emulated.ValueOf[emulated.Secp256k1Fp](0)
		witness.Signatures[i].R = emulated.ValueOf[emulated.Secp256k1Fr](1)
		witness.Signatures[i].S = emulated.ValueOf[emulated.Secp256k1Fr](1)
	}

	witness.VotingPowers[0] = 70
	witness.Signed[0] = 1

	fmt.Println("⚙️  Compiling Transition Circuit...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("📊 Transition Circuit constraints: %d\n", ccs.GetNbConstraints())

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254), test.NoTestEngine())
}
