package circuits

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/circuits/ed25519"
)

func TestTransitionCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit TransitionCircuit
	circuit.AllocateSlices()

	var witness TransitionCircuit
	for i := 0; i < 4; i++ {
		witness.PackedOldValidatorsHash[i] = 0
		witness.PackedNewValidatorsHash[i] = 0
	}
	witness.TotalPower = 100
	witness.AllocateSlices()

	for i := 0; i < MaxValidators; i++ {
		witness.VotingPowers[i] = 0
		witness.Signed[i] = 0
		witness.PublicKeys[i].A.X = emulated.ValueOf[ed25519.Ed25519Fp](0)
		witness.PublicKeys[i].A.Y = emulated.ValueOf[ed25519.Ed25519Fp](0)
		witness.Signatures[i].R.X = emulated.ValueOf[ed25519.Ed25519Fp](1)
		witness.Signatures[i].R.Y = emulated.ValueOf[ed25519.Ed25519Fp](1)
		witness.Signatures[i].S = emulated.ValueOf[ed25519.Ed25519Fr](1)
	}

	witness.VotingPowers[0] = 70
	witness.Signed[0] = 1

	fmt.Println("⚙️  Compiling Transition Circuit...")
	circuit.AllocateSlices()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("📊 Transition Circuit constraints: %d\n", ccs.GetNbConstraints())

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254), test.NoTestEngine())
}
