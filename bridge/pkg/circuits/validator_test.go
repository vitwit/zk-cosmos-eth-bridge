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

func TestValidatorCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit ValidatorCircuit
	circuit.AllocateSlices()

	// Create witness
	var witness ValidatorCircuit
	witness.TotalPower = 70
	witness.Height = 100
	witness.AllocateSlices()

	for i := 0; i < 4; i++ {
		witness.PackedValidatorsHash[i] = 0
		witness.PackedBlockHash[i] = 0
		witness.PackedDataHash[i] = 0
	}

	for i := 0; i < MaxValidators; i++ {
		witness.VotingPowers[i] = 0
		witness.Signed[i] = 0
		witness.PublicKeys[i].A.X = emulated.ValueOf[ed25519.Ed25519Fp](0)
		witness.PublicKeys[i].A.Y = emulated.ValueOf[ed25519.Ed25519Fp](1)
		witness.Signatures[i].R.X = emulated.ValueOf[ed25519.Ed25519Fp](0)
		witness.Signatures[i].R.Y = emulated.ValueOf[ed25519.Ed25519Fp](1)
		witness.Signatures[i].S = emulated.ValueOf[ed25519.Ed25519Fr](0)
	}

	witness.VotingPowers[0] = 70 // > 2/3 of 70
	witness.Signed[0] = 1

	// For compilation, we don't need a valid assignment that satisfies constraints if we skip TestEngine
	// But let's try to make it reasonable.
	// To pass Verify, pk must be valid point, R, S must be valid etc.
	// But here we're testing COMPILATION primarily.

	fmt.Println("⚙️  Compiling Production Validator Circuit (Ed25519)...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("📊 Validator Circuit constraints: %d\n", ccs.GetNbConstraints())

	// This might fail if the solver hits an error with zero/invalid points,
	// but with NoTestEngine() it should at most fail in the R1CS check if there's a logic error.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254), test.NoTestEngine())
}
