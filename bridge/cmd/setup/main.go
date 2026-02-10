package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/circuits"
	"golang.org/x/crypto/sha3"
)

func main() {
	_ = os.MkdirAll("keys", 0o755)
	_ = os.MkdirAll("contracts", 0o755)

	fmt.Printf("🔨 Compiling circuits with MaxValidators = %d...\n", circuits.MaxValidators)

	// 1. Transaction Inclusion Circuit
	setupCircuit("Transactions", &circuits.ZkBridgeCircuit{})

	// 2. Validator Finality Circuit
	valCirc := &circuits.ValidatorCircuit{}
	valCirc.AllocateSlices()
	setupCircuit("Validators", valCirc)

	// 3. Valset Transition Circuit
	transCirc := &circuits.TransitionCircuit{}
	transCirc.AllocateSlices()
	setupCircuit("Transitions", transCirc)

	fmt.Println("✨ Production setup complete. Keys and Verifiers generated.")
}

func setupCircuit(name string, circuit frontend.Circuit) {
	fmt.Printf("📦 Setting up %s Circuit...\n", name)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Printf("❌ Failed to compile %s: %v\n", name, err)
		return
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf("❌ Failed setup for %s: %v\n", name, err)
		return
	}

	// Save Proving Key
	pkFile, _ := os.Create(fmt.Sprintf("keys/%s.proving.key", name))
	pk.WriteTo(pkFile)
	pkFile.Close()

	// Save Verifying Key
	vkFile, _ := os.Create(fmt.Sprintf("keys/%s.verifying.key", name))
	vk.WriteTo(vkFile)
	vkFile.Close()

	// Export Solidity Verifier
	solFile, _ := os.Create(fmt.Sprintf("contracts/Verifier_%s.sol", name))
	vk.ExportSolidity(solFile, solidity.WithHashToFieldFunction(sha3.NewLegacyKeccak256()))
	solFile.Close()

	fmt.Printf("✅ %s setup complete.\n", name)
}
