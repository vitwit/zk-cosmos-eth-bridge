package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/sha3"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vitwit/zk-state-transition/testing/circuit"
)

const (
	pkPath = "proving.key"
	vkPath = "verification.key"
)

func main() {
	// 1. Compile the circuit
	fmt.Println("Compiling circuit...")

	var c circuit.InclusionCircuit

	compiledR1CS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		log.Fatal("Compile failed:", err)
	}

	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	// 2. Try to load existing keys, or generate new ones
	if _, err := os.Stat(pkPath); err == nil {
		fmt.Println("Loading existing keys from disk...")

		// Load Proving Key
		pk = groth16.NewProvingKey(ecc.BN254)
		f, err := os.Open(pkPath)
		if err != nil {
			log.Fatal("Failed to open proving key:", err)
		}
		_, err = pk.ReadFrom(f)
		f.Close()
		if err != nil {
			log.Fatal("Failed to read proving key:", err)
		}

		// Load Verification Key
		vk = groth16.NewVerifyingKey(ecc.BN254)
		f, err = os.Open(vkPath)
		if err != nil {
			log.Fatal("Failed to open verification key:", err)
		}
		_, err = vk.ReadFrom(f)
		f.Close()
		if err != nil {
			log.Fatal("Failed to read verification key:", err)
		}
	} else {
		fmt.Println("Generating proving/verifying keys (this may take a few minutes)...")
		pk, vk, err = groth16.Setup(compiledR1CS)
		if err != nil {
			log.Fatal("Setup failed:", err)
		}

		// Save Proving Key
		fmt.Println("Saving proving key to disk...")
		f, err := os.Create(pkPath)
		if err != nil {
			log.Fatal("Failed to create proving key file:", err)
		}
		_, err = pk.WriteTo(f)
		f.Close()
		if err != nil {
			log.Fatal("Failed to write proving key:", err)
		}

		// Save Verification Key
		fmt.Println("Saving verification key to disk...")
		f, err = os.Create(vkPath)
		if err != nil {
			log.Fatal("Failed to create verification key file:", err)
		}
		_, err = vk.WriteTo(f)
		f.Close()
		if err != nil {
			log.Fatal("Failed to write verification key:", err)
		}
	}

	// 3. Export Solidity Verifier
	fmt.Println("Exporting Verifier.sol...")
	f, err := os.Create("contracts/Verifier.sol")
	if err != nil {
		log.Fatal("Create file failed:", err)
	}
	defer f.Close()

	err = vk.ExportSolidity(f, solidity.WithHashToFieldFunction(sha3.NewLegacyKeccak256()))

	if err != nil {
		log.Fatal("Export Solidity failed:", err)
	}

	fmt.Println("✅ Verifier.sol generated successfully.")
	fmt.Println("📝 IMPORTANT: Redeploy the Verifier.sol contract on Ethereum!")
}
