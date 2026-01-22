package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vitwit/zk-cosmos-eth-bridge/zk-bridge/pkg/circuits"
	"golang.org/x/crypto/sha3"
)

func main() {
	fmt.Println("🔨 Compiling...")
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuits.ZkBridgeCircuit{})

	fmt.Println("🔐 ONE-TIME SETUP...")
	pk, vk, _ := groth16.Setup(ccs)

	_ = os.MkdirAll("keys", 0o755)
	_ = os.MkdirAll("contracts", 0o755)

	fmt.Println("💾 Saving keys and CCS...")
	f0, _ := os.Create("keys/circuit.ccs")
	ccs.WriteTo(f0)
	f0.Close()
	f1, _ := os.Create("keys/proving.key")
	pk.WriteTo(f1)
	f1.Close()
	f2, _ := os.Create("keys/verifying.key")
	vk.WriteTo(f2)
	f2.Close()

	fmt.Println("📜 Exporting Solidity...")
	f3, _ := os.Create("contracts/Verifier.sol")
	vk.ExportSolidity(f3, solidity.WithHashToFieldFunction(sha3.NewLegacyKeccak256()))
	f3.Close()

	fmt.Println("✨ Setup complete. Do NOT run this again unless circuit changes.")
}
