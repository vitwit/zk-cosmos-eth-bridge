package main

import (
	"fmt"
	"os"
	"regexp"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vitwit/zk-cosmos-eth-bridge/zk-bridge/pkg/circuits"
)

func main() {
	fmt.Println("🔨 Compiling Inclusion Circuit...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuits.ZkBridgeCircuit{})
	if err != nil {
		fmt.Printf("❌ Compilation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("🔐 Performing One-Time Setup...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf("❌ Setup failed: %v\n", err)
		os.Exit(1)
	}

	// Clean Architecture Paths (Relative to cmd/compiler execution)
	// We assume execution from project root via 'go run cmd/compiler/main.go'
	// OR from cmd/compiler directory.

	// Better to use relative paths from the EXECUTABLE logic?
	// If running `go run cmd/compiler/main.go`, CWD is root.
	// Target: keys/proving.key, contracts/Verifier.sol.

	baseDir, _ := os.Getwd()
	fmt.Printf("📍 Working Directory: %s\n", baseDir)

	var keysDir, contractsDir string
	if _, err := os.Stat("go.mod"); err == nil {
		// We are in root
		keysDir = "keys"
		contractsDir = "contracts"
	} else {
		// Assume we are in cmd/compiler (or similar depth)
		keysDir = "../../keys"
		contractsDir = "../../contracts"
	}

	// Ensure directories exist
	_ = os.MkdirAll(keysDir, 0o755)

	provingKeyPath := keysDir + "/proving.key"
	verifyingKeyPath := keysDir + "/verifying.key"
	verifierSolPath := contractsDir + "/Verifier.sol"

	// Save Proving Key
	fmt.Printf("💾 Saving Proving Key (%s)...\n", provingKeyPath)
	pkFile, _ := os.Create(provingKeyPath)
	pk.WriteTo(pkFile)
	pkFile.Close()

	// Save Verifying Key
	fmt.Printf("💾 Saving Verifying Key (%s)...\n", verifyingKeyPath)
	vkFile, _ := os.Create(verifyingKeyPath)
	vk.WriteTo(vkFile)
	vkFile.Close()

	fmt.Printf("📜 Exporting Solidity Verifier (%s)...\n", verifierSolPath)
	f, err := os.Create(verifierSolPath)
	if err != nil {
		fmt.Printf("❌ File creation failed: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	err = vk.ExportSolidity(f)
	if err != nil {
		fmt.Printf("❌ Export failed: %v\n", err)
		os.Exit(1)
	}
	f.Close() // Explicit close to flush

	// PATCH: Replace Transcript Hash with "Compressed Point + SHA256" logic.
	// GNARK Prover (Go) uses SHA256 hashing of COMPRESSED points (32 bytes).
	// Solidity export defaults to Uncompressed (64 bytes) inputs.
	// We must manually compress the point in Solidity before hashing.
	content, err := os.ReadFile(verifierSolPath)
	if err == nil {
		s := string(content)

		// 1. Ensure we match either keccak256 or sha256 (in case previous patch ran)
		// Match the multi-line block for publicCommitments[0] assignment
		re := regexp.MustCompile(`(?s)publicCommitments\[0\]\s*=\s*uint256\(\s*(?:keccak256|sha256)\(\s*abi\.encodePacked\(\s*commitments\[0\],\s*commitments\[1\],\s*publicAndCommitmentCommitted\s*\)\s*\)\s*\)\s*%\s*R;`)

		// Replacement logic: Compress commitments[0] based on commitments[1] (Y coordinate)
		// BN254 Half P approx: 10944121435919637611123202872628637544274182200208017171849102093287904247808
		replacement := `
            uint256 compressed = commitments[0];
            if (commitments[1] > 10944121435919637611123202872628637544274182200208017171849102093287904247808) {
                compressed = compressed | (1 << 255);
            }
            publicCommitments[0] = uint256(sha256(abi.encodePacked(compressed, publicAndCommitmentCommitted))) % R;`

		newContent := re.ReplaceAllString(s, replacement)

		err = os.WriteFile(verifierSolPath, []byte(newContent), 0o644)
		if err != nil {
			fmt.Printf("❌ Failed to patch Verifier.sol: %v\n", err)
		} else {
			fmt.Println("🔧 Patched Verifier.sol to use COMPRESSED inputs with SHA256 (matching Prover).")
		}
	}

	fmt.Println("✅ Verifier.sol and proving.key exported successfully.")
	fmt.Println("👉 IMPORTANT: The relayer will now use 'proving.key' to ensure compatibility.")
}
