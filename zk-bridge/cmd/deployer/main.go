package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env
	if err := godotenv.Load(); err != nil {
		if err := godotenv.Load("../../.env"); err != nil {
			log.Println("⚠️ No .env file found")
		}
	}

	rpcURL := os.Getenv("ETHEREUM_RPC_URL")
	privKeyHex := os.Getenv("RELAYER_PRIV_KEY")

	if rpcURL == "" {
		rpcURL = "http://localhost:8545"
	}
	if privKeyHex == "" {
		log.Fatal("❌ RELAYER_PRIV_KEY not set")
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, _ := crypto.HexToECDSA(privKeyHex)
	publicKey := privateKey.Public()
	fromAddress := crypto.PubkeyToAddress(*(publicKey.(*ecdsa.PublicKey)))

	chainID, _ := client.ChainID(context.Background())
	auth, _ := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	auth.GasLimit = uint64(5000000)

	fmt.Println("🚀 Deploying ZK-Bridge Contracts...")
	fmt.Printf("📍 Deployer Address: %s\n", fromAddress.Hex())
	fmt.Printf("⛓️  Chain ID: %s\n", chainID.String())

	// Deploy Verifier
	fmt.Println("\n📜 Deploying Verifier.sol...")
	verifierAddr, err := deployVerifier(client, auth)
	if err != nil {
		log.Fatalf("❌ Verifier deployment failed: %v", err)
	}
	fmt.Printf("✅ Verifier deployed at: %s\n", verifierAddr.Hex())

	// Deploy BridgeSource
	fmt.Println("\n📜 Deploying BridgeSource.sol...")
	sourceAddr, err := deployBridgeSource(client, auth)
	if err != nil {
		log.Fatalf("❌ BridgeSource deployment failed: %v", err)
	}
	fmt.Printf("✅ BridgeSource deployed at: %s\n", sourceAddr.Hex())

	// Deploy BridgeDestination
	fmt.Println("\n📜 Deploying BridgeDestination.sol...")
	destAddr, err := deployBridgeDestination(client, auth, verifierAddr)
	if err != nil {
		log.Fatalf("❌ BridgeDestination deployment failed: %v", err)
	}
	fmt.Printf("✅ BridgeDestination deployed at: %s\n", destAddr.Hex())

	fmt.Println("\n🎉 All contracts deployed successfully!")
	fmt.Println("\n📝 Update your .env file with:")
	fmt.Printf("BRIDGE_SOURCE_ADDR=%s\n", sourceAddr.Hex())
	fmt.Printf("BRIDGE_DEST_ADDR=%s\n", destAddr.Hex())
}

func deployVerifier(client *ethclient.Client, auth *bind.TransactOpts) (common.Address, error) {
	// Check if Verifier.sol exists
	if _, err := os.Stat("../../contracts/Verifier.sol"); err != nil {
		return common.Address{}, fmt.Errorf("Verifier.sol not found. Run: go run cmd/compiler/main.go")
	}

	// For simplicity, we assume Verifier.sol has been compiled to bytecode
	// In practice, you'd use solc or read from artifacts
	// For now, return a placeholder - user must compile manually or use Hardhat
	return common.Address{}, fmt.Errorf("Verifier deployment requires compiled bytecode. Please use Hardhat or solc to compile contracts first, then update this deployer")
}

func deployBridgeSource(client *ethclient.Client, auth *bind.TransactOpts) (common.Address, error) {
	// Simplified: requires compiled bytecode
	return common.Address{}, fmt.Errorf("BridgeSource deployment requires compiled bytecode")
}

func deployBridgeDestination(client *ethclient.Client, auth *bind.TransactOpts, verifierAddr common.Address) (common.Address, error) {
	// Simplified: requires compiled bytecode
	return common.Address{}, fmt.Errorf("BridgeDestination deployment requires compiled bytecode")
}
