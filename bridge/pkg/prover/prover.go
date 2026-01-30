package prover

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	gnark_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/circuits"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/rpc"
)

// GenerateProof fetches real data from Cosmos RPC and generates a SNARK proof.
func GenerateProof(cosmosRpcUrl string, txHashHex string, outputPath string) ([32]byte, [32]byte, error) {
	var root [32]byte
	var tx [32]byte
	client := rpc.NewCosmosClient(cosmosRpcUrl)

	// 1. Fetch real proof from Tendermint
	fmt.Printf("📡 Querying Merkle proof for TM Hash: %s...\n", txHashHex)
	resp, err := client.GetTxDetails(txHashHex)
	if err != nil {
		return root, tx, fmt.Errorf("failed to fetch tx proof: %v", err)
	}

	// 2. Resolve Hash and Root
	tmHash := resp.Result.Hash
	if tmHash == "" {
		tmHash = resp.Hash
	}
	if tmHash == "" {
		tmHash = resp.TxHash
	}

	leafHashStr := resp.Result.Proof.Proof.LeafHash
	if leafHashStr == "" {
		leafHashStr = tmHash
	}

	rootHashStr := resp.Result.Proof.RootHash
	if rootHashStr == "" {
		return root, tx, fmt.Errorf("merkle root_hash not found in response")
	}

	rootBytes, _ := rpc.DecodeHash(rootHashStr)
	leafBytes, _ := rpc.DecodeHash(leafHashStr)
	copy(root[:], rootBytes)
	copy(tx[:], leafBytes)

	aunts := resp.Result.Proof.Proof.Aunts
	index := 0
	indexStr := resp.Result.Proof.Proof.Index
	if indexStr != "" {
		fmt.Sscanf(indexStr, "%d", &index)
	}

	fmt.Printf("📊 Merkle Proof: AuntCount=%d\n", len(aunts))
	fmt.Println("⏳ Preparing ZK witness...")

	var witness circuits.ZkBridgeCircuit
	// Pack Root and TxHash into 4x uint64 each
	for i := 0; i < 4; i++ {
		witness.PackedRoot[i] = binary.BigEndian.Uint64(root[i*8 : (i+1)*8])
		witness.PackedTxHash[i] = binary.BigEndian.Uint64(tx[i*8 : (i+1)*8])
	}

	for i := 0; i < circuits.MerkleDepth; i++ {
		witness.ProofHelper[i] = 0
		for j := 0; j < 32; j++ {
			witness.ProofPath[i][j] = 0
		}
	}

	depth := len(aunts)
	witness.ActualDepth = big.NewInt(int64(depth))

	for i := 0; i < depth && i < circuits.MerkleDepth; i++ {
		siblingBytes, _ := rpc.DecodeHash(aunts[i])
		for j := 0; j < 32; j++ {
			witness.ProofPath[i][j] = big.NewInt(int64(siblingBytes[j]))
		}
		witness.ProofHelper[i] = index & 1
		index >>= 1
	}

	// 3. Compile and Prove
	fmt.Println("⚙️  Step 1/4: Compiling ZK Circuit (Optimizing constraints)...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuits.ZkBridgeCircuit{})
	if err != nil {
		return root, tx, err
	}

	fmt.Println("⚙️  Step 2/4: Loading Persistent Setup Keys...")

	// Robust path detection for keys
	var keysDir string
	if _, err := os.Stat("go.mod"); err == nil {
		// Running from root
		keysDir = "keys"
	} else {
		// Running from subdirectory
		keysDir = "../../keys"
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	pkPath := keysDir + "/proving.key"
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return root, tx, fmt.Errorf("proving.key not found at %s! Run 'go run cmd/compiler/main.go'", pkPath)
	}
	pk.ReadFrom(pkFile)
	pkFile.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	vkPath := keysDir + "/verifying.key"
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return root, tx, fmt.Errorf("verifying.key not found at %s!", vkPath)
	}
	vk.ReadFrom(vkFile)
	vkFile.Close()

	fmt.Println("⚙️  Step 3/4: Generating Full Witness...")
	fullWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		return root, tx, err
	}

	publicWitness, _ := fullWitness.Public()

	fmt.Println("🚀 Step 4/4: Calculating ZK-SNARK Proof...")
	proof, err := groth16.Prove(ccs, pk, fullWitness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		return root, tx, err
	}

	fmt.Println("✅ Proof generated locally.")
	if err := groth16.Verify(proof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)); err != nil {
		return root, tx, fmt.Errorf("local verification failed: %v", err)
	}

	// 4. Export JSON
	bn254Proof := proof.(*gnark_bn254.Proof)
	publicInputs := make([]string, 8)
	for i := 0; i < 4; i++ {
		publicInputs[i] = fmt.Sprintf("%d", witness.PackedRoot[i])
		publicInputs[4+i] = fmt.Sprintf("%d", witness.PackedTxHash[i])
	}

	// Handle Commitments
	commitments := [2]string{"0", "0"}
	commitmentPok := [2]string{"0", "0"}
	if len(bn254Proof.Commitments) > 0 {
		commitments[0] = bn254Proof.Commitments[0].X.String()
		commitments[1] = bn254Proof.Commitments[0].Y.String()
	}
	if len(bn254Proof.CommitmentPok.X.String()) > 0 {
		commitmentPok[0] = bn254Proof.CommitmentPok.X.String()
		commitmentPok[1] = bn254Proof.CommitmentPok.Y.String()
	}

	data := struct {
		A             [2]string    `json:"a"`
		B             [2][2]string `json:"b"`
		C             [2]string    `json:"c"`
		Commitments   [2]string    `json:"commitments"`
		CommitmentPok [2]string    `json:"commitmentPok"`
		Public        []string     `json:"public"`
	}{
		A: [2]string{bn254Proof.Ar.X.String(), bn254Proof.Ar.Y.String()},
		B: [2][2]string{
			{bn254Proof.Bs.X.A1.String(), bn254Proof.Bs.X.A0.String()},
			{bn254Proof.Bs.Y.A1.String(), bn254Proof.Bs.Y.A0.String()},
		},
		C:             [2]string{bn254Proof.Krs.X.String(), bn254Proof.Krs.Y.String()},
		Commitments:   commitments,
		CommitmentPok: commitmentPok,
		Public:        publicInputs,
	}

	out, _ := json.MarshalIndent(data, "", "  ")
	fmt.Printf("💾 Saving proof to %s\n", outputPath)
	return root, tx, os.WriteFile(outputPath, out, 0o644)
}

// SubmitProof automatically sends the ZK-SNARK proof to the EthBridge contract.
func SubmitProof(ethRpcUrl string, privKeyHex string, bridgeAddr string, recipient string, amount *big.Int, root [32]byte, txHash [32]byte, proofPath string, isMint bool) error {
	client, err := ethclient.Dial(ethRpcUrl)
	if err != nil {
		return err
	}

	privateKey, _ := crypto.HexToECDSA(privKeyHex)
	publicKey := privateKey.Public()
	fromAddress := crypto.PubkeyToAddress(*(publicKey.(*ecdsa.PublicKey)))

	nonce, _ := client.PendingNonceAt(context.Background(), fromAddress)
	gasPrice, _ := client.SuggestGasPrice(context.Background())
	chainID, _ := client.ChainID(context.Background())

	auth, _ := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(1500000)
	auth.GasPrice = gasPrice

	proofData, _ := os.ReadFile(proofPath)
	var p struct {
		A             [2]string    `json:"a"`
		B             [2][2]string `json:"b"`
		C             [2]string    `json:"c"`
		Commitments   [2]string    `json:"commitments"`
		CommitmentPok [2]string    `json:"commitmentPok"`
	}
	json.Unmarshal(proofData, &p)

	a := [2]*big.Int{}
	b := [2][2]*big.Int{}
	c := [2]*big.Int{}
	commits := [2]*big.Int{}
	pok := [2]*big.Int{}

	for i := 0; i < 2; i++ {
		a[i], _ = new(big.Int).SetString(p.A[i], 10)
		c[i], _ = new(big.Int).SetString(p.C[i], 10)
		commits[i], _ = new(big.Int).SetString(p.Commitments[i], 10)
		pok[i], _ = new(big.Int).SetString(p.CommitmentPok[i], 10)
		for j := 0; j < 2; j++ {
			b[i][j], _ = new(big.Int).SetString(p.B[i][j], 10)
		}
	}

	methodName := "mint"
	paramName := "lockTxHash"
	if !isMint {
		methodName = "unlock"
		paramName = "burnTxHash"
	}

	abiJSON := fmt.Sprintf(`[{"inputs":[{"internalType":"uint256[2]","name":"a","type":"uint256[2]"},{"internalType":"uint256[2][2]","name":"b","type":"uint256[2][2]"},{"internalType":"uint256[2]","name":"c","type":"uint256[2]"},{"internalType":"uint256[2]","name":"commitments","type":"uint256[2]"},{"internalType":"uint256[2]","name":"commitmentPok","type":"uint256[2]"},{"internalType":"bytes32","name":"root","type":"bytes32"},{"internalType":"bytes32","name":"%s","type":"bytes32"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"%s","outputs":[],"stateMutability":"nonpayable","type":"function"}]`, paramName, methodName)
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))
	contract := bind.NewBoundContract(common.HexToAddress(bridgeAddr), parsedABI, client, client, client)

	tx, err := contract.Transact(auth, methodName, a, b, c, commits, pok, root, txHash, common.HexToAddress(recipient), amount)
	if err != nil {
		return err
	}

	fmt.Printf("🚀 ZK-SNARK Proof submitted! Method=%s, Hash: %s\n", methodName, tx.Hash().Hex())
	return nil
}

func FetchLockDetails(evmRpcUrl string, bridgeAddr string, txHashHex string) (string, *big.Int, bool, error) {
	client, err := ethclient.Dial(evmRpcUrl)
	if err != nil {
		return "", nil, false, err
	}
	receipt, err := client.TransactionReceipt(context.Background(), common.HexToHash(txHashHex))
	if err != nil {
		return "", nil, false, err
	}

	lockEventSig := crypto.Keccak256Hash([]byte("Lock(address,uint256,address,uint256)")).Hex()
	burnEventSig := crypto.Keccak256Hash([]byte("Burn(address,uint256,address,uint256)")).Hex()

	for _, vLog := range receipt.Logs {
		logSig := vLog.Topics[0].Hex()
		logAddr := vLog.Address.Hex()

		if (logSig == lockEventSig || logSig == burnEventSig) && strings.EqualFold(logAddr, bridgeAddr) {
			amount := new(big.Int).SetBytes(vLog.Data[0:32])
			recipientAddressed := common.BytesToAddress(vLog.Data[32:64])
			return recipientAddressed.Hex(), amount, (logSig == lockEventSig), nil
		}
	}
	return "", nil, false, fmt.Errorf("lock or burn event not found")
}

func UpdateRoot(ethRpcUrl string, privKeyHex string, bridgeAddr string, newRoot [32]byte) error {
	client, err := ethclient.Dial(ethRpcUrl)
	if err != nil {
		return err
	}
	privateKey, _ := crypto.HexToECDSA(privKeyHex)
	chainID, _ := client.ChainID(context.Background())
	auth, _ := bind.NewKeyedTransactorWithChainID(privateKey, chainID)

	abiJSON := `[{"inputs":[{"internalType":"bytes32","name":"_newRoot","type":"bytes32"}],"name":"updateTrustedRoot","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))
	contract := bind.NewBoundContract(common.HexToAddress(bridgeAddr), parsedABI, client, client, client)
	tx, err := contract.Transact(auth, "updateTrustedRoot", newRoot)
	if err != nil {
		return err
	}
	fmt.Printf("🔄 Root update submitted. Hash: %s\n", tx.Hash().Hex())
	_, err = bind.WaitMined(context.Background(), client, tx)
	return err
}

// FetchEthLockDetails extracts details from an Ethereum Bridge event.
func FetchEthLockDetails(ethRpcUrl string, bridgeAddr string, txHashHex string) (string, *big.Int, bool, error) {
	client, err := ethclient.Dial(ethRpcUrl)
	if err != nil {
		return "", nil, false, err
	}
	receipt, err := client.TransactionReceipt(context.Background(), common.HexToHash(txHashHex))
	if err != nil {
		return "", nil, false, err
	}

	// event Locked(address indexed sender, uint256 amount, string cosmosRecipient, uint256 nonce);
	lockEventSig := crypto.Keccak256Hash([]byte("Locked(address,uint256,string,uint256)")).Hex()
	burnEventSig := crypto.Keccak256Hash([]byte("Burned(address,uint256,string,uint256)")).Hex()

	for _, vLog := range receipt.Logs {
		logSig := vLog.Topics[0].Hex()
		logAddr := vLog.Address.Hex()

		if (logSig == lockEventSig || logSig == burnEventSig) && strings.EqualFold(logAddr, bridgeAddr) {
			// Layout:
			// [0:32]   amount
			// [32:64]  offset to string data (usually 96)
			// [64:96]  nonce
			// [96:128] string length
			// [128:]   string data

			if len(vLog.Data) < 128 {
				continue
			}

			amount := new(big.Int).SetBytes(vLog.Data[0:32])

			// Extract string data using the offset and length
			strOffset := new(big.Int).SetBytes(vLog.Data[32:64]).Uint64()
			strLen := new(big.Int).SetBytes(vLog.Data[strOffset : strOffset+32]).Uint64()

			if uint64(len(vLog.Data)) < strOffset+32+strLen {
				return "", nil, false, fmt.Errorf("malformed event data: string out of bounds")
			}

			recipient := string(vLog.Data[strOffset+32 : strOffset+32+strLen])
			return recipient, amount, (logSig == lockEventSig), nil
		}
	}
	return "", nil, false, fmt.Errorf("ethereum event not found")
}

// UpdateEthRootOnCosmos updates the Ethereum trust anchor on the Cosmos bridge contract.
func UpdateEthRootOnCosmos(cosmosRpcUrl string, privKeyHex string, bridgeAddr string, newRoot [32]byte) error {
	client, err := ethclient.Dial(cosmosRpcUrl)
	if err != nil {
		return err
	}
	privateKey, _ := crypto.HexToECDSA(privKeyHex)
	chainID, _ := client.ChainID(context.Background())
	auth, _ := bind.NewKeyedTransactorWithChainID(privateKey, chainID)

	abiJSON := `[{"inputs":[{"internalType":"bytes32","name":"_newRoot","type":"bytes32"}],"name":"updateTrustedEthRoot","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))
	contract := bind.NewBoundContract(common.HexToAddress(bridgeAddr), parsedABI, client, client, client)
	tx, err := contract.Transact(auth, "updateTrustedEthRoot", newRoot)
	if err != nil {
		return err
	}
	fmt.Printf("🔄 Eth Root synced to Cosmos. Hash: %s\n", tx.Hash().Hex())
	_, err = bind.WaitMined(context.Background(), client, tx)
	return err
}

// SubmitEthProofToCosmos submits the MPT proof to the Cosmos bridge contract to mint/unlock assets.
func SubmitEthProofToCosmos(cosmosRpcUrl string, privKeyHex string, bridgeAddr string, recipient string, amount *big.Int, ethTxHash [32]byte, key []byte, proof [][]byte, isMint bool) error {
	client, err := ethclient.Dial(cosmosRpcUrl)
	if err != nil {
		return err
	}

	privateKey, _ := crypto.HexToECDSA(privKeyHex)
	chainID, _ := client.ChainID(context.Background())
	auth, _ := bind.NewKeyedTransactorWithChainID(privateKey, chainID)

	methodName := "mint"
	if !isMint {
		methodName = "unlock"
	}

	// abi for mint/unlock(address recipient, uint256 amount, bytes32 ethTxHash, bytes memory key, bytes[] memory mptProof)
	abiJSON := fmt.Sprintf(`[{"inputs":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"bytes32","name":"ethTxHash","type":"bytes32"},{"internalType":"bytes","name":"key","type":"bytes"},{"internalType":"bytes[]","name":"mptProof","type":"bytes[]"}],"name":"%s","outputs":[],"stateMutability":"nonpayable","type":"function"}]`, methodName)
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))
	contract := bind.NewBoundContract(common.HexToAddress(bridgeAddr), parsedABI, client, client, client)

	fmt.Printf("🚀 MPT Proof submission details:\n")
	fmt.Printf("  ├─ Target Key: %x\n", key)
	fmt.Printf("  ├─ Proof Nodes Count: %d\n", len(proof))
	for i, n := range proof {
		fmt.Printf("  │  └─ Node[%d]: %d bytes, Hash: %s\n", i, len(n), crypto.Keccak256Hash(n).Hex())
	}

	tx, err := contract.Transact(auth, methodName, common.HexToAddress(recipient), amount, ethTxHash, key, proof)
	if err != nil {
		return err
	}

	fmt.Printf("🚀 MPT Proof submitted to Cosmos! Method=%s, Hash: %s\n", methodName, tx.Hash().Hex())
	return nil
}
