package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vitwit/zk-state-transition/testing/pkg/prover"
)

// CosmosLock ABI for event parsing
const CosmosLockABI = `[
			{
				"anonymous": false,
				"inputs": [
					{
						"indexed": true,
						"internalType": "uint256",
						"name": "lockId",
						"type": "uint256"
					},
					{
						"indexed": true,
						"internalType": "address",
						"name": "sender",
						"type": "address"
					},
					{
						"indexed": false,
						"internalType": "uint256",
						"name": "amount",
						"type": "uint256"
					},
					{
						"indexed": true,
						"internalType": "address",
						"name": "ethDestination",
						"type": "address"
					}
				],
				"name": "Lock",
				"type": "event"
			},
			{
				"inputs": [],
				"name": "currentLockId",
				"outputs": [
					{
						"internalType": "uint256",
						"name": "",
						"type": "uint256"
					}
				],
				"stateMutability": "view",
				"type": "function"
			},
			{
				"inputs": [
					{
						"internalType": "address",
						"name": "ethDestination",
						"type": "address"
					}
				],
				"name": "lock",
				"outputs": [],
				"stateMutability": "payable",
				"type": "function"
			}
		]`

// EthereumBridge ABI for minting
const EthereumBridgeABI = ` [
			{
				"inputs": [
					{
						"internalType": "address",
						"name": "_verifier",
						"type": "address"
					},
					{
						"internalType": "address",
						"name": "_token",
						"type": "address"
					}
				],
				"stateMutability": "nonpayable",
				"type": "constructor"
			},
			{
				"anonymous": false,
				"inputs": [
					{
						"indexed": true,
						"internalType": "address",
						"name": "to",
						"type": "address"
					},
					{
						"indexed": false,
						"internalType": "uint256",
						"name": "amount",
						"type": "uint256"
					},
					{
						"indexed": true,
						"internalType": "bytes32",
						"name": "txHash",
						"type": "bytes32"
					}
				],
				"name": "Mint",
				"type": "event"
			},
			{
				"anonymous": false,
				"inputs": [
					{
						"indexed": true,
						"internalType": "bytes32",
						"name": "root",
						"type": "bytes32"
					}
				],
				"name": "RootAdded",
				"type": "event"
			},
			{
				"inputs": [
					{
						"internalType": "bytes32",
						"name": "_newRoot",
						"type": "bytes32"
					}
				],
				"name": "addRoot",
				"outputs": [],
				"stateMutability": "nonpayable",
				"type": "function"
			},
			{
				"inputs": [
					{
						"internalType": "uint256[8]",
						"name": "proof",
						"type": "uint256[8]"
					},
					{
						"internalType": "uint256[2]",
						"name": "commitments",
						"type": "uint256[2]"
					},
					{
						"internalType": "uint256[2]",
						"name": "commitmentPok",
						"type": "uint256[2]"
					},
					{
						"internalType": "uint256[8]",
						"name": "input",
						"type": "uint256[8]"
					},
					{
						"internalType": "bytes32",
						"name": "_txHash",
						"type": "bytes32"
					},
					{
						"internalType": "address",
						"name": "_to",
						"type": "address"
					},
					{
						"internalType": "uint256",
						"name": "_amount",
						"type": "uint256"
					}
				],
				"name": "mint",
				"outputs": [],
				"stateMutability": "nonpayable",
				"type": "function"
			},
			{
				"inputs": [],
				"name": "owner",
				"outputs": [
					{
						"internalType": "address",
						"name": "",
						"type": "address"
					}
				],
				"stateMutability": "view",
				"type": "function"
			},
			{
				"inputs": [],
				"name": "token",
				"outputs": [
					{
						"internalType": "contract WrappedEVMS",
						"name": "",
						"type": "address"
					}
				],
				"stateMutability": "view",
				"type": "function"
			},
			{
				"inputs": [
					{
						"internalType": "uint256",
						"name": "",
						"type": "uint256"
					}
				],
				"name": "usedLockIds",
				"outputs": [
					{
						"internalType": "bool",
						"name": "",
						"type": "bool"
					}
				],
				"stateMutability": "view",
				"type": "function"
			},
			{
				"inputs": [
					{
						"internalType": "bytes32",
						"name": "",
						"type": "bytes32"
					}
				],
				"name": "validRoots",
				"outputs": [
					{
						"internalType": "bool",
						"name": "",
						"type": "bool"
					}
				],
				"stateMutability": "view",
				"type": "function"
			},
			{
				"inputs": [],
				"name": "verifier",
				"outputs": [
					{
						"internalType": "contract IVerifier",
						"name": "",
						"type": "address"
					}
				],
				"stateMutability": "view",
				"type": "function"
			}
		],`

func main() {
	if len(os.Args) < 7 {
		fmt.Println("Usage: relayer <evmos_evm_rpc> <evmos_comet_rpc> <eth_rpc> <lock_contract_addr> <bridge_contract_addr> <private_key> [start_block]")
		return
	}

	evmosEvmRPC := os.Args[1]
	evmosCometRPC := os.Args[2]
	ethRPC := os.Args[3]
	lockAddr := common.HexToAddress(os.Args[4])
	bridgeAddr := common.HexToAddress(os.Args[5])
	privKeyHex := os.Args[6]

	var startBlock *int64
	if len(os.Args) > 7 {
		sb, err := strconv.ParseInt(os.Args[7], 10, 64)
		if err == nil {
			startBlock = &sb
		}
	}

	client, err := ethclient.Dial(evmosEvmRPC)
	if err != nil {
		log.Fatal(err)
	}

	ethClient, err := ethclient.Dial(ethRPC)
	if err != nil {
		log.Fatal(err)
	}

	// Fetch current block number BEFORE prover initialization
	var initialBlock uint64
	if startBlock != nil {
		initialBlock = uint64(*startBlock)
	} else {
		lb, err := client.BlockNumber(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		initialBlock = lb
	}

	contractAbi, err := abi.JSON(strings.NewReader(CosmosLockABI))
	if err != nil {
		log.Fatal(err)
	}

	bridgeAbi, err := abi.JSON(strings.NewReader(EthereumBridgeABI))
	if err != nil {
		log.Fatal(err)
	}

	p, err := prover.NewProver()
	if err != nil {
		log.Fatalf("Failed to initialize prover: %v", err)
	}

	query := ethereum.FilterQuery{
		Addresses: []common.Address{lockAddr},
	}

	// Check if RPC is HTTP, if so, default to polling
	if strings.HasPrefix(ethRPC, "http") {
		fmt.Println("HTTP RPC detected. Defaulting to polling mode...")
		pollLogs(client, query, contractAbi, bridgeAbi, ethClient, bridgeAddr, privKeyHex, evmosCometRPC, initialBlock, p)
		return
	}

	logs := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		fmt.Printf("Subscription failed: %v\n", err)
		fmt.Println("Note: Subscriptions require a WebSocket URL (ws:// or wss://).")
		fmt.Println("Falling back to polling mode...")
		pollLogs(client, query, contractAbi, bridgeAbi, ethClient, bridgeAddr, privKeyHex, evmosCometRPC, initialBlock, p)
		return
	}

	fmt.Printf("Relayer started. Listening for Lock events on %s...\n", lockAddr.Hex())

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case vLog := <-logs:
			processLog(vLog, contractAbi, bridgeAbi, ethClient, bridgeAddr, privKeyHex, evmosCometRPC, p)
		}
	}
}

func pollLogs(client *ethclient.Client, query ethereum.FilterQuery, contractAbi abi.ABI, bridgeAbi abi.ABI, ethClient *ethclient.Client, bridgeAddr common.Address, privKeyHex string, cometRPC string, initialBlock uint64, p *prover.Prover) {
	lastBlock := initialBlock - 1

	fmt.Printf("Polling started from block %d\n", lastBlock+1)

	for {
		time.Sleep(2 * time.Second)

		currentBlock, err := client.BlockNumber(context.Background())
		if err != nil {
			continue
		}

		if currentBlock > lastBlock {
			fromBlock := lastBlock + 1
			fmt.Printf("Checking blocks %d to %d...\n", fromBlock, currentBlock)

			query.FromBlock = big.NewInt(int64(fromBlock))
			query.ToBlock = big.NewInt(int64(currentBlock))

			vLogs, err := client.FilterLogs(context.Background(), query)
			if err != nil {
				fmt.Printf("Error filtering logs: %v\n", err)
				continue
			}

			for _, vLog := range vLogs {
				processLog(vLog, contractAbi, bridgeAbi, ethClient, bridgeAddr, privKeyHex, cometRPC, p)
			}
			lastBlock = currentBlock
		}
	}
}

func processLog(vLog types.Log, contractAbi abi.ABI, bridgeAbi abi.ABI, ethClient *ethclient.Client, bridgeAddr common.Address, privKeyHex string, cometRPC string, p *prover.Prover) {
	fmt.Printf("Detected Lock event in block %d, tx %s\n", vLog.BlockNumber, vLog.TxHash.Hex())

	// Parse event data
	event := struct {
		LockId         *big.Int
		Sender         common.Address
		Amount         *big.Int
		EthDestination common.Address
	}{}
	err := contractAbi.UnpackIntoInterface(&event, "Lock", vLog.Data)
	if err != nil {
		fmt.Printf("Error unpacking event: %v\n", err)
		return
	}

	// Indexed parameters are in vLog.Topics
	// Topic 0: Event Signature
	// Topic 1: lockId
	// Topic 2: sender
	// Topic 3: ethDestination
	if len(vLog.Topics) >= 4 {
		event.LockId = new(big.Int).SetBytes(vLog.Topics[1].Bytes())
		event.Sender = common.BytesToAddress(vLog.Topics[2].Bytes())
		event.EthDestination = common.BytesToAddress(vLog.Topics[3].Bytes())
	}

	cosmosTxHash := strings.TrimPrefix(vLog.TxHash.Hex(), "0x")

	fmt.Printf("Generating ZK proof for Cosmos Tx: %s at height %d\n", cosmosTxHash, vLog.BlockNumber)

	proof, err := p.GenerateInclusionProof(cometRPC, int64(vLog.BlockNumber), int(vLog.TxIndex), event.LockId.Uint64(), event.Amount.String(), event.EthDestination.Hex())
	if err != nil {
		fmt.Printf("Error generating proof: %v\n", err)
		return
	}

	// 1. Check if the block root is already registered on Ethereum
	fmt.Printf("Checking if block root %x is registered on Ethereum...\n", proof.Root)
	registered, err := isRootRegistered(ethClient, bridgeAddr, proof.Root)
	if err != nil {
		fmt.Printf("Error checking root: %v\n", err)
		return
	}

	if !registered {
		fmt.Println("Root not registered. Registering...")
		txHash, err := registerRoot(ethClient, bridgeAddr, privKeyHex, proof.Root)
		if err != nil {
			fmt.Printf("Error registering root: %v\n", err)
			return
		}
		fmt.Printf("Root registration tx submitted: %s\n", txHash.Hex())

		_, err = waitForReceipt(ethClient, txHash)
		if err != nil {
			fmt.Printf("Error waiting for root registration: %v\n", err)
			return
		}
	} else {
		fmt.Println("Root already registered.")
	}

	fmt.Println("ZK Proof generated successfully! Submitting to Ethereum...")

	txHash, err := submitMintTx(ethClient, bridgeAddr, bridgeAbi, privKeyHex, proof, event.EthDestination, event.Amount)
	if err != nil {
		fmt.Printf("Error submitting mint tx: %v\n", err)
		return
	}

	fmt.Printf("Mint tx submitted: %s\n", txHash.Hex())
	fmt.Printf("Proof submitted to Bridge at %s for destination %s\n", bridgeAddr.Hex(), event.EthDestination.Hex())
}

func isRootRegistered(client *ethclient.Client, bridgeAddr common.Address, root [32]byte) (bool, error) {
	bridgeAbi, _ := abi.JSON(strings.NewReader(EthereumBridgeABI))
	data, err := bridgeAbi.Pack("validRoots", root)
	if err != nil {
		return false, err
	}

	msg := ethereum.CallMsg{
		To:   &bridgeAddr,
		Data: data,
	}

	res, err := client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return false, err
	}

	var registered bool
	err = bridgeAbi.UnpackIntoInterface(&registered, "validRoots", res)
	return registered, err
}

func registerRoot(client *ethclient.Client, bridgeAddr common.Address, privKeyHex string, root [32]byte) (common.Hash, error) {
	privateKey, err := crypto.ToECDSA(common.Hex2Bytes(strings.TrimPrefix(privKeyHex, "0x")))
	if err != nil {
		return common.Hash{}, err
	}

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return common.Hash{}, err
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return common.Hash{}, err
	}

	bridgeAbi, _ := abi.JSON(strings.NewReader(EthereumBridgeABI))
	data, err := bridgeAbi.Pack("addRoot", root)
	if err != nil {
		return common.Hash{}, err
	}

	nonce, err := client.PendingNonceAt(context.Background(), auth.From)
	if err != nil {
		return common.Hash{}, err
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return common.Hash{}, err
	}

	tx := types.NewTransaction(nonce, bridgeAddr, big.NewInt(0), 200000, gasPrice, data)
	signedTx, err := auth.Signer(auth.From, tx)
	if err != nil {
		return common.Hash{}, err
	}

	return signedTx.Hash(), client.SendTransaction(context.Background(), signedTx)
}

func submitMintTx(client *ethclient.Client, bridgeAddr common.Address, bridgeAbi abi.ABI, privKeyHex string, proof *prover.ProofData, to common.Address, amount *big.Int) (common.Hash, error) {
	privateKey, err := crypto.ToECDSA(common.Hex2Bytes(strings.TrimPrefix(privKeyHex, "0x")))
	if err != nil {
		return common.Hash{}, err
	}

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return common.Hash{}, err
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return common.Hash{}, err
	}

	// Convert proof to big.Int for Solidity
	proofFlat := [8]*big.Int{}
	proofFlat[0] = new(big.Int)
	proofFlat[0].SetString(proof.A[0][2:], 16)
	proofFlat[1] = new(big.Int)
	proofFlat[1].SetString(proof.A[1][2:], 16)

	proofFlat[2] = new(big.Int)
	proofFlat[2].SetString(proof.B[0][0][2:], 16)
	proofFlat[3] = new(big.Int)
	proofFlat[3].SetString(proof.B[0][1][2:], 16)
	proofFlat[4] = new(big.Int)
	proofFlat[4].SetString(proof.B[1][0][2:], 16)
	proofFlat[5] = new(big.Int)
	proofFlat[5].SetString(proof.B[1][1][2:], 16)

	proofFlat[6] = new(big.Int)
	proofFlat[6].SetString(proof.C[0][2:], 16)
	proofFlat[7] = new(big.Int)
	proofFlat[7].SetString(proof.C[1][2:], 16)

	// Commitments and CommitmentPok
	commitments := [2]*big.Int{new(big.Int), new(big.Int)}
	commitments[0].SetString(proof.Commitments[0][2:], 16)
	commitments[1].SetString(proof.Commitments[1][2:], 16)

	commitmentPok := [2]*big.Int{new(big.Int), new(big.Int)}
	commitmentPok[0].SetString(proof.CommitmentPok[0][2:], 16)
	commitmentPok[1].SetString(proof.CommitmentPok[1][2:], 16)

	// Convert inputs to fixed-size array [8]*big.Int
	if len(proof.Inputs) != 8 {
		return common.Hash{}, fmt.Errorf("expected 8 inputs, got %d", len(proof.Inputs))
	}

	var inputs [8]*big.Int
	for i, input := range proof.Inputs {
		inputs[i] = new(big.Int)
		inputs[i].SetString(input, 10)
	}

	// Reconstruct txHash - CRITICAL: This must match what the contract expects
	// The txHash should be the original Cosmos transaction hash
	var txHashBytes [32]byte

	// Reconstruct txHash from TxHigh (inputs[2]) and TxLow (inputs[3])
	txHashInt := new(big.Int).Or(new(big.Int).Lsh(inputs[2], 128), inputs[3])
	txHashInt.FillBytes(txHashBytes[:])

	// Extended Debug logging
	fmt.Printf("\n=== Mint Transaction Debug ===\n")
	fmt.Printf("Bridge Address: %s\n", bridgeAddr.Hex())
	fmt.Printf("To Address: %s\n", to.Hex())
	fmt.Printf("Amount: %s wei\n", amount.String())
	fmt.Printf("\n--- Proof Components ---\n")
	fmt.Printf("Proof A[0]: %s\n", proofFlat[0].String())
	fmt.Printf("Proof A[1]: %s\n", proofFlat[1].String())
	fmt.Printf("Proof B[0][0]: %s\n", proofFlat[2].String())
	fmt.Printf("Proof B[0][1]: %s\n", proofFlat[3].String())
	fmt.Printf("Proof B[1][0]: %s\n", proofFlat[4].String())
	fmt.Printf("Proof B[1][1]: %s\n", proofFlat[5].String())
	fmt.Printf("Proof C[0]: %s\n", proofFlat[6].String())
	fmt.Printf("Proof C[1]: %s\n", proofFlat[7].String())
	fmt.Printf("\n--- Commitments ---\n")
	fmt.Printf("Commitment[0]: %s\n", commitments[0].String())
	fmt.Printf("Commitment[1]: %s\n", commitments[1].String())
	fmt.Printf("CommitmentPok[0]: %s\n", commitmentPok[0].String())
	fmt.Printf("CommitmentPok[1]: %s\n", commitmentPok[1].String())

	fmt.Printf("\n--- Public Inputs Breakdown ---\n")
	fmt.Printf("Root (inputs[0:2]): 0x%x%x\n", inputs[0], inputs[1])
	fmt.Printf("TxHash (inputs[2:4]): 0x%x%x\n", inputs[2], inputs[3])
	fmt.Printf("LockID (input[5]): %s\n", inputs[5].String())
	fmt.Printf("Amount (input[6:8]): %s (high: %s, low: %s)\n",
		new(big.Int).Or(new(big.Int).Lsh(inputs[6], 128), inputs[7]).String(),
		inputs[6].String(), inputs[7].String())
	fmt.Printf("Destination (input[4]): 0x%x\n", inputs[4])

	// Verify amount matches
	reconstructedAmount := new(big.Int).Or(new(big.Int).Lsh(inputs[6], 128), inputs[7])
	if reconstructedAmount.Cmp(amount) != 0 {
		fmt.Printf("⚠️  WARNING: Amount mismatch! Proof: %s, Param: %s\n", reconstructedAmount.String(), amount.String())
	}

	fmt.Printf("\n--- Transaction Parameters ---\n")
	fmt.Printf("Chain ID: %s\n", chainID.String())
	fmt.Printf("From: %s\n", auth.From.Hex())

	// First, estimate gas to see if it would succeed
	callData, err := bridgeAbi.Pack("mint", proofFlat, commitments, commitmentPok, inputs, txHashBytes, to, amount)
	if err != nil {
		return common.Hash{}, fmt.Errorf("error packing data: %v", err)
	}

	fmt.Printf("Calldata size: %d bytes\n", len(callData))
	fmt.Printf("Calldata size: %d bytes\n", len(callData))
	fmt.Printf("Calldata: %s\n", hex.EncodeToString(callData))

	// Skip gas estimation - it fails even though the transaction succeeds
	// Use fixed gas limit instead (must be under block gas limit of 10M)
	fmt.Printf("Using fixed gas limit for ZK proof verification...\n")

	msg := ethereum.CallMsg{
		From: auth.From,
		To:   &bridgeAddr,
		Data: callData,
	}

	estimatedGas, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return common.Hash{}, fmt.Errorf("tx would revert or exceed block gas: %v", err)
	}

	fmt.Printf("Estimated gas: %d\n", estimatedGas)

	if estimatedGas > 9_500_000 {
		return common.Hash{}, fmt.Errorf("proof too expensive: %d gas > block limit", estimatedGas)
	}

	gasLimit := estimatedGas + 100_000
	fmt.Printf("Gas limit: %d\n", gasLimit)

	nonce, err := client.PendingNonceAt(context.Background(), auth.From)
	if err != nil {
		return common.Hash{}, err
	}
	fmt.Printf("Nonce: %d\n", nonce)

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return common.Hash{}, err
	}
	fmt.Printf("Gas price: %s wei\n", gasPrice.String())

	fmt.Printf("==============================\n\n")

	tx := types.NewTransaction(nonce, bridgeAddr, big.NewInt(0), gasLimit, gasPrice, callData)
	signedTx, err := auth.Signer(auth.From, tx)
	if err != nil {
		return common.Hash{}, err
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to send transaction: %v", err)
	}

	return signedTx.Hash(), nil
}

// Helper function to check transaction receipt and decode revert reason
func waitForReceipt(client *ethclient.Client, txHash common.Hash) (*types.Receipt, error) {
	fmt.Printf("Waiting for transaction %s to be mined...\n", txHash.Hex())

	for i := 0; i < 60; i++ {
		receipt, err := client.TransactionReceipt(context.Background(), txHash)
		if err == nil {
			if receipt.Status == 0 {
				fmt.Printf("❌ Transaction failed!\n")
				fmt.Printf("Gas used: %d\n", receipt.GasUsed)

				// Try to get revert reason by replaying the transaction
				tx, _, err := client.TransactionByHash(context.Background(), txHash)
				if err == nil {
					// Get the from address from the transaction
					from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
					if err == nil {
						msg := ethereum.CallMsg{
							From:     from,
							To:       tx.To(),
							Gas:      tx.Gas(),
							GasPrice: tx.GasPrice(),
							Value:    tx.Value(),
							Data:     tx.Data(),
						}
						_, callErr := client.CallContract(context.Background(), msg, receipt.BlockNumber)
						if callErr != nil {
							fmt.Printf("Revert reason: %v\n", callErr)
						}
					}
				}
			} else {
				fmt.Printf("✅ Transaction successful!\n")
			}
			return receipt, nil
		}
		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("timeout waiting for transaction receipt")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
