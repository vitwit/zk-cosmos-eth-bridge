package main

import (
	"context"
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
const EthereumBridgeABI = `[
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
						"internalType": "uint256[2]",
						"name": "a",
						"type": "uint256[2]"
					},
					{
						"internalType": "uint256[2][2]",
						"name": "b",
						"type": "uint256[2][2]"
					},
					{
						"internalType": "uint256[2]",
						"name": "c",
						"type": "uint256[2]"
					},
					{
						"internalType": "uint256[]",
						"name": "input",
						"type": "uint256[]"
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
		]`

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

	proof, err := p.GenerateInclusionProof(cometRPC, int64(vLog.BlockNumber), cosmosTxHash, event.LockId.Uint64(), event.Amount.String(), event.EthDestination.Hex())
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
		fmt.Println("Waiting for root registration to be mined...")
		time.Sleep(5 * time.Second) // Simple wait for POC
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
	a := [2]*big.Int{new(big.Int), new(big.Int)}
	a[0].SetString(proof.A[0][2:], 16)
	a[1].SetString(proof.A[1][2:], 16)

	b := [2][2]*big.Int{
		{new(big.Int), new(big.Int)},
		{new(big.Int), new(big.Int)},
	}
	b[0][0].SetString(proof.B[0][0][2:], 16)
	b[0][1].SetString(proof.B[0][1][2:], 16)
	b[1][0].SetString(proof.B[1][0][2:], 16)
	b[1][1].SetString(proof.B[1][1][2:], 16)

	c := [2]*big.Int{new(big.Int), new(big.Int)}
	c[0].SetString(proof.C[0][2:], 16)
	c[1].SetString(proof.C[1][2:], 16)

	inputs := make([]*big.Int, len(proof.Inputs))
	for i, input := range proof.Inputs {
		inputs[i] = new(big.Int)
		inputs[i].SetString(input, 10)
	}

	// Reconstruct txHash from proof inputs (last 32 bytes)
	// Reconstruct txHash from proof inputs (last 32 bytes of the first 64 inputs)
	var txHash [32]byte
	for i := 0; i < 32; i++ {
		txHash[i] = byte(inputs[i+32].Uint64())
	}

	data, err := bridgeAbi.Pack("mint", a, b, c, inputs, txHash, to, amount)
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

	tx := types.NewTransaction(nonce, bridgeAddr, big.NewInt(0), 1000000, gasPrice, data)
	signedTx, err := auth.Signer(auth.From, tx)
	if err != nil {
		return common.Hash{}, err
	}

	return signedTx.Hash(), client.SendTransaction(context.Background(), signedTx)
}
