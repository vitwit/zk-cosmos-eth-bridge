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
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"golang.org/x/sync/errgroup"

	"github.com/vitwit/zk-state-transition/testing/pkg/prover"
)

// ===========================
// ABIs
// ===========================

// BridgeSource (ETH -> COSMOS) [MPT Path]
const BridgeSourceABI = `[
    {
      "anonymous": false,
      "inputs": [
        { "indexed": true, "internalType": "address", "name": "token", "type": "address" },
        { "indexed": true, "internalType": "address", "name": "sender", "type": "address" },
        { "indexed": false, "internalType": "string", "name": "recipient", "type": "string" },
        { "indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256" },
        { "indexed": false, "internalType": "uint256", "name": "nonce", "type": "uint256" }
      ],
      "name": "Locked",
      "type": "event"
    },
    {
      "inputs": [
        { "internalType": "bytes", "name": "headerRlp", "type": "bytes" }
      ],
      "name": "submitHeader",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        { "internalType": "bytes[]", "name": "proof", "type": "bytes[]" },
        { "internalType": "bytes", "name": "rawReceipt", "type": "bytes" },
        { "internalType": "uint64", "name": "blockNumber", "type": "uint64" },
        { "internalType": "bytes", "name": "path", "type": "bytes" }
      ],
      "name": "unlock",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
]`

// BridgeDestination (ETH -> COSMOS) [MPT Path]
const BridgeDestinationABI = `[
    {
      "inputs": [
        { "internalType": "bytes", "name": "headerRlp", "type": "bytes" },
        { "internalType": "bytes", "name": "signatures", "type": "bytes" }
      ],
      "name": "submitHeader",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        { "internalType": "bytes[]", "name": "proof", "type": "bytes[]" },
        { "internalType": "bytes", "name": "rawReceipt", "type": "bytes" },
        { "internalType": "uint64", "name": "blockNumber", "type": "uint64" },
        { "internalType": "bytes", "name": "path", "type": "bytes" }
      ],
      "name": "claim",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "anonymous": false,
      "inputs": [
        { "indexed": true, "internalType": "address", "name": "sender", "type": "address" },
        { "indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256" },
        { "indexed": false, "internalType": "address", "name": "recipient", "type": "address" }
      ],
      "name": "Burned",
      "type": "event"
    }
]`

// CosmosLock (COSMOS -> ETH) [ZK Path (Source) & MPT Destination]
const CosmosLockABI = `[
    {
        "anonymous": false,
        "inputs": [
            { "indexed": true, "internalType": "uint256", "name": "lockId", "type": "uint256" },
            { "indexed": true, "internalType": "address", "name": "sender", "type": "address" },
            { "indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256" },
            { "indexed": true, "internalType": "address", "name": "ethDestination", "type": "address" }
        ],
        "name": "Lock",
        "type": "event"
    },
    {
      "inputs": [
        { "internalType": "bytes", "name": "headerRlp", "type": "bytes" }
      ],
      "name": "submitHeader",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        { "internalType": "bytes[]", "name": "proof", "type": "bytes[]" },
        { "internalType": "bytes", "name": "rawReceipt", "type": "bytes" },
        { "internalType": "uint64", "name": "blockNumber", "type": "uint64" },
        { "internalType": "bytes", "name": "path", "type": "bytes" }
      ],
      "name": "unlock",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
]`

// MintBridge (COSMOS -> ETH) [ZK Path (Destination) & MPT Source]
const MintBridgeABI = `[
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
						"indexed": false,
						"internalType": "string",
						"name": "recipient",
						"type": "string"
					}
				],
				"name": "Burned",
				"type": "event"
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
						"internalType": "uint256",
						"name": "amount",
						"type": "uint256"
					},
					{
						"internalType": "string",
						"name": "recipient",
						"type": "string"
					}
				],
				"name": "burn",
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
		]`

// ===========================
// Main Entry Point
// ===========================

func main() {
	if len(os.Args) < 8 {
		fmt.Println("Usage: unified-relayer <eth_rpc> <evmos_evm_rpc> <evmos_comet_rpc> <eth_priv_key> <bridge_source_addr> <bridge_dest_addr> <cosmos_lock_addr> <mint_bridge_addr> [start_block]")
		fmt.Println("Example: unified-relayer http://localhost:8546 http://localhost:8545 http://localhost:26657 0xkey 0xSrc 0xDest 0xLock 0xMint 0")
		return
	}

	ethRPC := os.Args[1]
	evmosEvmRPC := os.Args[2]
	evmosCometRPC := os.Args[3]
	privKeyHex := os.Args[4]

	// Addrs
	bridgeSourceAddr := common.HexToAddress(os.Args[5]) // Eth
	bridgeDestAddr := common.HexToAddress(os.Args[6])   // Cosmos
	cosmosLockAddr := common.HexToAddress(os.Args[7])   // Cosmos
	mintBridgeAddr := common.HexToAddress(os.Args[8])   // Eth

	var startBlock uint64
	if len(os.Args) > 9 {
		if sb, err := strconv.ParseUint(os.Args[9], 10, 64); err == nil {
			startBlock = sb
		}
	}

	fmt.Println("==================================================")
	fmt.Println("🚀 Unified ZK + MPT Relayer Starting...")
	fmt.Println("==================================================")
	fmt.Printf("Eth RPC:        %s\n", ethRPC)
	fmt.Printf("Evmos RPC:      %s\n", evmosEvmRPC)
	fmt.Printf("Comet RPC:      %s\n", evmosCometRPC)
	fmt.Printf("BridgeSource:   %s\n", bridgeSourceAddr.Hex())
	fmt.Printf("BridgeDest:     %s\n", bridgeDestAddr.Hex())
	fmt.Printf("CosmosLock:     %s\n", cosmosLockAddr.Hex())
	fmt.Printf("MintBridge:     %s\n", mintBridgeAddr.Hex())
	fmt.Println("==================================================")

	// Clients
	ethClient, err := ethclient.Dial(ethRPC)
	if err != nil {
		log.Fatal(err)
	}

	evmosClient, err := ethclient.Dial(evmosEvmRPC)
	if err != nil {
		log.Fatal(err)
	}

	// RPC Client for MPT Proofs (Eth)
	ethRPCClient, err := rpc.Dial(ethRPC)
	if err != nil {
		log.Fatal(err)
	}

	// ABIs
	bridgeSourceAbi, _ := abi.JSON(strings.NewReader(BridgeSourceABI))
	bridgeDestAbi, _ := abi.JSON(strings.NewReader(BridgeDestinationABI))
	cosmosLockAbi, _ := abi.JSON(strings.NewReader(CosmosLockABI))
	mintBridgeAbi, _ := abi.JSON(strings.NewReader(MintBridgeABI))

	// ZK Prover
	p, err := prover.NewProver()
	if err != nil {
		log.Fatalf("Failed to initialize ZK prover: %v", err)
	}

	var g errgroup.Group

	// 1. Loop A: Eth -> Cosmos (MPT)
	g.Go(func() error {
		return runMptLoop(ethClient, ethRPCClient, evmosClient, bridgeSourceAbi, bridgeDestAbi, bridgeSourceAddr, bridgeDestAddr, privKeyHex, startBlock)
	})

	// 2. Loop B: Cosmos -> Eth (ZK)
	g.Go(func() error {
		return runZkLoop(evmosClient, ethClient, cosmosLockAbi, mintBridgeAbi, cosmosLockAddr, mintBridgeAddr, privKeyHex, evmosCometRPC, startBlock, p)
	})

	// 3. Loop C: Eth -> Cosmos (Return Trip for ZK Bridge) [MPT Path]
	g.Go(func() error {
		fmt.Println("[MPT Loop 2] Started (MintBridge -> CosmosLock)")
		return runMptLoop(ethClient, ethRPCClient, evmosClient, mintBridgeAbi, cosmosLockAbi, mintBridgeAddr, cosmosLockAddr, privKeyHex, startBlock)
	})

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}

// ===========================
// Loop A: MPT (Eth -> Cosmos)
// ===========================

func runMptLoop(srcClient *ethclient.Client, srcRPC *rpc.Client, destClient *ethclient.Client, srcAbi, destAbi abi.ABI, srcAddr, destAddr common.Address, key string, startBlock uint64) error {
	fmt.Println("[MPT Loop] Started (Eth -> Cosmos)")
	lastBlock := startBlock

	for {
		time.Sleep(5 * time.Second)
		currentBlock, err := srcClient.BlockNumber(context.Background())
		if err != nil {
			log.Printf("[MPT] Error fetching block: %v", err)
			continue
		}

		if currentBlock > lastBlock {
			query := ethereum.FilterQuery{
				Addresses: []common.Address{srcAddr},
				FromBlock: big.NewInt(int64(lastBlock + 1)),
				ToBlock:   big.NewInt(int64(currentBlock)),
			}

			logs, err := srcClient.FilterLogs(context.Background(), query)
			if err == nil {
				for _, vLog := range logs {
					processMptLog(vLog, srcClient, srcRPC, destClient, destAbi, destAddr, key)
				}
				lastBlock = currentBlock
			}
		}
	}
}

func processMptLog(vLog types.Log, srcClient *ethclient.Client, srcRPC *rpc.Client, destClient *ethclient.Client, destAbi abi.ABI, destAddr common.Address, key string) {
	fmt.Printf("[MPT] Detected Locked event in block %d\n", vLog.BlockNumber)

	// Fetch Header
	header, _ := srcClient.HeaderByNumber(context.Background(), big.NewInt(int64(vLog.BlockNumber)))
	headerRlp, _ := rlp.EncodeToBytes(header)

	// Submit Header
	fmt.Printf("[MPT] Submitting Header to Cosmos...\n")
	submitTx(destClient, destAbi, destAddr, key, "submitHeader", headerRlp, []byte{})
	time.Sleep(2 * time.Second)

	// Generate Proof
	receipts, _ := srcClient.BlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(vLog.BlockNumber)))
	var targetReceipt *types.Receipt
	var targetIndex int
	for i, r := range receipts {
		if r.TxHash == vLog.TxHash {
			targetReceipt = r
			targetIndex = i
			break
		}
	}

	proofBytes, _ := GenerateReceiptProof(receipts, targetIndex)
	receiptRlp, _ := targetReceipt.MarshalBinary()
	path, _ := rlp.EncodeToBytes(uint(targetIndex))

	// Claim
	fmt.Printf("[MPT] Submitting Claim to Cosmos...\n")
	submitTx(destClient, destAbi, destAddr, key, "claim", proofBytes, receiptRlp, uint64(vLog.BlockNumber), path)
}

// ===========================
// Loop B: ZK (Cosmos -> Eth)
// ===========================

func runZkLoop(srcClient *ethclient.Client, destClient *ethclient.Client, srcAbi, destAbi abi.ABI, srcAddr, destAddr common.Address, key string, cometRPC string, startBlock uint64, p *prover.Prover) error {
	fmt.Println("[ZK Loop] Started (Cosmos -> Eth)")

	// Default to polling
	lastBlock := startBlock
	for {
		time.Sleep(5 * time.Second)
		currentBlock, err := srcClient.BlockNumber(context.Background())
		if err != nil {
			continue
		}

		if currentBlock > lastBlock {
			query := ethereum.FilterQuery{
				Addresses: []common.Address{srcAddr},
				FromBlock: big.NewInt(int64(lastBlock + 1)),
				ToBlock:   big.NewInt(int64(currentBlock)),
			}

			logs, err := srcClient.FilterLogs(context.Background(), query)
			if err == nil {
				for _, vLog := range logs {
					processZkLog(vLog, srcAbi, destAbi, destClient, destAddr, key, cometRPC, p)
				}
				lastBlock = currentBlock
			}
		}
	}
}

func processZkLog(vLog types.Log, srcAbi, destAbi abi.ABI, destClient *ethclient.Client, destAddr common.Address, key string, cometRPC string, p *prover.Prover) {
	fmt.Printf("[ZK] Detected Lock event in block %d\n", vLog.BlockNumber)

	// Parse Event
	event := struct {
		LockId         *big.Int
		Sender         common.Address
		Amount         *big.Int
		EthDestination common.Address
	}{}
	srcAbi.UnpackIntoInterface(&event, "Lock", vLog.Data)
	if len(vLog.Topics) >= 4 {
		event.LockId = new(big.Int).SetBytes(vLog.Topics[1].Bytes())
		// event.Sender = common.BytesToAddress(vLog.Topics[2].Bytes()) // Sender format may vary
		// event.EthDestination = common.BytesToAddress(vLog.Topics[3].Bytes())
		// Actually UnpackIntoInterface handles non-indexed. Topics handle indexed.
		// For simplicity, let's assume we can fetch data or re-parse.
		// The ZK Prover needs strictly: LockID, Amount, Destination
	}

	// Quick hack: Recode manual parsing or rely on Unpack if not indexed.
	// But they ARE indexed.
	// Let's re-parse properly.
	lockId := new(big.Int).SetBytes(vLog.Topics[1].Bytes())
	// ethDest := common.BytesToAddress(vLog.Topics[3].Bytes())
	// amount is non-indexed, so it IS in vLog.Data

	// We need amount.
	// Unpack again
	unpacked := struct{ Amount *big.Int }{}
	srcAbi.UnpackIntoInterface(&unpacked, "Lock", vLog.Data)
	amount := unpacked.Amount
	ethDest := common.BytesToAddress(vLog.Topics[3].Bytes())

	fmt.Printf("[ZK] Generating Proof for LockID %s, Amount %s\n", lockId.String(), amount.String())

	proof, err := p.GenerateInclusionProof(cometRPC, int64(vLog.BlockNumber), int(vLog.TxIndex), lockId.Uint64(), amount.String(), ethDest.Hex())
	if err != nil {
		fmt.Printf("[ZK] Proof Gen Error: %v\n", err)
		return
	}

	// Register Root?
	registered, _ := isRootRegistered(destClient, destAddr, destAbi, proof.Root)
	if !registered {
		fmt.Printf("[ZK] Registering Root %x...\n", proof.Root)
		submitTx(destClient, destAbi, destAddr, key, "addRoot", proof.Root)
		time.Sleep(2 * time.Second)
	}

	// Submit Mint
	fmt.Printf("[ZK] Submitting Mint...\n")
	err = submitMintTx(destClient, destAddr, destAbi, key, proof, ethDest, amount)
	if err != nil {
		fmt.Printf("[ZK] Mint Failed: %v\n", err)
	} else {
		fmt.Printf("[ZK] Mint Submitted!\n")
	}
}

// ===========================
// Helpers (MPT)
// ===========================

type OrderedProof struct{ nodes [][]byte }

func (o *OrderedProof) Put(key []byte, value []byte) error {
	node := make([]byte, len(value))
	copy(node, value)
	o.nodes = append(o.nodes, node)
	return nil
}
func (o *OrderedProof) Delete(key []byte) error { return nil }

func GenerateReceiptProof(receipts []*types.Receipt, index int) ([][]byte, error) {
	db := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
	tr, _ := trie.New(trie.TrieID(common.Hash{}), db)
	for i, r := range receipts {
		key, _ := rlp.EncodeToBytes(uint(i))
		val, _ := r.MarshalBinary()
		tr.Update(key, val)
	}
	path, _ := rlp.EncodeToBytes(uint(index))
	proof := &OrderedProof{}
	tr.Prove(path, proof)
	return proof.nodes, nil
}

// ===========================
// Helpers (TX)
// ===========================

func submitTx(client *ethclient.Client, abi abi.ABI, addr common.Address, privKeyHex string, method string, args ...interface{}) (common.Hash, error) {
	privateKey, _ := crypto.ToECDSA(common.Hex2Bytes(strings.TrimPrefix(privKeyHex, "0x")))
	chainID, _ := client.ChainID(context.Background())
	auth, _ := bind.NewKeyedTransactorWithChainID(privateKey, chainID)

	// Increase gas for safety
	// auth.GasLimit = 1000000

	data, err := abi.Pack(method, args...)
	if err != nil {
		return common.Hash{}, err
	}

	gasPrice, _ := client.SuggestGasPrice(context.Background())
	nonce, _ := client.PendingNonceAt(context.Background(), auth.From)

	tx := types.NewTransaction(nonce, addr, big.NewInt(0), 5000000, gasPrice, data) // High gas limit for verification
	signedTx, _ := auth.Signer(auth.From, tx)
	return signedTx.Hash(), client.SendTransaction(context.Background(), signedTx)
}

// ===========================
// Helpers (ZK)
// ===========================

func isRootRegistered(client *ethclient.Client, bridgeAddr common.Address, bridgeAbi abi.ABI, root [32]byte) (bool, error) {
	data, _ := bridgeAbi.Pack("validRoots", root)
	msg := ethereum.CallMsg{To: &bridgeAddr, Data: data}
	res, err := client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return false, err
	}
	var registered bool
	bridgeAbi.UnpackIntoInterface(&registered, "validRoots", res)
	return registered, nil
}

func submitMintTx(client *ethclient.Client, bridgeAddr common.Address, bridgeAbi abi.ABI, privKeyHex string, proof *prover.ProofData, to common.Address, amount *big.Int) error {
	// Reconstruct Inputs for Solidity
	proofFlat := [8]*big.Int{}
	for i := 0; i < 2; i++ {
		proofFlat[i] = new(big.Int)
		proofFlat[i].SetString(proof.A[i][2:], 16)
	}
	// ... (Simplifying B and C parsing for brevity, assume similar strict parsing as original)
	// B is [2][2] in solidity but flats are tricky.
	// Let's copy strictly from original main.go logic if possible or assume simple mapping.
	// Actually, Gnark solidity verifier expects [8] uint256 for A(2), B(2x2=4), C(2).
	// Wait, standard gnark verifier input is usually Proof struct.

	// Re-implementing the parsing logic strictly:
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

	commitments := [2]*big.Int{new(big.Int), new(big.Int)}
	commitments[0].SetString(proof.Commitments[0][2:], 16)
	commitments[1].SetString(proof.Commitments[1][2:], 16)

	commitmentPok := [2]*big.Int{new(big.Int), new(big.Int)}
	commitmentPok[0].SetString(proof.CommitmentPok[0][2:], 16)
	commitmentPok[1].SetString(proof.CommitmentPok[1][2:], 16)

	var inputs [8]*big.Int
	for i, input := range proof.Inputs {
		inputs[i] = new(big.Int)
		inputs[i].SetString(input, 10)
	}

	// TxHash reconstruction
	var txHashBytes [32]byte
	txHashInt := new(big.Int).Or(new(big.Int).Lsh(inputs[2], 128), inputs[3])
	txHashInt.FillBytes(txHashBytes[:])

	_, err := submitTx(client, bridgeAbi, bridgeAddr, privKeyHex, "mint", proofFlat, commitments, commitmentPok, inputs, txHashBytes, to, amount)
	return err
}
