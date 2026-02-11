package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/prover"
	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/rpc"
)

var (
	CosmosWsUrl      string
	CosmosRpcUrl     string
	CosmosEvmRpcUrl  string
	BridgeCosmosAddr string
	EthereumRpcUrl   string
	EthereumWsUrl    string
	BridgeEthAddr    string
	RelayerPrivKey   string
)

type WsRequest struct {
	Jsonrpc string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
	ID      int      `json:"id"`
}

type WsResponse struct {
	Result struct {
		Events map[string][]string `json:"events"`
		Data   struct {
			Value struct {
				TxResult struct {
					Hash string `json:"hash"`
				} `json:"tx_result"`
			} `json:"value"`
		} `json:"data"`
	} `json:"result"`
}

func init() {
	if err := godotenv.Load(); err != nil {
		if err := godotenv.Load("../../.env"); err != nil {
			log.Println("⚠️ No .env file found, relying on system environment variables")
		}
	}

	CosmosWsUrl = os.Getenv("COSMOS_WS_URL")
	CosmosRpcUrl = os.Getenv("COSMOS_RPC_URL")
	CosmosEvmRpcUrl = os.Getenv("COSMOS_EVM_RPC_URL")
	BridgeCosmosAddr = os.Getenv("BRIDGE_COSMOS_ADDR")
	EthereumRpcUrl = os.Getenv("ETHEREUM_RPC_URL")
	EthereumWsUrl = os.Getenv("ETHEREUM_WS_URL")
	BridgeEthAddr = os.Getenv("BRIDGE_ETH_ADDR")
	RelayerPrivKey = os.Getenv("RELAYER_PRIV_KEY")

	if RelayerPrivKey == "" {
		log.Fatal("❌ RELAYER_PRIV_KEY is not set")
	}
}

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// 1. Cosmos Monitor
	fmt.Printf("🔌 Connecting to Cosmos WebSocket at %s...\n", CosmosWsUrl)
	c, _, err := websocket.DefaultDialer.Dial(CosmosWsUrl, nil)
	if err != nil {
		log.Fatal("❌ Dial error:", err)
	}
	defer c.Close()

	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("⚠️ Read error:", err)
				return
			}

			var resp WsResponse
			if err := json.Unmarshal(message, &resp); err != nil {
				continue
			}

			txHash := resp.Result.Data.Value.TxResult.Hash
			if txHash == "" && resp.Result.Events != nil {
				if hashes, ok := resp.Result.Events["tx.hash"]; ok && len(hashes) > 0 {
					txHash = hashes[0]
				}
			}

			if txHash != "" {
				go processCosmosEvent(txHash)
			}
		}
	}()

	subReq := WsRequest{
		Jsonrpc: "2.0",
		Method:  "subscribe",
		Params:  []string{"tm.event='Tx'"},
		ID:      1,
	}

	subBytes, _ := json.Marshal(subReq)
	if err := c.WriteMessage(websocket.TextMessage, subBytes); err != nil {
		log.Fatal("❌ Subscription failed:", err)
	}

	fmt.Println("✅ Subscribed to Cosmos Tx events")

	// 3. Ethereum Monitor (WebSocket Subscription)
	go func() {
		fmt.Printf("🛰️ Monitoring Ethereum for Lock/Burn events at %s...\n", BridgeEthAddr)

		lockedTopic := crypto.Keccak256Hash([]byte("Locked(address,uint256,string,uint256)"))
		burnedTopic := crypto.Keccak256Hash([]byte("Burned(address,uint256,string,uint256)"))

		fmt.Printf("🔍 Relayer searching for topics:\n")
		fmt.Printf("   ├─ Locked: %s\n", lockedTopic.Hex())
		fmt.Printf("   └─ Burned: %s\n", burnedTopic.Hex())

		if EthereumWsUrl == "" {
			log.Fatal("❌ ETHEREUM_WS_URL is not set")
		}

		client, err := ethclient.Dial(EthereumWsUrl)
		if err != nil {
			log.Fatal("❌ Failed to connect to Ethereum WebSocket:", err)
		}

		query := ethereum.FilterQuery{
			Addresses: []common.Address{common.HexToAddress(BridgeEthAddr)},
			Topics: [][]common.Hash{
				{lockedTopic, burnedTopic}, // Match either topic
			},
		}

		logs := make(chan types.Log)
		sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
		if err != nil {
			log.Fatal("❌ Failed to subscribe to Ethereum logs:", err)
		}

		fmt.Println("✅ Subscribed to Ethereum events")

		for {
			select {
			case err := <-sub.Err():
				log.Println("⚠️ Subscription error:", err)
				log.Fatal("❌ Subscription connection lost")
			case vLog := <-logs:
				fmt.Printf("\n🚀 New Ethereum event: %s\n", vLog.TxHash.Hex())

				isLock := vLog.Topics[0] == lockedTopic

				// Convert types.Log to rpc.EthLog
				rpcLog := rpc.EthLog{
					Address:     vLog.Address.Hex(),
					Topics:      make([]string, len(vLog.Topics)),
					Data:        common.Bytes2Hex(vLog.Data),
					BlockNumber: fmt.Sprintf("0x%x", vLog.BlockNumber),
					TxHash:      vLog.TxHash.Hex(),
				}
				for i, t := range vLog.Topics {
					rpcLog.Topics[i] = t.Hex()
				}

				go processEthEvent(rpcLog, isLock)
			}
		}
	}()

	fmt.Println("🛰️ Bidirectional Relayer active! Monitoring both chains...")

	for {
		select {
		case <-done:
			return
		case <-interrupt:
			log.Println("🛑 Relayer stopping...")
			return
		}
	}
}

func processCosmosEvent(tmTxHash string) {
	fmt.Printf("\n🚀 New Tendermint Tx detected: %s\n", tmTxHash)

	// Add a small retry loop to allow Tendermint to index the transaction
	var resp *rpc.TxResponse
	var err error
	cosmosClient := rpc.NewCosmosClient(CosmosRpcUrl)

	for i := 0; i < 5; i++ {
		resp, err = cosmosClient.GetTxDetails(tmTxHash)
		if err == nil && resp.Error.Code == 0 && (resp.Result.Hash != "" || resp.Hash != "") {
			break
		}
		fmt.Printf("⏳ Tx not indexed yet, retrying... (%d/5)\n", i+1)
		time.Sleep(1 * time.Second)
	}

	if resp == nil || (resp.Result.Hash == "" && resp.Hash == "") {
		fmt.Printf("ℹ️ Skipping: Transaction not found or indexing timeout.\n")
		return
	}

	evmTxHash := resp.GetEvmHash()
	if evmTxHash == "" {
		fmt.Printf("ℹ️ Skipping non-EVM transaction (No ethereum_tx event found).\n")
		return
	}
	fmt.Printf("⛓️ Mapped to EVM Hash: %s\n", evmTxHash)

	recipient, amount, isMint, err := prover.FetchLockDetails(CosmosEvmRpcUrl, BridgeCosmosAddr, evmTxHash)
	if err != nil {
		fmt.Printf("❌ Skipping: %v\n", err)
		return
	}
	fmt.Printf("✅ Cosmos Event found! Type=%s, Recipient=%s, Amount=%s\n", map[bool]string{true: "Lock", false: "Burn"}[isMint], recipient, amount.String())

	outputPath := "proof_event.json"
	_, actualTx, err := prover.GenerateProof(CosmosRpcUrl, tmTxHash, outputPath)
	if err != nil {
		fmt.Printf("❌ ZK Proof generation failed: %v\n", err)
		return
	}

	hUint64 := uint64(0)
	fmt.Sscanf(resp.Result.Height, "%d", &hUint64)

	// 4. Ensure the block header is synchronized on Ethereum
	ethClient := rpc.NewEthClient(EthereumRpcUrl)
	existingRoot, _ := ethClient.GetTrustedRoot(BridgeEthAddr, hUint64)
	if existingRoot != [32]byte{} {
		fmt.Printf("ℹ️ Header for height %d already anchored on Ethereum. Skipping sync.\n", hUint64)
	} else {
		fmt.Printf("🔄 Synchronizing Header for height %d on Ethereum (Anchoring DataHash)...\n", hUint64)
		headerProofPath := fmt.Sprintf("proof_header_%d.json", hUint64)
		err = prover.GenerateValidatorProof(CosmosRpcUrl, fmt.Sprintf("%d", hUint64), headerProofPath)
		if err != nil {
			fmt.Printf("❌ Failed to generate header proof: %v\n", err)
			return
		}

		// Fetch metadata needed for verification
		cosmosClient = rpc.NewCosmosClient(CosmosRpcUrl)
		commitResp, _ := cosmosClient.GetCommit(fmt.Sprintf("%d", hUint64))
		valResp, _ := cosmosClient.GetValidators(fmt.Sprintf("%d", hUint64))
		bHashSlice, _ := rpc.DecodeHash(commitResp.Result.SignedHeader.Header.AppHash)
		dHashSlice, _ := rpc.DecodeHash(commitResp.Result.SignedHeader.Header.DataHash)

		var bHash [32]byte
		var dHash [32]byte
		copy(bHash[:], bHashSlice)
		copy(dHash[:], dHashSlice)

		var totalPower big.Int
		totalPower.SetString(valResp.Result.Total, 10)

		err = prover.SubmitHeaderProof(EthereumRpcUrl, RelayerPrivKey, BridgeEthAddr, hUint64, bHash, dHash, &totalPower, headerProofPath)
		if err != nil {
			fmt.Printf("❌ Header sync failed: %v\n", err)
			return
		}
	}

	// 5. Submit Transaction Proof
	err = prover.SubmitProof(EthereumRpcUrl, RelayerPrivKey, BridgeEthAddr, hUint64, recipient, amount, actualTx, outputPath, isMint)
	if err != nil {
		fmt.Printf("❌ ZK Proof submission failed: %v\n", err)
	} else {
		fmt.Println("🎉 Cosmos -> Eth Relay Complete!")
	}
}

func processEthEvent(logItem rpc.EthLog, isLock bool) {
	fmt.Printf("\n🚀 New Ethereum event: %s (Type: %s)\n", logItem.TxHash, map[bool]string{true: "Lock", false: "Burn"}[isLock])

	// 1. Fetch event details from Ethereum (Recipient, Amount)
	recipient, amount, isMint, err := prover.FetchEthLockDetails(EthereumRpcUrl, BridgeEthAddr, logItem.TxHash)
	if err != nil {
		fmt.Printf("❌ Failed to fetch Ethereum event details: %v\n", err)
		return
	}
	fmt.Printf("✅ Ethereum event details: Recipient=%s, Amount=%s\n", recipient, amount.String())

	// 2. Fetch MPT Proof for the transaction receipt
	ethClient := rpc.NewEthClient(EthereumRpcUrl)
	proof, err := ethClient.GetReceiptProof(logItem.TxHash)
	if err != nil {
		fmt.Printf("❌ Failed to fetch MPT proof: %v\n", err)
		return
	}

	receiptRootBytes := common.HexToHash(proof.ReceiptRoot)
	txHashBytes := common.HexToHash(logItem.TxHash)

	// 3. Synchronize Ethereum Root on Cosmos
	fmt.Println("🔄 Synchronizing Ethereum Root on Cosmos...")
	err = prover.UpdateEthRootOnCosmos(CosmosEvmRpcUrl, RelayerPrivKey, BridgeCosmosAddr, receiptRootBytes)
	if err != nil {
		fmt.Printf("⚠️ Root sync failed: %v\n", err)
	}

	// 4. Submit Proof to Cosmos for Verification and Execution
	fmt.Println("🚀 Submitting Proof to Cosmos (MPT Proof)...")
	err = prover.SubmitEthProofToCosmos(
		CosmosEvmRpcUrl,
		RelayerPrivKey,
		BridgeCosmosAddr,
		recipient,
		amount,
		txHashBytes,
		proof.Key,
		proof.Proof,
		isMint,
	)

	if err != nil {
		fmt.Printf("❌ Submission failed: %v\n", err)
	} else {
		fmt.Println("🎉 Eth -> Cosmos Relay Complete!")
		fmt.Println("🛡️ Verification performed by CosmosBridge.sol using LibMPT library.")
	}
}
