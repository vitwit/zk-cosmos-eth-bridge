package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

	// 1. Cosmos Event Monitor
	go func() {
		for {
			log.Printf("🔌 Connecting to Cosmos WebSocket: %s\n", CosmosWsUrl)
			c, _, err := websocket.DefaultDialer.Dial(CosmosWsUrl, nil)
			if err != nil {
				log.Printf("❌ Cosmos Dial error: %v, retrying in 5s...\n", err)
				time.Sleep(5 * time.Second)
				continue
			}

			// Subscribe to transaction events
			subTx := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "subscribe",
				"id":      1,
				"params":  map[string]interface{}{"query": "tm.event='Tx'"},
			}
			if err := c.WriteJSON(subTx); err != nil {
				log.Printf("⚠️ Subscription failed (Tx): %v\n", err)
				c.Close()
				continue
			}

			// Subscribe to block events for validator set monitoring
			subBlock := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "subscribe",
				"id":      2,
				"params":  map[string]interface{}{"query": "tm.event='NewBlock'"},
			}
			if err := c.WriteJSON(subBlock); err != nil {
				log.Printf("⚠️ Subscription failed (NewBlock): %v\n", err)
				c.Close()
				continue
			}

			log.Println("✅ Successfully subscribed to Cosmos events")

			connClosed := make(chan struct{})
			go func() {
				defer close(connClosed)
				for {
					var msg map[string]interface{}
					if err := c.ReadJSON(&msg); err != nil {
						log.Printf("⚠️ Cosmos read error: %v\n", err)
						return
					}

					result, ok := msg["result"].(map[string]interface{})
					if !ok {
						continue
					}

					query, _ := result["query"].(string)
					if query == "tm.event='NewBlock'" {
						// Process blocks in background; proverMutex handles serialization
						go handleCosmosBlock(result, CosmosRpcUrl)
					} else if query == "tm.event='Tx'" {
						events, _ := result["events"].(map[string]interface{})
						txHashes, _ := events["tx.hash"].([]interface{})
						if len(txHashes) > 0 {
							txHash := txHashes[0].(string)
							// Process transactions in background; proverMutex handles serialization
							go processCosmosEvent(txHash)
						}
					}
				}
			}()

			<-connClosed
			c.Close()
			log.Println("🔄 Reconnecting to Cosmos WebSocket...")
			time.Sleep(5 * time.Second)
		}
	}()

	// 2. Ethereum Event Monitor
	go func() {
		lockedTopic := crypto.Keccak256Hash([]byte("Locked(address,uint256,string,uint256)"))
		burnedTopic := crypto.Keccak256Hash([]byte("Burned(address,uint256,string,uint256)"))

		for {
			log.Printf("🔌 Connecting to Ethereum WebSocket: %s\n", EthereumWsUrl)
			client, err := ethclient.Dial(EthereumWsUrl)
			if err != nil {
				log.Printf("❌ Ethereum Dial error: %v, retrying in 5s...\n", err)
				time.Sleep(5 * time.Second)
				continue
			}

			query := ethereum.FilterQuery{
				Addresses: []common.Address{common.HexToAddress(BridgeEthAddr)},
				Topics: [][]common.Hash{
					{lockedTopic, burnedTopic},
				},
			}

			logs := make(chan types.Log)
			sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
			if err != nil {
				log.Printf("❌ Failed to subscribe to Ethereum logs: %v\n", err)
				client.Close()
				time.Sleep(5 * time.Second)
				continue
			}

			log.Println("✅ Successfully subscribed to Ethereum events")

		Loop:
			for {
				select {
				case err := <-sub.Err():
					log.Printf("⚠️ Ethereum subscription failed: %v\n", err)
					break Loop
				case vLog := <-logs:
					fmt.Printf("\n🚀 New Ethereum event detected: %s\n", vLog.TxHash.Hex())

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

					go processEthEvent(rpcLog)
				}
			}
			client.Close()
			log.Println("🔄 Reconnecting to Ethereum WebSocket...")
			time.Sleep(5 * time.Second)
		}
	}()

	fmt.Println("🛰️ Bidirectional Bridge Relayer is running...")

	<-interrupt
	log.Println("🛑 Termination signal received, stopping relayer...")
}

func handleCosmosBlock(result map[string]interface{}, cosmosRpc string) {
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return
	}
	block, ok := data["value"].(map[string]interface{})["block"].(map[string]interface{})
	if !ok {
		return
	}
	header, ok := block["header"].(map[string]interface{})
	if !ok {
		return
	}

	height := header["height"].(string)
	vHash := header["validators_hash"].(string)

	ethClient := rpc.NewEthClient(os.Getenv("ETHEREUM_RPC_URL"))
	bridgeAddr := os.Getenv("BRIDGE_ETH_ADDR")

	anchoredHash, err := ethClient.GetCurrentValidatorsHash(bridgeAddr)
	if err != nil {
		return // Silently skip if contract not reachable/deployed
	}

	// Handle uninitialized contract state
	if anchoredHash == "" || anchoredHash == "0x" || anchoredHash == "0x0000000000000000000000000000000000000000000000000000000000000000" {
		return
	}

	if strings.TrimPrefix(strings.ToLower(vHash), "0x") != strings.TrimPrefix(strings.ToLower(anchoredHash), "0x") {
		lastHeight, _ := ethClient.GetLastProcessedHeight(bridgeAddr)
		if lastHeight == 0 {
			return
		}

		fmt.Printf("🔄 Validator Set change detected at height %s! Anchored: %s, Latest: %s\n", height, anchoredHash, vHash)
		oldHeight := strconv.FormatUint(lastHeight, 10)

		fmt.Printf("⚙️ Generating Transition Proof: OldHeight=%s -> NewHeight=%s\n", oldHeight, height)
		// Sequentiality is handled by the proverMutex inside GenerateTransitionProof
		newHash, err := prover.GenerateTransitionProof(cosmosRpc, oldHeight, height, "proof_transition.json")
		if err != nil {
			fmt.Printf("❌ Transition proof generation failed: %v\n", err)
			return
		}

		fmt.Printf("🚀 Submitting transition proof to Ethereum...\n")
		err = prover.UpdateValidatorSetOnEth(os.Getenv("ETHEREUM_RPC_URL"), os.Getenv("RELAYER_PRIV_KEY"), os.Getenv("BRIDGE_ETH_ADDR"), "proof_transition.json", newHash)
		if err != nil {
			fmt.Printf("❌ Failed to update validator set on Ethereum: %v\n", err)
		} else {
			fmt.Println("✅ Validator set updated successfully on Ethereum")
		}
	}
}

func processCosmosEvent(tmTxHash string) {
	fmt.Printf("\n🚀 New Tendermint Tx detected: %s\n", tmTxHash)
	cosmosClient := rpc.NewCosmosClient(CosmosRpcUrl)

	var resp *rpc.TxResponse
	var err error
	for i := 0; i < 5; i++ {
		resp, err = cosmosClient.GetTxDetails(tmTxHash)
		if err == nil && resp.Error.Code == 0 && (resp.Result.Hash != "" || resp.Hash != "") {
			break
		}
		fmt.Printf("⏳ Waiting for transaction index... (%d/5)\n", i+1)
		time.Sleep(1 * time.Second)
	}

	if resp == nil || (resp.Result.Hash == "" && resp.Hash == "") {
		return
	}

	evmTxHash := resp.GetEvmHash()
	if evmTxHash == "" {
		return
	}
	fmt.Printf("🔗 Mapped to Cosmos EVM Hash: %s\n", evmTxHash)

	recipient, amount, isMint, err := prover.FetchLockDetails(CosmosEvmRpcUrl, BridgeCosmosAddr, evmTxHash)
	if err != nil {
		fmt.Printf("❌ Failed to fetch event details: %v\n", err)
		return
	}

	fmt.Printf("💎 Event: %s, Amount: %s, Recipient: %s\n", map[bool]string{true: "Mint", false: "Unlock"}[isMint], amount.String(), recipient)

	outputPath := "proof_event.json"
	fmt.Printf("⚙️ Generating ZK Proof for event inclusion...\n")
	// Sequentiality is handled by the proverMutex inside GenerateProof
	_, actualTx, err := prover.GenerateProof(CosmosRpcUrl, tmTxHash, outputPath)
	if err != nil {
		fmt.Printf("❌ Proof generation failed: %v\n", err)
		return
	}

	hUint64, _ := strconv.ParseUint(resp.Result.Height, 10, 64)

	ethClient := rpc.NewEthClient(EthereumRpcUrl)
	existingRoot, _ := ethClient.GetTrustedRoot(BridgeEthAddr, hUint64)
	if existingRoot == [32]byte{} {
		fmt.Printf("🔄 Header height %d not anchored. Synchronizing...\n", hUint64)
		headerProofPath := fmt.Sprintf("proof_header_%d.json", hUint64)
		actualVHash, bh, tp, err := prover.GenerateValidatorProof(CosmosRpcUrl, strconv.FormatUint(hUint64, 10), headerProofPath)
		if err != nil {
			fmt.Printf("❌ Header proof generation failed: %v\n", err)
			return
		}

		commit, _ := cosmosClient.GetCommit(strconv.FormatUint(hUint64, 10))
		dHashSlice, _ := rpc.DecodeHash(commit.Result.SignedHeader.Header.DataHash)
		var dHash [32]byte
		copy(dHash[:], dHashSlice)

		fmt.Printf("🚀 Submitting Header proof to Ethereum...\n")
		err = prover.SubmitHeaderProof(EthereumRpcUrl, RelayerPrivKey, BridgeEthAddr, hUint64, bh, dHash, tp, headerProofPath)
		if err != nil {
			fmt.Printf("❌ Header sync failed: %v\n", err)
			_ = actualVHash
			return
		}
		fmt.Println("✅ Header synchronized")
	}

	fmt.Printf("🚀 Submitting ZK event proof to Ethereum...\n")
	err = prover.SubmitProof(EthereumRpcUrl, RelayerPrivKey, BridgeEthAddr, hUint64, recipient, amount, actualTx, outputPath, isMint)
	if err != nil {
		fmt.Printf("❌ Proof submission failed: %v\n", err)
	} else {
		fmt.Println("🎉 Cosmos -> Ethereum relay completed successfully")
	}
}

func processEthEvent(logItem rpc.EthLog) {
	fmt.Printf("\n🚀 New Ethereum event: %s\n", logItem.TxHash)

	recipient, amount, isMint, err := prover.FetchEthLockDetails(EthereumRpcUrl, BridgeEthAddr, logItem.TxHash)
	if err != nil {
		fmt.Printf("❌ Failed to fetch event details: %v\n", err)
		return
	}

	fmt.Printf("💎 Event: %s, Amount: %s, Recipient: %s\n", map[bool]string{true: "Lock", false: "Burn"}[isMint], amount.String(), recipient)

	ethClient := rpc.NewEthClient(EthereumRpcUrl)
	fmt.Printf("⚙️ Fetching MPT proof from Ethereum...\n")
	proof, err := ethClient.GetReceiptProof(logItem.TxHash)
	if err != nil {
		fmt.Printf("❌ MPT proof fetch failed: %v\n", err)
		return
	}

	receiptRootBytes := common.HexToHash(proof.ReceiptRoot)
	txHashBytes := common.HexToHash(logItem.TxHash)

	fmt.Printf("🔄 Synchronizing Ethereum root on Cosmos...\n")
	_ = prover.UpdateEthRootOnCosmos(CosmosEvmRpcUrl, RelayerPrivKey, BridgeCosmosAddr, receiptRootBytes)

	fmt.Printf("🚀 Submitting MPT proof to Cosmos...\n")
	err = prover.SubmitEthProofToCosmos(CosmosEvmRpcUrl, RelayerPrivKey, BridgeCosmosAddr, recipient, amount, txHashBytes, proof.Key, proof.Proof, isMint)
	if err != nil {
		fmt.Printf("❌ Submission failed: %v\n", err)
	} else {
		fmt.Println("🎉 Ethereum -> Cosmos relay completed successfully")
	}
}
