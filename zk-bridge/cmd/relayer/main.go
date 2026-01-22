package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/vitwit/zk-cosmos-eth-bridge/zk-bridge/pkg/prover"
	"github.com/vitwit/zk-cosmos-eth-bridge/zk-bridge/pkg/rpc"
)

var (
	CosmosWsUrl      string
	CosmosRpcUrl     string
	CosmosEvmRpcUrl  string
	BridgeSourceAddr string
	EthereumRpcUrl   string
	BridgeDestAddr   string
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
	// key paths are relative to root if running from root
	// .env should be in root
	if err := godotenv.Load(); err != nil {
		// Try loading from ../../.env if running from cmd/relayer
		if err := godotenv.Load("../../.env"); err != nil {
			log.Println("⚠️ No .env file found, relying on system environment variables")
		}
	}

	CosmosWsUrl = os.Getenv("COSMOS_WS_URL")
	CosmosRpcUrl = os.Getenv("COSMOS_RPC_URL")
	CosmosEvmRpcUrl = os.Getenv("COSMOS_EVM_RPC_URL")
	BridgeSourceAddr = os.Getenv("BRIDGE_SOURCE_ADDR")
	EthereumRpcUrl = os.Getenv("ETHEREUM_RPC_URL")
	BridgeDestAddr = os.Getenv("BRIDGE_DEST_ADDR")
	RelayerPrivKey = os.Getenv("RELAYER_PRIV_KEY")

	if RelayerPrivKey == "" {
		log.Fatal("❌ RELAYER_PRIV_KEY is not set")
	}
}

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

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
				go processEvent(txHash)
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

	fmt.Println("🛰️ Relayer active! Monitoring Cosmos for Lock events...")

	for {
		select {
		case <-done:
			return
		case <-interrupt:
			log.Println("🛑 Relayer stopping...")
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("⚠️ Close error:", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

func processEvent(tmTxHash string) {
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

	// Standard process continues...
	fmt.Printf("🔍 Fetching Lock details for EVM Tx: %s\n", evmTxHash)
	recipient, amount, err := prover.FetchLockDetails(CosmosEvmRpcUrl, BridgeSourceAddr, evmTxHash)
	if err != nil {
		fmt.Printf("❌ Skipping: %v\n", err)
		return
	}
	fmt.Printf("✅ Legitimate Bridge Lock found! Recipient=%s, Amount=%s\n", recipient, amount.String())

	outputPath := "proof_event.json"
	fmt.Println("🧬 Generating ZK-SNARK Inclusion Proof from Real RPC...")

	// Path to proving key: keys/proving.key (assuming root execution)
	// We can make this robust or just assume correct execution dir.
	// For now, let's assume root.
	root, actualTx, err := prover.GenerateProof(CosmosRpcUrl, tmTxHash, outputPath)
	if err != nil {
		fmt.Printf("❌ Proving failed: %v\n", err)
		return
	}
	fmt.Println("✅ ZK-SNARK Proof generated.")

	fmt.Println("🔄 Synchronizing Trusted Root on Ethereum...")
	err = prover.UpdateRoot(EthereumRpcUrl, RelayerPrivKey, BridgeDestAddr, root)
	if err != nil {
		fmt.Printf("⚠️ Root sync failed: %v\n", err)
	}

	fmt.Println("🚀 Submitting ZK-SNARK to Ethereum...")
	err = prover.SubmitProof(EthereumRpcUrl, RelayerPrivKey, BridgeDestAddr, recipient, amount, root, actualTx, outputPath)
	if err != nil {
		fmt.Printf("❌ Submission failed: %v\n", err)
	} else {
		fmt.Println("🎉 Relay Complete!")
	}
}
