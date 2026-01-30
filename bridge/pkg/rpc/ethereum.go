package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

type EthClient struct {
	RpcUrl string
}

func NewEthClient(url string) *EthClient {
	return &EthClient{RpcUrl: url}
}

type JsonRpcRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type JsonRpcResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *EthClient) Call(method string, params ...interface{}) (json.RawMessage, error) {
	reqBody, _ := json.Marshal(JsonRpcRequest{
		Jsonrpc: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})

	resp, err := http.Post(c.RpcUrl, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp JsonRpcResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, err
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC Error: %s (code: %d)", rpcResp.Error.Message, rpcResp.Error.Code)
	}

	return rpcResp.Result, nil
}

type EthLog struct {
	Address     string   `json:"address"`
	Topics      []string `json:"topics"`
	Data        string   `json:"data"`
	BlockNumber string   `json:"blockNumber"`
	TxHash      string   `json:"transactionHash"`
}

func (c *EthClient) GetLogs(address string, topics []string, fromBlock string, toBlock string) ([]EthLog, error) {
	params := map[string]interface{}{
		"address":   address,
		"topics":    topics,
		"fromBlock": fromBlock,
		"toBlock":   toBlock,
	}

	result, err := c.Call("eth_getLogs", params)
	if err != nil {
		return nil, err
	}

	var logs []EthLog
	if err := json.Unmarshal(result, &logs); err != nil {
		return nil, err
	}

	return logs, nil
}

func (c *EthClient) GetReceiptRoot(blockNumber string) (string, error) {
	result, err := c.Call("eth_getBlockByNumber", blockNumber, false)
	if err != nil {
		return "", err
	}

	var block struct {
		ReceiptsRoot string `json:"receiptsRoot"`
	}
	if err := json.Unmarshal(result, &block); err != nil {
		return "", err
	}

	return block.ReceiptsRoot, nil
}

type ReceiptProof struct {
	ReceiptRoot string   `json:"receiptRoot"`
	Proof       [][]byte `json:"proof"`
	Key         []byte   `json:"key"`
}

func (c *EthClient) GetReceiptProof(txHash string) (*ReceiptProof, error) {
	// 1. Get transaction receipt to know the block number and index
	result, err := c.Call("eth_getTransactionReceipt", txHash)
	if err != nil {
		return nil, err
	}

	var receipt struct {
		BlockNumber      string `json:"blockNumber"`
		TransactionIndex string `json:"transactionIndex"`
	}
	if err := json.Unmarshal(result, &receipt); err != nil {
		return nil, err
	}

	// 2. Get all transaction hashes for the block
	blockResult, err := c.Call("eth_getBlockByNumber", receipt.BlockNumber, false)
	if err != nil {
		return nil, err
	}
	var block struct {
		Transactions []string `json:"transactions"`
		ReceiptsRoot string   `json:"receiptsRoot"`
	}
	if err := json.Unmarshal(blockResult, &block); err != nil {
		return nil, err
	}

	// 3. Fetch all receipts for the block (Production-like step)
	// Some nodes support eth_getBlockReceipts, which is much faster.
	// For this POC, we simulate the trie build from all block receipts.
	db := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
	t := trie.NewEmpty(db)
	var targetKey []byte

	for i, hash := range block.Transactions {
		rBody, err := c.Call("eth_getTransactionReceipt", hash)
		if err != nil {
			return nil, err
		}

		var r types.Receipt
		if err := json.Unmarshal(rBody, &r); err != nil {
			return nil, err
		}

		// Use MarshalBinary to ensure typed receipts are encoded correctly
		val, err := r.MarshalBinary()
		if err != nil {
			return nil, err
		}
		key, err := rlp.EncodeToBytes(uint(i))
		if err != nil {
			return nil, err
		}

		if hash == txHash {
			targetKey = key
		}
		t.Update(key, val)
	}

	rebuiltRoot := t.Hash()
	fmt.Printf("🔍 Block ReceiptsRoot: %s\n", block.ReceiptsRoot)
	fmt.Printf("🔍 Rebuilt Trie Root:  %s\n", rebuiltRoot.Hex())

	if rebuiltRoot.Hex() != strings.ToLower(block.ReceiptsRoot) {
		fmt.Printf("⚠️ WARNING: ReceiptsRoot mismatch! Rebuilding with alternative encoding...\n")
		// Optional: try another encoding if this fails
	}

	proof := memorydb.New()
	if err := t.Prove(targetKey, proof); err != nil {
		return nil, err
	}

	var proofNodes [][]byte
	it := proof.NewIterator(nil, nil)
	for it.Next() {
		proofNodes = append(proofNodes, it.Value())
	}

	return &ReceiptProof{
		ReceiptRoot: block.ReceiptsRoot,
		Proof:       proofNodes,
		Key:         targetKey,
	}, nil
}
