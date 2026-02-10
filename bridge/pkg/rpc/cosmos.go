package rpc

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// TxResponse captures both successful results and error messages from Tendermint RPC.
type TxResponse struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`

	// Success Payload
	Result struct {
		Hash     string `json:"hash"`
		TxHash   string `json:"txhash"`
		Height   string `json:"height"`
		Index    int    `json:"index"`
		TxResult struct {
			Code   int     `json:"code"`
			Events []Event `json:"events"`
		} `json:"tx_result"`
		Events []Event `json:"events"`

		Proof struct {
			RootHash string `json:"root_hash"`
			Data     any    `json:"data"`
			Proof    struct {
				Total    string   `json:"total"`
				Index    string   `json:"index"`
				LeafHash string   `json:"leaf_hash"`
				Aunts    []string `json:"aunts"`
			} `json:"proof"`
		} `json:"proof"`
	} `json:"result"`

	// Error Payload
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`

	// Top-level fields
	Hash   string  `json:"hash"`
	TxHash string  `json:"txhash"`
	Events []Event `json:"events"`

	Raw []byte `json:"-"`
}

type Event struct {
	Type       string      `json:"type"`
	Attributes []Attribute `json:"attributes"`
}

type Attribute struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type CosmosClient struct {
	RpcUrl string
}

func NewCosmosClient(url string) *CosmosClient {
	return &CosmosClient{RpcUrl: url}
}

func (c *CosmosClient) GetTxDetails(txHash string) (*TxResponse, error) {
	url := fmt.Sprintf("%s/tx?hash=0x%s&prove=true", c.RpcUrl, strings.TrimPrefix(txHash, "0x"))
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var txResp TxResponse
	txResp.Raw = body
	if err := json.Unmarshal(body, &txResp); err != nil {
		return nil, err
	}

	return &txResp, nil
}

// DecodeHash tries to decode a string as hex or base64.
func DecodeHash(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	// Try hex first
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	// Try base64
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("invalid hash format: %s", s)
}

// GetEvmHash extracts the ethereumTxHash from events.
func (r *TxResponse) GetEvmHash() string {
	var allEvents []Event
	allEvents = append(allEvents, r.Events...)
	allEvents = append(allEvents, r.Result.Events...)
	allEvents = append(allEvents, r.Result.TxResult.Events...)

	for _, event := range allEvents {
		eType := strings.ToLower(decodeStringIfSmall(event.Type))
		if eType == "ethereum_tx" || eType == "ethereum-tx" || eType == "evm" {
			for _, attr := range event.Attributes {
				key := strings.ToLower(decodeStringIfSmall(attr.Key))
				if key == "ethereumtxhash" || key == "txhash" || key == "eth_tx_hash" {
					val := decodeStringIfSmall(attr.Value)
					if len(val) >= 64 {
						if !strings.HasPrefix(val, "0x") {
							val = "0x" + val
						}
						return val
					}
				}
			}
		}
	}
	return ""
}

// ValidatorSetResponse captures response from /validators
type ValidatorSetResponse struct {
	Result struct {
		BlockHeight    string      `json:"block_height"`
		Validators     []Validator `json:"validators"`
		Total          string      `json:"total"`
		ValidatorsHash string      `json:"validators_hash"`
	} `json:"result"`
}

type Validator struct {
	Address string `json:"address"`
	PubKey  struct {
		Type  string `json:"type"`
		Value string `json:"value"` // base64
	} `json:"pub_key"`
	VotingPower string `json:"voting_power"`
}

// CommitResponse captures response from /commit
type CommitResponse struct {
	Result struct {
		SignedHeader struct {
			Header struct {
				Height         string `json:"height"`
				Time           string `json:"time"`
				ChainID        string `json:"chain_id"`
				ValidatorsHash string `json:"validators_hash"`
				AppHash        string `json:"app_hash"`
				DataHash       string `json:"data_hash"`
			} `json:"header"`
			Commit struct {
				Height     string      `json:"height"`
				Signatures []CommitSig `json:"signatures"`
			} `json:"commit"`
		} `json:"signed_header"`
	} `json:"result"`
}

type CommitSig struct {
	BlockIDFlag      int    `json:"block_id_flag"`
	ValidatorAddress string `json:"validator_address"`
	Timestamp        string `json:"timestamp"`
	Signature        string `json:"signature"` // base64
}

func (c *CosmosClient) GetValidators(height string) (*ValidatorSetResponse, error) {
	url := fmt.Sprintf("%s/validators?height=%s", c.RpcUrl, height)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var valResp ValidatorSetResponse
	if err := json.Unmarshal(body, &valResp); err != nil {
		return nil, err
	}
	return &valResp, nil
}

func (c *CosmosClient) GetCommit(height string) (*CommitResponse, error) {
	url := fmt.Sprintf("%s/commit?height=%s", c.RpcUrl, height)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var commitResp CommitResponse
	if err := json.Unmarshal(body, &commitResp); err != nil {
		return nil, err
	}
	return &commitResp, nil
}

func decodeStringIfSmall(s string) string {
	if s == "" || len(s)%4 != 0 {
		return s
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	for _, r := range string(decoded) {
		if r < 32 || r > 126 {
			return s
		}
	}
	return string(decoded)
}
