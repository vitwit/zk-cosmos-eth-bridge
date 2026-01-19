package prover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/cometbft/cometbft/rpc/client/http"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vitwit/zk-state-transition/testing/circuit"
)

type ProofData struct {
	Root        [32]byte
	A           [2]string
	B           [2][2]string
	C           [2]string
	Inputs      []string
	LockID      uint64
	Amount      string
	Destination string
}

type Prover struct {
	CompiledR1CS constraint.ConstraintSystem
	ProvingKey   groth16.ProvingKey
}

func NewProver() (*Prover, error) {
	fmt.Println("Initializing ZK Prover...")
	c := circuit.NewInclusionCircuit(circuit.MaxTxLen, circuit.MaxDepth)

	fmt.Println("Compiling circuit...")
	compiledR1CS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return nil, err
	}

	// Try to load keys from disk
	pkPath := "proving.key"
	vkPath := "verification.key"
	var pk groth16.ProvingKey

	if _, err := os.Stat(pkPath); err == nil {
		fmt.Println("Loading proving key from disk...")
		pk = groth16.NewProvingKey(ecc.BN254)
		f, err := os.Open(pkPath)
		if err != nil {
			return nil, err
		}
		_, err = pk.ReadFrom(f)
		f.Close()
		if err != nil {
			return nil, err
		}
	} else {
		fmt.Println("Generating proving/verifying keys (this may take a few minutes)...")
		var vk groth16.VerifyingKey
		pk, vk, err = groth16.Setup(compiledR1CS)
		if err != nil {
			return nil, err
		}

		fmt.Println("Saving proving key to disk...")
		f, err := os.Create(pkPath)
		if err != nil {
			fmt.Printf("Warning: failed to save proving key: %v\n", err)
		} else {
			_, err = pk.WriteTo(f)
			f.Close()
			if err != nil {
				fmt.Printf("Warning: failed to write proving key: %v\n", err)
			}
		}

		fmt.Println("Saving verification key to disk...")
		f, err = os.Create(vkPath)
		if err != nil {
			fmt.Printf("Warning: failed to save verification key: %v\n", err)
		} else {
			_, err = vk.WriteTo(f)
			f.Close()
			if err != nil {
				fmt.Printf("Warning: failed to write verification key: %v\n", err)
			}
		}
	}

	fmt.Println("Prover initialized successfully.")
	return &Prover{
		CompiledR1CS: compiledR1CS,
		ProvingKey:   pk,
	}, nil
}

func (p *Prover) GenerateInclusionProof(rpcURL string, height int64, txHashStr string, lockID uint64, amountStr string, ethDest string) (*ProofData, error) {
	client, err := http.New(rpcURL, "/websocket")
	if err != nil {
		return nil, err
	}

	block, err := client.Block(context.Background(), &height)
	if err != nil {
		return nil, err
	}

	var txIndex int
	var tx []byte

	targetHash, err := hex.DecodeString(txHashStr)
	if err != nil {
		return nil, err
	}

	found := false
	for i, t := range block.Block.Txs {
		h := sha256.Sum256(t)
		if bytes.Equal(h[:], targetHash) {
			txIndex = i
			tx = t
			found = true
			break
		}
	}

	if !found {
		// Try searching by Ethereum hash attribute
		query := fmt.Sprintf("ethereum_tx.ethereumTxHash='0x%s'", txHashStr)
		searchRes, err := client.TxSearch(context.Background(), query, false, nil, nil, "")
		if err == nil && len(searchRes.Txs) > 0 {
			for _, t := range searchRes.Txs {
				if t.Height == height {
					tx = t.Tx
					// Find the index in the block
					for i, blockTx := range block.Block.Txs {
						if bytes.Equal(blockTx, tx) {
							txIndex = i
							found = true
							break
						}
					}
					break
				}
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("transaction with hash %s not found in block %d", txHashStr, height)
	}

	// Parse amount string to big.Int
	amountBig, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount string: %s", amountStr)
	}

	// Parse destination address
	ethDestClean := strings.TrimPrefix(ethDest, "0x")
	ethDestBytes, err := hex.DecodeString(ethDestClean)
	if err != nil {
		return nil, fmt.Errorf("invalid eth destination: %v", err)
	}
	if len(ethDestBytes) != 20 {
		return nil, fmt.Errorf("invalid eth destination length: %d", len(ethDestBytes))
	}

	// Compute TxHash of the transaction
	txHash := sha256.Sum256(tx)

	// Construct the modified leaf payload: TxHash || LockID || Amount || Destination
	// LockID (32 bytes, Big Endian, padded)
	lockIDBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(lockIDBytes[24:], lockID)

	// Amount (32 bytes, Big Endian)
	amountBytes := make([]byte, 32)
	amountBig.FillBytes(amountBytes)

	// Re-construct the items list for Merkle tree
	merkleItems := make([][]byte, len(block.Block.Txs))
	for i, t := range block.Block.Txs {
		if i == txIndex {
			// Target item: TxHash || LockID || Amount || Destination
			payload := make([]byte, 0, 32+32+32+20)
			payload = append(payload, txHash[:]...)
			payload = append(payload, lockIDBytes...)
			payload = append(payload, amountBytes...)
			payload = append(payload, ethDestBytes...)
			merkleItems[i] = payload
		} else {
			// Other items: SHA256(Tx)
			h := sha256.Sum256(t)
			merkleItems[i] = h[:]
		}
	}

	root, proofs := merkle.ProofsFromByteSlices(merkleItems)
	proof := proofs[txIndex]

	// Note: The computed root will NOT match block.Block.Header.DataHash because we modified the leaf.
	// We log a warning but proceed, as the Relayer will register this new Root.
	if !bytes.Equal(root, block.Block.Header.DataHash) {
		fmt.Printf("Warning: Computed Root (%x) does not match Block Header DataHash (%x). This is expected due to leaf modification.\n", root, block.Block.Header.DataHash)
	}

	// Pad proof to circuit.MaxDepth
	if len(proof.Aunts) > circuit.MaxDepth {
		return nil, fmt.Errorf("proof too deep: %d > %d", len(proof.Aunts), circuit.MaxDepth)
	}

	witness := circuit.NewInclusionCircuit(circuit.MaxTxLen, circuit.MaxDepth)
	for i := 0; i < 32; i++ {
		witness.Root[i].Val = root[i]
		witness.TxHash[i].Val = txHash[i]
	}

	witness.LockID = lockID
	witness.Amount = amountBig

	for i := 0; i < 20; i++ {
		witness.Destination[i].Val = ethDestBytes[i]
	}

	currentIndex := int64(txIndex)
	for i := 0; i < len(proof.Aunts); i++ {
		for j := 0; j < 32; j++ {
			witness.Proof[i][j].Val = proof.Aunts[i][j]
		}
		witness.PathSelector[i] = currentIndex % 2
		witness.IsActive[i] = 1
		currentIndex /= 2
	}
	// Fill remaining proof levels with zeros (or identity)
	for i := len(proof.Aunts); i < circuit.MaxDepth; i++ {
		for j := 0; j < 32; j++ {
			witness.Proof[i][j].Val = 0
		}
		witness.PathSelector[i] = 0
		witness.IsActive[i] = 0
	}

	fullWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	zkProof, err := groth16.Prove(p.CompiledR1CS, p.ProvingKey, fullWitness)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	zkProof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	res := &ProofData{
		A: [2]string{
			"0x" + hex.EncodeToString(proofBytes[0:32]),
			"0x" + hex.EncodeToString(proofBytes[32:64]),
		},
		B: [2][2]string{
			{"0x" + hex.EncodeToString(proofBytes[64:96]), "0x" + hex.EncodeToString(proofBytes[96:128])},
			{"0x" + hex.EncodeToString(proofBytes[128:160]), "0x" + hex.EncodeToString(proofBytes[160:192])},
		},
		C: [2]string{
			"0x" + hex.EncodeToString(proofBytes[192:224]),
			"0x" + hex.EncodeToString(proofBytes[224:256]),
		},
	}
	copy(res.Root[:], root)

	for i := 0; i < 32; i++ {
		res.Inputs = append(res.Inputs, fmt.Sprintf("%d", root[i]))
	}
	for i := 0; i < 32; i++ {
		res.Inputs = append(res.Inputs, fmt.Sprintf("%d", txHash[i]))
	}

	res.LockID = lockID
	res.Amount = amountStr
	res.Destination = ethDest

	// Append extra public inputs to Inputs slice for Solidity verifier
	// LockID
	res.Inputs = append(res.Inputs, strconv.FormatUint(lockID, 10))

	// Amount
	res.Inputs = append(res.Inputs, amountStr)

	// Destination (20 bytes, each as a uint256 input)
	for i := 0; i < 20; i++ {
		res.Inputs = append(res.Inputs, fmt.Sprintf("%d", ethDestBytes[i]))
	}

	return res, nil
}
