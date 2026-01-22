package prover

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/cometbft/cometbft/rpc/client/http"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vitwit/zk-state-transition/testing/circuit"
)

type ProofData struct {
	Root          [32]byte
	A             [2]string
	B             [2][2]string
	C             [2]string
	Commitments   [2]string
	CommitmentPok [2]string
	Inputs        []string
	LockID        uint64
	Amount        string
	Destination   string
}

type Prover struct {
	CompiledR1CS constraint.ConstraintSystem
	ProvingKey   groth16.ProvingKey
	VerifyingKey groth16.VerifyingKey
}

func NewProver() (*Prover, error) {
	fmt.Println("Initializing ZK Prover...")

	var c circuit.InclusionCircuit

	fmt.Println("Compiling circuit...")
	compiledR1CS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return nil, err
	}

	pkPath := "proving.key"
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

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

		vk = groth16.NewVerifyingKey(ecc.BN254)
		f, err = os.Open("verification.key")
		if err != nil {
			return nil, err
		}
		_, err = vk.ReadFrom(f)
		f.Close()
		if err != nil {
			return nil, err
		}
	} else {
		fmt.Println("Generating proving/verifying keys (this may take a few minutes)...")
		pk, vk, err = groth16.Setup(compiledR1CS)
		if err != nil {
			return nil, err
		}

		fmt.Println("Saving proving key to disk...")
		f, err := os.Create(pkPath)
		if err == nil {
			pk.WriteTo(f)
			f.Close()
		}

		fmt.Println("Saving verification key to disk...")
		f, err = os.Create("verification.key")
		if err == nil {
			vk.WriteTo(f)
			f.Close()
		}
	}

	// Debug: Print Pedersen points from VK
	vk_bn254 := vk.(*groth16_bn254.VerifyingKey)
	if len(vk_bn254.CommitmentKeys) > 0 {
		fmt.Printf("DEBUG: VK Pedersen G X0: %s\n", vk_bn254.CommitmentKeys[0].G.X.A0.BigInt(new(big.Int)).String())
		fmt.Printf("DEBUG: VK Pedersen G X1: %s\n", vk_bn254.CommitmentKeys[0].G.X.A1.BigInt(new(big.Int)).String())
		fmt.Printf("DEBUG: VK Pedersen GSigmaNeg X0: %s\n", vk_bn254.CommitmentKeys[0].GSigmaNeg.X.A0.BigInt(new(big.Int)).String())
		fmt.Printf("DEBUG: VK Pedersen GSigmaNeg X1: %s\n", vk_bn254.CommitmentKeys[0].GSigmaNeg.X.A1.BigInt(new(big.Int)).String())
	}

	fmt.Println("Prover initialized successfully.")
	return &Prover{
		CompiledR1CS: compiledR1CS,
		ProvingKey:   pk,
		VerifyingKey: vk,
	}, nil
}

func (p *Prover) GenerateInclusionProof(rpcURL string, height int64, txIndex int, lockID uint64, amountStr string, ethDest string) (*ProofData, error) {
	client, err := http.New(rpcURL, "/websocket")
	if err != nil {
		return nil, err
	}

	block, err := client.Block(context.Background(), &height)
	if err != nil {
		return nil, err
	}

	if txIndex < 0 || txIndex >= len(block.Block.Txs) {
		return nil, fmt.Errorf("transaction index %d out of bounds (total txs: %d)", txIndex, len(block.Block.Txs))
	}
	tx := block.Block.Txs[txIndex]

	amountBig, _ := new(big.Int).SetString(amountStr, 10)
	ethDestClean := strings.TrimPrefix(ethDest, "0x")
	ethDestBytes, _ := hex.DecodeString(ethDestClean)
	txHash := sha256.Sum256(tx)

	lockIDBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(lockIDBytes[24:], lockID)
	amountBytes := make([]byte, 32)
	amountBig.FillBytes(amountBytes)

	merkleItems := make([][]byte, len(block.Block.Txs))
	for i, t := range block.Block.Txs {
		if i == txIndex {
			payload := make([]byte, 0, 32+32+32+20)
			payload = append(payload, txHash[:]...)
			payload = append(payload, lockIDBytes...)
			payload = append(payload, amountBytes...)
			payload = append(payload, ethDestBytes...)
			merkleItems[i] = payload
		} else {
			h := sha256.Sum256(t)
			merkleItems[i] = h[:]
		}
	}

	root, proofs := merkle.ProofsFromByteSlices(merkleItems)
	proof := proofs[txIndex]
	var witness circuit.InclusionCircuit

	// Helper to split 32 bytes into high/low 16 bytes
	split32 := func(b []byte) (*big.Int, *big.Int) {
		high := new(big.Int).SetBytes(b[:16])
		low := new(big.Int).SetBytes(b[16:])
		return high, low
	}

	witness.RootHigh, witness.RootLow = split32(root)
	witness.TxHigh, witness.TxLow = split32(txHash[:])
	witness.Dest = circuit.PackBytesBE(ethDestBytes)
	witness.LockID = lockID

	amtBytes := make([]byte, 32)
	amountBig.FillBytes(amtBytes)
	witness.AmtHigh, witness.AmtLow = split32(amtBytes)

	currentIndex := int64(txIndex)
	for i := 0; i < len(proof.Aunts); i++ {
		for j := 0; j < 32; j++ {
			witness.Proof[i][j].Val = proof.Aunts[i][j]
		}
		witness.PathSelector[i] = currentIndex % 2
		witness.IsActive[i] = 1
		currentIndex /= 2
	}

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

	zkProof, err := groth16.Prove(p.CompiledR1CS, p.ProvingKey, fullWitness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		return nil, err
	}

	// Helper to pad hex string to 32 bytes (64 chars)
	padHex32 := func(s string) string {
		if len(s) >= 64 {
			return s
		}
		return strings.Repeat("0", 64-len(s)) + s
	}

	g16proof := zkProof.(*groth16_bn254.Proof)
	res := &ProofData{
		A: [2]string{
			"0x" + padHex32(g16proof.Ar.X.BigInt(new(big.Int)).Text(16)),
			"0x" + padHex32(g16proof.Ar.Y.BigInt(new(big.Int)).Text(16)),
		},
		B: [2][2]string{
			{
				"0x" + padHex32(g16proof.Bs.X.A1.BigInt(new(big.Int)).Text(16)),
				"0x" + padHex32(g16proof.Bs.X.A0.BigInt(new(big.Int)).Text(16)),
			},
			{
				"0x" + padHex32(g16proof.Bs.Y.A1.BigInt(new(big.Int)).Text(16)),
				"0x" + padHex32(g16proof.Bs.Y.A0.BigInt(new(big.Int)).Text(16)),
			},
		},
		C: [2]string{
			"0x" + padHex32(g16proof.Krs.X.BigInt(new(big.Int)).Text(16)),
			"0x" + padHex32(g16proof.Krs.Y.BigInt(new(big.Int)).Text(16)),
		},
	}

	fmt.Printf("Number of commitments: %d\n", len(g16proof.Commitments))
	if len(g16proof.Commitments) > 0 {
		res.Commitments = [2]string{
			"0x" + padHex32(g16proof.Commitments[0].X.BigInt(new(big.Int)).Text(16)),
			"0x" + padHex32(g16proof.Commitments[0].Y.BigInt(new(big.Int)).Text(16)),
		}
		res.CommitmentPok = [2]string{
			"0x" + padHex32(g16proof.CommitmentPok.X.BigInt(new(big.Int)).Text(16)),
			"0x" + padHex32(g16proof.CommitmentPok.Y.BigInt(new(big.Int)).Text(16)),
		}

		// Debug: Compute commitment hashes to compare with Solidity
		cx := g16proof.Commitments[0].X.BigInt(new(big.Int))
		cy := g16proof.Commitments[0].Y.BigInt(new(big.Int))
		cxBytes := make([]byte, 32)
		cx.FillBytes(cxBytes)
		cyBytes := make([]byte, 32)
		cy.FillBytes(cyBytes)

		packed := append(cxBytes, cyBytes...)
		shaHash := sha256.Sum256(packed)
		keccakHash := crypto.Keccak256(packed)

		fmt.Printf("DEBUG: Commitment X: 0x%x\n", cxBytes)
		fmt.Printf("DEBUG: Commitment Y: 0x%x\n", cyBytes)
		fmt.Printf("DEBUG: SHA256 Hash: 0x%x\n", shaHash)
		fmt.Printf("DEBUG: Keccak256 Hash: 0x%x\n", keccakHash)
		fmt.Printf("DEBUG: Scalar Field R: %s\n", ecc.BN254.ScalarField().String())

		shaChallenge := new(big.Int).SetBytes(shaHash[:])
		shaChallenge.Mod(shaChallenge, ecc.BN254.ScalarField())
		fmt.Printf("DEBUG: SHA256 Challenge (mod R): %s\n", shaChallenge.String())

		keccakChallenge := new(big.Int).SetBytes(keccakHash)
		keccakChallenge.Mod(keccakChallenge, ecc.BN254.ScalarField())
		fmt.Printf("DEBUG: Keccak256 Challenge (mod R): %s\n", keccakChallenge.String())

	} else {
		res.Commitments = [2]string{"0x0", "0x0"}
		res.CommitmentPok = [2]string{"0x0", "0x0"}
	}

	// Use original root for consistency with on-chain registration
	copy(res.Root[:], root)

	// Extract public inputs from witness vector for correct ordering
	pubWitness, _ := fullWitness.Public()
	vec := pubWitness.Vector().(fr.Vector)
	res.Inputs = make([]string, 0, len(vec))
	for i := 0; i < len(vec); i++ {
		v := vec[i].BigInt(new(big.Int))
		res.Inputs = append(res.Inputs, v.String())
	}

	res.LockID = lockID
	res.Amount = amountStr
	res.Destination = ethDest

	return res, nil
}
