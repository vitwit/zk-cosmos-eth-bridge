package circuits_test

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/vitwit/zk-cosmos-eth-bridge/zk-bridge/pkg/circuits"
)

func TestZkBridgeCircuit_Inclusion_Depth32(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit circuits.ZkBridgeCircuit

	// 1. Setup Mock Transaction and Merkle Tree (Real-ish)
	txHash := sha256.Sum256([]byte("real-lock-tx-data"))

	// Tendermint tree with arbitrary leaves
	leaves := make([][32]byte, 16)
	targetIndex := 7
	leaves[targetIndex] = txHash
	for i := range leaves {
		if i != targetIndex {
			leaves[i] = sha256.Sum256([]byte{byte(i)})
		}
	}

	var proofPath [circuits.MerkleDepth][32]byte
	var proofHelper [circuits.MerkleDepth]int
	currentLevel := leaves
	currIdx := targetIndex

	depth := 4 // We test with a depth 4 tree in a depth 32 circuit
	for i := 0; i < depth; i++ {
		nextLevel := make([][32]byte, len(currentLevel)/2)
		for j := 0; j < len(currentLevel); j += 2 {
			h := sha256.New()
			h.Write(currentLevel[j][:])
			h.Write(currentLevel[j+1][:])
			var res [32]byte
			copy(res[:], h.Sum(nil))
			nextLevel[j/2] = res

			if j == currIdx || j+1 == currIdx {
				if j == currIdx {
					proofPath[i] = currentLevel[j+1]
					proofHelper[i] = 0
				} else {
					proofPath[i] = currentLevel[j]
					proofHelper[i] = 1
				}
				currIdx = j / 2
			}
		}
		currentLevel = nextLevel
	}
	root := currentLevel[0]

	// 2. Setup Witness with packed format (big-endian, matching circuit)
	witness := circuits.ZkBridgeCircuit{}

	// Pack root and txHash into 4 uint64 values each (big-endian)
	for i := 0; i < 4; i++ {
		var rootPart, txPart uint64
		for j := 0; j < 8; j++ {
			// Big-endian: most significant byte first
			rootPart = (rootPart << 8) | uint64(root[i*8+(7-j)])
			txPart = (txPart << 8) | uint64(txHash[i*8+(7-j)])
		}
		witness.PackedRoot[i] = rootPart
		witness.PackedTxHash[i] = txPart
	}
	witness.ActualDepth = big.NewInt(int64(depth))

	for i := 0; i < circuits.MerkleDepth; i++ {
		for j := 0; j < 32; j++ {
			witness.ProofPath[i][j] = big.NewInt(int64(proofPath[i][j]))
		}
		witness.ProofHelper[i] = proofHelper[i]
	}

	// 3. Verify Circuit
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}
