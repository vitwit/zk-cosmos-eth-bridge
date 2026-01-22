package circuit

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestInclusionCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	// 1. Prepare dummy data
	txHash := sha256.Sum256([]byte("dummy_tx"))
	lockID := uint64(123)
	amount := new(big.Int).SetUint64(1000)
	dest := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

	lockIDBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(lockIDBytes[24:], lockID)
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)

	// Leaf = H(0x00 || TxHash || LockID || Amount || Destination)
	payload := make([]byte, 0, 1+32+32+32+20)
	payload = append(payload, 0)
	payload = append(payload, txHash[:]...)
	payload = append(payload, lockIDBytes...)
	payload = append(payload, amountBytes...)
	payload = append(payload, dest[:]...)
	leafHash := sha256.Sum256(payload)

	// Merkle Tree (simplified: 2 leaves, depth=1)
	// Leaf2 = H(0x00 || dummy_tx_2 || lockID2 || amount2 || dest2)
	// For simplicity, we'll just use a dummy hash as the sibling
	dummyTx2 := sha256.Sum256([]byte("dummy_tx_2"))
	lockID2Bytes := make([]byte, 32)
	binary.BigEndian.PutUint64(lockID2Bytes[24:], 456)
	amount2Bytes := make([]byte, 32)
	new(big.Int).SetUint64(2000).FillBytes(amount2Bytes)
	dest2 := [20]byte{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}

	payload2 := make([]byte, 0, 1+32+32+32+20)
	payload2 = append(payload2, 0)
	payload2 = append(payload2, dummyTx2[:]...)
	payload2 = append(payload2, lockID2Bytes...)
	payload2 = append(payload2, amount2Bytes...)
	payload2 = append(payload2, dest2[:]...)
	leaf2Hash := sha256.Sum256(payload2)

	// Root = H(0x01 || Leaf || Leaf2)
	// Our leaf is on the left (PathSelector[0] = 0)
	rootPayload := make([]byte, 0, 1+32+32)
	rootPayload = append(rootPayload, 1)
	rootPayload = append(rootPayload, leafHash[:]...)
	rootPayload = append(rootPayload, leaf2Hash[:]...)
	root := sha256.Sum256(rootPayload)

	// 2. Build Witness
	var witness InclusionCircuit

	split32 := func(b []byte) (*big.Int, *big.Int) {
		high := new(big.Int).SetBytes(b[:16])
		low := new(big.Int).SetBytes(b[16:])
		return high, low
	}

	witness.RootHigh, witness.RootLow = split32(root[:])
	witness.TxHigh, witness.TxLow = split32(txHash[:])
	witness.Dest = PackBytesBE(dest[:])
	witness.LockID = lockID
	witness.AmtHigh, witness.AmtLow = split32(amountBytes)

	// Set the Merkle proof (sibling hash at depth 1)
	// Since we have MaxDepth array, we only activate level 0
	for j := 0; j < 32; j++ {
		witness.Proof[0][j].Val = leaf2Hash[j]
	}
	witness.PathSelector[0] = 0 // leaf is left child, sibling is right
	witness.IsActive[0] = 1     // This level is active

	// Fill remaining levels as inactive
	for i := 1; i < MaxDepth; i++ {
		for j := 0; j < 32; j++ {
			witness.Proof[i][j].Val = 0
		}
		witness.PathSelector[i] = 0
		witness.IsActive[i] = 0 // Inactive
	}

	// 3. Run Test
	var circuit InclusionCircuit
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestInclusionCircuitDepth2(t *testing.T) {
	assert := test.NewAssert(t)

	// Build a 4-leaf Merkle tree (depth=2)
	// Tree structure:
	//         Root
	//        /    \
	//      H1      H2
	//     / \     / \
	//    L0 L1   L2 L3
	//
	// We'll prove inclusion of L1 (index 1)

	// Create 4 leaves
	leaves := make([][32]byte, 4)
	for i := 0; i < 4; i++ {
		txHash := sha256.Sum256([]byte("tx_" + string(rune('0'+i))))
		lockID := uint64(100 + i)
		amount := new(big.Int).SetUint64(1000 * uint64(i+1))
		dest := [20]byte{}
		for j := 0; j < 20; j++ {
			dest[j] = byte(i*20 + j)
		}

		lockIDBytes := make([]byte, 32)
		binary.BigEndian.PutUint64(lockIDBytes[24:], lockID)
		amountBytes := make([]byte, 32)
		amount.FillBytes(amountBytes)

		payload := make([]byte, 0, 1+32+32+32+20)
		payload = append(payload, 0)
		payload = append(payload, txHash[:]...)
		payload = append(payload, lockIDBytes...)
		payload = append(payload, amountBytes...)
		payload = append(payload, dest[:]...)
		leaves[i] = sha256.Sum256(payload)
	}

	// Build tree level 1
	h1Payload := make([]byte, 0, 1+32+32)
	h1Payload = append(h1Payload, 1)
	h1Payload = append(h1Payload, leaves[0][:]...)
	h1Payload = append(h1Payload, leaves[1][:]...)
	h1 := sha256.Sum256(h1Payload)

	h2Payload := make([]byte, 0, 1+32+32)
	h2Payload = append(h2Payload, 1)
	h2Payload = append(h2Payload, leaves[2][:]...)
	h2Payload = append(h2Payload, leaves[3][:]...)
	h2 := sha256.Sum256(h2Payload)

	// Build root
	rootPayload := make([]byte, 0, 1+32+32)
	rootPayload = append(rootPayload, 1)
	rootPayload = append(rootPayload, h1[:]...)
	rootPayload = append(rootPayload, h2[:]...)
	root := sha256.Sum256(rootPayload)

	// Prove inclusion of leaf at index 1 (L1)
	// Path: L1 -> H1 -> Root
	// Siblings: L0 (at level 0), H2 (at level 1)
	// Index 1 in binary: 01
	//   - Level 0: bit=1 (L1 is right child, L0 is left sibling)
	//   - Level 1: bit=0 (H1 is left child, H2 is right sibling)

	targetIndex := 1
	txHash := sha256.Sum256([]byte("tx_1"))
	lockID := uint64(101)
	amount := new(big.Int).SetUint64(2000)
	dest := [20]byte{}
	for j := 0; j < 20; j++ {
		dest[j] = byte(1*20 + j)
	}

	lockIDBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(lockIDBytes[24:], lockID)
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)

	// Build witness
	var witness InclusionCircuit

	split32 := func(b []byte) (*big.Int, *big.Int) {
		high := new(big.Int).SetBytes(b[:16])
		low := new(big.Int).SetBytes(b[16:])
		return high, low
	}

	witness.RootHigh, witness.RootLow = split32(root[:])
	witness.TxHigh, witness.TxLow = split32(txHash[:])
	witness.Dest = PackBytesBE(dest[:])
	witness.LockID = lockID
	witness.AmtHigh, witness.AmtLow = split32(amountBytes)

	// Merkle proof for index 1:
	// Level 0: sibling is L0, path selector = 1 (current is right)
	// Level 1: sibling is H2, path selector = 0 (current is left)
	currentIdx := targetIndex

	// Level 0
	for j := 0; j < 32; j++ {
		witness.Proof[0][j].Val = leaves[0][j] // L0 is sibling
	}
	witness.PathSelector[0] = currentIdx % 2 // 1
	witness.IsActive[0] = 1
	currentIdx /= 2

	// Level 1
	for j := 0; j < 32; j++ {
		witness.Proof[1][j].Val = h2[j] // H2 is sibling
	}
	witness.PathSelector[1] = currentIdx % 2 // 0
	witness.IsActive[1] = 1

	// Fill remaining levels as inactive
	for i := 2; i < MaxDepth; i++ {
		for j := 0; j < 32; j++ {
			witness.Proof[i][j].Val = 0
		}
		witness.PathSelector[i] = 0
		witness.IsActive[i] = 0
	}

	// Run test
	var circuit InclusionCircuit
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestInclusionCircuitInvalidProof(t *testing.T) {
	assert := test.NewAssert(t)

	// This test should FAIL because we provide a wrong sibling hash

	txHash := sha256.Sum256([]byte("dummy_tx"))
	lockID := uint64(123)
	amount := new(big.Int).SetUint64(1000)
	dest := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

	lockIDBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(lockIDBytes[24:], lockID)
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)

	payload := make([]byte, 0, 1+32+32+32+20)
	payload = append(payload, 0)
	payload = append(payload, txHash[:]...)
	payload = append(payload, lockIDBytes...)
	payload = append(payload, amountBytes...)
	payload = append(payload, dest[:]...)
	leafHash := sha256.Sum256(payload)

	// Correct sibling
	dummyTx2 := sha256.Sum256([]byte("dummy_tx_2"))
	lockID2Bytes := make([]byte, 32)
	binary.BigEndian.PutUint64(lockID2Bytes[24:], 456)
	amount2Bytes := make([]byte, 32)
	new(big.Int).SetUint64(2000).FillBytes(amount2Bytes)
	dest2 := [20]byte{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}

	payload2 := make([]byte, 0, 1+32+32+32+20)
	payload2 = append(payload2, 0)
	payload2 = append(payload2, dummyTx2[:]...)
	payload2 = append(payload2, lockID2Bytes...)
	payload2 = append(payload2, amount2Bytes...)
	payload2 = append(payload2, dest2[:]...)
	leaf2Hash := sha256.Sum256(payload2)

	// Correct root
	rootPayload := make([]byte, 0, 1+32+32)
	rootPayload = append(rootPayload, 1)
	rootPayload = append(rootPayload, leafHash[:]...)
	rootPayload = append(rootPayload, leaf2Hash[:]...)
	root := sha256.Sum256(rootPayload)

	// Build witness with WRONG sibling (use all zeros)
	var witness InclusionCircuit

	split32 := func(b []byte) (*big.Int, *big.Int) {
		high := new(big.Int).SetBytes(b[:16])
		low := new(big.Int).SetBytes(b[16:])
		return high, low
	}

	witness.RootHigh, witness.RootLow = split32(root[:])
	witness.TxHigh, witness.TxLow = split32(txHash[:])
	witness.Dest = PackBytesBE(dest[:])
	witness.LockID = lockID
	witness.AmtHigh, witness.AmtLow = split32(amountBytes)

	// WRONG sibling: all zeros instead of leaf2Hash
	wrongSibling := [32]byte{}
	for j := 0; j < 32; j++ {
		witness.Proof[0][j].Val = wrongSibling[j]
	}
	witness.PathSelector[0] = 0
	witness.IsActive[0] = 1

	for i := 1; i < MaxDepth; i++ {
		for j := 0; j < 32; j++ {
			witness.Proof[i][j].Val = 0
		}
		witness.PathSelector[i] = 0
		witness.IsActive[i] = 0
	}

	// This should fail
	var circuit InclusionCircuit
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "Expected proof verification to fail with invalid sibling")
}
