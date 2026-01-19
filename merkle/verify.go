package merkle

import (
	"crypto/sha256"
	"fmt"
)

// LeafHash computes the hash of a leaf node: SHA256(0x00 || value)
func LeafHash(value []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(value)
	return h.Sum(nil)
}

// InnerHash computes the hash of an inner node: SHA256(0x01 || left || right)
func InnerHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// VerifyInclusion verifies a Merkle proof for a leaf value against a root hash.
// index is the 0-based index of the leaf.
// total is the total number of leaves in the tree.
func VerifyInclusion(root []byte, leaf []byte, index int64, total int64, proof [][]byte) (bool, error) {
	if index < 0 || index >= total {
		return false, fmt.Errorf("invalid index")
	}

	// In CometBFT, the leaf of the Merkle tree is the SHA256 of the transaction
	txHash := sha256.Sum256(leaf)
	computedHash := LeafHash(txHash[:])

	for _, p := range proof {
		if index%2 == 0 {
			// index is even, so the proof element is the right sibling
			computedHash = InnerHash(computedHash, p)
		} else {
			// index is odd, so the proof element is the left sibling
			computedHash = InnerHash(p, computedHash)
		}
		index /= 2
	}

	if string(computedHash) != string(root) {
		return false, nil
	}

	return true, nil
}
