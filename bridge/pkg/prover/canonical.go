package prover

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"

	"github.com/vitwit/zk-cosmos-eth-bridge/bridge/pkg/rpc"
)

// --- Canonical Tendermint Hashing Helpers ---

// HashLeaf computes SHA256(0x00 || data)
func HashLeaf(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	var res [32]byte
	copy(res[:], h.Sum(nil))
	return res
}

// ProtoEncodeInt64 encodes an int64 as a Protobuf Varint
func ProtoEncodeInt64(v int64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, uint64(v))
	return buf[:n]
}

// HashHeaderLeaves computes the 14 leaf hashes for a Tendermint header
func HashHeaderLeaves(header rpc.CommitResponse) [14][32]byte {
	var leaves [14][32]byte
	res := header.Result.SignedHeader.Header

	// Leaf 1: Version (Simplified for PoC, should be ProtoEncode(Version))
	leaves[0] = HashLeaf([]byte{0x08, 0x0b, 0x10, 0x0b}) // Example: block=11, app=11

	// Leaf 2: ChainID
	leaves[1] = HashLeaf([]byte(res.ChainID))

	// Leaf 3: Height
	height, _ := strconv.ParseInt(res.Height, 10, 64)
	leaves[2] = HashLeaf(ProtoEncodeInt64(height))

	// Leaf 4: Time (Simplified, should be ProtoEncode(Time))
	leaves[3] = HashLeaf([]byte(res.Time))

	leaves[4] = HashLeaf(dec(res.LastBlockID.Hash))
	leaves[5] = HashLeaf(dec(res.LastCommitHash))
	leaves[6] = HashLeaf(dec(res.DataHash))
	leaves[7] = HashLeaf(dec(res.ValidatorsHash))
	leaves[8] = HashLeaf(dec(res.NextValidatorsHash))
	leaves[9] = HashLeaf(dec(res.ConsensusHash))
	leaves[10] = HashLeaf(dec(res.AppHash))
	leaves[11] = HashLeaf(dec(res.LastResultsHash))
	leaves[12] = HashLeaf(dec(res.EvidenceHash))
	leaves[13] = HashLeaf(dec(res.ProposerAddress))
	return leaves
}

// ProtoEncodeVote encodes a CanonicalVote for signing (CometBFT v0.38.19)
func ProtoEncodeVote(chainID string, height int64, round int32, blockHash []byte, timestamp string) []byte {
	// CanonicalVote layout:
	// Type (1): 0x08 | 0x02 (Precommit)
	// Height (2): 0x11 | fixed64 (8 bytes LE)
	// Round (3): 0x19 | sfixed64 (8 bytes LE)
	// BlockID (4): 0x22 | Length | [CanonicalBlockID]
	// Timestamp (5): 0x2a | Length | [google.protobuf.Timestamp]
	// ChainID (6): 0x32 | Length | string

	var res []byte
	// 1. Type
	res = append(res, 0x08, 0x02)

	// 2. Height (fixed64 LE)
	res = append(res, 0x11)
	hBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(hBuf, uint64(height))
	res = append(res, hBuf...)

	// 3. Round (sfixed64 LE)
	res = append(res, 0x19)
	rBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(rBuf, uint64(round))
	res = append(res, rBuf...)

	// 4. BlockID (Tag 4, Message)
	// CanonicalBlockID: Tag 1 (bytes) | Tag 2 (PartSetHeader)
	// For simplicity in PoC, we only hash Tag 1 if Tag 2 is empty
	bid := []byte{0x0a, 0x20} // Tag 1 (Hash), Length 32
	bid = append(bid, blockHash...)
	res = append(res, 0x22, uint8(len(bid)))
	res = append(res, bid...)

	// 5. Timestamp (Tag 5, Message)
	// For now, we skip or use a fixed length for timestamp if it's constant per commit
	// In production, parse RFC3339 and encode as Tag1(seconds) and Tag2(nanos)
	// res = append(res, 0x2a, ...)

	// 6. ChainID (Tag 6, String)
	res = append(res, 0x32, uint8(len(chainID)))
	res = append(res, []byte(chainID)...)

	return res
}

// HashValidator computes the leaf hash for a single validator for ValidatorsHash.
func HashValidator(addr []byte, pubkey []byte, power int64, priority int64) [32]byte {
	pBytes := ProtoEncodeInt64(power)
	prBytes := ProtoEncodeInt64(priority)

	leaves := make([][32]byte, 4)
	leaves[0] = HashLeaf(addr)
	leaves[1] = HashLeaf(pubkey)
	leaves[2] = HashLeaf(pBytes)
	leaves[3] = HashLeaf(prBytes)

	return RFC6962MerkleRoot(leaves)
}

// RFC6962MerkleRoot computes the root of a Merkle tree given leaf hashes.
func RFC6962MerkleRoot(leaves [][32]byte) [32]byte {
	n := len(leaves)
	if n == 0 {
		return [32]byte{}
	}
	if n == 1 {
		return leaves[0]
	}

	k := 1
	for k < n {
		k <<= 1
	}
	k >>= 1

	left := RFC6962MerkleRoot(leaves[:k])
	right := RFC6962MerkleRoot(leaves[k:])

	h := sha256.New()
	h.Write([]byte{1}) // Inner node prefix
	h.Write(left[:])
	h.Write(right[:])
	var res [32]byte
	copy(res[:], h.Sum(nil))
	return res
}

// HashValidators computes the ValidatorsHash for a list of validators.
func HashValidators(vals []rpc.Validator) [32]byte {
	leafHashes := make([][32]byte, len(vals))
	for i, v := range vals {
		p, _ := strconv.ParseInt(v.VotingPower, 10, 64)
		pr, _ := strconv.ParseInt(v.ProposerPriority, 10, 64)
		// PubKey is base64 encoded in RPC
		// In production, we'd use the actual Protobuf encoded PubKey.
		// For PoC, we assume the PubKey.Value is the bytes of the PK.
		// Note: Ed25519 PubKey in Protobuf has a prefix (0x0a 0x20).
		pkBytes, _ := rpc.DecodeHash(v.PubKey.Value)
		// Protobuf PublicKey wrap: Tag 1 (Ed25519) | Length 32
		protoPK := append([]byte{0x0a, 0x20}, pkBytes...)

		leafHashes[i] = HashValidator(dec(v.Address), protoPK, p, pr)
	}
	return RFC6962MerkleRoot(leafHashes)
}

func dec(s string) []byte {
	b, _ := rpc.DecodeHash(s)
	return b
}
