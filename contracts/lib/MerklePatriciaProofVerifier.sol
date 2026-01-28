// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./RLPReader.sol";

library MerklePatriciaProofVerifier {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for RLPReader.Iterator;
    using RLPReader for bytes;

    /// @dev Validates a Merkle-Patricia-Trie proof.
    ///      If the proof proves the inclusion of some key-value pair in the
    ///      trie, the value is returned. Otherwise, i.e. if the proof is
    ///      invalid or it proves the absence of the key, the empty byte array
    ///      is returned.
    /// @param rootHash is the Keccak-256 hash of the root node of the MPT.
    /// @param path is the key of the node whose inclusion is proved.
    /// @param stack is the stack of MPT nodes (each RLP encoded) which,
    ///        starting from the root, leads to the node of the proved key.
    /// @return value content of the proved node, or an empty byte array if the
    ///         proof is invalid.
    struct VerifyContext {
        bytes mptKey;
        uint256 mptKeyOffset;
        bytes32 nodeHashHash;
    }

    struct NodeData {
        bytes path; // Shared path for Leaf/Extension
        bytes value; // Value for Leaf, NextHash for Extension
        uint256 prefix;
        uint256 nibbleLen;
        bool isOdd;
        bool isLeaf;
    }

    function verify(
        bytes32 rootHash,
        bytes memory path,
        bytes[] memory stack
    ) internal pure returns (bytes memory value) {
        VerifyContext memory ctx;
        ctx.mptKey = _nibblesFromBytes(path);
        ctx.mptKeyOffset = 0;
        ctx.nodeHashHash = rootHash;

        for (uint256 i = 0; i < stack.length; i++) {
            bytes memory rlpNode = stack[i];

            if (keccak256(rlpNode) != ctx.nodeHashHash) {
                return new bytes(0);
            }

            RLPReader.RLPItem memory node = RLPReader.toRlpItem(rlpNode);
            if (!node.isList()) {
                return new bytes(0);
            }

            uint256 itemCount = _countItems(node);

            if (itemCount == 2) {
                if (!_processExtensionOrLeaf(ctx, node)) {
                    return new bytes(0);
                }
                // If we found the value (isLeaf and reached end), return it immediately?
                // The helper updates ctx. If leaf, it sets value? 
                // Let's refactor helper to return (bool success, bool finished, bytes result)
                
                // Re-implementation inside helper is tricky with references.
                // Let's keep loop simple.
                // We need to fetch the ValueItem again if we want to return it.
                // Or simplified: Just update hash.
                
                // Note: _processExtensionOrLeaf ONLY updates hash or returns failure.
                // EXCEPT if it is a LEAF, we need the value.
                
                // Optimized approach:
                // Decode node type first.
                RLPReader.Iterator memory it = node.iterator();
                RLPReader.RLPItem memory pathItem = it.next();
                RLPReader.RLPItem memory valueItem = it.next();
                
                NodeData memory nd = _decodeNodeData(pathItem);
                
                if (!_matchPath(ctx, nd)) {
                    return new bytes(0);
                }
                
                if (nd.isLeaf) {
                    if (ctx.mptKeyOffset == ctx.mptKey.length) {
                        return valueItem.toBytes();
                    }
                    return new bytes(0);
                } else {
                    // Extension
                    if (valueItem.len < 32) return new bytes(0);
                    ctx.nodeHashHash = valueItem.toBytes32();
                }

            } else if (itemCount == 17) {
                RLPReader.Iterator memory it = node.iterator();
                
                if (ctx.mptKeyOffset == ctx.mptKey.length) {
                    for (uint k = 0; k < 16; k++) it.next();
                    return it.next().toBytes();
                } else {
                    uint8 nibble = uint8(ctx.mptKey[ctx.mptKeyOffset]);
                    ctx.mptKeyOffset++;
                    for (uint k = 0; k < nibble; k++) it.next();
                    RLPReader.RLPItem memory child = it.next();
                    if (child.len < 32) return new bytes(0);
                    ctx.nodeHashHash = child.toBytes32();
                }
            } else {
                return new bytes(0);
            }
        }
        return new bytes(0);
    }

    function _processExtensionOrLeaf(VerifyContext memory ctx, RLPReader.RLPItem memory node) private pure returns (bool) {
        RLPReader.Iterator memory it = node.iterator();
        RLPReader.RLPItem memory pathItem = it.next();
        RLPReader.RLPItem memory valueItem = it.next();
        
        NodeData memory nd = _decodeNodeData(pathItem);
        
        if (!_matchPath(ctx, nd)) {
            return false;
        }
        
        if (nd.isLeaf) {
            // Leaf: Return success only if we consumed the whole key
            return ctx.mptKeyOffset == ctx.mptKey.length;
        } else {
            // Extension: Update hash and continue
            if (valueItem.len < 32) return false;
            ctx.nodeHashHash = valueItem.toBytes32();
            return true;
        }
    }

    function _decodeNodeData(RLPReader.RLPItem memory pathItem) private pure returns (NodeData memory nd) {
        nd.path = pathItem.toBytes();
        uint256 prefix;
        bytes memory p = nd.path;
        assembly { prefix := byte(0, mload(add(p, 0x20))) }
        nd.prefix = prefix;
        
        nd.nibbleLen = nd.path.length * 2;
        nd.isOdd = (prefix >> 4) % 2 == 1;
        nd.isLeaf = (prefix >> 5) == 1;
        
        if (nd.isOdd) {
            nd.nibbleLen -= 1;
        } else {
            nd.nibbleLen -= 2;
        }
    }

    function _matchPath(VerifyContext memory ctx, NodeData memory nd) private pure returns (bool) {
        uint256 overlap = nd.isOdd ? 1 : 2;
        bytes memory nodeKey = _nibblesFromBytesPartial(nd.path, overlap, nd.nibbleLen);
        
        if (!_checkPathMatch(ctx.mptKey, ctx.mptKeyOffset, nodeKey)) {
            return false;
        }
        ctx.mptKeyOffset += nd.nibbleLen;
        return true;
    }
    
    function _countItems(RLPReader.RLPItem memory item) private pure returns (uint256) {
        RLPReader.Iterator memory it = item.iterator();
        uint256 count = 0;
        while(it.hasNext()){
            it.next();
            count++;
        }
        return count;
    }

    function _checkPathMatch(bytes memory mptKey, uint256 offset, bytes memory cleanPath) private pure returns (bool) {
         if (offset + cleanPath.length > mptKey.length) {
             return false;
         }
         
         for (uint256 i = 0; i < cleanPath.length; i++) {
             if (mptKey[offset + i] != cleanPath[i]) {
                 return false;
             }
         }
         return true;
    }

    function _nibblesFromBytes(bytes memory input) private pure returns (bytes memory) {
        bytes memory nibbles = new bytes(input.length * 2);
        for (uint256 i = 0; i < input.length; i++) {
            nibbles[i * 2] = input[i] >> 4;
            nibbles[i * 2 + 1] = input[i] & 0x0f;
        }
        return nibbles;
    }
    
    function _nibblesFromBytesPartial(bytes memory input, uint256 nibbleOffset, uint256 outputLen) private pure returns (bytes memory) {
         bytes memory nibbles = new bytes(outputLen);
         
         // input is [0xAB, 0xCD]
         // nibbles is [A, B, C, D]
         // offset 1 (skip first nibble -> B)
         // outputLen 3 -> B, C, D
         
         uint256 currentNibbleIdx = nibbleOffset;
         for (uint256 i = 0; i < outputLen; i++) {
             uint256 byteIdx = currentNibbleIdx / 2;
             bool isHigh = (currentNibbleIdx % 2) == 0;
             
             if (isHigh) {
                 nibbles[i] = input[byteIdx] >> 4;
             } else {
                 nibbles[i] = input[byteIdx] & 0x0f;
             }
             currentNibbleIdx++;
         }
         return nibbles;
    }
}
