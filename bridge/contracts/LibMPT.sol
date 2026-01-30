// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./RLPReader.sol";

library LibMPT {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for RLPReader.Iterator;
    using RLPReader for bytes;

    /**
     * @dev Verifies an MPT proof for a receipt in an Ethereum block.
     * @param root The receiptsRoot from the Ethereum block header.
     * @param mptProof RLP encoded nodes of the MPT proof.
     * @param key The RLP encoded index of the transaction in the block.
     */
    function verifyMPTProof(
        bytes32 root,
        bytes[] memory mptProof,
        bytes memory key
    ) internal pure returns (bytes memory value) {
        bytes32 expectedHash = root;
        uint256 nibblePos = 0;
        bytes memory nibbles = _toNibbles(key);

        for (uint256 step = 0; step < 100; step++) { // Prevent infinite loops
            bytes memory nodeRaw;
            bool found = false;
            for (uint256 i = 0; i < mptProof.length; i++) {
                if (mptProof[i].length > 0 && keccak256(mptProof[i]) == expectedHash) {
                    nodeRaw = mptProof[i];
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                // Better debugging: Return a hint if the root itself is missing
                if (expectedHash == root) revert("LibMPT: root node not found in proof");
                revert("LibMPT: intermediate node not found in proof");
            }

            RLPReader.RLPItem memory item = nodeRaw.toRlpItem();
            require(item.isList(), "LibMPT: nodeRaw is not an RLP list");
            
            RLPReader.RLPItem[] memory node = item.toList();

            if (node.length == 2) {
                // Extension or Leaf node
                bytes memory nodeNibbles = _getNibbles(node[0].toBytes());
                
                // Match nibbles
                for (uint256 j = 0; j < nodeNibbles.length; j++) {
                    require(nibbles[nibblePos] == nodeNibbles[j], "LibMPT: path mismatch in ext/leaf");
                    nibblePos++;
                }

                uint8 prefix = uint8(node[0].toBytes()[0]);
                uint8 kind = prefix >> 4;

                if (kind == 2 || kind == 3) {
                    // Leaf node
                    require(nibblePos == nibbles.length, "LibMPT: key not fully consumed at leaf");
                    return node[1].toBytes();
                } else {
                    // Extension node
                    expectedHash = node[1].toBytes32();
                }
            } else if (node.length == 17) {
                // Branch node
                if (nibblePos == nibbles.length) {
                    // Value is at index 16
                    return node[16].toBytes();
                }

                uint8 nibble = uint8(nibbles[nibblePos]);
                nibblePos++;
                
                RLPReader.RLPItem memory child = node[nibble];
                require(child.len > 0, "LibMPT: empty branch child");
                
                expectedHash = child.toBytes32();
            } else {
                if (node.length == 0) revert("LibMPT: node length 0");
                if (node.length == 1) revert("LibMPT: node length 1");
                if (node.length == 3) revert("LibMPT: node length 3");
                if (node.length >= 4 && node.length <= 16) revert("LibMPT: node length 4-16");
                revert("LibMPT: node length > 17");
            }
        }

        revert("LibMPT: proof depth exceeded");
    }

    // --- Private Helpers ---

    function _toNibbles(bytes memory key) private pure returns (bytes memory) {
        bytes memory nibbles = new bytes(key.length * 2);
        for (uint256 i = 0; i < key.length; i++) {
            nibbles[i * 2] = bytes1(uint8(key[i]) >> 4);
            nibbles[i * 2 + 1] = bytes1(uint8(key[i]) & 0x0f);
        }
        return nibbles;
    }

    function _getNibbles(bytes memory encodedPath) private pure returns (bytes memory) {
        uint8 prefix = uint8(encodedPath[0]);
        
        bytes memory fullNibbles = _toNibbles(encodedPath);
        uint256 start = (prefix & 0x10 == 0) ? 2 : 1; // if even parity, skip first nibble (prefix)
        
        uint256 len = fullNibbles.length - start;
        bytes memory result = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            result[i] = fullNibbles[start + i];
        }
        return result;
    }
}
