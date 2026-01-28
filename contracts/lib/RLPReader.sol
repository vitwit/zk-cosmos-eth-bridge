// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/**
 * @title RLPReader
 * @dev RLPReader is a library for parsing and decoding data in RLP format.
 * Adapted from Hamdi's RLPReader.
 */
library RLPReader {
    uint8 constant STRING_SHORT_START = 0x80;
    uint8 constant STRING_LONG_START = 0xb8;
    uint8 constant LIST_SHORT_START = 0xc0;
    uint8 constant LIST_LONG_START = 0xf8;
    uint8 constant WORD_SIZE = 32;

    struct RLPItem {
        uint256 len;
        uint256 memPtr;
    }

    struct Iterator {
        RLPItem item;
        uint256 nextPtr;
    }

    /*
     * @dev Returns the next element in the iteration. Reverts if it has not next element.
     * @param self The iterator.
     * @return The next element in the iteration.
     */
    function next(Iterator memory self) internal pure returns (RLPItem memory) {
        require(hasNext(self));

        uint256 ptr = self.nextPtr;
        uint256 len = _itemLength(ptr);
        self.nextPtr = ptr + len;

        return RLPItem(len, ptr);
    }
    
    /*
     * @dev Reads a list of RLP items.
     * @param self The RLPItem.
     * @return The list of RLPItems.
     */
    function readList(RLPItem memory self) internal pure returns (RLPItem[] memory) {
        require(isList(self));
        
        uint256 itemCount = 0;
        Iterator memory it = iterator(self);
        while(hasNext(it)){
            next(it);
            itemCount++;
        }
        
        RLPItem[] memory items = new RLPItem[](itemCount);
        it = iterator(self);
        uint256 idx = 0;
        while(hasNext(it)){
            items[idx] = next(it);
            idx++;
        }
        return items;
    }

    /*
     * @dev Returns true if the iteration has more elements.
     * @param self The iterator.
     * @return true if the iteration has more elements.
     */
    function hasNext(Iterator memory self) internal pure returns (bool) {
        RLPItem memory item = self.item;
        return self.nextPtr < item.memPtr + item.len;
    }

    /*
     * @dev To RLPItem.
     * @param item The RLPItem.
     * @return The RLPItem.
     */
    function toRlpItem(bytes memory item) internal pure returns (RLPItem memory) {
        uint256 memPtr;
        assembly {
            memPtr := add(item, 0x20)
        }

        return RLPItem(item.length, memPtr);
    }

    /*
     * @dev Create an iterator.
     * @param self The RLPItem.
     * @return An iterator.
     */
    function iterator(RLPItem memory self) internal pure returns (Iterator memory) {
        require(isList(self));

        uint256 ptr = self.memPtr + _payloadOffset(self.memPtr);
        return Iterator(self, ptr);
    }

    /*
     * @dev Return the RLP encoded bytes.
     * @param self The RLPItem.
     * @return The RLP encoded bytes.
     */
    function toBytes(RLPItem memory self) internal pure returns (bytes memory) {
        uint256 offset = _payloadOffset(self.memPtr);
        uint256 len = self.len - offset;
        uint256 memPtr = self.memPtr + offset;

        bytes memory copy = new bytes(len);
        assembly {
            let src := memPtr
            let dest := add(copy, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } {
                mstore(add(dest, i), mload(add(src, i)))
            }
        }
        return copy;
    }

    /*
     * @dev Decode a standard RLPItem.
     * @param self The RLPItem.
     * @return The decoded string.
     */
    function toBoolean(RLPItem memory self) internal pure returns (bool) {
        require(self.len == 1);
        uint256 result;
        uint256 memPtr = self.memPtr;
        assembly {
            result := byte(0, mload(memPtr))
        }
        return result > 0;
    }

    /*
     * @dev Decode an RLPItem into a uint256.
     * @param self The RLPItem.
     * @return The decoded uint256.
     */
    function toUint(RLPItem memory self) internal pure returns (uint256) {
        require(self.len <= 33);

        uint256 lenVal = _itemLength(self.memPtr);
        uint256 len = self.len;
        uint256 offset = _payloadOffset(self.memPtr);
        uint256 payloadLen = len - offset;
        uint256 memPtr = self.memPtr + offset;

        uint256 result;
        assembly {
            result := mload(memPtr)
            // shift to the correct location if payload is short
            if lt(payloadLen, 32) {
                result := div(result, exp(256, sub(32, payloadLen)))
            }
        }
        return result;
    }

    function toUintStrict(RLPItem memory self) internal pure returns (uint256) {
        return toUint(self);
    }

    /*
     * @dev Decode an RLPItem into a address.
     * @param self The RLPItem.
     * @return The decoded address.
     */
    function toAddress(RLPItem memory self) internal pure returns (address) {
        // 1 byte for the length prefix
        require(self.len == 21);
        return address(uint160(toUint(self)));
    }

    /*
     * @dev Decode an RLPItem into a bytes32.
     * @param self The RLPItem.
     * @return The decoded bytes32.
     */
    function toBytes32(RLPItem memory self) internal pure returns (bytes32) {
        return bytes32(toUint(self));
    }

    /*
     * @dev Create a string from an RLPItem.
     * @param self The RLPItem.
     * @return The decoded string.
     */
    function toString(RLPItem memory self) internal pure returns (string memory) {
        return string(toBytes(self));
    }

    /*
     * @dev Check if the RLPItem is a list.
     * @param self The RLPItem.
     * @return true if the item is a list.
     */
    function isList(RLPItem memory self) internal pure returns (bool) {
        if (self.len == 0) return false;

        uint256 memPtr = self.memPtr;
        uint256 typeId;
        assembly {
            typeId := byte(0, mload(memPtr))
        }

        return typeId >= LIST_SHORT_START;
    }

    /*
     * @dev Check if the RLPItem is NULL.
     * @param self The RLPItem.
     * @return true if the item is NULL.
     */
    function isNull(RLPItem memory self) internal pure returns (bool) {
        return self.len == 0;
    }

    /*
     * @dev Check if the RLPItem is an empty string.
     * @param self The RLPItem.
     * @return true if the item is an empty string.
     */
    function isEmpty(RLPItem memory self) internal pure returns (bool) {
        if (isNull(self)) {
            return false;
        }

        uint256 b0;
        uint256 memPtr = self.memPtr;
        assembly {
            b0 := byte(0, mload(memPtr))
        }
        return (self.len == 1 && b0 == 0x80) || (self.len == 5 && b0 == 0xb8 && _allZeros(memPtr + 1, 4));
    }

    function _allZeros(uint256 ptr, uint256 len) private pure returns (bool) {
        for (uint256 i = 0; i < len; i++) {
            uint256 b;
            assembly {
                b := byte(0, mload(add(ptr, i)))
            }
            if (b != 0) return false;
        }
        return true;
    }

    function itemLength(bytes memory item) internal pure returns (uint256) {
        uint256 memPtr;
        assembly {
            memPtr := add(item, 0x20)
        }
        return _itemLength(memPtr);
    }

    function _itemLength(uint256 memPtr) private pure returns (uint256) {
        uint256 itemLen;
        uint256 byte0;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < STRING_SHORT_START) {
            itemLen = 1;
        } else if (byte0 < STRING_LONG_START) {
            itemLen = byte0 - STRING_SHORT_START + 1;
        } else if (byte0 < LIST_SHORT_START) {
            assembly {
                let byteLen := sub(byte0, 0xb7) // STRING_LONG_START - 1
                let len := mload(add(memPtr, 1))
                // shift to the correct location if payload is short
                if lt(byteLen, 32) {
                    len := div(len, exp(256, sub(32, byteLen)))
                }
                itemLen := add(len, add(byteLen, 1))
            }
        } else if (byte0 < LIST_LONG_START) {
            itemLen = byte0 - LIST_SHORT_START + 1;
        } else {
            assembly {
                let byteLen := sub(byte0, 0xf7) // LIST_LONG_START - 1
                let len := mload(add(memPtr, 1))
                // shift to the correct location if payload is short
                if lt(byteLen, 32) {
                    len := div(len, exp(256, sub(32, byteLen)))
                }
                itemLen := add(len, add(byteLen, 1))
            }
        }

        return itemLen;
    }

    function _payloadOffset(uint256 memPtr) private pure returns (uint256) {
        uint256 byte0;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < STRING_SHORT_START) {
            return 0;
        } else if (byte0 < STRING_LONG_START) {
            return 1;
        } else if (byte0 < LIST_SHORT_START) {
            return byte0 - 0xb7 + 1; // STRING_LONG_START - 1
        } else if (byte0 < LIST_LONG_START) {
            return 1;
        } else {
            return byte0 - 0xf7 + 1; // LIST_LONG_START - 1
        }
    }
}
