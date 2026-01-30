// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RLPReader
 * @dev A simple and efficient RLP decoding library for Solidity.
 */
library RLPReader {
    uint8 constant STRING_SHORT_START = 0x80;
    uint8 constant STRING_LONG_START = 0xb8;
    uint8 constant LIST_SHORT_START = 0xc0;
    uint8 constant LIST_LONG_START = 0xf8;

    struct RLPItem {
        uint256 len;
        uint256 memPtr;
    }

    struct Iterator {
        RLPItem item; // List item being iterated
        uint256 nextPtr; // Position of the next item in the list
    }

    /*
     * @dev Returns an RLPItem from a bytes RLP-encoded input.
     */
    function toRlpItem(bytes memory item) internal pure returns (RLPItem memory) {
        uint256 memPtr;
        assembly {
            memPtr := add(item, 0x20)
        }
        return RLPItem(item.length, memPtr);
    }

    /*
     * @dev Returns an iterator for an RLP list.
     */
    function iterator(RLPItem memory item) internal pure returns (Iterator memory) {
        require(isList(item), "RLPReader: Item is not a list");
        uint256 ptr = item.memPtr + _payloadOffset(item.memPtr);
        return Iterator(item, ptr);
    }

    /*
     * @dev Returns whether the next item exists in the iterator.
     */
    function hasNext(Iterator memory it) internal pure returns (bool) {
        return it.nextPtr < it.item.memPtr + it.item.len;
    }

    /*
     * @dev Moves the iterator to the next item and returns it.
     */
    function next(Iterator memory it) internal pure returns (RLPItem memory) {
        require(hasNext(it), "RLPReader: Iteration out of bounds");
        uint256 ptr = it.nextPtr;
        uint256 len = _itemLength(ptr);
        it.nextPtr = ptr + len;
        return RLPItem(len, ptr);
    }

    /*
     * @dev Returns the number of items in an RLP list.
     */
    function numItems(RLPItem memory item) internal pure returns (uint256) {
        if (!isList(item)) return 0;
        uint256 count = 0;
        Iterator memory it = iterator(item);
        while (hasNext(it)) {
            next(it);
            count++;
        }
        return count;
    }

    /*
     * @dev Returns the RLPItem at the specified index in a list.
     */
    function at(RLPItem memory item, uint256 index) internal pure returns (RLPItem memory) {
        require(isList(item), "RLPReader: Item is not a list");
        Iterator memory it = iterator(item);
        uint256 i = 0;
        while (hasNext(it)) {
            RLPItem memory itItem = next(it);
            if (i == index) return itItem;
            i++;
        }
        revert("RLPReader: Index out of bounds");
    }

    /*
     * @dev Decodes an RLPItem to bytes.
     */
    function toBytes(RLPItem memory item) internal pure returns (bytes memory) {
        uint256 len = _payloadLength(item.memPtr);
        uint256 offset = _payloadOffset(item.memPtr);
        bytes memory result = new bytes(len);
        uint256 destPtr;
        assembly {
            destPtr := add(result, 0x20)
        }
        _copy(item.memPtr + offset, destPtr, len);
        return result;
    }

    /*
     * @dev Decodes an RLPItem to an address.
     */
    function toAddress(RLPItem memory item) internal pure returns (address) {
        require(!isList(item), "RLPReader: Expected string item for address");
        bytes memory b = toBytes(item);
        require(b.length == 20, "RLPReader: Invalid address length");
        address result;
        assembly {
            result := div(mload(add(b, 32)), exp(256, 12))
        }
        return result;
    }

    /*
     * @dev Decodes an RLPItem to a uint256.
     */
    function toUint(RLPItem memory item) internal pure returns (uint256) {
        require(!isList(item), "RLPReader: Expected string item for uint");
        uint256 offset = _payloadOffset(item.memPtr);
        uint256 len = _payloadLength(item.memPtr);
        require(len <= 32, "RLPReader: uint too long");
        
        uint256 result = 0;
        uint256 ptr = item.memPtr + offset;
        for (uint256 i = 0; i < len; i++) {
            uint8 b = _getByte(ptr + i);
            result = result * 256 + uint256(b);
        }
        return result;
    }

    /*
     * @dev Returns true if the RLPItem is a list.
     */
    function isList(RLPItem memory item) internal pure returns (bool) {
        if (item.len == 0) return false;
        uint8 b = _getByte(item.memPtr);
        return b >= LIST_SHORT_START;
    }

    /*
     * @dev Returns an array of RLPItems from an RLP list.
     */
    function toList(RLPItem memory item) internal pure returns (RLPItem[] memory) {
        uint256 count = numItems(item);
        RLPItem[] memory result = new RLPItem[](count);
        Iterator memory it = iterator(item);
        uint256 i = 0;
        while (hasNext(it)) {
            result[i] = next(it);
            i++;
        }
        return result;
    }

    /*
     * @dev Decodes an RLPItem to a bytes32.
     */
    function toBytes32(RLPItem memory item) internal pure returns (bytes32) {
        return bytes32(toUint(item));
    }

    // --- Private Helpers ---

    function _payloadOffset(uint256 memPtr) private pure returns (uint256) {
        uint8 b = _getByte(memPtr);
        if (b < 0x80) return 0;
        if (b < 0xb8) return 1;
        if (b < 0xc0) return 1 + (b - 0xb7);
        if (b < 0xf8) return 1;
        return 1 + (b - 0xf7);
    }

    function _payloadLength(uint256 memPtr) private pure returns (uint256) {
        uint8 b = _getByte(memPtr);
        if (b < 0x80) return 1;
        if (b < 0xb8) return b - 0x80;
        if (b < 0xc0) return _readLength(memPtr, b - 0xb7);
        if (b < 0xf8) return b - 0xc0;
        return _readLength(memPtr, b - 0xf7);
    }

    function _itemLength(uint256 memPtr) private pure returns (uint256) {
        uint8 b = _getByte(memPtr);
        if (b < 0x80) return 1;
        if (b < 0xb8) return b - 0x80 + 1;
        if (b < 0xc0) return 1 + (b - 0xb7) + _readLength(memPtr, b - 0xb7);
        if (b < 0xf8) return b - 0xc0 + 1;
        return 1 + (b - 0xf7) + _readLength(memPtr, b - 0xf7);
    }

    function _readLength(uint256 memPtr, uint8 lenOfLen) private pure returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < lenOfLen; i++) {
            result = result * 256 + uint256(_getByte(memPtr + 1 + i));
        }
        return result;
    }

    function _getByte(uint256 memPtr) private pure returns (uint8) {
        uint8 b;
        assembly {
            b := byte(0, mload(memPtr))
        }
        return b;
    }

    function _copy(uint256 src, uint256 dest, uint256 len) private pure {
        if (len == 0) return;
        assembly {
            for { let i := 0 } lt(i, len) { i := add(i, 32) } {
                mstore(add(dest, i), mload(add(src, i)))
            }
        }
    }
}
