// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "./lib/RLPReader.sol";
import "./lib/MerklePatriciaProofVerifier.sol";

contract BridgeSource is Ownable {
    using SafeERC20 for IERC20;
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    event Locked(address indexed token, address indexed sender, string recipient, uint256 amount, uint256 nonce);
    event Unlocked(address indexed recipient, uint256 amount);

    uint256 public nonce;
    mapping(uint256 => bytes32) public blockReceiptsRoot;
    mapping(bytes32 => bool) public processedUnlocks;
    address public bridgeDestinationAddress;

    constructor() Ownable(msg.sender) {}

    function setDestinationAddress(address _dest) public onlyOwner {
        bridgeDestinationAddress = _dest;
    }

    function lock(address token, uint256 amount, string calldata recipient) external payable {
        require(amount > 0, "Amount must be > 0");
        if (token == address(0)) {
            require(msg.value == amount, "ETH mismatch");
        } else {
            require(msg.value == 0, "No ETH expected");
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }
        nonce++;
        emit Locked(token, msg.sender, recipient, amount, nonce);
    }

    function submitHeader(bytes memory headerRlp) public {
        RLPReader.RLPItem[] memory items = headerRlp.toRlpItem().readList();
        require(items.length > 8, "Invalid Header RLP");
        // Eth Header: 5=ReceiptsRoot, 8=Number
        uint256 blockNum = items[8].toUint();
        bytes32 receiptsRoot = bytes32(items[5].toBytes());
        blockReceiptsRoot[blockNum] = receiptsRoot;
    }

    function unlock(bytes[] memory proof, bytes memory rawReceipt, uint64 blockNumber, bytes memory path) public {
        bytes32 root = blockReceiptsRoot[blockNumber];
        require(root != bytes32(0), "Block header not found");

        bytes memory value = MerklePatriciaProofVerifier.verify(root, path, proof);
        require(value.length > 0, "Invalid MPT Proof");
        
        // Handle Typed Receipt prefix
        if (rawReceipt.length > 0 && uint8(rawReceipt[0]) < 128) {
             bytes memory stripped = new bytes(rawReceipt.length - 1);
            for (uint i = 0; i < stripped.length; i++) {
                stripped[i] = rawReceipt[i + 1];
            }
            // Verify integrity of the FULL receipt against MPT value
            require(keccak256(value) == keccak256(rawReceipt), "Receipt mismatch");
            // Use stripped for decoding
            rawReceipt = stripped;
        } else {
            require(keccak256(value) == keccak256(rawReceipt), "Receipt mismatch");
        }

        RLPReader.RLPItem[] memory receiptItems = rawReceipt.toRlpItem().readList();
        RLPReader.RLPItem[] memory logs = receiptItems[3].readList();

        bool found = false;
        uint256 amount;
        address recipient;

        for (uint i = 0; i < logs.length; i++) {
            RLPReader.RLPItem[] memory logItems = logs[i].readList();
            if (logItems[0].toAddress() == bridgeDestinationAddress) {
                // Check event signature? For now trust address + data structure
                // Burned(address,uint256,address) -> data contains amount, recipient
                RLPReader.RLPItem[] memory topics = logItems[1].readList();
                if (topics.length >= 2) {
                    // indexed sender is topics[1]
                    bytes memory data = logItems[2].toBytes();
                    (amount, recipient) = abi.decode(data, (uint256, address));
                    found = true;
                    break;
                }
            }
        }
        require(found, "Burn log not found");

        bytes32 unlockId = keccak256(abi.encodePacked(blockNumber, path));
        require(!processedUnlocks[unlockId], "Unlock already processed");
        processedUnlocks[unlockId] = true;

        payable(recipient).transfer(amount);
        emit Unlocked(recipient, amount);
    }
}
