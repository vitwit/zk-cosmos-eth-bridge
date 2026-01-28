// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./lib/RLPReader.sol";
import "./lib/MerklePatriciaProofVerifier.sol";

contract CosmosLock {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    // Event emitted when a lock occurs
    event Lock(
        uint256 indexed lockId,          // Unique ID for this lock
        address indexed sender,          // Who sent the ETH
        uint256 amount,                  // How much ETH was locked
        address indexed ethDestination   // Destination address on the other chain
    );

    event Unlocked(address indexed recipient, uint256 amount);

    uint256 private _lockCounter;        // Counter to generate unique lock IDs
    
    // MPT Verification State
    mapping(uint256 => bytes32) public blockReceiptRoots;
    mapping(bytes32 => bool) public processedUnlocks;
    address public mintBridgeAddress; // Address of MintBridge on Ethereum

    function setMintBridgeAddress(address _addr) external {
        mintBridgeAddress = _addr;
    }

    function lock(address ethDestination) external payable {
        require(msg.value > 0, "Amount must be greater than 0");
        _lockCounter++;
        emit Lock(_lockCounter, msg.sender, msg.value, ethDestination);
    }

    function currentLockId() external view returns (uint256) {
        return _lockCounter;
    }

    // --- MPT Verification Logic ---

    function submitHeader(bytes memory headerRlp) public {
        RLPReader.RLPItem[] memory items = headerRlp.toRlpItem().readList();
        require(items.length > 8, "Invalid Header RLP");
        // Eth Header: 5=ReceiptsRoot, 8=Number
        uint256 blockNum = items[8].toUint();
        bytes32 receiptsRoot = bytes32(items[5].toBytes());
        blockReceiptRoots[blockNum] = receiptsRoot;
    }

    function unlock(bytes[] memory proof, bytes memory rawReceipt, uint64 blockNumber, bytes memory path) public {
        bytes32 root = blockReceiptRoots[blockNumber];
        require(root != bytes32(0), "Block header not found");

        bytes memory value = MerklePatriciaProofVerifier.verify(root, path, proof);
        require(value.length > 0, "Invalid MPT Proof");
        
        // Handle EIP-2718 Typed Receipt
        if (rawReceipt.length > 0 && uint8(rawReceipt[0]) < 128) {
             bytes memory stripped = new bytes(rawReceipt.length - 1);
            for (uint i = 0; i < stripped.length; i++) {
                stripped[i] = rawReceipt[i + 1];
            }
            require(keccak256(value) == keccak256(rawReceipt), "Receipt mismatch");
            rawReceipt = stripped;
        } else {
            require(keccak256(value) == keccak256(rawReceipt), "Receipt mismatch");
        }

        RLPReader.RLPItem[] memory receiptItems = rawReceipt.toRlpItem().readList();
        // [status, cumGas, bloom, logs]
        require(receiptItems.length >= 4, "Invalid Receipt");
        RLPReader.RLPItem[] memory logs = receiptItems[3].readList();

        bool found = false;
        uint256 amount;
        address recipient; // The cosmos recipient string parsed to address? 
                           // Wait, MintBridge emits `string recipient`.
                           // If we sent "0x..." string, we can parse it to address.
                           // Since validation on Evmos requires address for transfer.

        for (uint i = 0; i < logs.length; i++) {
            RLPReader.RLPItem[] memory logItems = logs[i].readList();
            if (logItems[0].toAddress() == mintBridgeAddress) {
                // Burned(address indexed sender, uint256 amount, string recipient)
                // Topic0: Sig, Topic1: Sender
                RLPReader.RLPItem[] memory topics = logItems[1].readList();
                if (topics.length >= 2) {
                    bytes memory data = logItems[2].toBytes();
                    // data: amount (32), recipient (string)
                    string memory recipientStr;
                    (amount, recipientStr) = abi.decode(data, (uint256, string));
                    
                    // Parse string to address
                    recipient = parseAddress(recipientStr);
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

    function parseAddress(string memory s) internal pure returns (address) {
        bytes memory b = bytes(s);
        uint result = 0;
        for (uint i = 0; i < b.length; i++) {
            uint8 c = uint8(b[i]);
            if (c >= 48 && c <= 57) { result = result * 16 + (c - 48); }
            else if(c >= 65 && c <= 70) { result = result * 16 + (c - 55); }
            else if(c >= 97 && c <= 102) { result = result * 16 + (c - 87); }
        }
        return address(uint160(result));
    }
}
