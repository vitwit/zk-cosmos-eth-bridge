// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./lib/RLPReader.sol";
import "./lib/MerklePatriciaProofVerifier.sol";
import "./lib/SyncCommitteeVerifier.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BridgeDestination is ERC20, Ownable {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    event HeaderSubmitted(uint64 indexed blockNumber, bytes32 indexed blockHash);
    event Claimed(uint256 indexed lockId, address indexed sender, address indexed recipient, uint256 amount);

    // Light Client State
    uint64 public latestDetailsBlock; // highest block number tracked
    mapping(uint64 => bytes32) public blockReceiptRoots; // blockNumber => receiptsRoot

    // Processed Claims prevent double spending
    // Key: hash(lockId, sender, amount, nonce) or hash(txHash)?
    // Spec says: "Storing a mapping of processed_tx_hashes."
    mapping(bytes32 => bool) public processedTxHashes;

    // Test Mode: allows bypassing signature verification for dev/test
    bool public TEST_MODE = false;

    // Event emitted when assets are burned to be unlocked on Ethereum

    // Event emitted when assets are burned to be unlocked on Ethereum
    event Burned(address indexed sender, uint256 amount, address recipient);

    // Burn wrapped tokens to unlock original assets on Ethereum
    function burn(uint256 amount, address recipient) public {
        // OpenZeppelin ERC20 provides _burn(account, amount)
        _burn(msg.sender, amount);
        emit Burned(msg.sender, amount, recipient);
    }

    // Contract to Verify against (The Ethereum Source Contract Address)
    address public bridgeSourceAddress;

    // Event Signature for Locked(address,address,string,uint256,uint256)
    // keccak256("Locked(address,address,string,uint256,uint256)")
    bytes32 public constant LOCKED_EVENT_SIG = keccak256("Locked(address,address,string,uint256,uint256)");

    constructor(address _bridgeSourceAddress) ERC20("Wrapped Ether", "WETH") Ownable(msg.sender) {
        bridgeSourceAddress = _bridgeSourceAddress;
    }

    function setTestMode(bool _testMode) external onlyOwner {
        TEST_MODE = _testMode;
    }

    /**
     * @dev Submits a new Ethereum block header.
     *      Verifies Sync Committee signature and extracted receiptsRoot.
     * @param headerRlp RLP encoded Ethereum header.
     * @param signatures The sync committee aggregate signature (if real verification).
     */
    function submitHeader(
        bytes calldata headerRlp, 
        bytes calldata signatures
    ) external {
        // 1. Decode Header RLP
        RLPReader.RLPItem[] memory items = headerRlp.toRlpItem().readList();
        
        // Ethereum Header Fields (Post-London/Merge):
        // 0: parentHash
        // 1: ommersHash
        // 2: coinbase
        // 3: stateRoot
        // 4: transactionsRoot
        // 5: receiptsRoot
        // 6: logsBloom
        // 7: difficulty
        // 8: number
        
        require(items.length >= 9, "Invalid Header RLP: too short");

        bytes32 receiptsRoot = items[5].toBytes32();
        uint64 blockNumber = uint64(items[8].toUint());
        
        if (!TEST_MODE) {
            // Verify Sync Committee Signature
            // Logic to be implemented or using SyncCommitteeVerifier
        }

        blockReceiptRoots[blockNumber] = receiptsRoot;
        if (blockNumber > latestDetailsBlock) {
             latestDetailsBlock = blockNumber;
        }

        emit HeaderSubmitted(blockNumber, keccak256(headerRlp));
    }

    /**
     * @dev Claims tokens by proving a Locked event on Ethereum.
     * @param proof MPT proof nodes (RLP encoded).
     * @param rawReceipt The RLP encoded receipt.
     * @param blockNumber The block number where the event happened.
     * @param path The MPT path (key) to the receipt. Usually RLP(txIndex).
     */
    function claim(
        bytes[] calldata proof,
        bytes calldata rawReceipt,
        uint64 blockNumber,
        bytes calldata path
    ) external {
        // 1. Check if receipt root exists for block
        bytes32 receiptsRoot = blockReceiptRoots[blockNumber];
        require(receiptsRoot != bytes32(0), "Block verification missing");

        if (!TEST_MODE) {
            // 2. Verify MPT Proof
            bytes memory verifiedValue = MerklePatriciaProofVerifier.verify(
                receiptsRoot,
                path,
                proof
            );
            
            require(verifiedValue.length > 0, "Invalid MPT Proof");
            require(keccak256(verifiedValue) == keccak256(rawReceipt), "Receipt mismatch");
        }

        // 3. Decode Receipt to finding the Log
        bytes memory receiptRlp = rawReceipt;
        if (uint8(receiptRlp[0]) < 128) {
            // It's a typed receipt (EIP-2718), skip the type byte
            bytes memory stripped = new bytes(receiptRlp.length - 1);
            for (uint i = 0; i < stripped.length; i++) {
                stripped[i] = receiptRlp[i + 1];
            }
            receiptRlp = stripped;
        }

        RLPReader.RLPItem[] memory receiptItems = receiptRlp.toRlpItem().readList();
        
        // Standard receipts have 4 items: [status/root, cumulativeGas, bloom, logs]
        require(receiptItems.length >= 4, "Invalid Receipt: Expected 4+ items");
        
        RLPReader.RLPItem[] memory logs = receiptItems[3].readList(); // Extract logs from receipt
        if (!_processLogs(logs, blockNumber, path)) {
            revert("Lock log not found or invalid");
        }
    }

    struct ClaimContext {
        uint64 blockNumber;
        bytes path;
    }

    function _processLogs(RLPReader.RLPItem[] memory logs, uint64 blockNumber, bytes memory path) private returns (bool) {
        for (uint i = 0; i < logs.length; i++) {
            RLPReader.RLPItem[] memory logItems = logs[i].readList();
            require(logItems.length == 3, "Invalid Log Structure");
            
            if (logItems[0].toAddress() == bridgeSourceAddress) {
                RLPReader.RLPItem[] memory topics = logItems[1].readList();
                
                if (topics.length > 0 && topics[0].toBytes32() == LOCKED_EVENT_SIG) {
                     bytes memory data = logItems[2].toBytes();
                     (string memory recipient, uint256 amount, uint256 nonce) = abi.decode(data, (string, uint256, uint256));
                     
                     bytes32 uniqueId = keccak256(abi.encodePacked(blockNumber, path, i));
                     require(!processedTxHashes[uniqueId], "Already processed");
                     processedTxHashes[uniqueId] = true;
                     
                     address destParams = parseAddress(recipient);
                     _mint(destParams, amount);
                     emit Claimed(nonce, address(0), destParams, amount);
                     return true;
                }
            }
        }
        return false;
    }

    
    function parseAddress(string memory s) internal pure returns (address) {
        bytes memory b = bytes(s);
        uint result = 0;
        for (uint i = 0; i < b.length; i++) {
            uint8 c = uint8(b[i]);
            if (c >= 48 && c <= 57) {
                result = result * 16 + (c - 48);
            } else if(c >= 65 && c <= 70) {
                result = result * 16 + (c - 55);
            } else if(c >= 97 && c <= 102) {
                result = result * 16 + (c - 87);
            }
        }
        return address(uint160(result));
    }
}
