// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./LibMPT.sol";
import "./RLPReader.sol";

contract CosmosBridge is ERC20 {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for RLPReader.Iterator;
    using RLPReader for bytes;

    event Lock(
        address indexed sender,
        uint256 amount,
        address ethDestination,
        uint256 nonce
    );

    event BridgeMinted(address recipient, uint256 amount, bytes32 ethTxHash);
    event BridgeUnlocked(address recipient, uint256 amount, bytes32 ethTxHash);
    event Burn(address indexed sender, uint256 amount, address ethDestination, uint256 nonce);

    // Event hashes from EthBridge on Ethereum
    bytes32 constant ETH_LOCKED_TOPIC = keccak256("Locked(address,uint256,string,uint256)");
    bytes32 constant ETH_BURNED_TOPIC = keccak256("Burned(address,uint256,string,uint256)");

    struct LockDetails {
        address sender;
        uint256 amount;
        address ethDestination;
        uint256 nonce;
    }

    mapping(uint256 => LockDetails) public locks;
    uint256 public nextNonce;
    
    mapping(bytes32 => bool) public processedEthTxs;
    bytes32 public trustedEthReceiptRoot;
    address public ethBridgeSource;

    constructor(address _ethBridgeSource) ERC20("Wrapped ETH", "WETH") {
        ethBridgeSource = _ethBridgeSource;
    }

    function lock(address ethDestination) external payable {
        require(msg.value > 0, "Amount must be > 0");
        
        uint256 currentNonce = nextNonce;
        locks[currentNonce] = LockDetails({
            sender: msg.sender,
            amount: msg.value,
            ethDestination: ethDestination,
            nonce: currentNonce
        });

        emit Lock(msg.sender, msg.value, ethDestination, currentNonce);
        nextNonce++;
    }

    function burn(uint256 amount, address ethDestination) external {
        require(amount > 0, "Amount must be > 0");
        _burn(msg.sender, amount);
        
        uint256 currentNonce = nextNonce++;
        emit Burn(msg.sender, amount, ethDestination, currentNonce);
    }

    /**
     * @dev Mint WETH tokens on Cosmos based on Ethereum Lock event.
     */
    function mint(
        address recipient,
        uint256 amount,
        bytes32 ethTxHash,
        bytes memory key,
        bytes[] memory mptProof
    ) external {
        require(!processedEthTxs[ethTxHash], "Tx already processed");
        
        // 1. Verify MPT Inclusion Proof
        bytes memory receiptRaw = LibMPT.verifyMPTProof(trustedEthReceiptRoot, mptProof, key);
        
        // 2. Parse Receipt and Verify Event
        _verifyEthereumEvent(receiptRaw, ethBridgeSource, ETH_LOCKED_TOPIC, recipient, amount);

        processedEthTxs[ethTxHash] = true;
        _mint(recipient, amount);
        emit BridgeMinted(recipient, amount, ethTxHash);
    }

    /**
     * @dev Unlock native tokens on Cosmos based on Ethereum Burn event.
     */
    function unlock(
        address payable recipient,
        uint256 amount,
        bytes32 ethTxHash,
        bytes memory key,
        bytes[] memory mptProof
    ) external {
        require(!processedEthTxs[ethTxHash], "Tx already processed");
        require(address(this).balance >= amount, "Insufficient balance in vault");

        // 1. Verify MPT Inclusion Proof
        bytes memory receiptRaw = LibMPT.verifyMPTProof(trustedEthReceiptRoot, mptProof, key);
        
        // 2. Parse Receipt and Verify Event
        _verifyEthereumEvent(receiptRaw, ethBridgeSource, ETH_BURNED_TOPIC, recipient, amount);

        processedEthTxs[ethTxHash] = true;
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        emit BridgeUnlocked(recipient, amount, ethTxHash);
    }

    function _verifyEthereumEvent(
        bytes memory receiptRaw,
        address expectedEmitter,
        bytes32 expectedTopic,
        address /* expectedRecipient */,
        uint256 expectedAmount
    ) internal pure {
        bytes memory rlpReceipt = receiptRaw;
        // EIP-2718 Typed Receipts start with a byte < 0x80 (the type).
        // RLP lists start with 0xc0 or higher.
        if (uint8(receiptRaw[0]) < 0x80) {
            rlpReceipt = new bytes(receiptRaw.length - 1);
            for (uint256 i = 0; i < rlpReceipt.length; i++) {
                rlpReceipt[i] = receiptRaw[i+1];
            }
        }

        RLPReader.RLPItem[] memory receipt = rlpReceipt.toRlpItem().toList();
        // Receipt: [status, cumulativeGas, logsBloom, logs]
        RLPReader.RLPItem[] memory logs = receipt[3].toList();

        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            RLPReader.RLPItem[] memory log = logs[i].toList();
            // Log: [address, topics, data]
            address emitter = log[0].toAddress();
            RLPReader.RLPItem[] memory topics = log[1].toList();
            
            if (emitter == expectedEmitter && topics.length > 0 && topics[0].toBytes32() == expectedTopic) {
                bytes memory data = log[2].toBytes();
                uint256 amount;
                assembly {
                    amount := mload(add(data, 32))
                }
                
                require(amount == expectedAmount, "Amount mismatch in event");
                found = true;
                break;
            }
        }
        require(found, "Valid bridge event not found in receipt");
    }

    function updateTrustedEthRoot(bytes32 _newRoot) external {
        trustedEthReceiptRoot = _newRoot;
    }

    function getLockDetails(uint256 nonce) external view returns (
        address sender,
        uint256 amount,
        address ethDestination
    ) {
        LockDetails storage details = locks[nonce];
        return (details.sender, details.amount, details.ethDestination);
    }
}
