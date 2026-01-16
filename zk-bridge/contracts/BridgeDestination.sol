// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

interface IVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[8] calldata input
    ) external view;
}

contract BridgeDestination is ERC20 {
    IVerifier public immutable verifier;
    bytes32 public trustedBlockRoot;
    
    mapping(bytes32 => bool) public processedTxs;

    event BridgeMinted(address recipient, uint256 amount, bytes32 txHash);
    // Debug event to inspect inputs being passed to verifier
    event DebugInputs(uint256[8] inputs);

    constructor(address _verifier, bytes32 _initialRoot) ERC20("Wrapped TEST", "WTEST") {
        verifier = IVerifier(_verifier);
        trustedBlockRoot = _initialRoot;
    }

    /**
     * @dev Mint WTEST tokens on Ethereum by providing a ZK proof of transaction inclusion on Cosmos.
     */
    function mint(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory commitments,
        uint256[2] memory commitmentPok,
        bytes32 root,
        bytes32 lockTxHash,
        address recipient,
        uint256 amount
    ) external {
        // 1. Ensure the root is trusted
        require(root == trustedBlockRoot, "Untrusted block root");

        // 2. Prevent double-spending
        require(!processedTxs[lockTxHash], "Transaction already processed");

        // 3. Pack Public Inputs
        uint256[8] memory packedInputs = getPackedInputs(root, lockTxHash);

        // Emit debug event BEFORE verifyProof to see what we calculated
        emit DebugInputs(packedInputs);

        // 4. Pack Proof for gnark Verifier (8 elements)
        uint256[8] memory proof;
        proof[0] = a[0];
        proof[1] = a[1];
        proof[2] = b[0][0];
        proof[3] = b[0][1];
        proof[4] = b[1][0];
        proof[5] = b[1][1];
        proof[6] = c[0];
        proof[7] = c[1];

        // 5. Call Verifier with commitments
        verifier.verifyProof(proof, commitments, commitmentPok, packedInputs);

        // 6. Mark as processed and mint WTEST tokens
        processedTxs[lockTxHash] = true;
        _mint(recipient, amount);
        
        emit BridgeMinted(recipient, amount, lockTxHash);
    }
    
    // View function to debug packing logic
    function getPackedInputs(bytes32 root, bytes32 lockTxHash) public pure returns (uint256[8] memory packedInputs) {
        // Pack Root (0..3)
        for (uint256 i = 0; i < 4; i++) {
            uint64 val = 0;
            for (uint256 j = 0; j < 8; j++) {
                val = (val << 8) | uint64(uint8(root[i * 8 + j]));
            }
            packedInputs[i] = uint256(val);
        }

        // Pack TxHash (4..7)
        for (uint256 i = 0; i < 4; i++) {
            uint64 val = 0;
            for (uint256 j = 0; j < 8; j++) {
                val = (val << 8) | uint64(uint8(lockTxHash[i * 8 + j]));
            }
            packedInputs[4 + i] = uint256(val);
        }
    }
    
    // Admin function to update trusted root for this POC version
    function updateTrustedRoot(bytes32 _newRoot) external {
        trustedBlockRoot = _newRoot;
    }
}
