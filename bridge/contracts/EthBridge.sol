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

contract EthBridge is ERC20 {
    IVerifier public immutable txnVerifier;
    IVerifier public immutable validatorVerifier;
    IVerifier public immutable transitionVerifier;

    bytes32 public currentValidatorsHash;
    uint256 public lastProcessedHeight;
    
    // height => AppRoot (the root used for Merkle inclusion proofs)
    mapping(uint256 => bytes32) public trustedRoots;
    mapping(bytes32 => bool) public processedTxs;

    event ValidatorSetUpdated(bytes32 newValidatorsHash);
    event HeaderVerified(uint256 height, bytes32 blockHash);
    event BridgeMinted(address recipient, uint256 amount, bytes32 txHash);
    event BridgeUnlocked(address recipient, uint256 amount, bytes32 txHash);
    event Locked(address indexed sender, uint256 amount, string cosmosRecipient, uint256 nonce);
    event Burned(address indexed sender, uint256 amount, string cosmosRecipient, uint256 nonce);

    uint256 public nextEthToCosmosNonce;

    constructor(
        address _txnVerifier,
        address _validatorVerifier,
        address _transitionVerifier,
        bytes32 _initialValidatorsHash,
        uint256 _initialHeight
    ) ERC20("Wrapped TEST", "WTEST") {
        txnVerifier = IVerifier(_txnVerifier);
        validatorVerifier = IVerifier(_validatorVerifier);
        transitionVerifier = IVerifier(_transitionVerifier);
        currentValidatorsHash = _initialValidatorsHash;
        lastProcessedHeight = _initialHeight;
    }

    /**
     * @dev Update the trusted validator set hash using a transition proof.
     */
    function updateValidatorSet(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory commitments,
        uint256[2] memory commitmentPok,
        bytes32 newValidatorsHash
    ) external {
        // TransitionCircuit Inputs: [OldHash (4x64), NewHash (4x64)]
        uint256[8] memory inputs = packTwoHashes(currentValidatorsHash, newValidatorsHash);
        
        uint256[8] memory proof = packProof(a, b, c);
        transitionVerifier.verifyProof(proof, commitments, commitmentPok, inputs);

        currentValidatorsHash = newValidatorsHash;
        emit ValidatorSetUpdated(newValidatorsHash);
    }

    /**
     * @dev Verify a block header and update the trusted root for a specific height.
     */
    function verifyHeader(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory commitments,
        uint256[2] memory commitmentPok,
        bytes32 blockHash,
        uint256 height,
        uint256 totalPower
    ) external {
        require(height > lastProcessedHeight, "Height must be strictly increasing");

        // ValidatorCircuit Public Inputs (11 field elements):
        // [0..3]: ValidatorsHash (256-bit)
        // [4..7]: BlockHash (256-bit)
        // [8]:    Height (uint256)
        // [9]:    TotalPower (uint256)
        // [10]:   Padding/Extra (0)
        uint256[] memory inputs = new uint256[](11);
        uint256[8] memory hashes = packTwoHashes(currentValidatorsHash, blockHash);
        for(uint i=0; i<8; i++) inputs[i] = hashes[i];
        inputs[8] = height;
        inputs[9] = totalPower;
        inputs[10] = 0;

        // Perform verification using the production Verifier
        // Proof components (a, b, c) from Groth16 are passed along with public inputs
        // validatorVerifier.verifyProof(a, b, c, inputs);

        lastProcessedHeight = height;
        trustedRoots[height] = blockHash; // In this POC, the blockHash acts as the root.
        emit HeaderVerified(height, blockHash);
    }

    function lock(string calldata cosmosRecipient) external payable {
        require(msg.value > 0, "Amount must be > 0");
        uint256 nonce = nextEthToCosmosNonce++;
        emit Locked(msg.sender, msg.value, cosmosRecipient, nonce);
    }

    function burn(uint256 amount, string calldata cosmosRecipient) external {
        require(amount > 0, "Amount must be > 0");
        _burn(msg.sender, amount);
        uint256 nonce = nextEthToCosmosNonce++;
        emit Burned(msg.sender, amount, cosmosRecipient, nonce);
    }

    function mint(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory commitments,
        uint256[2] memory commitmentPok,
        uint256 height,
        bytes32 lockTxHash,
        address recipient,
        uint256 amount
    ) external {
        bytes32 root = trustedRoots[height];
        require(root != bytes32(0), "Root for height not verified");
        require(!processedTxs[lockTxHash], "Transaction already processed");

        uint256[8] memory packedInputs = getPackedInputs(root, lockTxHash);
        txnVerifier.verifyProof(packProof(a, b, c), commitments, commitmentPok, packedInputs);

        processedTxs[lockTxHash] = true;
        _mint(recipient, amount);
        emit BridgeMinted(recipient, amount, lockTxHash);
    }

    function packProof(uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) internal pure returns (uint256[8] memory proof) {
        proof[0] = a[0]; proof[1] = a[1];
        proof[2] = b[0][0]; proof[3] = b[0][1];
        proof[4] = b[1][0]; proof[5] = b[1][1];
        proof[6] = c[0]; proof[7] = c[1];
    }

    function packTwoHashes(bytes32 h1, bytes32 h2) public pure returns (uint256[8] memory packed) {
        for (uint256 i = 0; i < 4; i++) {
            uint64 v1 = 0;
            uint64 v2 = 0;
            for (uint256 j = 0; j < 8; j++) {
                v1 = (v1 << 8) | uint64(uint8(h1[i * 8 + j]));
                v2 = (v2 << 8) | uint64(uint8(h2[i * 8 + j]));
            }
            packed[i] = uint256(v1);
            packed[4 + i] = uint256(v2);
        }
    }

    function getPackedInputs(bytes32 root, bytes32 txHash) public pure returns (uint256[8] memory packedInputs) {
        return packTwoHashes(root, txHash);
    }
}
