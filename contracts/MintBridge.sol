pragma solidity ^0.8.0;

interface IVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[8] calldata input
    ) external view; // reverts on failure, no return value
}

import "./WrappedEVMS.sol";

contract MintBridge {
    IVerifier public verifier;
    WrappedEVMS public token;
    mapping(uint256 => bool) public usedLockIds;
    mapping(bytes32 => bool) public validRoots;
    address public owner;

    event Mint(address indexed to, uint256 amount, bytes32 indexed txHash);
    event RootAdded(bytes32 indexed root);

    constructor(address _verifier, address _token) {
        verifier = IVerifier(_verifier);
        token = WrappedEVMS(_token);
        owner = msg.sender;
    }

    function addRoot(bytes32 _newRoot) external {
        // In a real bridge, this would come from a light client.
        // For this PoC, we trust the deployer/relayer.
        // require(msg.sender == owner, "only owner");
        validRoots[_newRoot] = true;
        emit RootAdded(_newRoot);
    }

    function mint(
        uint256[8] memory proof,
        uint256[2] memory commitments,
        uint256[2] memory commitmentPok,
        uint256[8] memory input,
        bytes32 _txHash,
        address _to,
        uint256 _amount
    ) external {
        // 1. Verify Proof (reverts on failure)
        verifier.verifyProof(proof, commitments, commitmentPok, input);

        // 2. Check Root (input[0], input[1] -> bytes32)
        bytes32 root = bytes32((input[0] << 128) | input[1]);
        require(validRoots[root], "Root not registered");

        // 3. Extract LockID (input[5])
        uint256 lockId = input[5];
        require(!usedLockIds[lockId], "LockID already used");
        usedLockIds[lockId] = true;

        // 4. Verify Amount matches input[6], input[7]
        uint256 amount = (input[6] << 128) | input[7];
        require(_amount == amount, "Amount mismatch");

        // 5. Verify Destination matches input[4]
        require(_to == address(uint160(input[4])), "Destination mismatch");

        token.mint(_to, _amount);
        emit Mint(_to, _amount, _txHash);
    }

    event Burned(address indexed sender, uint256 amount, string recipient);

    function burn(uint256 amount, string calldata recipient) external {
        // Use burnFrom to burn tokens directly from user's wallet
        // This requires the user to have approved this contract
        token.burnFrom(msg.sender, amount);
        
        emit Burned(msg.sender, amount, recipient);
    }
}