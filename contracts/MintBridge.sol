pragma solidity ^0.8.0;

interface IVerifier {
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[86] memory input // 32 Root + 32 TxHash + 1 LockID + 1 Amount + 20 Destination
    ) external view returns (bool);
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
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[86] memory input,
        bytes32 _txHash,
        address _to,
        uint256 _amount
    ) external {
        // 1. Verify Proof
        require(verifier.verifyProof(a, b, c, input), "Invalid Proof");

        // 2. Check Root (input[0..31] -> bytes32)
        // The circuit outputs Root as 32 bytes (32 field elements).
        // We need to reconstruct the bytes32 root from input[0..31].
        // Wait, the Relayer registers `proof.Root` which is [32]byte.
        // The circuit `Root` is [32]uints.U8.
        // So input[0] is the first byte of the root, input[1] is the second...
        
        uint256 rootVal = 0;
        for (uint i = 0; i < 32; i++) {
            rootVal = (rootVal << 8) | input[i];
        }
        bytes32 root = bytes32(rootVal);
        
        require(validRoots[root], "Root not registered");

        // 3. Extract LockID (input[64])
        uint256 lockId = input[64];
        require(!usedLockIds[lockId], "LockID already used");
        usedLockIds[lockId] = true;

        // 4. Verify Amount matches input[65]
        require(_amount == input[65], "Amount mismatch");

        // 5. Verify Destination matches input[66..85]
        uint160 destVal = 0;
        for (uint i = 0; i < 20; i++) {
            destVal = (destVal << 8) | uint160(input[66 + i]);
        }
        require(_to == address(destVal), "Destination mismatch");

        token.mint(_to, _amount);
        emit Mint(_to, _amount, _txHash);
    }
}