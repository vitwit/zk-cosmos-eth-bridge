// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BridgeSource {
    event Lock(
        address indexed sender,
        uint256 amount,
        address ethDestination,
        uint256 nonce
    );

    struct LockDetails {
        address sender;
        uint256 amount;
        address ethDestination;
        uint256 nonce;
    }

    mapping(uint256 => LockDetails) public locks;
    uint256 public nextNonce;

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

    function getLockDetails(uint256 nonce) external view returns (
        address sender,
        uint256 amount,
        address ethDestination
    ) {
        LockDetails storage details = locks[nonce];
        return (details.sender, details.amount, details.ethDestination);
    }
}
