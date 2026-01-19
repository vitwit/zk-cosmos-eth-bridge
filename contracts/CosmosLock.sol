// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CosmosLock {
    // Event emitted when a lock occurs
    event Lock(
        uint256 indexed lockId,          // Unique ID for this lock
        address indexed sender,          // Who sent the ETH
        uint256 amount,                  // How much ETH was locked
        address indexed ethDestination   // Destination address on the other chain
    );

    uint256 private _lockCounter;        // Counter to generate unique lock IDs

    function lock(address ethDestination) external payable {
        require(msg.value > 0, "Amount must be greater than 0");

        // Increment lock ID counter
        _lockCounter++;

        // Emit the event
        emit Lock(_lockCounter, msg.sender, msg.value, ethDestination);
    }

    // Optional: view function to see current lock ID
    function currentLockId() external view returns (uint256) {
        return _lockCounter;
    }
}
