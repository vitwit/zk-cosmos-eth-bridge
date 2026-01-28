// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

library BLS {
    // EIP-2537 Precompile Addresses (Proposed)
    // Note: These might vary on different chains implementing standard vs proprietary.
    // Cosmos EVM v0.4.1 typically follows strict EIP-2537.
    address constant BLS12_G1ADD = address(0x0a);
    address constant BLS12_G1MUL = address(0x0b);
    address constant BLS12_G1MULTIEXP = address(0x0c);
    address constant BLS12_G2ADD = address(0x0d);
    address constant BLS12_G2MUL = address(0x0e);
    address constant BLS12_G2MULTIEXP = address(0x0f);
    address constant BLS12_PAIRING_CHECK = address(0x10);
    address constant BLS12_MAP_FP_TO_G1 = address(0x11);
    address constant BLS12_MAP_FP2_TO_G2 = address(0x12);

    // Errors
    error BLS_G1AddFailed();
    error BLS_PairingCheckFailed();

    /**
     * @dev Aggregates a list of G1 points.
     * @param points List of G1 points (flattened: x, y). 64 bytes each check? No, 128 bytes (2 * 32? No, BLS12-381 is 48 bytes compressed, 96 uncompressed? No).
     * EIP-2537 G1 points are 128 bytes (X: 64, Y: 64) in the call? 
     * Actually field modulus is 381 bits (< 384 bits = 48 bytes).
     * Usually encoded as 64 bytes for alignment in EVM (top bits zero).
     * X: 48 bytes, Y: 48 bytes.
     * EIP-2537 Input format for G1 user input: 128 bytes (64 bytes X, 64 bytes Y).
     */
    function aggregateG1(bytes[] memory points) internal view returns (bytes memory) {
        if (points.length == 0) {
            return new bytes(128); // Infinity?
        }
        
        // We can use G1MULTIEXP or just loop G1ADD
        // G1ADD loop:
        bytes memory result = points[0];
        for (uint i = 1; i < points.length; i++) {
            (bool success, bytes memory ret) = BLS12_G1ADD.staticcall(abi.encodePacked(result, points[i]));
            if (!success) revert BLS_G1AddFailed();
            result = ret;
        }
        return result;
    }

    /**
     * @dev Checks the pairing of (A1, B1) and (A2, B2).
     * e(A1, B1) * e(A2, B2) == 1?
     * @param a1 G1 point
     * @param b1 G2 point
     * @param a2 G1 point
     * @param b2 G2 point
     */
    function verifyPairing(
        bytes memory a1, bytes memory b1,
        bytes memory a2, bytes memory b2
    ) internal view returns (bool) {
        // Pairing check takes list of (G1, G2) pairs.
        // G1 is 128 bytes. G2 is 256 bytes (4 * 64).
        // Input: G1_1 || G2_1 || G1_2 || G2_2 ...
        
        bytes memory input = abi.encodePacked(a1, b1, a2, b2);
        (bool success, bytes memory ret) = BLS12_PAIRING_CHECK.staticcall(input);
        
        if (!success) {
            // If staticcall failed, maybe precompile doesn't exist.
            // In TEST_MODE (simulated via catch), we could return true? No, this is library.
            // We assume if it fails, it's invalid input OR missing precompile.
            // Missing precompile usually limits gas or returns 0.
            return false;
        }
        
        // Output is 32 bytes (uint256). 1 if true, 0 if false.
        return abi.decode(ret, (uint256)) == 1;
    }
}
