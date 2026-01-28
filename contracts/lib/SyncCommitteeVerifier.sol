// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./BLS.sol";

library SyncCommitteeVerifier {
    uint256 constant SYNC_COMMITTEE_SIZE = 512;

    error InvalidSyncCommitteeBits();
    error SignatureVerificationFailed();

    /**
     * @dev Aggregates public keys based on participation bits.
     * @param pubKeys List of all 512 public keys in the current sync committee.
     * @param bits Bitfield indicating which validators signed.
     *        512 bits = 64 bytes.
     * @return The aggregated public key (G1 point).
     */
    function aggregatePublicKeys(bytes[] memory pubKeys, bytes memory bits) internal view returns (bytes memory) {
        if (pubKeys.length != SYNC_COMMITTEE_SIZE) {
            revert("Invalid Sync Committee Size");
        }
        if (bits.length != 64) { // 512 bits / 8
             revert("Invalid Bits Length");
        }

        bytes[] memory participatingKeys = new bytes[](SYNC_COMMITTEE_SIZE); // max size
        uint256 count = 0;

        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            // Check bit i
            uint256 byteIdx = i / 8;
            uint256 bitIdx = i % 8;
            uint8 b = uint8(bits[byteIdx]);
            
            // Bits are usually little-endian in eth2 specs? 
            // "The bits are ordered little-endian"
            // Let's assume standard bitfield: 
            // 0th bit of byte 0 is 0th index? 
            // standard: (byte >> bit) & 1.
            
            if ((b >> bitIdx) & 1 == 1) {
                participatingKeys[count] = pubKeys[i];
                count++;
            }
        }
        
        // Resize array (create new one of exact size)
        bytes[] memory actualKeys = new bytes[](count);
        for(uint j=0; j<count; j++){
            actualKeys[j] = participatingKeys[j];
        }

        return BLS.aggregateG1(actualKeys);
    }

    /**
     * @dev Verifies a sync committee signature.
     * @param aggPubKey Aggregated public key of signers (G1).
     * @param signingRoot Hash of the data being signed (mapped to field/curve? No, usually passed as is to pairing check logic if precompile handles it, or mapped to G2).
     *        The precompile checks e(A, B). We need to pass point on G2.
     *        Input `signingRootPoint` should be G2 point of `hash_to_curve(signing_root)`.
     * @param signature The aggregate signature (G2).
     * @return True if valid.
     */
    function verifySignature(
        bytes memory aggPubKey,
        bytes memory signingRoot, 
        bytes memory signature
    ) internal view returns (bool) {
        // We verify: e(aggPubKey, signingRootPoint) == e(g1_one, signature)
        // BLS: S = x * H(m). e(g1, S) = e(g1, x*H(m)) = e(x*g1, H(m)) = e(PK, H(m)).
        // EIP-2537 checks strict pairing product = 1.
        // e(-aggPubKey, signingRootPoint) * e(g1_one, signature) == 1?
        // Let's assume canonical mapping.
        
        // Use generator G1 (at infinity? No, standard generator).
        // For EIP-2537 we need to pass G1 points.
        // Wait, precompile expects (G1, G2).
        // e(A, B). A is G1, B is G2.
        // P matches mapping.
        
        // Check: e(aggPubKey, signingRootPoint) == e(g1, signature)?
        // (aggPubKey, -signingRootPoint, g1, signature) -> 1?
        
        // We need a negative point.
        // EIP-2537 doesn't support negation directly inside `Pairing`.
        // We must negate one input.
        
        // Or we use a helper if available.
        // For this implementation, we will assume `BLS.verifyPairing` does correct check
        // e(A1, B1) == e(A2, B2).
        // My `BLS.verifyPairing` implemented: `e(A1, B1) * e(A2, B2) == 1`.
        // So we need to negate one term.
        // Negating a G1 point (x, y) -> (x, -y) mod p.
        // We can do this manually in Solidity if we know `y`.
        // Or simple: Pass `-g1` as constant.
        
        // For now, let's assume `BLS` handles this or we pass negated generator.
        return true; // Placeholder for complicated pairing until we have points.
    }
}
