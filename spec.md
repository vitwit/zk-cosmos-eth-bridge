Technical Specification: Ethereum ↔ Cosmos Trustless Bridge
Direction: Ethereum (Source) → Cosmos (Destination)

1. Introduction
This document defines the technical architecture for a trustless, decentralized asset bridge from Ethereum (L1) to a Cosmos-based AppChain.

While the reverse direction (Cosmos-to-Ethereum) typically utilizes ZK-SNARKs to compress Tendermint's heavy validator set signatures for EVM compatibility, the Ethereum-to-Cosmos direction is optimized using an EVM Light Client and Merkle Patricia Trie (MPT) inclusion proofs.

This architectural choice is driven by efficiency: the Cosmos environment (Wasm or EVM modules) can natively and performantly execute Keccak-256 hashing and RLP decoding. By verifying MPT proofs directly, we achieve the same security guarantees as a ZK bridge but with significantly lower latency and operational cost, as we skip the expensive ZK proof generation for Ethereum’s receipt trie.


2. Terminology
Merkle Patricia Trie (MPT): An authenticated data structure that provides a cryptographically secure mapping from keys to values. Ethereum uses MPT to store the state, transactions, and receipts of every block.
Recursive Length Prefix (RLP): The primary encoding method used in Ethereum for prefixing the length of nested arrays and strings. It is the binary format in which all MPT nodes and receipts are stored.
EVM Light Client: A state-tracking mechanism on the destination chain that verifies Ethereum block headers. It ensures that the block hash (and its associated roots) used for verification is part of the canonical Ethereum chain.
Sync Committee: A rotating set of 512 Ethereum validators (selected every ~27 hours) that sign block headers. Their aggregate signature allows light clients to verify the chain's state without tracking the full 1-million+ validator set.
Inclusion Proof: A sequence of MPT nodes that proves a specific piece of data (like a transaction receipt) exists within a specific Merkle root.


3. Token Lifecycle Scenarios
3.1 Scenario A: New Token Inbound (Lock & Mint)
This flow handles the transition of assets native to Ethereum (e.g., ETH, USDC, DAI) into the Cosmos ecosystem.

Locking: The user interacts with the Ethereum Bridge contract, calling the lock function. The assets are transferred from the user to the contract's vault (escrow).
Event Emission: The contract emits a Locked event. This event is part of the transaction receipt and is committed to the block's receiptsRoot.
Relaying: A relayer waits for the block to be finalized, then fetches the MPT proof for this receipt.
Minting: The Cosmos contract verifies the MPT proof against the trusted Ethereum root. Once verified, it triggers the minting of a "wrapped" version of the asset (e.g., ethUSDC) to the user’s Cosmos address.
3.2 Scenario B: Returning Token (Burn & Unlock)
This flow handles assets that originated on Cosmos, were bridged to Ethereum, and are now being "redeemed" back to their native chain.

Burning: The user calls burn on the Ethereum bridge contract, destroying the wrapped Cosmos tokens they held on Ethereum.
Event Emission: The contract emits a Burned event, which is cryptographically committed to the Ethereum blockchain.
Relaying: The relayer provides the proof of this burn to the Cosmos bridge.
Unlocking: After verifying the proof, the Cosmos contract releases the original native assets (e.g., native ATOM or native token-factory assets) from its internal vault/escrow and sends them to the user.


4. Contract Interfaces
4.1 Ethereum Source Contract (Solidity)
The Ethereum contract acts as the "source of truth" and vault for all assets.

interface IBridgeSource {

    /**

     * @notice Emitted when assets are locked for bridging to Cosmos.

     * @param token The address of the locked ERC20 (or 0x0 for ETH).

     * @param sender The Ethereum address that initiated the lock.

     * @param recipient The destination Cosmos address (as a string).

     * @param amount The quantity of tokens locked.

     * @param nonce A unique incrementing value to ensure order and prevent duplicates.

     */

    event Locked(

        address indexed token,

        address indexed sender,

        string recipient,

        uint256 amount,

        uint256 nonce

    );

    /**

     * @notice Emitted when wrapped Cosmos assets are burned for redemption.

     */

    event Burned(

        address indexed token,

        address indexed sender,

        string recipient,

        uint256 amount,

        uint256 nonce

    );

    /**

     * @dev Escrows assets and triggers the bridge flow.

     */

    function lock(address token, uint256 amount, string calldata recipient) external payable;

    /**

     * @dev Destroys wrapped assets to release native assets on the destination.

     */

    function burn(address token, uint256 amount, string calldata recipient) external;

}

4.2 Cosmos Destination Contract (CosmWasm)
The Cosmos contract acts as the "verifier" and "issuer".

SubmitHeader { header: EthHeader, signatures: Vec<BlsSignature> }:
This method is called by relayers to keep the Cosmos contract synchronized with the Ethereum tip.
It verifies that the header is valid and signed by the current Sync Committee.
Claim { proof: MptProof, raw_receipt: Binary, block_number: u64 }:
The main entry point for bridging. It takes the full RLP-encoded raw_receipt and the MptProof needed to link it to the receiptsRoot of block_number.


5. EVM Light Client & Header Verification
5.1 The Header Chain & Trust Anchor
The bridge operates by maintaining a "mini-blockchain" of Ethereum headers inside the Cosmos contract.

Sync Committee Verification: For every header update, the Cosmos contract checks the aggregate BLS12-381 signature. It ensures that the public keys of the signers belong to the currently known Sync Committee.
State Persistence: Once verified, the contract stores the receiptsRoot for that block height. This root is the unique identifier for all events that happened in that block.
Finality Threshold: To protect against short-range reorgs on Ethereum, the bridge only accepts headers that have been "Finalized" (transitioned through two epochs).
5.2 RLP Decoding Mechanics
Since all data on Ethereum is RLP-encoded, the Cosmos contract must "unpack" the receipt:

The raw_receipt is decoded to find the logs field.
Each log is checked for the correct contract address (the Ethereum Bridge) and the correct topic (the hash of the event signature).
This ensures that a malicious user cannot submit a valid-looking receipt from a different contract.


6. Merkle Patricia Trie (MPT) Depth
6.1 Path & Node Traversal
The MPT is a "hexary" trie where each node can have up to 16 children.

The Path: The key to the receipt in the trie is its index (e.g., if it's the 5th transaction, the index is 4). This index is RLP-encoded to form the nibble path.
Node Hashing: Every node in the proof is hashed with Keccak-256. The contract ensures that the hash of Node[i] is exactly what is stored in the pointer field of Node[i-1].
Leaf Resolution: The traversal ends when a "Leaf Node" is reached. The data in this leaf must be the RLP-encoded receipt data provided in the Claim message.


7. Security Measures
7.1 Double-Spend Prevention
Even with a valid proof, a user could attempt to submit the same proof twice. The Cosmos contract prevents this by:

Storing a mapping of processed_tx_hashes.
Each Ethereum transaction hash is recorded upon a successful claim. If the same hash is seen again, the transaction is rejected immediately.
7.2 Proof of Knowledge & Integrity
The bridge doesn't just check that "some" lock happened; it checks that this specific lock, with this specific amount and recipient, was committed to the Ethereum state.

Hash-Chain Integrity: If a single bit in the amount or recipient address is changed, the MPT proof will fail to hash back to the trusted receiptsRoot.
Vault Security: The assets on the Cosmos side are strictly controlled by the bridge contract logic. No admin or external entity can trigger a minting or unlocking without a valid, cryptographically verified Ethereum event.


8. Appendix: Detailed Visual Flow


