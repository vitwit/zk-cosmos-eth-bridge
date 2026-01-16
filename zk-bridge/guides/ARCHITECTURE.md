# Architecture Overview

## Project Structure

```
zk-bridge/
├── cmd/                    # Executable commands
│   ├── compiler/          # ZK circuit compilation & key generation
│   ├── deployer/          # Contract deployment tool
│   └── relayer/           # Bridge relayer service
├── contracts/             # Solidity smart contracts
│   ├── BridgeSource.sol   # Lock tokens on Cosmos
│   ├── BridgeDestination.sol  # Mint tokens on Ethereum
│   └── Verifier.sol       # ZK proof verifier (generated)
├── pkg/                   # Shared Go packages
│   ├── circuits/          # GNARK circuit definitions
│   ├── prover/            # Proof generation logic
│   └── rpc/               # RPC client implementations
├── keys/                  # Generated cryptographic keys
│   ├── proving.key        # For proof generation
│   └── verifying.key      # For verification
└── guides/                # Documentation
```

## Components

### 1. ZK Circuit (`pkg/circuits/`)

Implements Merkle tree inclusion proof circuit using GNARK:
- Verifies transaction exists in Tendermint block
- Validates Merkle path from leaf to root
- Supports up to 32-level tree depth
- Packs public inputs (root + txHash) into 8 uint64 values

### 2. Compiler (`cmd/compiler/`)

Generates cryptographic setup:
- Compiles circuit to R1CS constraints
- Performs Groth16 trusted setup
- Exports Solidity verifier contract
- Applies SHA256 + compression patch to match prover

**Output:**
- `keys/proving.key` - Proving key (~450MB)
- `keys/verifying.key` - Verification key
- `contracts/Verifier.sol` - Solidity verifier

### 3. Prover (`pkg/prover/`)

Generates ZK-SNARK proofs:
- Fetches Merkle proof from Cosmos RPC
- Constructs witness from proof data
- Generates Groth16 proof using proving key
- Exports proof in Solidity-compatible format

### 4. Relayer (`cmd/relayer/`)

Monitors and relays cross-chain messages:
- Subscribes to Cosmos transaction events
- Detects lock events on BridgeSource
- Generates inclusion proofs
- Submits proofs to BridgeDestination

### 5. Smart Contracts

**BridgeSource (Cosmos EVM)**
- `lock(address recipient, uint256 amount)` - Lock tokens for bridging
- Emits `Locked` event with recipient and amount

**BridgeDestination (Ethereum)**
- `mint(proof, root, txHash, recipient, amount)` - Verify proof and mint
- Maintains trusted Merkle root
- Prevents replay attacks via processed tx tracking

**Verifier (Ethereum)**
- `verifyProof(proof, commitments, input)` - Verify Groth16 proof
- Auto-generated from circuit
- Patched to use SHA256 with compressed points

## Data Flow

```
1. User locks tokens on Cosmos
   ↓
2. Cosmos EVM emits Locked event
   ↓
3. Relayer detects event via WebSocket
   ↓
4. Relayer fetches Merkle proof from Tendermint
   ↓
5. Prover generates ZK-SNARK proof
   ↓
6. Relayer submits proof to Ethereum
   ↓
7. Verifier validates proof on-chain
   ↓
8. BridgeDestination mints tokens to recipient
```

## Security Model

- **Trustless**: No trusted relayer, anyone can submit proofs
- **ZK Privacy**: Proof reveals no information beyond validity
- **Replay Protection**: Each transaction can only be processed once
- **Root Synchronization**: Trusted root updated by relayer (can be decentralized)

## Key Design Decisions

### Path Resolution
All tools use robust path detection:
- Check for `go.mod` to determine if running from root
- Use `keys/` or `../../keys/` accordingly
- Prevents "file not found" errors

### Environment Configuration
Relayer uses `.env` file for all configuration:
- No hardcoded addresses or keys
- Easy deployment to different networks
- Secure credential management

### Modular Architecture
- Circuits, prover, and RPC clients are separate packages
- Commands are thin wrappers around pkg/ functionality
- Easy to test and extend
