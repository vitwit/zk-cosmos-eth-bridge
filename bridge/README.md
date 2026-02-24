# Cosmos-Eth Bridge: Bidirectional Cosmos-Ethereum Bridge

A high-performance Zero-Knowledge proof-based bridge facilitating trustless, bidirectional asset transfers between Cosmos (EVM-compatible) and Ethereum.

## 🌟 Key Features

- **Triple-Verifier Architecture**: Modular ZK logic for block finality (Ed25519/Quorum), validator transitions, and transaction inclusion.
- **Sequential Finality**: On-chain block height tracking prevents replays and ensures cryptographic consistency.
- **Bidirectional Transfers**: Trustless transfers between Ethereum (MPT-based) and Cosmos (ZK-SNARK based).
- **Real-Time Orchestration**: Automated Go-based relayer handles header synchronization and event detection using WebSockets.

## 🏗️ Project Architecture

```
bridge/
├── cmd/
│   ├── setup/          # Generates ZK keys and Verifier_*.sol
│   └── relayer/        # Bidirectional relayer (Cosmos ↔ Ethereum)
├── contracts/          # Smart Contracts
│   ├── CosmosBridge.sol# Bridge gateway on Cosmos EVM
│   ├── EthBridge.sol   # Bridge gateway on Ethereum
│   ├── LibMPT.sol      # MPT proof verification library
│   └── Verifier_*.sol  # Auto-generated ZK Verifiers (Transactions, Validators, Transitions)
├── pkg/
│   ├── circuits/       # GNARK ZK-SNARK circuit definitions
│   ├── prover/         # Proof generation and submission logic
│   ├── rpc/            # Multi-chain RPC clients
│   └── trie/           # MPT implementation for Go
├── keys/               # Proving/Verifying keys (Generated)
└── guides/             # In-depth technical guides
```

## 🚀 Quick Start

### 1. Prerequisites

- Go 1.21+
- Node.js & npm (for Solidity tools)
- Access to an Ethereum RPC (e.g., Anvil/Sepolia) and a Cosmos EVM RPC.

### 2. Initial Setup

```bash
# Initialize environment
cp .env.example .env
# Edit .env with your private keys and RPC URLs

# Generate ZK keys and Solidity Verifiers (Triple-Verifier)
go run cmd/setup/main.go
```

### 3. Deploy Contracts

Contracts must be deployed to both Cosmos and Ethereum. Recommended tools:

**Option A: Using Forge (Foundry) - Recommended for speed**
```bash
# 1. Deploy Verifiers to Ethereum
forge create --rpc-url $ETH_RPC_URL --private-key $PRIV_KEY contracts/Verifier_Transactions.sol:Verifier
forge create --rpc-url $ETH_RPC_URL --private-key $PRIV_KEY contracts/Verifier_Validators.sol:Verifier
forge create --rpc-url $ETH_RPC_URL --private-key $PRIV_KEY contracts/Verifier_Transitions.sol:Verifier
# Record as $TX_VERIFIER, $VAL_VERIFIER, $TRANS_VERIFIER

# 2. Deploy EthBridge to Ethereum
# Get INITIAL_VAL_SET_HASH and INITIAL_HEIGHT from Cosmos
forge create --rpc-url $ETH_RPC_URL --private-key $PRIV_KEY contracts/EthBridge.sol:EthBridge \
  --constructor-args $TX_VERIFIER $VAL_VERIFIER $TRANS_VERIFIER $INITIAL_VAL_SET_HASH $INITIAL_HEIGHT
# Record address as $ETH_BRIDGE_ADDR

# 3. Deploy CosmosBridge to Cosmos
# Requires $ETH_BRIDGE_ADDR (the Ethereum contract address)
forge create --rpc-url $COSMOS_RPC_URL --private-key $PRIV_KEY contracts/CosmosBridge.sol:CosmosBridge --constructor-args $ETH_BRIDGE_ADDR
```

**Option B: Using Remix IDE**
1. Open [Remix](https://remix.ethereum.org).
2. Upload the `contracts/` directory.
3. Compile and deploy using the `Injected Provider` (MetaMask) or custom RPC.

### 4. Run the Relayer

The relayer monitors both chains for `Locked` and `Burned` events.

```bash
go run cmd/relayer/main.go
```

## 🔄 Bridge Flows

### Ethereum → Cosmos (Lock & Mint)
1. User calls `lock()` on `EthBridge.sol`.
2. Relayer detects the event, generates an MPT proof of the receipt.
3. Relayer calls `mint()` on `CosmosBridge.sol` with the proof.
4. `CosmosBridge` verifies the proof using `LibMPT` and mints tokens.

### Cosmos → Ethereum (Burn & Unlock)
1. User calls `burn()` on `CosmosBridge.sol`.
2. Relayer detects the event, generates a ZK-SNARK proof of transaction inclusion.
3. Relayer calls `unlock()` on `EthBridge.sol` with the ZK proof.
4. `EthBridge` verifies the ZK proof and releases native assets.

## 📚 Technical Documentation

For detailed implementation details, see the `guides/` directory:
- [Architecture Deep Dive](guides/ARCHITECTURE.md)
- [Deployment & Relayer Setup](guides/DEPLOYMENT.md)
- [End-to-End Testing Guide](guides/TESTING_GUIDE.md)

## 🔧 Testing

```bash
# Run Go unit tests
go test ./pkg/...

# Run end-to-end bridge test (requires local nodes)
# Follow steps in guides/TESTING_GUIDE.md
```

## 📝 License

This project is licensed under the MIT License.
