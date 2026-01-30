# ZK Cosmos-Ethereum Bridge

A bidirectional bridge infrastructure for trustless asset transfers between Cosmos-based EVM chains and Ethereum, utilizing Zero-Knowledge proofs for scaling and security.

> [!WARNING]
> This project is a **Proof of Concept (POC)** and is **not production-ready**. It is intended for demonstration and testing purposes only.

## Overview

This repository provides the complete infrastructure to bridge assets between a Cosmos-based chain and Ethereum. It is composed of the following core components:

- **[evmd](evmd/README.md)**: A standalone Cosmos-based EVM chain implementation, serving as the sample Cosmos network.
- **[bridge](bridge/README.md)**: The core bridge logic, including relayers and on-chain verifiers. It implements a bidirectional flow with distinct verification mechanisms for each direction.

## Key Features

- **Bidirectional Transfers**: Full support for Lock, Mint, Burn, and Unlock operations in both directions (Ethereum ↔ Cosmos), allowing any asset to be bridged securely.
- **ZK-SNARK Verification (Cosmos → Ethereum)**: Uses ZK-SNARKs (Groth16) for trustless verification of Tendermint transaction inclusion on Ethereum.
- **On-chain MPT Proofs (Ethereum → Cosmos)**: Leverages Merkle Patricia Trie (MPT) receipts verification in Solidity for trustless validation of Ethereum events on Cosmos.
- **Modular Architecture**: Clean separation between ZK circuits, multi-chain relayers, and smart contracts.

## Getting Started

### 1. Setup Local Nodes

To run and test the bridge, you need both a local Cosmos EVM node and a local Ethereum node.

#### Cosmos Node (evmd)
Run the provided script to spin up the local Cosmos EVM chain:
```bash
# Initialize and start the local Cosmos EVM node
./local_evm_node.sh
```

#### Ethereum Node (Anvil)
We recommend using [Anvil](https://book.getfoundry.sh/anvil/) for local Ethereum development. Start Anvil with a custom chain ID and port to avoid conflicts:
```bash
# Start Anvil on port 8545 with chain ID 1337
anvil --port 8545 --chain-id 1337
```

### 2. Setup the Bridge
Once the nodes are running, refer to the bridge documentation for deployment and relayer setup:
- **Configure and run the bridge**: See [bridge/README.md](bridge/README.md).

## License

MIT
