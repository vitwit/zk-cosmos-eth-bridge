# ZK Cosmos-Ethereum Bridge

A Zero-Knowledge proof-based bridge infrastructure for cross-chain communication between Cosmos-based EVM chains and Ethereum.

> [!WARNING]
> This project is a **Proof of Concept (POC)** and is **not production-ready**. It is intended for demonstration and testing purposes only.

## Overview

This repository contains two main components:

- **[evmd](evmd/README.md)**: A standalone Cosmos-based EVM chain implementation, used as the source for cross-chain transfers.
- **[zk-bridge](zk-bridge/README.md)**: The core bridge infrastructure, providing ZK circuit definitions, proof generation logic, and on-chain verifiers for secure asset transfers.

## Key Features

- **ZK-SNARK Based Verification**: Securely verify cross-chain state transitions without relying on trusted intermediaries.
- **Cosmos EVM Integration**: Native support for Cosmos SDK chains with EVM capabilities.
- **Clean Architecture**: Modular design for ZK circuits, relayers, and smart contracts.

## Getting Started

Refer to the internal READMEs for specific setup and execution instructions:

1.  **Run the local EVM chain**: See [evmd/README.md](evmd/README.md).
2.  **Setup and run the bridge**: See [zk-bridge/README.md](zk-bridge/README.md).

## License

MIT
