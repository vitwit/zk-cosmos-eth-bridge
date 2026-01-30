# Deployment & Setup Guide

This guide provides a unified workflow for deploying the Cosmos-Eth Bridge contracts and configuring the relayer for bidirectional transfers.

## 1. Prerequisites

- **Private Key**: An account with gas tokens on both Cosmos and Ethereum.
- **RPC/WS Endpoints**:
  - Cosmos: RPC (`http://...:26657`) and WebSocket (`ws://...:26657/websocket`)
  - Ethereum: RPC (`http://...:8545`)
- **Tooling**: 
  - [Foundry](https://book.getfoundry.sh/getting-started/installation) (for Forge/Cast)
  - Go 1.21+
  - Node.js & npm
- **Local Environment** (Required for POC testing):
  - **Anvil (Ethereum)**: Part of Foundry.
  - **Cosmos Local Node**: The project's native build (see `./local_evm_node.sh`).

---

## 2. Local Development Setup (Quick Start)

If you are developing locally, start your nodes in separate terminal windows:

### A. Start Ethereum (Anvil)
```bash
# Start a clean local Ethereum node
anvil --chain-id 31337
```

### B. Start Cosmos EVM Node
Follow the setup instructions in the root directory: run `./local_evm_node.sh`. Ensure the EVM module is active and listening on `http://localhost:8545`.

---

## 3. Initial ZK Setup

Generate the verifier contract and cryptographic keys. **This is required before deploying to Ethereum.**

```bash
go run cmd/setup/main.go
```
- **Output**: `keys/proving.key`, `keys/verifying.key`, and `contracts/Verifier.sol`.

---

### Step A: Deploy to Ethereum
The `EthBridge.sol` handles Cosmos → Ethereum (Minting) and Ethereum → Cosmos (Burning).

1. **Deploy Verifier**:
   Generate the `Verifier.sol` via `go run cmd/setup/main.go` first.
   ```bash
   forge create --rpc-url $ETH_RPC --private-key $PRIV_KEY contracts/Verifier.sol:Verifier
   ```
   **Record address**: `$VERIFIER_ADDR`

2. **Deploy EthBridge**:
   Requires the Verifier address and an initial Cosmos Root (`data_hash`).
   ```bash
   # Get current Cosmos root
   export INITIAL_ROOT=$(curl -s $COSMOS_RPC/block | jq -r '.result.block.header.data_hash' | xargs -I {} echo 0x{})
   
   # Deploy
   forge create --rpc-url $ETH_RPC --private-key $PRIV_KEY contracts/EthBridge.sol:EthBridge --constructor-args $VERIFIER_ADDR $INITIAL_ROOT
   ```
   **Record address**: `$ETH_BRIDGE_ADDR`

---

### Step B: Deploy to Cosmos EVM
The `CosmosBridge.sol` facilitates Cosmos → Ethereum (Locking) and Ethereum → Cosmos (Minting/Unlocking). **Requires the Ethereum Bridge address.**

**Using Forge (Foundry):**
```bash
forge create --rpc-url $COSMOS_RPC --private-key $PRIV_KEY contracts/CosmosBridge.sol:CosmosBridge --constructor-args $ETH_BRIDGE_ADDR
```

### Option C: Deployment via Remix IDE (Interactive)

1. Open [Remix IDE](https://remix.ethereum.org).
2. Upload the `contracts/` directory.
3. **Compile**: Go to the "Solidity Compiler" tab and click "Compile".
4. **Deploy**:
   - Set Environment to **Injected Provider** (MetaMask) or **Custom RPC**.
   - **Deploy EthBridge**: Provide `_verifier` (address from Step A.1) and `_initialRoot` (see Step A.2).
   - **Deploy CosmosBridge**: Provide `_ethBridgeSource` (address of the `EthBridge` deployed on Ethereum).
   - **Note**: Prefix all `bytes32` values with `0x`.

---

## 4. Contract Interaction & Maintenance

### Loading an Existing Contract (Remix)
1. Ensure the exact source code is compiled.
2. Go to the "Deploy & Run" tab.
3. Paste the contract address into the **At Address** field and click the button.

### How to "Update" a Contract
Smart contracts are immutable. To change logic:
1. Apply changes to the `.sol` file.
2. Compile and **Redeploy**.
3. **IMPORTANT**: Update your `.env` file with the new contract address and restart the relayer.

### Root Management (Manual)
The `EthBridge` requires a `trustedRoot` from Cosmos.
- **Get Root**: `curl -s localhost:26657/block | jq -r '.result.block.header.data_hash'`.
- **Update**: Call `updateTrustedRoot(0x...)` on the `EthBridge` contract.

---

## 5. Relayer Configuration

The relayer orchestrates the cross-chain movement of assets. It uses a `.env` file for all configuration.

### Configure Environment
```bash
cp .env.example .env
nano .env
```

| Variable | Description |
|----------|-------------|
| `COSMOS_WS_URL` | WebSocket URL for Cosmos node |
| `COSMOS_RPC_URL` | RPC URL for Cosmos node (Tendermint) |
| `COSMOS_EVM_RPC_URL` | RPC URL for Cosmos EVM (Eth-compatible) |
| `ETHEREUM_RPC_URL` | RPC URL for Ethereum |
| `ETHEREUM_WS_URL` | WebSocket URL for Ethereum |
| `BRIDGE_COSMOS_ADDR` | Address of `CosmosBridge` |
| `BRIDGE_ETH_ADDR` | Address of `EthBridge` |
| `RELAYER_PRIV_KEY` | Private key for submitting proofs |

### Start the Relayer
```bash
go run cmd/relayer/main.go
```

---

## 5. Troubleshooting & Maintenance

- **Proving Key Not Found**: Ensure you ran `cmd/setup` and the `keys/` directory is present.
- **Root Mismatch**: The relayer automatically syncs roots, but if a manual mint fails, ensure the `trustedRoot` on the destination matches a valid block on the source.
- **WebSocket Timeout**: If the relayer loses connection, it will log an error. Ensure your Cosmos node allows WebSocket connections from the relayer's IP.
- **Gas Issues**: Ensure the `RELAYER_PRIV_KEY` has enough native tokens on BOTH chains to perform synchronization and proof submissions.
