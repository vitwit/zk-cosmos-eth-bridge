# ZK Bridge Local Development Guide

This guide provides step-by-step instructions to run the ZK-based Cosmos-Ethereum bridge locally using a local Evmos chain and Anvil (Ethereum).

## Prerequisites
- **Go**: 1.22+
- **Foundry**: (for Anvil and Cast) `curl -L https://foundry.paradigm.xyz | bash`
- **Evmos (Cosmos/EVM)**: `git clone https://github.com/cosmos/evm.git && cd evm && make install` (binary: `evmd`)
- **Solidity Compiler (solc)**: `sudo apt-get install solc` (or equivalent)
- **jq**: `sudo apt-get install jq`

---

## 1. Start Local Chains

### Terminal 1: Evmos
Start a single-node Evmos chain.
```bash
# Start chain using local_node.sh
cd cosmos-evm
./local_node.sh -y --no-install > ../evmd_local.log 2>&1 &
cd ..

# Verify it's running
tail -f evmd_local.log
```
*RPCs: CometBFT `http://localhost:26657`, EVM `http://localhost:8545`*
*Chain ID: `9001`*
*Dev0 Private Key: `88cbead91aee890d27bf06e003ade3d4e952427e88f88d31d61d3ef5e5d54305`*
```
*RPCs: CometBFT `http://localhost:26657`, EVM `http://localhost:8545`*

### Terminal 2: Anvil (Ethereum)
Start a local Ethereum node.
```bash
anvil --chain-id 1337 --port 8546 --block-time 1
```
*RPC: `http://localhost:8546`*
*Private Key (Account 0): `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`*

---

## 2. Deploy Cosmos Lock Contract (Evmos)

### Terminal 3: Deployment
```bash
cd testing

# 1. Compile CosmosLock
solc --optimize --combined-json abi,bin contracts/CosmosLock.sol -o build/evmos

# 2. Deploy
# Note: We use evmosd tx wasm if it was CosmWasm, but this is an EVM contract.
# We can use `cast` (from Foundry) to deploy to Evmos EVM too!
export EVMOS_RPC=http://localhost:8545
# Get Dev0's private key (already known from local_node.sh)
ALICE_KEY=88cbead91aee890d27bf06e003ade3d4e952427e88f88d31d61d3ef5e5d54305

LOCK_ADDR=$(cast send --rpc-url $EVMOS_RPC --private-key $ALICE_KEY --create $(jq -r '.contracts["contracts/CosmosLock.sol:CosmosLock"].bin' build/evmos/combined.json) --json | jq -r '.contractAddress')

echo "CosmosLock Address: $LOCK_ADDR"
```

---

## 3. Prepare ZK Components

### Generate Keys and Verifier
The Prover needs to generate the ZK keys (`proving.key`, `verification.key`) first.

```bash
# 1. Build Prover
go build -o bin/prover ./cmd/prover

# 2. Run Prover once to generate keys (it will fail to find tx but will gen keys)
# Ignore the error.
./bin/prover http://localhost:26657 1 0x00 0 0 0x00

# 3. Generate Solidity Verifier
go run github.com/consensys/gnark-frontend/cmd/solidity \
    -circuit=./circuit/inclusion.go \
    -pk=./proving.key \
    -vk=./verification.key \
    -out=./contracts/Verifier.sol
```

---

## 4. Deploy Ethereum Contracts (Anvil)

```bash
export ETH_RPC=http://localhost:8546
export ETH_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# 1. Compile Contracts
solc --optimize --combined-json abi,bin contracts/Verifier.sol contracts/WrappedEVMS.sol contracts/MintBridge.sol -o build/ethereum

# 2. Deploy Verifier
VERIFIER_ADDR=$(cast send --rpc-url $ETH_RPC --private-key $ETH_KEY --create $(jq -r '.contracts["contracts/Verifier.sol:Verifier"].bin' build/ethereum/combined.json) --json | jq -r '.contractAddress')
echo "Verifier: $VERIFIER_ADDR"

# 3. Deploy Wrapped Token
TOKEN_ADDR=$(cast send --rpc-url $ETH_RPC --private-key $ETH_KEY --create $(jq -r '.contracts["contracts/WrappedEVMS.sol:WrappedEVMS"].bin' build/ethereum/combined.json) --json | jq -r '.contractAddress')
echo "WrappedEVMS: $TOKEN_ADDR"

# 4. Deploy MintBridge
# Constructor: (Verifier, Token)
BRIDGE_ADDR=$(cast send --rpc-url $ETH_RPC --private-key $ETH_KEY --create $(jq -r '.contracts["contracts/MintBridge.sol:MintBridge"].bin' build/ethereum/combined.json) $VERIFIER_ADDR $TOKEN_ADDR --json | jq -r '.contractAddress')
echo "MintBridge: $BRIDGE_ADDR"
```

---

## 5. Run the Relayer

```bash
# 1. Build Relayer
go build -o bin/relayer ./cmd/relayer

# 2. Run Relayer
# Usage: relayer <evmos_evm_rpc> <evmos_comet_rpc> <eth_rpc> <lock_addr> <bridge_addr> <eth_priv_key>
./bin/relayer \
  http://localhost:8545 \
  http://localhost:26657 \
  http://localhost:8546 \
  $LOCK_ADDR \
  $BRIDGE_ADDR \
  $ETH_KEY
```

---

## 6. Test the Bridge

### 1. Lock Tokens on Evmos
Send a transaction to the `CosmosLock` contract.
```bash
# Destination on Ethereum (e.g., Account 1 from Anvil)
DEST_ADDR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
AMOUNT=1000000000000000000 # 1 ETH

# Call lock(address)
cast send --rpc-url http://localhost:8545 --private-key $ALICE_KEY $LOCK_ADDR "lock(address)" $DEST_ADDR --value $AMOUNT
```

### 2. Verify Mint on Ethereum
Check the balance of the destination address on Anvil.
```bash
cast call --rpc-url http://localhost:8546 $TOKEN_ADDR "balanceOf(address)(uint256)" $DEST_ADDR
```
You should see `1000000000000000000`.

---

## Troubleshooting
- **Root Mismatch Warning**: You will see "Computed Root ... does not match Block Header". This is **expected** because we modified the leaf hashing logic for security. The Relayer registers the new root automatically.

## 7. Using Remix & MetaMask

If you prefer using Remix instead of the CLI:

### Setup
1.  **Browser A (Evmos)**:
    -   Install MetaMask.
    -   Add Network: `http://localhost:8545` (Chain ID: 9001).
    -   Import Dev0 key: `88cbead91aee890d27bf06e003ade3d4e952427e88f88d31d61d3ef5e5d54305`.
    -   Open [Remix](https://remix.ethereum.org).
    -   Connect MetaMask.

2.  **Browser B (Ethereum)**:
    -   Install MetaMask.
    -   Add Network: `http://localhost:8546` (Chain ID: 1337).
    -   Import Anvil Account 0 key.
    -   Open [Remix](https://remix.ethereum.org).
    -   Connect MetaMask.

### Deployment Steps
1.  **Evmos (Browser A)**:
    -   Copy `contracts/CosmosLock.sol` to Remix.
    -   Compile.
    -   Deploy `CosmosLock`.
    -   **Copy the Contract Address**.

2.  **Ethereum (Browser B)**:
    -   Copy `contracts/Verifier.sol`, `contracts/WrappedEVMS.sol`, `contracts/MintBridge.sol` to Remix.
    -   Compile all.
    -   Deploy `Verifier`. Copy Address.
    -   Deploy `WrappedEVMS`. Copy Address.
    -   Deploy `MintBridge` (Constructor: Verifier Address, WrappedEVMS Address). Copy Address.

3.  **Run Relayer**:
    -   Update your `relayer` command with the new addresses you copied from Remix.

4.  **Test**:
    -   **Browser A**: Use Remix to call `lock(dest_addr)` on `CosmosLock`.
    -   **Browser B**: Watch the `WrappedEVMS` balance increase!

