# End-to-End Integration Testing Guide (ZK-Bridge)

This guide explains how to test the complete ZK-bridge flow, from locking tokens on Cosmos to automatic minting on Ethereum, using real-time data and ZK-SNARKs.

## 1. Prerequisites

- **Cosmos EVM**: A running node (local Ethermint/Evmos or testnet) with WebSocket and RPC enabled (usually ports 26657 and 8545)
- **Ethereum Destination**: An Ethereum RPC (e.g., Sepolia, Hardhat, or Anvil)
- **ZK toolkit**: Go installed (v1.21+) and the project directory ready
- **Tools**: `curl` and `jq` installed for terminal-based root retrieval
- **Remix IDE**: For easy contract deployment and interaction (optional)

## 2. Phase 1: Contract Deployment

### A. Compile ZK Circuit

**CRITICAL FIRST STEP**: Generate the Verifier contract and cryptographic keys.

```bash
cd zk-bridge
go run cmd/compiler/main.go
```

This generates:
- `keys/proving.key` - Required for proof generation (~450MB)
- `keys/verifying.key` - Verification key
- `contracts/Verifier.sol` - Solidity verifier with SHA256 patch

### B. Deploy BridgeSource on Cosmos (via Remix)

1. Open [Remix IDE](https://remix.ethereum.org) and connect to your Cosmos EVM node via **Injected Provider** or **Custom RPC**
2. Upload `contracts/BridgeSource.sol`
3. Compile and deploy `BridgeSource.sol`
4. **Record the address**: `0xBRIDGE_SOURCE`

### C. Deploy Verifier on Ethereum

1. Upload the generated `contracts/Verifier.sol` to Remix
2. Deploy `Verifier.sol` on the **Ethereum destination**
3. **Record the address**: `0xVERIFIER`

### D. Deploy BridgeDestination on Ethereum

1. Deploy `BridgeDestination.sol` with the following constructor arguments:
   - `_verifier`: `0xVERIFIER` (from step C)
   - `_initialRoot`: The **transaction Merkle root** of a valid Cosmos block
     - **IMPORTANT**: Remix requires `bytes32` values to be prefixed with **`0x`** (e.g., `0xE3B0...`)
     - For the POC, you can use any 32-byte hash initially and update it later (see **Root Management** below)
2. **Record the address**: `0xBRIDGE_DEST`

### E. Root Management (How to get the root)

In Tendermint, the transaction Merkle root is stored in the block header as `data_hash`.

1. **Fetch current root from Cosmos**:
   ```bash
   curl -s http://localhost:26657/block | jq -r '.result.block.header.data_hash'
   ```
   *Note: If the result is `ABCD...`, use `0xABCD...` in Remix.*

2. **Update on Ethereum (if needed)**:
   - If you want to bridge for a *new* block, call `updateTrustedRoot(bytes32 _newRoot)` on your `BridgeDestination` contract via Remix
   - **Prefix the hash with `0x`** when passing as an argument

---

## 3. Phase 2: Relayer Configuration

### Configure Environment

Create and edit your `.env` file:

```bash
cd zk-bridge
cp .env.example .env
nano .env
```

Update with your deployed addresses and RPC URLs:

```bash
# Cosmos Configuration
COSMOS_WS_URL=ws://<YOUR_COSMOS_IP>:26657/websocket
COSMOS_RPC_URL=http://<YOUR_COSMOS_IP>:26657
COSMOS_EVM_RPC_URL=http://<YOUR_COSMOS_IP>:8545

# Ethereum Configuration
ETHEREUM_RPC_URL=http://<YOUR_ETH_RPC>

# Contract Addresses (from Phase 1)
BRIDGE_SOURCE_ADDR=0xBRIDGE_SOURCE
BRIDGE_DEST_ADDR=0xBRIDGE_DEST

# Relayer Private Key (must have gas on Ethereum)
RELAYER_PRIV_KEY=your_private_key_here
```

### Start the Relayer

```bash
go run cmd/relayer/main.go
```

You should see:
```
🔌 Connecting to Cosmos WebSocket at ws://localhost:26657/websocket...
🛰️ Relayer active! Monitoring Cosmos for Lock events...
```

---

## 4. Phase 3: Automated Testing Flow

The relayer is now **fully automated** and handles trust synchronization itself.

### Step 1: Perform the Lock (Cosmos)

**Via Remix:**
1. Go to **Remix**, connect to your Cosmos EVM
2. Load your deployed `BridgeSource` contract
3. In the **Value** field (above contract functions), enter amount:
   - Example: `100000000000000000` (0.1 ETH in Wei)
   - **Note**: This is a global field, not inside the `lock` function
4. Call `lock` with:
   - `ethDestination`: Your desired Ethereum recipient address (e.g., `0xC6Fe5D33615a1C52c08018c47E8Bc53646A0E101`)
5. Confirm the transaction

**Via CLI (Cast):**
```bash
cast send $BRIDGE_SOURCE_ADDR "lock(address)" 0xRECIPIENT_ADDRESS \
  --value 0.1ether \
  --rpc-url $COSMOS_EVM_RPC \
  --private-key $YOUR_KEY
```

### Step 2: Observe the Magic

The relayer will automatically:

1. **Detect** your lock transaction hash via WebSockets
   ```
   🚀 New Tendermint Tx detected: ABC123...
   ⛓️  Mapped to EVM Hash: 0xDEF456...
   ```

2. **Fetch** the `Lock` event details (recipient and amount) from Cosmos EVM
   ```
   ✅ Legitimate Bridge Lock found! Recipient=0x..., Amount=100000000000000000
   ```

3. **Synchronize** the Cosmos Block Root (the `data_hash`) with the Ethereum `BridgeDestination` contract
   ```
   🔄 Synchronizing Trusted Root on Ethereum...
   ```

4. **Generate** the ZK-SNARK inclusion proof (this takes 2-4 minutes)
   ```
   🧬 Generating ZK-SNARK Inclusion Proof from Real RPC...
   ⚙️  Step 1/4: Compiling ZK Circuit...
   ⚙️  Step 2/4: Loading Persistent Setup Keys...
   ⚙️  Step 3/4: Generating Full Witness...
   🚀 Step 4/4: Calculating ZK-SNARK Proof...
   ✅ ZK-SNARK Proof generated.
   ```

5. **Submit** the proof and data to Ethereum to trigger the `mint`
   ```
   🚀 Submitting ZK-SNARK to Ethereum...
   🎉 Relay Complete!
   ```

### Step 3: Verify Success

**Option 1: Check Balance via Remix**
1. In Remix, load `BridgeDestination.sol` at your deployed address
2. Call `balanceOf` with your recipient address
3. The value should be updated (remember decimals: 10^18)
   - Example: `100000000000000000` = 0.1 WTEST

**Option 2: Check Transaction Status via CLI**
```bash
# Use the Ethereum Tx Hash from the relayer output
curl -X POST --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["YOUR_TX_HASH"],"id":1}' \
  -H "Content-Type: application/json" \
  http://localhost:8545
```

Successful transactions will show `"status": "0x1"`.

**Option 3: Using Cast**
```bash
cast call $BRIDGE_DEST_ADDR "balanceOf(address)" 0xRECIPIENT_ADDRESS \
  --rpc-url $ETHEREUM_RPC_URL
```

---

## 5. Troubleshooting

### Proof Generation Fails

**Error: `proving.key not found`**
- **Solution**: Run `go run cmd/compiler/main.go` first to generate keys
- **Verify**: Check that `keys/proving.key` exists (should be ~450MB)

**Error: `Merkle proof data invalid`**
- **Solution**: Ensure transaction is indexed on Cosmos
- **Check**: Wait a few seconds after lock transaction confirms
- **Verify**: Query the transaction via RPC to ensure it's available

### Transaction Reverts (`status: 0x0`)

**Error: `ProofInvalid()`**
- **Cause**: Mismatch between proving key and deployed Verifier
- **Solution**: 
  1. Delete old `keys/` directory
  2. Run `go run cmd/compiler/main.go` to regenerate
  3. Redeploy `Verifier.sol` and `BridgeDestination.sol`
  4. Update `.env` with new addresses

**Error: `RootMismatch()`**
- **Cause**: Trusted root doesn't match the block containing the transaction
- **Solution**: Relayer should auto-update root, but you can manually call `updateTrustedRoot`

**Error: `AlreadyProcessed()`**
- **Cause**: Transaction has already been bridged
- **Solution**: This is expected behavior (replay protection)

### No Lock Events Detected

**Relayer shows no activity**
- **Check WebSocket connection**: Verify `COSMOS_WS_URL` is correct
- **Verify contract address**: Ensure `BRIDGE_SOURCE_ADDR` in `.env` matches deployed contract
- **Check transaction**: Confirm the lock transaction actually succeeded on Cosmos

**Wrong contract monitored**
- **Solution**: Update `BRIDGE_SOURCE_ADDR` in `.env` and restart relayer

### Relayer Crashes

**Error: `RELAYER_PRIV_KEY not set`**
- **Solution**: Ensure `.env` file exists and contains `RELAYER_PRIV_KEY`

**Error: `connection refused`**
- **Solution**: Verify Cosmos and Ethereum nodes are running
- **Check**: Test RPC URLs with `curl`

---

## 6. Advanced Testing Scenarios

### Testing Multiple Locks

You can lock multiple times and the relayer will process each sequentially:

```bash
# Lock 1
cast send $BRIDGE_SOURCE_ADDR "lock(address)" 0xRECIPIENT1 --value 0.1ether ...

# Lock 2
cast send $BRIDGE_SOURCE_ADDR "lock(address)" 0xRECIPIENT2 --value 0.2ether ...
```

### Testing Different Amounts

```bash
# Small amount
cast send $BRIDGE_SOURCE_ADDR "lock(address)" 0xRECIPIENT --value 0.001ether ...

# Large amount
cast send $BRIDGE_SOURCE_ADDR "lock(address)" 0xRECIPIENT --value 10ether ...
```

### Verifying Merkle Proofs Manually

You can inspect the generated proof:

```bash
cat proof_event.json | jq .
```

This shows the full ZK-SNARK proof structure including:
- `a`, `b`, `c` - Proof points
- `commitments` - Pedersen commitments
- `public` - Public inputs (packed root + txHash)

---

## 7. Performance Benchmarks

Typical timings on a modern machine:

- **Lock Transaction**: ~2-5 seconds (Cosmos block time)
- **Event Detection**: <1 second (WebSocket)
- **Proof Generation**: 2-4 minutes (depends on CPU)
- **Ethereum Submission**: ~12 seconds (Ethereum block time)

**Total End-to-End**: ~3-5 minutes

---

## 8. Trust Model Note

In this **POC**, the relayer performs an "Automated Admin" step by calling `updateTrustedRoot` before minting. This provides a seamless "zero-touch" testing experience.

In a **Production** environment, this relayer step would be replaced by a **ZK-Light Client Proof**, where the relayer proves the Cosmos consensus (validator signatures) to update the root autonomously on Ethereum without requiring admin privileges.

---

## 9. Cleanup & Reset

### Reset for Fresh Test

```bash
# Stop relayer (Ctrl+C)

# Delete generated proof
rm proof_event.json

# Redeploy contracts (if needed)
# Update .env with new addresses

# Restart relayer
go run cmd/relayer/main.go
```

### Full Reset (Including Keys)

```bash
# Remove all generated files
rm -rf keys/
rm proof_event.json

# Regenerate everything
go run cmd/compiler/main.go

# Redeploy all contracts
# Update .env

# Restart relayer
go run cmd/relayer/main.go
```
