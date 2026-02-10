This guide details how to verify the bidirectional bridge functionality using standard CLI tools (`cast`) and automated relayer processes.

## 1. Phase 1: Initial Setup (ZK Key Generation)

**CRITICAL**: You must generate the cryptographic keys and the Solidity verifier before any testing can occur.

```bash
# From the project root
go run cmd/setup/main.go
```
This generates:
- `keys/*.proving.key`: Required by the relayer for each of the three circuits.
- `keys/*.verifying.key`: Used for local verification checks.
- `contracts/Verifier_*.sol`: Three specialized verifier contracts (Transactions, Validators, Transitions).

---

## 2. Prerequisite: Running Local Nodes

Before any bridge operations, ensure your local environment is active:

1. **Start Anvil** (Local Ethereum): `anvil --port 8545 --chain-id 1337`
2. **Start Cosmos Node** (Cosmos RPC at `:26657`, EVM at `:8545`): `./local_evm_node.sh`
3. **Verify Connection**:
   ```bash
   # Check Ethereum
   cast block-number --rpc-url http://localhost:8545
   # Check Cosmos
   curl -s http://localhost:26657/status | jq .result.sync_info.latest_block_height
   ```

---

## 3. Phase 2: Contract Deployment

Before running the relayer, you must deploy the gateways to both chains.

### A. Deploy Verifiers (Ethereum)
```bash
forge create --rpc-url $ETHEREUM_RPC --private-key $USER_KEY contracts/Verifier_Transactions.sol:Verifier
forge create --rpc-url $ETHEREUM_RPC --private-key $USER_KEY contracts/Verifier_Validators.sol:Verifier
forge create --rpc-url $ETHEREUM_RPC --private-key $USER_KEY contracts/Verifier_Transitions.sol:Verifier
```
**Record addresses**: `$TX_VERIFIER`, `$VAL_VERIFIER`, `$TRANS_VERIFIER`

### B. Deploy EthBridge (Ethereum)
Requires initial Cosmos validator set and verifier addresses:
```bash
export VAL_SET=$(curl -s $COSMOS_RPC/block | jq -r '.result.block.header.validators_hash' | xargs -I {} echo 0x{})
export HEIGHT=$(curl -s $COSMOS_RPC/status | jq -r '.result.sync_info.latest_block_height')

forge create --rpc-url $ETHEREUM_RPC --private-key $USER_KEY contracts/EthBridge.sol:EthBridge \
  --constructor-args $TX_VERIFIER $VAL_VERIFIER $TRANS_VERIFIER $VAL_SET $HEIGHT
```
**Record address**: `$ETH_BRIDGE_ADDR`

### C. Deploy CosmosBridge (Cosmos)
**Requires the Ethereum Bridge address.**
```bash
forge create --rpc-url $COSMOS_EVM_RPC --private-key $USER_KEY contracts/CosmosBridge.sol:CosmosBridge --constructor-args $ETH_BRIDGE_ADDR
```
**Record address**: `$BRIDGE_SOURCE_ADDR`

---

## 3. Phase 3: Environment Verification & Relayer

Ensure your `.env` is configured correctly and the relayer is running:
```bash
go run cmd/relayer/main.go
```
*Wait for: "🛰️ Relayer active! Monitoring both chains..."*

---

---

## 4. Test Flow 1: Cosmos → Ethereum (ZK-SNARK)

**Goal**: Securely lock native tokens on Cosmos and mint wrapped tokens on Ethereum using ZK-SNARKs.

### Step 1: Initiate Lock on Cosmos
```bash
# Use the addresses from Phase 2
cast send $BRIDGE_SOURCE "lock(address)" $ETH_RECIPIENT \
  --value 0.1ether \
  --rpc-url $COSMOS_EVM_RPC \
  --private-key $USER_KEY
```

### Step 2: Observe Relayer
- **Detection**: Relayer detects the transaction via WebSocket.
- **ZK Generation**: Prover generates a proof of inclusion (~2-4 mins).
- **Submission**: Relayer calls `mint()` on `EthBridge.sol`.

### Step 3: Verify on Ethereum
```bash
# Check WETH balance on Ethereum
cast call $BRIDGE_ETH_ADDR "balanceOf(address)" $ETH_RECIPIENT \
  --rpc-url $ETH_RPC
```

---

## 5. Test Flow 2: Ethereum → Cosmos (MPT-Proof)

**Goal**: Securely lock native ETH on Ethereum and mint wrapped tokens on Cosmos using MPT proofs.

### Step 1: Initiate Lock on Ethereum
```bash
# Provide recipient as a string (hex format)
cast send $BRIDGE_ETH_ADDR "lock(string)" "0xCOSMOS_EVM_ADDR" \
  --value 0.1ether \
  --rpc-url $ETH_RPC \
  --private-key $USER_KEY
```

### Step 2: Observe Relayer
- **Detection**: Relayer detects the `Locked` event from the receipt.
- **MPT Generation**: Prover builds a Merkle Patricia Trie proof of the receipt.
- **Submission**: Relayer calls `mint()` on `CosmosBridge.sol`.

### Step 3: Verify on Cosmos
```bash
# Check balance on Cosmos EVM
cast call $BRIDGE_COSMOS_ADDR "balanceOf(address)" $COSMOS_EVM_ADDR \
  --rpc-url $COSMOS_EVM_RPC
```

---

## 6. Test Flow 3: Return Paths (Burn & Unlock)

Both directions support "Burning" wrapped tokens to "Unlock" native assets on the original chain.

### Burn on Cosmos (to unlock on Ethereum)
```bash
cast send $BRIDGE_COSMOS_ADDR "burn(uint256,address)" $AMOUNT $ETH_RECIPIENT \
  --rpc-url $COSMOS_EVM_RPC \
  --private-key $USER_KEY
```

### Burn on Ethereum (to unlock on Cosmos)
```bash
cast send $BRIDGE_ETH_ADDR "burn(uint256,string)" $AMOUNT "0xCOSMOS_RECIPIENT" \
  --rpc-url $ETH_RPC \
  --private-key $USER_KEY
```

---

## 7. Helpful Commands

### Convert Bech32 to Hex (Cosmos)
```bash
cast --to-checksum THE_COSMOS_BECH32_ADDRESS
```

### Check Contract State
```bash
# Check Trusted Root on EthBridge for specific height
cast call $BRIDGE_ETH_ADDR "trustedRoots(uint256)(bytes32)" $HEIGHT --rpc-url $ETH_RPC

# Check Native Balance
cast balance $ADDRESS --rpc-url $RPC_URL
```

---

## 6. Performance Benchmarks

Typical timings for end-to-end bridging on a modern developer machine:

- **Lock Transaction**: ~2-5 seconds (Source block time)
- **Event Detection**: <1 second (WebSocket/RPC polling)
- **Proof Generation**:
  - **ZK Path**: 2-4 minutes (CPU intensive)
  - **MPT Path**: <1 second (Lightweight RLP)
- **Submission**: ~12 seconds (Destination block time)

**Total End-to-End**: 
- Cosmos -> Eth: ~3-5 minutes
- Eth -> Cosmos: ~20-30 seconds

---

## 7. Advanced Testing Scenarios

### Testing Multiple Locks
The relayer is designed to handle multiple concurrent events. You can fire multiple `lock` transactions in rapid succession; the relayer will queue them and process each sequentially.

---

## 8. Trust Model & Future Roadmap

**IMPORTANT**: This version implements **cryptographically verified payload inclusion** for both directions.

- **On-Chain (Secure)**: 
  - **Cosmos -> Eth**: Verified by triple-verifier suite (Transactions, Validators, Transitions). Block header consensus is cryptographically verified in-circuit.
  - **Eth -> Cosmos**: Verified by `LibMPT.sol` (MPT Proof) and `RLPReader.sol` (Receipt Decoding). Transaction data and event logs are strictly verified against the trusted root.
- **Future Roadmap**:
  - **On-Chain Light Clients**: For full decentralization, future upgrades will implement on-chain Light Clients to verify peer-chain consensus (e.g., Ethereum Sync Committees or Tendermint signatures) directly.
  - **EVM-Light Client on Cosmos**: Implementing a native Ethereum light client module on Cosmos to verify Ethereum PoS headers without relying on relayer synchronization.