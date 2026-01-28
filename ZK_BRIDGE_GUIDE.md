# 🌟 Unified ZK + MPT Bridge Guide

This guide runs the COMPLETE bidirectional bridge:
1.  **Eth -> Cosmos**: Secured by **MPT Proofs**.
2.  **Cosmos -> Eth**: Secured by **ZK Proofs**.

## **Prerequisites**
-   **Terminal 1**: Evmos Node (`./setup_evmos_local.sh`) - Port `8545` (EVM) & `26657` (Comet).
-   **Terminal 2**: Anvil Node (`anvil --port 8546 --chain-id 1234`).

---

## **1. Build the Unified Relayer**
Compile the single binary that handles both directions.

```bash
cd /home/vitwit/zk-state-transition/testing
go build -o bin/unified-relayer ./cmd/unified-relayer
```

## **2. Generate ZK Keys (One-Time)**
If you haven't already:
```bash
# Generate keys (ignore execution error, keys will be created)
go build -o bin/prover ./cmd/prover
./bin/prover http://localhost:26657 1 0x00 0 0 0x00
```

---

## **3. Deploy Contracts**

### **A. Ethereum Contracts (Anvil)**
Deploy: `Verifier`, `WrappedEVMS`, `MintBridge` (ZK Side) AND `BridgeSource` (MPT Side).

```bash
export ETH_RPC="http://localhost:8546"
export ETH_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# 1. ZK Verifier
go run github.com/consensys/gnark-frontend/cmd/solidity -circuit=./circuit/inclusion.go -pk=./proving.key -vk=./verification.key -out=./contracts/Verifier.sol
solc --optimize --combined-json abi,bin contracts/Verifier.sol -o build
VERIFIER=$(cast send --rpc-url $ETH_RPC --private-key $ETH_KEY --create $(jq -r '.contracts["contracts/Verifier.sol:Verifier"].bin' build/combined.json) --json | jq -r '.contractAddress')

# 2. Wrapped Token (on Eth)
solc --optimize --combined-json abi,bin contracts/WrappedEVMS.sol -o build
TOKEN=$(cast send --rpc-url $ETH_RPC --private-key $ETH_KEY --create $(jq -r '.contracts["contracts/WrappedEVMS.sol:WrappedEVMS"].bin' build/combined.json) --json | jq -r '.contractAddress')

# 3. MintBridge (on Eth) - Receives ZK Proofs
solc --optimize --combined-json abi,bin contracts/MintBridge.sol -o build
MINT_BRIDGE=$(cast send --rpc-url $ETH_RPC --private-key $ETH_KEY --create $(jq -r '.contracts["contracts/MintBridge.sol:MintBridge"].bin' build/combined.json) $VERIFIER $TOKEN --json | jq -r '.contractAddress')

# 4. BridgeSource (on Eth) - Locks Eth for MPT
forge create contracts/BridgeSource.sol:BridgeSource --rpc-url $ETH_RPC --private-key $ETH_KEY
# Note the Deployed Address: BRIDGE_SOURCE
```

### **B. Cosmos Contracts (Evmos)**
Deploy: `CosmosLock` (ZK Side) AND `BridgeDestination` (MPT Side).

```bash
export EVMOS_RPC="http://localhost:8545"
# Use Key from setup script logs (e.g. 0xe9b1...)
export EVMOS_KEY="0xe9b1d63e8acd7fe676acb43afb390d4b0202dab61abec9cf2a561e4becb147de"

# 5. CosmosLock (on Cosmos) - Source for ZK
solc --optimize --combined-json abi,bin contracts/CosmosLock.sol -o build
COSMOS_LOCK=$(cast send --rpc-url $EVMOS_RPC --private-key $EVMOS_KEY --create $(jq -r '.contracts["contracts/CosmosLock.sol:CosmosLock"].bin' build/combined.json) --json | jq -r '.contractAddress')

# 6. BridgeDestination (on Cosmos) - Sink for MPT
# (Requires RLPReader/Verifier libraries first - use deploy_eth_cosmos.sh helper logic or manual)
# ... For simplicity, assume address BRIDGE_DEST
```

---

## **4. Run the Unified Relayer**

Connects everything together.

```bash
./bin/unified-relayer \
  http://localhost:8546 \
  http://localhost:8545 \
  http://localhost:26657 \
  $ETH_KEY \
  $BRIDGE_SOURCE \
  $BRIDGE_DEST \
  $COSMOS_LOCK \
  $MINT_BRIDGE \
  0
```

## **5. Test Flows**

### **Flow 1: Eth -> Cosmos (MPT)**
1.  **Lock** ETH on `BridgeSource`.
2.  Relayer proves MPT.
3.  **Claim** executes on `BridgeDestination`.

### **Flow 2: Cosmos -> Eth (ZK)**
1.  **Lock** Evmos on `CosmosLock`.
2.  Relayer generates ZK Proof.
3.  **Mint** executes on `MintBridge`.

---

## **6. Browser Testing (Remix + MetaMask)**

If you prefer a GUI, follow these steps to use the bridge with Remix.

### **A. Connect MetaMask**
Configure your browser extension with the local networks.

| Network | RPC URL | Chain ID | Currency |
|---------|---------|----------|----------|
| **Local Eth** | `http://localhost:8546` | `1234` | ETH |
| **Local Evmos** | `http://localhost:8545` | `9000` | EVMOS |

*Tip: Import the dev private key `0xac09...` (Eth) and your derived Evmos key to have funds.*

### **B. Load Contracts in Remix**
1.  Open [Remix IDE](https://remix.ethereum.org).
2.  Create files for `BridgeSource.sol`, `BridgeDestination.sol`, `CosmosLock.sol`, and `MintBridge.sol`.
3.  Paste the code from your local `contracts/` directory.

### **C. Interact**

#### **1. Eth -> Cosmos Flow**
1.  Switch MetaMask to **Local Eth**.
2.  Compile `BridgeSource.sol`.
3.  In "Deploy & Run", select **Injected Provider - MetaMask**.
4.  Paste the **BridgeSource Address** (from deployment logs) into "At Address" and click.
5.  Call `lock`:
    *   `token`: `0x0000000000000000000000000000000000000000` (for ETH)
    *   `amount`: `100000000000000000` (0.1 ETH)
    *   `recipient`: Your Evmos Address string.
    *   **Value** (Top Right): `0.1` Ether.
    *   **Transact**.
6.  *Watch the terminal running `unified-relayer` - it will process the event!*
7.  Switch MetaMask to **Local Evmos** and check your balance on `BridgeDestination` (WETH).

#### **2. Cosmos -> Eth Flow (The "Return Leg")**
1.  **Switch MetaMask** to **Local Evmos**.
2.  Compile `CosmosLock.sol`.
3.  Paste **CosmosLock Address** and click "At Address".
4.  Call `lock`:
    *   `ethDestination`: **CRITICAL**: Use the exact MetaMask address you have active on Ethereum (e.g., `0xf39F...`).
    *   **Value**: `1` Ether (1 Evmos).
5.  *Watch the terminal* - Relayer generates ZK Proof and mints `WrappedEVMS` on Ethereum.
6.  **Switch MetaMask** to **Local Eth**.
7.  Check Balance:
    *   Load `WrappedEVMS.sol` at its address.
    *   Call `balanceOf` with your address. **It must be > 0 before proceeding!**
8.  Call `approve`:
    *   `spender`: Your `MintBridge` address.
    *   `amount`: `1000000...` (The amount you want to return).
9.  Call `burn` on `MintBridge`:
    *   `amount`: Same as above.
    *   `recipient`: Your Cosmos address (e.g. `cosmos1...`).

---

## **7. Troubleshooting "Insufficient Balance" (Error 0xfb8f41b2)**

If you see an error during `burn` on Ethereum, it is almost always because the account calling the function does not own the tokens.

**Checklist:**
1.  **Contract Redepolyment**: If you redeployed your contracts, ALL previous balances are gone. You must run a new `lock` on Cosmos to mint tokens to the *new* contract address.
2.  **Recipient Match**: In the Cosmos `lock(ethDestination)` call, did you use the **exact** 0x-address that is currently active in your MetaMask?
3.  **Balance Check**: In Remix, call `balanceOf(your_address)` on the `WrappedEVMS` contract. If it returns `0`, you cannot burn.
4.  **Allowance**: Ensure you called `approve` on the **Token** contract, not the Bridge contract, and that you used the correct **Bridge** address as the spender.

