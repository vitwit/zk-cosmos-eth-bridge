# Testing Guide: ZK-Based Cosmos to Ethereum Bridge

Follow these steps to test the end-to-end flow of the bridge using a local environment.

## Prerequisites
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (recommended for local Ethereum testing)
- Go 1.21+
- Access to a Cosmos RPC node (e.g., `http://localhost:26657`)

## Step 1: Start a Local Ethereum Node
Open a new terminal and start Anvil (part of Foundry):
```bash
anvil
```
This will give you a local RPC URL: `http://127.0.0.1:8545`.

## Step 2: Deploy the Contracts
In another terminal, deploy the `Verifier.sol` and `EthereumBridge.sol` contracts.

1. **Deploy Verifier**:
```bash
forge create --rpc-url http://127.0.0.1:8545 --private-key <ANVIL_PRIVATE_KEY> Verifier.sol:Verifier
```
*Note: Copy the deployed address.*

2. **Deploy EthereumBridge**:
```bash
# Replace <VERIFIER_ADDRESS> and <INITIAL_ROOT>
forge create --rpc-url http://127.0.0.1:8545 --private-key <ANVIL_PRIVATE_KEY> contracts/EthereumBridge.sol:EthereumBridge --constructor-args <VERIFIER_ADDRESS> <INITIAL_ROOT>
```

## Step 3: Generate ZK Proof
Run the prover tool to get the proof data for a specific transaction.

```bash
# Example: Fetching tx at index 0 from height 100
go run ./cmd/prover/main.go http://localhost:26657 100 0
```

Copy the **Solidity Proof Data** output from the terminal. It will look like this:
```text
A: [uint256(0x...), uint256(0x...)]
B: [[uint256(0x...), uint256(0x...)], [uint256(0x...), uint256(0x...)]]
C: [uint256(0x...), uint256(0x...)]
Input: [uint256(123), ...]
```

## Step 4: Verify on Ethereum
Use `cast` (part of Foundry) to call the `mint` function on the `EthereumBridge` contract.

```bash
# Replace placeholders with the output from Step 3
cast send --rpc-url http://127.0.0.1:8545 --private-key <ANVIL_PRIVATE_KEY> <BRIDGE_ADDRESS> \
"mint(uint256[2],uint256[2][2],uint256[2],uint256[32],bytes32,address,uint256)" \
"<A_ARRAY>" "<B_ARRAY>" "<C_ARRAY>" "<INPUT_ARRAY>" <TX_HASH> <DESTINATION_ADDRESS> <AMOUNT>
```

## Expected Result
If the proof is valid, the transaction will succeed, and you will see a `Mint` event in the Anvil logs. If the proof or root is incorrect, the transaction will revert with "Invalid ZK proof" or "Root mismatch".
