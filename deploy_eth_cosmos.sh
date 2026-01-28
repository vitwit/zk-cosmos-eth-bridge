#!/bin/bash
set -e

# Configuration
ETH_RPC="http://localhost:8546"
ETH_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
COSMOS_RPC="http://localhost:8545"
COSMOS_KEY="0xe9b1d63e8acd7fe676acb43afb390d4b0202dab61abec9cf2a561e4becb147de"

mkdir -p out

echo "=== Deploying BridgeSource (Eth) ==="
forge create contracts/BridgeSource.sol:BridgeSource --rpc-url $ETH_RPC --private-key $ETH_KEY --broadcast --json > source_deploy.json
SOURCE_ADDR=$(jq -r '.deployedTo' source_deploy.json)
echo "BridgeSource Deployed: $SOURCE_ADDR"

echo "=== Deploying BridgeDestination (Cosmos) ==="
# Constructor(address source)
# Workaround for Evmos: forge create defaults to dry-run, so we use cast send --create manually
BYTECODE=$(forge inspect contracts/BridgeDestination.sol:BridgeDestination bytecode)
ARGS=$(cast abi-encode "constructor(address)" $SOURCE_ADDR)
# Remove 0x prefix from ARGS if BYTECODE has it? No, forge inspect returns 0x... usually? 
# forge inspect bytecode returns 0x...
# cast abi-encode returns 0x...
# We need 0x{BYTECODE_NO_PREFIX}{ARGS_NO_PREFIX}
# forge inspect returns 0x...
# cast abi-encode returns 0x...
BYTECODE_CLEAN=${BYTECODE#0x}
ARGS_CLEAN=${ARGS#0x}
INIT_CODE="0x${BYTECODE_CLEAN}${ARGS_CLEAN}"

echo "Deploying BridgeDestination via cast send..."
# Send and get tx hash
DEST_TX=$(cast send --rpc-url $COSMOS_RPC --private-key $COSMOS_KEY --legacy --create $INIT_CODE --json | jq -r '.transactionHash')
echo "Destination Tx: $DEST_TX"

# Get contract address from receipt
DEST_ADDR=$(cast receipt --rpc-url $COSMOS_RPC $DEST_TX --json | jq -r '.contractAddress')
echo "BridgeDestination Deployed: $DEST_ADDR"

echo "Disabling TEST_MODE (Enabling Cryptographic Verification)..."
cast send --rpc-url $COSMOS_RPC --private-key $COSMOS_KEY $DEST_ADDR "setTestMode(bool)" false

echo "=== Deployment Complete ==="
echo "Source: $SOURCE_ADDR"
echo "Destination: $DEST_ADDR"

# Save addresses to a file for the relayer
echo "SOURCE_ADDR=$SOURCE_ADDR" > .bridge_env
echo "DEST_ADDR=$DEST_ADDR" >> .bridge_env
