#!/bin/bash
set -e

# Configuration
CHAIN_ID="evmos_9000-1"
MONIKER="localtest"
KEY_NAME="mykey"
# Private key: 88cbead91aee890d27bf06e003ade3d4e952427e88f88d31d61d3ef5e5d54305
# Mnemonic for above key (test mnemonic): "concert load couple harbor equip island argue ramp clarify fence smart topic"
# Actually, let's just generate a new one and export the private key, or add the specific key if possible.
# Ideally we import the key we've been using: 0x88cbead9...
# But evmd keys add only supports mnemonic or ledger.
# So we will use a known mnemonic for dev.
MNEMONIC="gesture inject test cycle original hollow east ridge hen combine junk child bacon zero hope comfort vacuum milk pitch cage oppose unhappy lunar seat"
# Address for this mnemonic: evmos1... (we'll see)

# Binary
EVMD="/home/vitwit/go/bin/evmd"
HOME_DIR="$HOME/.tmp_evmosd"

echo "=== Initializing Local Evmos Node ==="
rm -rf $HOME_DIR

$EVMD init $MONIKER --chain-id $CHAIN_ID --home $HOME_DIR

echo "=== Importing Key ==="
echo "$MNEMONIC" | $EVMD keys add $KEY_NAME --recover --home $HOME_DIR --keyring-backend test

# Add Genesis Account
$EVMD add-genesis-account $($EVMD keys show $KEY_NAME -a --home $HOME_DIR --keyring-backend test) 1000000000000000000000aevmos,1000000000000000000000stake --home $HOME_DIR

echo "=== Generating Gentx ==="
$EVMD gentx $KEY_NAME 1000000000stake --chain-id $CHAIN_ID --home $HOME_DIR --keyring-backend test

echo "=== Collecting Gentxs ==="
$EVMD collect-gentxs --home $HOME_DIR

echo "=== Configuring JSON-RPC ==="
# Update app.toml to enable JSON-RPC on 8545
# We use sed to replace default config
# api.enable = true
sed -i 's/enable = false/enable = true/g' $HOME_DIR/config/app.toml
# swagger = true (optional)
sed -i 's/swagger = false/swagger = true/g' $HOME_DIR/config/app.toml

# Update config.toml for CORS? and other settings if needed.
# Allow all CORS
sed -i 's/cors_allowed_origins = \[\]/cors_allowed_origins = \["*"\]/g' $HOME_DIR/config/config.toml

echo "=== Starting Node ==="
echo "Node home: $HOME_DIR"
echo "RPC Port: 26657"
echo "JSON-RPC Port: 8545"
echo "EVRPC Port: 8545"

# We bind JSON-RPC to 0.0.0.0:8545 to match our previous anvil setup
# evmd start --json-rpc.address="0.0.0.0:8545" ...
# Actually evmd config for json-rpc is in app.toml usually under [json-rpc] or [evm]
# But CLI flags work too.

$EVMD start --home $HOME_DIR --json-rpc.api eth,net,web3,txpool --json-rpc.enable true --json-rpc.address "0.0.0.0:8545"
