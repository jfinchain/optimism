#!/usr/bin/env bash


set -eu


L2_URL="http://localhost:9545"

OP_NODE="$PWD/op-node"
CONTRACTS_BEDROCK="$PWD/packages/contracts-bedrock"
DEVNET="$PWD/.devnet"

# Helper method that waits for a given URL to be up. Can't use
# cURL's built-in retry logic because connection reset errors
# are ignored unless you're using a very recent version of cURL
function wait_up {
  echo -n "Waiting for $1 to come up..."
  i=0
  until curl -s -f -o /dev/null "$1"
  do
    echo -n .
    sleep 0.25

    ((i=i+1))
    if [ "$i" -eq 300 ]; then
      echo " Timeout!" >&2
      exit 1
    fi
  done
  echo "Done!"
}

mkdir -p ./.devnet

# Regenerate the L1 genesis file if necessary. The existence of the genesis
# file is used to determine if we need to recreate the devnet's state folder.
if [ ! -f "$DEVNET/done" ]; then
  echo "Regenerating genesis files"

  TIMESTAMP=$(date +%s | xargs printf '0x%x')
  cat "$CONTRACTS_BEDROCK/deploy-config/jfintest.json" | jq -r ".l1GenesisBlockTimestamp = \"$TIMESTAMP\"" > /tmp/bedrock-devnet-deploy-config.json

  (
    cd "$OP_NODE"
    go run cmd/main.go genesis l2 \
        --l1-rpc http://65.108.44.103:8003 \
        --deploy-config /tmp/bedrock-devnet-deploy-config.json \
        --deployment-dir $CONTRACTS_BEDROCK/deployments/ \
        --outfile.l2 $DEVNET/genesis-l2.json \
        --outfile.rollup $DEVNET/rollup.json
    touch "$DEVNET/done"
  )
fi

# Bring up L2.
(
  cd ops-bedrock
  echo "Bringing up L2..."
  docker-compose up -d l2
  wait_up $L2_URL
)

L2OO_ADDRESS="0x25E0D6E5a35Afeac83167B9A01dEa0a8E23853bE"
SEQUENCER_GENESIS_HASH="$(jq -r '.genesis.l2.hash' < $DEVNET/rollup.json)"
SEQUENCER_BATCH_INBOX_ADDRESS="$(cat $DEVNET/rollup.json | jq -r '.batch_inbox_address')"

# Bring up everything else.
(
  cd ops-bedrock
  echo "Bringing up devnet..."
  L2OO_ADDRESS="$L2OO_ADDRESS" \
      SEQUENCER_GENESIS_HASH="$SEQUENCER_GENESIS_HASH" \
      SEQUENCER_BATCH_INBOX_ADDRESS="$SEQUENCER_BATCH_INBOX_ADDRESS" \
      docker-compose up -d op-proposer op-batcher

)

echo "Devnet ready."
