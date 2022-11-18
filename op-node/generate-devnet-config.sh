#!/usr/bin/env sh
set -eu
NETWORK=devnetL1


TIMESTAMP=$(date +%s | xargs printf '0x%x')
cat "devnetL1.json" | jq -r ".l1GenesisBlockTimestamp = \"$TIMESTAMP\"" > /tmp/bedrock-devnet-deploy-config.json
(
  op-node genesis devnet \
      --deploy-config /tmp/bedrock-devnet-deploy-config.json \
      --outfile.l1 /config/genesis-l1.json \
      --outfile.l2 /config/genesis-l2.json \
      --outfile.rollup /config/rollup.json
)