#!/usr/bin/env bash
cd op-batcher && ./bin/op-batcher \
    --l2-eth-rpc=http://localhost:8545 \
    --rollup-rpc=http://localhost:8547 \
    --poll-interval=1s \
    --sub-safety-margin=6 \
    --num-confirmations=1 \
    --safe-abort-nonce-too-low-count=3 \
    --resubmission-timeout=30s \
    --rpc.addr=0.0.0.0 \
    --rpc.port=8548 \
    --target-l1-tx-size-bytes=2048 \
    --l1-eth-rpc=$GOERLI_RPC_URL \
    --private-key=$BATCHER_KEY