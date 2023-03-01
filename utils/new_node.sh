#!/usr/bin/env bash
cp ./utils/genesis.json ../op-geth/genesis.json
cp ./utils/rollup.json ./op-node/rollup.json
cd ../op-geth
openssl rand -hex 32 > jwt.txt
cp jwt.txt ../optimism/op-node
./build/bin/geth init --datadir=./datadir ./genesis.json
cd ../optimism