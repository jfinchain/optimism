#!/usr/bin/env bash
cd op-node && ./bin/op-node \
	--l2=http://localhost:8551 \
	--l2.jwt-secret=./jwt.txt \
	--sequencer.enabled \
	--sequencer.l1-confs=3 \
	--verifier.l1-confs=3 \
	--rollup.config=./rollup.json \
	--rpc.addr=0.0.0.0 \
	--rpc.port=8547 \
	--p2p.listen.ip=0.0.0.0 \
	--p2p.listen.tcp=9003 \
	--p2p.listen.udp=9003 \
	--rpc.enable-admin \
	--p2p.sequencer.key=$SEQUENCER_KEY \
	--l1=$GOERLI_RPC_URL \
	--l1.rpckind=alchemy
