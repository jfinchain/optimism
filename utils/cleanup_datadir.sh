cd ../op-geth
rm -rf datadir
mkdir datadir
echo "pwd" > datadir/password
echo "$SEQUENCER_KEY" > datadir/block-signer-key
./build/bin/geth account import --datadir=./datadir --password=./datadir/password ./datadir/block-signer-key
./build/bin/geth init --datadir=./datadir ./genesis.json