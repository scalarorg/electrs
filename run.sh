#! /bin/bash
DIR="$( cd "$( dirname "$0" )" && pwd )"

mkdir -p "${HOME}/electrs"

testnet3() {
    # export DAEMON_RPC_ADDR="127.0.0.1:18332"
    export DAEMON_RPC_ADDR="192.168.1.253:18332"
    export DAEMON_CONF_PATH=$DIR/testnet3.env
    export START_HEIGHT=3193400
    export STOP_HEIGHT=3193600
    $DIR/start testnet
}
testnet4() {
    export DAEMON_RPC_ADDR="127.0.0.1:48332"
    export DAEMON_CONF_PATH=$DIR/testnet4.env
    export ELECTRUM_RPC_ADDR="0.0.0.0:60001"
    export DB_FOLDER=./electrs
    # Index from genesis
    export START_HEIGHT=0
    # stop height it not working yet
    # export STOP_HEIGHT=52650
    export FETCH_SIZE=64
    export TAG=SCALAR
    export VERSION=1
    $DIR/start.scalar testnet4
}

regtest() {
    # export DAEMON_RPC_ADDR="127.0.0.1:48332"
    export DAEMON_RPC_ADDR="localhost:18332"
    export DAEMON_CONF_PATH=$DIR/regtest.env
    export ELECTRUM_RPC_ADDR="127.0.0.1:60401"
    export DB_FOLDER=./electrs
    # Index from genesis
    export START_HEIGHT=0
    export VAULT_TAG="01020304"
    export VAULT_VERSION=0
    $DIR/start.scalar regtest
}
$@