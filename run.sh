#! /bin/bash
DIR="$( cd "$( dirname "$0" )" && pwd )"

mkdir -p "${HOME}/electrs"

testnet3() {
    # export DAEMON_RPC_ADDR="127.0.0.1:18332"
    export DAEMON_CONF_PATH=$DIR/testnet3.env
    export START_HEIGHT=3193400
    export STOP_HEIGHT=3193600
    export DAEMON_RPC_ADDR="192.168.1.253:18332"
    $DIR/start testnet
}
testnet4() {
    # export DAEMON_RPC_ADDR="127.0.0.1:48332"
    export DAEMON_CONF_PATH=$DIR/testnet4.env
    export ELECTRUM_RPC_ADDR="127.0.0.1:60001"
    # Index from genesis
    export START_HEIGHT=0
    export DAEMON_RPC_ADDR="192.168.1.254:48332"
    $DIR/start.scalar testnet4
}

$@