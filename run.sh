#! /bin/bash
DIR="$( cd "$( dirname "$0" )" && pwd )"
RUST_LOG=debug
# export JOB_THREAD_COUNT=4
export DAEMON_RPC_ADDR="192.168.1.253:18332"
mkdir -p "${HOME}/electrs"
$DIR/start $@
