#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname "$0" )" &> /dev/null && pwd )
REPO_ROOT=$( cd -- "$( dirname $( dirname "$0" ) )" &> /dev/null && pwd )

docker run --rm \
    -v "${REPO_ROOT}:/work" \
    --entrypoint "starknet-compile-deprecated" \
    starknet/cairo-lang:0.12.2 \
    /work/src/udc_deployer.cairo --account_contract --output /work/src/classes/UdcDeployer.json
