#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname "$0" )" &> /dev/null && pwd )
REPO_ROOT=$( cd -- "$( dirname $( dirname "$0" ) )" &> /dev/null && pwd )

docker run --rm \
    -v "${REPO_ROOT}:/work" \
    --entrypoint "cairo-format" \
    starknet/cairo-lang:0.12.2 \
    -i /work/src/udc_deployer.cairo
