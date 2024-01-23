#!/bin/bash

usage() {
  echo "USAGE: $0 <FILENAME> <ADDDRESS>"
  exit 1
}

# Bail if less than two arguments
if [ "$#" -lt 2 ]; then
  echo "ERROR: Missing arguments."
  usage
fi

echo $(dirname $(realpath $0))/..

UTILS=$(dirname $(realpath $0))
DIR=GHIDRA_$(basename $1)
FILENAME=$(realpath $1)
ADDR=$2

# Create the project directory
mkdir $DIR || true

# Install ghidra
pushd $UTILS
source ../docker/install/ghidra.sh

echo "Gathering ghidra coverage/redqueen for $1 based at $2"

./ghidra/support/analyzeHeadless \
  $DIR \
  temp \
  -readOnly \
  -import \
  $FILENAME \
  -scriptPath \
  ../docker/coverage_scripts \
  -postScript \
  ghidra_script_bb_worker.py \
  $ADDR

popd >/dev/null
