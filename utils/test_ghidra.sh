#!nix-shell -p openjdk

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
FILENAME=$(realpath $1)
FILEDIR=$(dirname $FILENAME)/$(basename $1)_ghidra
ADDR=$2

# Create the project directory
mkdir $FILEDIR || true

# Install ghidra
pushd $UTILS
source ../docker/install/ghidra.sh

echo "Gathering ghidra coverage/redqueen for $1 based at $2"

./ghidra/support/analyzeHeadless \
  $FILEDIR \
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
