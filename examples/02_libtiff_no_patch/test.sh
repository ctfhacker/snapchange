#!/usr/bin/env bash

source ../test.include.sh

setup_build

# Reset the snapshot
make reset

# There is a chance this example will crash on a different ASAN crash before ASAN_READ.
# Retry a few times to try and catch the ASAN_READ crash
for f in $(seq 0 10); do 
    start_fuzzing

    # Kill the example 02 fuzzers
    ps -ef | rg Example02 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

    # Check if the fuzzer found a crash
    ls snapshot/crashes/ASAN_READ* >/dev/null
    STATUS=$?
    if [ "$STATUS" -gt 0 ]; then
        echo "fuzzer found crash other than ASAN_READ (expected sometimes).. trying again for ASAN_READ"
    else
        log_success "fuzzing"
        exit 0
    fi

    # Delete the current crashes and retry
    rm -rf snapshot/crashes
done
