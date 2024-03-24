#!/usr/bin/env bash
rm -rf snapshot
rm -rf target
rm fuzzer.log

docker rmi --force snapchange_example2_no_patch:fuzzer
docker rmi --force snapchange_example2_no_patch:snapshot
docker rmi --force snapchange_example2_no_patch:target
