#!/bin/bash
set -ex

# Build the base snapchange image used for snapshotting
pushd ../../docker
    if [[ "$(docker images -q snapchange_snapshot 2>/dev/null)" == "" ]]; then
        docker build --no-cache -t snapchange_snapshot .
    fi
popd

# Build the target Dockerfile
docker build --no-cache -t snapchange_example3:target . -f dockers/Dockerfile.target

# Combine the target the snapshot mechanism
docker build --no-cache -t snapchange_example3:snapshot . -f dockers/Dockerfile.snapshot

# Run the image to take the snapshot
docker run --rm -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    snapchange_example3:snapshot

sha256sum ./snapshot/ffmpeg.bin ./snapshot/vmlinux
