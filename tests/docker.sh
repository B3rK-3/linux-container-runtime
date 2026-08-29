#!/bin/sh
# Run Linux checks in Docker on Colima; keep Linux build artifacts off the host.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker --context "${DOCKER_CONTEXT:-colima}" run --rm --privileged --cgroupns=private \
    --mount "type=bind,src=$project,dst=/src,readonly" ubuntu:24.04 bash -lc '
    set -eu
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends build-essential pkg-config libcap-dev libseccomp-dev busybox-static python3
    cp -a /src /work
    cd /work
    make clean
    make CFLAGS="-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wformat=2 -Werror -fstack-protector-strong"
    mkdir /sys/fs/cgroup/contained-runner
    echo "$$" > /sys/fs/cgroup/contained-runner/cgroup.procs
    echo "+memory +cpu +pids" > /sys/fs/cgroup/cgroup.subtree_control
    make test-unit test-cli test-lines
    ./tests/integration.sh ./contained
    ./tests/regression.sh ./contained
'
