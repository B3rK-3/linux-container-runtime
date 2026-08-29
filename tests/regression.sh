#!/bin/bash
# Regression coverage for setup failures, resource settings and workload lifecycle.
set -eEu
trap 'echo "regression failed at line $LINENO: $BASH_COMMAND" >&2' ERR
binary=$(realpath "${1:-./contained}")
parent=${CONTAINED_CGROUP_PARENT:-/sys/fs/cgroup}
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
rootfs=$temporary/rootfs
mkdir -p "$rootfs/bin" "$rootfs/dev" "$rootfs/proc"
cp "$(command -v busybox)" "$rootfs/bin/busybox"
ln -s busybox "$rootfs/bin/sh"
run() { "$binary" --rootfs "$rootfs" --cgroup-parent "$parent" "$@"; }
expect_status() {
    expected=$1
    shift
    if "$@"; then actual=0; else actual=$?; fi
    [ "$actual" -eq "$expected" ] || { echo "expected $expected, got $actual" >&2; exit 1; }
}
groups() { find "$parent" -maxdepth 1 -type d -name 'contained-*' | sort; }
groups > "$temporary/before"
cc -static -Wall -Wextra -Werror tests/probe.c -o "$rootfs/bin/probe"
run -- /bin/probe
python3 tests/terminal.py "$binary" "$rootfs"
expect_status 37 run -- /bin/sh -c 'exit 37'
expect_status 125 run -- /missing
# The supervisor can itself be PID 1; child cleanup must still be isolated.
expect_status 125 unshare --pid --fork --mount-proc "$binary" \
    --rootfs "$rootfs" --cgroup-parent "$parent" -- /missing
expect_status 1 run -- /bin/busybox touch /blocked
run --writable-rootfs -- /bin/busybox touch /allowed
[ -f "$rootfs/allowed" ]
# A high inherited descriptor must not survive even after lowering NOFILE.
exec 100< "$rootfs/allowed"
run --nofile 32 -- /bin/sh -c 'test ! -e /proc/self/fd/100'
exec 100<&-
# Reject symlink mountpoints and clean up after failed child setup.
rmdir "$rootfs/proc"
ln -s /tmp "$rootfs/proc"
expect_status 125 run -- /bin/sh -c 'exit 0'
rm "$rootfs/proc"
mkdir "$rootfs/proc"
# Keep PID 1 alive long enough to inspect real cgroup controller values.
"$binary" --rootfs "$rootfs" --cgroup-parent "$parent" --memory 64M --cpu 25000/100000 --pids 16 --nofile 64 -- /bin/sh -c \
    'trap "exit 42" TERM; echo ready; while :; do /bin/busybox sleep 1; done' > "$temporary/output" &
supervisor=$!
for attempt in $(seq 1 100); do
    if grep -q ready "$temporary/output"; then break; fi
    sleep 0.05
done
grep -q ready "$temporary/output"
child=$(cat "/proc/$supervisor/task/$supervisor/children" | tr -d ' ')
group=$(awk -F: '$1 == "0" {print $3}' "/proc/$child/cgroup")
[ "$(cat "$parent$group/memory.max")" = 67108864 ]
[ "$(cat "$parent$group/memory.swap.max")" = 0 ]
[ "$(cat "$parent$group/cpu.max")" = '25000 100000' ]
[ "$(cat "$parent$group/pids.max")" = 16 ]
kill -TERM "$supervisor"
expect_status 42 wait "$supervisor"
groups > "$temporary/after"
cmp "$temporary/before" "$temporary/after"
echo 'lifecycle, resource and mount regression tests passed'
