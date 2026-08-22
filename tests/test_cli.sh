#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

binary=${1:-./contained}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/contained-cli.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

expect_status()
{
    expected=$1
    fragment=$2
    shift 2

    set +e
    "$binary" "$@" >"$temporary/stdout" 2>"$temporary/stderr"
    actual=$?
    set -e
    if [ "$actual" -ne "$expected" ]; then
        echo "expected status $expected, got $actual: $*" >&2
        cat "$temporary/stderr" >&2
        exit 1
    fi
    if ! cat "$temporary/stdout" "$temporary/stderr" | grep -F -- "$fragment" >/dev/null; then
        echo "missing diagnostic '$fragment': $*" >&2
        cat "$temporary/stdout" "$temporary/stderr" >&2
        exit 1
    fi
}

expect_status 0 "Usage:" --help
expect_status 2 "--rootfs is required" -- /bin/true
expect_status 2 "invalid memory limit" --rootfs /tmp --memory 0 -- /bin/true
expect_status 2 "invalid CPU limit" --rootfs /tmp --cpu 50000 -- /bin/true
expect_status 2 "invalid PID limit" --rootfs /tmp --pids many -- /bin/true
expect_status 2 "invalid file-descriptor limit" --rootfs /tmp --nofile 2 -- /bin/true
expect_status 2 "invalid hostname" --rootfs /tmp --hostname bad/name -- /bin/true
expect_status 2 "a command is required" --rootfs /tmp
expect_status 2 "resolve rootfs" --rootfs "$temporary/does-not-exist" -- /bin/true

printf '%s\n' "CLI validation tests passed"
