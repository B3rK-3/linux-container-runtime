#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

binary=${1:-./contained}

skip()
{
    echo "SKIP: $*" >&2
    exit 77
}

fail()
{
    echo "FAIL: $*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || skip "Linux is required"
[ -x "$binary" ] || fail "runtime binary is missing: $binary"
[ -r /proc/self/ns/user ] || skip "namespace procfs entries are unavailable"
[ -r /sys/fs/cgroup/cgroup.controllers ] || skip "cgroup v2 is unavailable"

if command -v unshare >/dev/null 2>&1; then
    unshare --user --map-root-user true >/dev/null 2>&1 || \
        skip "user namespaces are disabled by host policy"
elif [ "$(id -u)" -ne 0 ]; then
    skip "cannot probe user namespaces without unshare"
fi

cgroup_parent=${CONTAINED_CGROUP_PARENT:-/sys/fs/cgroup}
[ -r "$cgroup_parent/cgroup.controllers" ] || \
    skip "cgroup parent is not a v2 cgroup: $cgroup_parent"
probe="$cgroup_parent/contained-test-probe-$$"
mkdir "$probe" >/dev/null 2>&1 || \
    skip "cgroup parent is not delegated for child creation: $cgroup_parent"
probe_ok=true
for interface in memory.max cpu.max pids.max cgroup.procs; do
    [ -e "$probe/$interface" ] || probe_ok=false
done
rmdir "$probe" >/dev/null 2>&1 || true
[ "$probe_ok" = true ] || skip "memory, CPU, and PID controllers are not delegated"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/contained-integration.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

rootfs=${CONTAINED_TEST_ROOTFS:-}
inside_readlink=
inside_applet=
if [ -n "$rootfs" ]; then
    [ -d "$rootfs/proc" ] && [ -d "$rootfs/dev" ] || \
        skip "CONTAINED_TEST_ROOTFS must contain /proc and /dev directories"
    [ -x "$rootfs/bin/sh" ] || skip "test rootfs has no /bin/sh"
    if [ -x "$rootfs/usr/bin/readlink" ]; then
        inside_readlink=/usr/bin/readlink
    elif [ -x "$rootfs/bin/readlink" ]; then
        inside_readlink=/bin/readlink
    elif [ -x "$rootfs/bin/busybox" ]; then
        inside_readlink=/bin/busybox
        inside_applet=readlink
    else
        skip "test rootfs has no readlink implementation"
    fi
else
    busybox=$(command -v busybox 2>/dev/null || true)
    [ -n "$busybox" ] || skip "set CONTAINED_TEST_ROOTFS or install static busybox"
    linkage=$(ldd "$busybox" 2>&1 || true)
    case "$linkage" in
        *"not a dynamic executable"*|*"statically linked"*) ;;
        *) skip "available busybox is dynamic; set CONTAINED_TEST_ROOTFS" ;;
    esac
    rootfs="$temporary/rootfs"
    mkdir -p "$rootfs/bin" "$rootfs/proc" "$rootfs/dev"
    cp "$busybox" "$rootfs/bin/busybox"
    ln -s busybox "$rootfs/bin/sh"
    inside_readlink=/bin/busybox
    inside_applet=readlink
fi

command -v readlink >/dev/null 2>&1 || skip "host readlink command is required"
for namespace in uts mnt pid ipc net user; do
    eval "host_$namespace=\$(readlink /proc/self/ns/$namespace)"
done

set +e
"$binary" \
    --rootfs "$rootfs" \
    --memory 64M \
    --cpu 25000/100000 \
    --pids 16 \
    --nofile 64 \
    --hostname contained-test \
    --cgroup-parent "$cgroup_parent" \
    -- /bin/sh -c '
        IFS= read -r host < /proc/sys/kernel/hostname
        printf "hostname=%s\n" "$host"
        printf "nofile=%s\n" "$(ulimit -n)"
        for namespace in uts mnt pid ipc net user; do
            if [ -n "$2" ]; then
                value=$("$1" "$2" "/proc/self/ns/$namespace")
            else
                value=$("$1" "/proc/self/ns/$namespace")
            fi
            printf "ns.%s=%s\n" "$namespace" "$value"
        done
        while IFS=: read -r key value; do
            case "$key" in
                CapEff|CapBnd|NoNewPrivs|Seccomp)
                    value=${value#"${value%%[![:space:]]*}"}
                    printf "status.%s=%s\n" "$key" "$value"
                    ;;
            esac
        done < /proc/self/status
    ' contained-test "$inside_readlink" "$inside_applet" \
    >"$temporary/output" 2>"$temporary/error"
status=$?
set -e

if [ "$status" -ne 0 ]; then
    if grep -E "clone six namespaces|user-namespace policy|cgroup controller|delegated cgroup|child (make mount propagation private|bind root filesystem|make root bind private|construct minimal /dev|apply rootfs mount flags|pivot root|detach old root|mount isolated /proc): (Operation not permitted|Permission denied)" \
        "$temporary/error" >/dev/null 2>&1; then
        skip "host policy does not permit the required namespace/mount/cgroup setup"
    fi
    cat "$temporary/error" >&2
    fail "contained exited with status $status"
fi

contains_line()
{
    grep -Fx "$1" "$temporary/output" >/dev/null 2>&1 || \
        fail "missing result: $1"
}

contains_line "hostname=contained-test"
contains_line "nofile=64"
contains_line "status.CapEff=0000000000000000"
contains_line "status.CapBnd=0000000000000000"
contains_line "status.NoNewPrivs=1"
contains_line "status.Seccomp=2"

for namespace in uts mnt pid ipc net user; do
    child_value=$(sed -n "s/^ns\.$namespace=//p" "$temporary/output")
    [ -n "$child_value" ] || fail "missing $namespace namespace result"
    eval "host_value=\$host_$namespace"
    [ "$child_value" != "$host_value" ] || \
        fail "$namespace namespace was not isolated"
done

printf '%s\n' "isolation integration test passed"
