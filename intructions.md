# Using and Understanding Contained

Contained is a small, Linux-only container runtime for learning. It runs one
command in new Linux namespaces, gives it a separate root filesystem, applies
resource limits, and removes several kinds of privilege. It is useful for
learning how Docker-like isolation is assembled from kernel primitives. It is
not a production OCI runtime or a safe place to run untrusted code.

## Source size and automated verification

The C implementation totals 539 lines, excluding comments, blank lines, and
formatting-only lines such as a bare `}`; `tests/count_source_lines.awk` defines
that rule and `make test-lines` fails above the 550-line ceiling. Tests and
documentation are additional to the runtime source count.

For the complete automated Linux check on this Mac:

```sh
colima start
make test-docker
```

This uses the disposable Docker setup below and treats skipped integration tests
as failures. Linux 5.9+ is required; inherited descriptors are closed using
`close_range(2)` rather than an older-kernel fallback.

## Run it on this Mac

macOS cannot provide the Linux namespace and cgroup APIs directly. Colima runs
a Linux VM with Docker Engine, and the outer privileged Docker container gives
Contained the kernel features it needs for this experiment.

From a macOS terminal, start Colima and enter this project:

```sh
colima start
cd /Users/kuax/projects/deshaw/contained
```

Start a disposable Linux development container:

```sh
docker run --rm -it \
  --privileged \
  --cgroupns=private \
  --mount type=bind,src="$PWD",dst=/src,readonly \
  ubuntu:24.04 \
  bash -lc '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
      build-essential pkg-config libcap-dev libseccomp-dev busybox-static

    cp -a /src/. /work
    cd /work
    make clean
    make

    mkdir /sys/fs/cgroup/contained-runner
    echo "$$" > /sys/fs/cgroup/contained-runner/cgroup.procs
    echo "+memory +cpu +pids" > /sys/fs/cgroup/cgroup.subtree_control

    exec bash
  '
```

The source mount is read-only. The command copies it to `/work`, so compiling
Linux binaries does not leave architecture-specific build files in the macOS
checkout.

Inside the outer container, create a deliberately tiny root filesystem. Static
BusyBox supplies both the shell and basic commands, so no dynamic libraries are
needed inside the new root.

```sh
mkdir -p rootfs/bin rootfs/proc rootfs/dev
cp "$(command -v busybox)" rootfs/bin/busybox
ln -s busybox rootfs/bin/sh
```

Launch an interactive contained shell:

```sh
./contained \
  --rootfs ./rootfs \
  --memory 128M \
  --cpu 50000/100000 \
  --pids 32 \
  --nofile 128 \
  --hostname sandbox \
  --cgroup-parent /sys/fs/cgroup \
  -- /bin/sh
```

You are now inside the contained workload, whose prompt normally looks like
`/ #`. Try:

```sh
hostname
ulimit -n
cat /proc/self/status | grep -E 'CapEff|CapBnd|NoNewPrivs|Seccomp'
for namespace in uts mnt pid ipc net user; do
  printf '%s: ' "$namespace"
  readlink "/proc/self/ns/$namespace"
done
```

`exit` leaves the contained shell. A second `exit` leaves the outer Docker
container. `colima stop` stops the VM when you are finished.

## What the Docker setup does

`--privileged` is required only for this learning setup. It gives the outer
container permission to create namespaces, mount filesystems, and write its
cgroup tree. It is not a security boundary for an untrusted workload.

`--cgroupns=private` makes `/sys/fs/cgroup` inside the outer Docker container
refer to its own cgroup namespace rather than the Docker VM's whole hierarchy.
The setup command moves the outer shell into `contained-runner`, leaving the
cgroup root empty. cgroup v2 requires a parent cgroup to contain no processes
before it can enable domain controllers for child cgroups. The following write
then enables the three controllers that Contained needs:

```sh
echo "+memory +cpu +pids" > /sys/fs/cgroup/cgroup.subtree_control
```

Contained creates a fresh child cgroup under that root for each workload and
writes `memory.max`, `cpu.max`, `pids.max`, and related values there.

## The execution model

At a high level, the parent process configures a blocked child and then lets it
become the workload:

```text
outer shell
    |
    +-- contained parent
            |
            +-- clone(): blocked child in new user, PID, mount, UTS,
                         IPC, and network namespaces
            |
            +-- parent writes UID/GID maps and cgroup limits
            |
            +-- child builds its mount tree, drops privilege, loads seccomp
                    |
                    +-- execvp(): workload, such as /bin/sh
```

The six namespaces have different jobs:

| Namespace | Effect |
| --- | --- |
| User | Container UID 0 maps to the invoking host identity. |
| PID | The workload becomes PID 1 from the container's viewpoint. |
| Mount | Mount changes and the new root do not alter the outer environment. |
| UTS | The hostname is private. |
| IPC | System V IPC and POSIX message queues are separate. |
| Network | Starts without a configured external interface. |

## Read the code in this order

1. [`src/config.h`](src/config.h) defines the configuration structure and
   defaults.
2. [`src/config.c`](src/config.c) parses flags such as `--memory`, `--cpu`,
   and `--rootfs`. Start here if you want an approachable file.
3. [`src/contained.c`](src/contained.c) contains the runtime. Read its `main()`
   function first: it gives the top-level parent-side sequence.
4. In the same file, read `child_main()`. It is the sequence that runs inside
   the new namespaces before `execvp()` starts the workload.
5. Follow the helper functions called by `child_main()`:
   `setup_mount_tree()`, `drop_all_capabilities()`, and
   `install_seccomp_filter()`. Resource limits and descriptor closure are inline
   in `child_main()`. Parent failure paths share the `cleanup()` exit handler.
6. Read [`tests/integration.sh`](tests/integration.sh) alongside the runtime.
   It tells you which observable properties the project promises.

## Important implementation details

### Parent/child synchronization

The parent and child communicate through a `SOCK_SEQPACKET` socket pair. The
child sends `R` when it is ready for ID mapping. The parent then writes the
UID/GID maps in `/proc/<pid>/`, creates and configures the child cgroup, and
sends `G`. The child does no mount or privilege-sensitive work until it receives
that release token.

The parent writes `deny` to `/proc/<pid>/setgroups` before the one-entry GID
map. Linux requires that ordering for an unprivileged caller. That means
rootless Linux cannot clear the inherited supplementary-group list; the README
describes this boundary in more detail.

### Root filesystem and mounts

`setup_mount_tree()` makes mount propagation private, bind-mounts the supplied
rootfs, creates a new minimal `/dev`, mounts an isolated `/proc`, and calls
`pivot_root()`. `pivot_root()` changes the process's real root mount; unlike a
simple `chroot()`, it prevents the workload from retaining a path to the old
root through its current working directory.

The rootfs must contain empty `proc` and `dev` directories because they are
mount points. It is read-only unless `--writable-rootfs` is supplied. The new
`/dev` is a tmpfs with only a few device files and a private `devpts` instance.

### Limits

The runtime uses two layers of limits:

| Flag | cgroup v2 setting | Process limit |
| --- | --- | --- |
| `--memory 128M` | `memory.max` | `RLIMIT_AS` |
| `--cpu 50000/100000` | `cpu.max` | none |
| `--pids 32` | `pids.max` | `RLIMIT_NPROC` |
| `--nofile 128` | none | `RLIMIT_NOFILE` |

Cgroup limits cover the workload's cgroup; `setrlimit()` limits the process and
its descendants. Using both where possible is intentional: each has different
kernel semantics.

### Dropping privilege

Before executing the workload, the child:

1. Sets `no_new_privs` and disables dumpability.
2. Clears ambient, bounding, permitted, effective, and inheritable
   capabilities.
3. Locks securebits so set-user-ID behavior cannot restore those capabilities.
4. Closes inherited descriptors other than standard input, output, and error.
5. Installs a default-deny seccomp filter with a list of common runtime,
   filesystem, signal, and local-socket syscalls.

This is why `/proc/self/status` shows zero capability masks, `NoNewPrivs: 1`,
and `Seccomp: 2` in the workload.

### Interactive shells

The child is placed in its own process group so the parent can forward signals
to the workload and its descendants. If standard input is a terminal, the
parent also calls `tcsetpgrp()` to make that child group the terminal's
foreground group. Without that handoff an interactive shell is a background job
and cannot read your keystrokes. On exit, Contained restores the outer terminal
group.

## Experiments

Run each experiment from inside the contained `/bin/sh` shell unless noted.

### Check the private hostname

```sh
hostname
```

It should print `sandbox`, while the outer Docker shell has a different
hostname.

### Inspect namespaces

```sh
for namespace in uts mnt pid ipc net user; do
  printf '%s: ' "$namespace"
  readlink "/proc/self/ns/$namespace"
done
```

Run the same loop in the outer shell. The namespace inode labels should differ.

### Observe the open-file limit

```sh
ulimit -n
```

It should equal the `--nofile` value. Relaunch with `--nofile 64` and compare.

### See the security state

```sh
grep -E '^(CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status
```

### Test the read-only rootfs

```sh
touch /created-inside
```

It should fail by default. Exit, relaunch with `--writable-rootfs`, and run it
again. The file is created in `./rootfs` in the outer Docker container, which
is why that option is suitable only for a disposable tree.

### Check that network setup is absent

The BusyBox image here intentionally contains few networking tools, but the
new network namespace starts with no configured external interface. You can
compare `/proc/net/dev` inside and outside the runtime.

## Test and modify it

In the outer Docker shell, run:

```sh
make test
```

This runs parser/unit tests, CLI validation tests, and the isolation integration
test. If you change C source, rebuild with `make`. If you switch between macOS
and Linux builds in the same directory, run `make clean` first because object
files are architecture-specific.

Useful places to experiment safely:

- Add a new CLI option in `src/config.c`, then add parser coverage in
  `tests/test_config.c`.
- Add a syscall name to the seccomp allowlist, rebuild, and observe how a
  workload's behavior changes. Keep the default-deny design.
- Add a result to `tests/integration.sh` and make the runtime prove it.
- Change one resource limit at a time and inspect the cgroup files from the
  outer shell while the workload is running.

Do not point `--rootfs` at `/`, your home directory, or a directory containing
credentials, agent sockets, or container-engine sockets. Use a purpose-built,
disposable rootfs only.
