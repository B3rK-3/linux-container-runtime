# Contained

Contained is a small Linux container-runtime CLI written in C. It starts one command in a new set of kernel namespaces, gives that command a private root mount, applies cgroup v2 and `setrlimit(2)` resource ceilings, removes Linux capabilities, and installs a default-deny libseccomp filter. It is intended for learning and controlled local experiments, not as a replacement for a maintained OCI runtime.

## Prerequisites

- Linux with user namespaces and cgroup v2 enabled
- a writable cgroup v2 parent delegated with the `memory`, `cpu`, and `pids` controllers
- a C11 compiler, GNU make, `pkg-config`, libcap development headers, and libseccomp 2.5 or newer
- a dedicated root filesystem containing the workload and its libraries, plus real `/proc` and `/dev` directories to use as mountpoints

On Debian or Ubuntu, the build dependencies are typically:

```sh
sudo apt install build-essential pkg-config libcap-dev libseccomp-dev
make
```

Rootless namespace creation may be disabled by distribution policy. Cgroup delegation is separate from user-namespace support: either run in a service/scope with `Delegate=yes`, pass its cgroup path with `--cgroup-parent`, or run as root on a host where the selected parent can enable controllers. Contained fails rather than silently running without a requested isolation layer.

## Safe example

Use a disposable, purpose-built image—not `/`, a home directory, or a tree containing host control sockets. For example, after extracting a minimal distribution image at `./rootfs` and ensuring `rootfs/proc` and `rootfs/dev` exist:

```sh
sudo ./contained \
  --rootfs ./rootfs \
  --memory 128M \
  --cpu 50000/100000 \
  --pids 32 \
  --nofile 128 \
  --hostname demo-box \
  --cgroup-parent /sys/fs/cgroup \
  -- /bin/sh
```

The root filesystem is read-only by default. `--writable-rootfs` opts into writes to the supplied tree. Memory suffixes `K`, `M`, `G`, `KiB`, `MiB`, and `GiB` are binary multiples. CPU is the exact cgroup v2 `QUOTA/PERIOD` pair in microseconds; `50000/100000` permits half of one CPU. Run `./contained --help` for all options and defaults.

## Architecture and setup order

The parent validates paths and allocates a 1 MiB `mmap`-backed child stack with inaccessible guard pages. It then calls `clone(2)` once, requesting exactly these six namespaces:

1. **UTS** (`CLONE_NEWUTS`)
2. **mount** (`CLONE_NEWNS`)
3. **PID** (`CLONE_NEWPID`)
4. **IPC** (`CLONE_NEWIPC`)
5. **network** (`CLONE_NEWNET`)
6. **user** (`CLONE_NEWUSER`)

A `SOCK_SEQPACKET` synchronization channel keeps the child blocked. Before the parent changes `/proc/<pid>/setgroups`, the child clears inherited supplementary groups and sends a ready token. The parent writes `deny` to `setgroups`, maps container UID/GID 0 to the invoking real UID/GID, creates a unique cgroup, writes `memory.max`, `memory.swap.max`, `cpu.max`, and `pids.max`, and moves the blocked child into it. Only then does it release the child.

The child becomes PID 1 in the new PID namespace and performs privileged setup while it still has capabilities in its new user namespace:

1. switch to mapped UID/GID 0 and set the UTS hostname;
2. recursively make host mount propagation private;
3. bind the supplied rootfs, apply `nosuid`/`nodev` and read-only flags, and construct a fresh `/dev` tmpfs with only null/zero/full/random/urandom, optional tty, a private devpts instance, and `/dev/shm`;
4. use `pivot_root(2)` and detach the old root, then mount a PID-namespace-specific `/proc`;
5. set `no_new_privs`, disable dumpability, empty the capability bounding, permitted, effective, inheritable, and ambient sets, and lock securebits;
6. apply `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`, `RLIMIT_CORE`, and `RLIMIT_MEMLOCK` bounds;
7. close every inherited file descriptor except standard input/output/error;
8. load the seccomp allowlist and `execvp(3)` the workload.

The parent forwards `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` to the child's process group and returns the workload's exit status. A parent-death signal kills a child whose supervisor disappears. On normal exit and every handled setup failure, the parent aborts/reaps the child, asks cgroup v2 to kill stragglers, retries cgroup removal while descendants drain, closes synchronization descriptors, and unmaps the dedicated stack. Namespace-owned mounts disappear with the child mount namespace.

## Resource flags

| Flag | Enforcement |
| --- | --- |
| `--memory SIZE` | `memory.max`, no swap via `memory.swap.max`, and `RLIMIT_AS` |
| `--cpu QUOTA/PERIOD` | cgroup v2 `cpu.max` |
| `--pids COUNT` | cgroup v2 `pids.max` and `RLIMIT_NPROC` |
| `--nofile COUNT` | soft and hard `RLIMIT_NOFILE` |

Core dumps and memory locking are independently bounded to zero. A limit that the kernel or current hard limits cannot apply is a fatal setup error.

## Security boundaries

- The user namespace maps only one UID and one GID. Container root is the invoking host identity; it is **not** permission to files that identity could not already access. Running Contained as host root maps container root to host root and therefore weakens this boundary.
- The mount namespace does not make unsafe rootfs contents safe. Do not include Docker/containerd sockets, SSH agents, credentials, device nodes, or bind mounts into host data. The host root `/` is explicitly rejected.
- The network namespace starts with no configured external interface. Seccomp permits creation of `AF_UNIX` sockets only; internet sockets, namespace manipulation, mounts, `ptrace`, eBPF, perf events, keyrings, kernel modules, and reboot operations remain denied by the default action.
- Capabilities are dropped only after mount and hostname setup. File capabilities cannot restore them because the bounding set is empty and `no_new_privs` is set.
- Seccomp reduces syscall attack surface but is not a proof against kernel vulnerabilities. The allowlist includes broad file I/O and `ioctl` needed by ordinary dynamically linked programs.
- There is no LSM policy, image verification, encrypted storage, virtual machine boundary, network setup, or OCI lifecycle support. `SIGKILL`, host crashes, and forced power loss can leave a cgroup directory that an administrator must remove after it is empty.

## Checks

```sh
make test-unit
make test-cli
make test-integration
make test
```

The unit check covers byte/count/CPU parsing, hostname validation, and complete option parsing without requiring privilege. The CLI check covers user-facing validation diagnostics on Linux. The integration check verifies all six namespace identities, hostname isolation, the file-descriptor limit, empty effective/bounding capability sets, `no_new_privs`, and seccomp mode. It exits with status 77 (reported as a skip by the Makefile) on non-Linux hosts or when user namespaces, required mount permissions, a delegated cgroup v2 parent, or a usable test rootfs are unavailable. Set `CONTAINED_TEST_ROOTFS` and optionally `CONTAINED_CGROUP_PARENT` for CI. A static BusyBox rootfs is created automatically when available.

## Source attribution

This project is an original, modern cgroup-v2 implementation inspired by Lizzie Dixon's **[Linux containers in 500 lines of code](https://blog.lizzie.io/linux-containers-in-500-loc.html)**. That article's discussion of namespace synchronization, mount isolation, capabilities, syscall filtering, and resource controls informed this design; the implementation here is adapted for the behavior and CLI documented above.
