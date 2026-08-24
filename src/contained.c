/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/securebits.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024)
#define NAMESPACES (CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUSER)
static struct container_config config;
static volatile sig_atomic_t child_pid;
static int channel[2] = {-1, -1};
static pid_t owner, terminal_group;
static char cgroup[PATH_MAX];
static void *stack = MAP_FAILED;
static size_t stack_size;

static void fail(const char *operation)
{
    fprintf(stderr, "contained: %s: %s\n", operation, strerror(errno));
    exit(125);
}

/* One checked path writer handles both proc ID maps and cgroup interfaces. */
static void write_value(const char *directory, const char *name, const char *value)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", directory, name) >= (int)sizeof(path))
    {
        errno = ENAMETOOLONG;
        fail(directory);
    }
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        fail(path);
    ssize_t count;
    do
    {
        count = write(fd, value, strlen(value));
    } while (count < 0 && errno == EINTR);
    int error = count < 0 ? errno : EIO;
    int closed = close(fd);
    if (count != (ssize_t)strlen(value))
    {
        errno = error;
        fail(path);
    }
    if (closed < 0)
        fail(path);
}

static void token(int fd, char expected, bool sending)
{
    char value = expected;
    ssize_t count;
    do
    {
        count = sending ? send(fd, &value, 1, MSG_NOSIGNAL) : recv(fd, &value, 1, 0);
    } while (count < 0 && errno == EINTR);
    if (count != 1 || value != expected)
    {
        if (count >= 0)
            errno = EPIPE;
        fail("synchronize parent and child");
    }
}

static void forward_signal(int number)
{
    int saved = errno;
    if (child_pid > 0 && kill(-child_pid, number) < 0 && errno == ESRCH)
        (void)kill(child_pid, number);
    errno = saved;
}

static void signals(void (*handler)(int))
{
    const int numbers[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
    struct sigaction action = {.sa_handler = handler};
    sigemptyset(&action.sa_mask);
    for (size_t i = 0; i < sizeof(numbers) / sizeof(*numbers); ++i)
        if (sigaction(numbers[i], &action, NULL) < 0)
            fail("set signal handler");
}

/// ??????????
static int foreground(pid_t group)
{
    struct sigaction ignore = {.sa_handler = SIG_IGN}, previous;
    sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGTTOU, &ignore, &previous) < 0)
        return -1;
    int result = tcsetpgrp(STDIN_FILENO, group), saved = errno;
    if (sigaction(SIGTTOU, &previous, NULL) < 0)
        return -1;
    errno = saved;
    return result;
}

static void cleanup(void)
{
    if (getpid() != owner)
        return; /* Child failures must never clean the supervisor. */
    if (child_pid > 0)
    {
        (void)kill(child_pid, SIGKILL);
        while (waitpid(child_pid, NULL, 0) < 0 && errno == EINTR)
        {
        }
        child_pid = 0;
    }
    bool failed = terminal_group > 0 && foreground(terminal_group) < 0;
    if (cgroup[0])
    {
        /* Reaping PID 1 kills descendants; allow time for cgroup accounting to drain. */
        int result = -1;
        for (int i = 0; i < 50 && result < 0; ++i)
        {
            result = rmdir(cgroup);
            if (result < 0 && errno != EBUSY && errno != ENOTEMPTY)
                break;
            if (result < 0)
                nanosleep(&(struct timespec){.tv_nsec = 10000000}, NULL);
        }
        if (result < 0)
        {
            perror("contained: remove cgroup");
            failed = true;
        }
    }
    for (int i = 0; i < 2; ++i)
        if (channel[i] >= 0)
            close(channel[i]);
    if (stack != MAP_FAILED)
        munmap(stack, stack_size);
    if (failed)
        _Exit(125);
}

static void configure_child(pid_t pid)
{
    char path[PATH_MAX], value[128];
    snprintf(path, sizeof(path), "/proc/%ld", (long)pid);
    write_value(path, "setgroups", "deny\n"); // Linux requires this before an ordinary, non-root parent is allowed to create the child’s GID mapping.
    snprintf(value, sizeof(value), "0 %lu 1\n", (unsigned long)getuid()); // allows current user to be root inside the container
    write_value(path, "uid_map", value);
    snprintf(value, sizeof(value), "0 %lu 1\n", (unsigned long)getgid());
    write_value(path, "gid_map", value);
    write_value(config.cgroup_parent, "cgroup.subtree_control", "+memory +cpu +pids");
    //XXXXXX is placeholder for now
    if (snprintf(path, sizeof(path), "%s/contained-XXXXXX", config.cgroup_parent) >= (int)sizeof(path))
    {
        errno = ENAMETOOLONG;
        fail("cgroup path");
    }
    //XXXXXXX is modified here with random unique number
    if (!mkdtemp(path))
        fail("create delegated cgroup");
    
    //copy path to cgroup
    strcpy(cgroup, path);
    snprintf(value, sizeof(value), "%" PRIu64, config.memory_bytes);
    write_value(cgroup, "memory.max", value);
    write_value(cgroup, "memory.swap.max", "0");
    write_value(cgroup, "memory.oom.group", "1");
    snprintf(value, sizeof(value), "%" PRIu64 " %" PRIu64, config.cpu.quota, config.cpu.period);
    write_value(cgroup, "cpu.max", value);
    snprintf(value, sizeof(value), "%" PRIu64, config.pids);
    write_value(cgroup, "pids.max", value);
    //child added to cgroup procs
    snprintf(value, sizeof(value), "%ld", (long)pid);
    write_value(cgroup, "cgroup.procs", value);
}

static void setup_mount_tree(void)
{
    const unsigned long restricted = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    struct stat status;
    /*
     * clone(CLONE_NEWNS) already gave this child a copy of the parent's
     * mount map.  It can still see the parent's files at this point.
     * MS_PRIVATE only stops future mount/unmount changes from appearing in
     * the parent; it does not copy files or hide host paths.
     */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0 ||
        /* Make rootfs its own mount so we can later set flags on this view. */
        mount(config.rootfs, config.rootfs, NULL, MS_BIND, NULL) < 0 ||
        /* Keep mount changes to that new rootfs mount in this namespace. */
        mount(NULL, config.rootfs, NULL, MS_PRIVATE, NULL) < 0 || chdir(config.rootfs) < 0)
        fail("bind private root filesystem");
    // checks that proc and dev exist
    const char *points[] = {"proc", "dev"};
    for (int i = 0; i < 2; ++i)
    {
        if (lstat(points[i], &status) < 0)
            fail("inspect rootfs mountpoint");
        if (!S_ISDIR(status.st_mode))
        {
            errno = ENOTDIR;
            fail("rootfs mountpoint");
        }
    }
    /*
     * Put a blank, temporary filesystem over rootfs/dev.  New entries here
     * exist only in this child and vanish when it exits; host /dev is unchanged.
     */
    if (mount("tmpfs", "dev", "tmpfs", restricted, "mode=755,size=4m") < 0)
        fail("mount minimal /dev");
    /*
     * tmpfs is only the private /dev layout.  For each selected device below,
     * create an empty target, then bind-mount the real host device onto it.
     * This deliberately exposes null/zero/etc., but not the entire host /dev.
     */
    const char *devices[] = {"null", "zero", "full", "random", "urandom", "tty"};
    for (size_t i = 0; i < sizeof(devices) / sizeof(*devices); ++i)
    {
        char source[32], target[32];
        snprintf(source, sizeof(source), "/dev/%s", devices[i]);
        snprintf(target, sizeof(target), "dev/%s", devices[i]);
        if (lstat(source, &status) < 0)
        {
            if (i == 5 && errno == ENOENT)
                continue;
            fail(source);
        }
        int fd = open(target, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0666);
        if (fd < 0 || close(fd) < 0 || mount(source, target, NULL, MS_BIND, NULL) < 0)
            fail("bind device");
    }
    /* devpts supplies private pseudo-terminals; /dev/shm is temporary shared memory. */
    if (mkdir("dev/pts", 0755) < 0 || mkdir("dev/shm", 01777) < 0 ||
        mount("devpts", "dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
              "newinstance,ptmxmode=0666,mode=0620,gid=0") < 0 ||
        mount("tmpfs", "dev/shm", "tmpfs", restricted, "mode=1777,size=16m") < 0)
        fail("mount devpts and shared memory");
    const char *links[][2] = {{"pts/ptmx", "dev/ptmx"}, {"/proc/self/fd", "dev/fd"}, {"/proc/self/fd/0", "dev/stdin"}, {"/proc/self/fd/1", "dev/stdout"}, {"/proc/self/fd/2", "dev/stderr"}};
    for (size_t i = 0; i < sizeof(links) / sizeof(*links); ++i)
        if (symlink(links[i][0], links[i][1]) < 0)
            fail("link standard devices");
    if (mount("proc", "proc", "proc", restricted, NULL) < 0)
        fail("mount isolated /proc");
    /*
     * pivot_root needs an empty directory under the new root where Linux can
     * temporarily place the old host root.  We remove it again before making
     * the rootfs read-only, so it never remains in the supplied rootfs.
     */
    if (mkdir(".old-root", 0700) < 0)
        fail("create old-root mountpoint");
    unsigned long flags = MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV;
    if (!config.writable_rootfs)
        flags |= MS_RDONLY;
    /*
     * Make the prepared rootfs become /.  Linux temporarily places the old
     * host root at /.old-root, which is then explicitly detached and removed.
     */
    if (syscall(SYS_pivot_root, ".", ".old-root") < 0 || chdir("/") < 0 ||
        umount2("/.old-root", MNT_DETACH) < 0 || rmdir("/.old-root") < 0)
        fail("pivot root and detach old root");
    if (mount(NULL, "/", NULL, flags, NULL) < 0)
        fail("apply rootfs mount flags");
}

static void drop_all_capabilities(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) < 0 ||
        prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) < 0 ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L) < 0)
        fail("disable privilege gains");
    /* Probe the running kernel, including capabilities newer than our headers. */
    for (int cap = 0;; ++cap)
    {
        if (prctl(PR_CAPBSET_READ, cap, 0L, 0L, 0L) < 0)
        {
            if (errno == EINVAL)
                break;
            fail("read capability bounding set");
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0L, 0L, 0L) < 0)
            fail("drop capability");
    }
    unsigned long bits = SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
                         SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS_LOCKED;
    if (prctl(PR_SET_SECUREBITS, bits, 0L, 0L, 0L) < 0)
        fail("lock securebits");
    cap_t empty = cap_init();
    if (!empty || cap_set_proc(empty) < 0)
        fail("clear capability sets");
    if (cap_free(empty) < 0)
        fail("free capability sets");
}

static void seccomp_check(int result)
{
    if (result < 0)
    {
        errno = -result;
        fail("install seccomp allowlist");
    }
}

static void install_seccomp_filter(void)
{
    /* Default-deny; namespace creation and privileged kernel APIs stay absent. */
    static const char *const calls[] = {
        "execve", "exit", "exit_group", "fork", "vfork", "wait4", "waitid",
        "getpid", "getppid", "gettid", "getpgrp", "getpgid", "getsid",
        "setpgid", "setsid", "kill", "tkill", "tgkill",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend",
        "rt_sigtimedwait", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "sigaltstack",
        "restart_syscall", "set_tid_address", "set_robust_list",
        "get_robust_list", "futex", "futex_waitv", "rseq", "membarrier",
        "sched_yield", "sched_getaffinity", "sched_setaffinity",
        "sched_getparam", "sched_getscheduler", "sched_get_priority_max",
        "sched_get_priority_min", "getpriority", "setpriority",
        "prlimit64", "getrlimit", "getrusage", "times", "uname", "sysinfo",
        "getuid", "geteuid", "getgid", "getegid", "getresuid", "getresgid",
        "getgroups", "capget", "prctl", "personality",
        "brk", "mmap", "mmap2", "munmap", "mprotect", "mremap", "madvise",
        "mincore", "msync", "arch_prctl", "set_thread_area",
        "get_thread_area", "modify_ldt", "clock_gettime", "clock_getres",
        "clock_nanosleep", "nanosleep", "gettimeofday", "time", "getrandom",
        "read", "write", "readv", "writev", "pread64", "pwrite64",
        "preadv", "pwritev", "preadv2", "pwritev2", "lseek", "_llseek",
        "close", "close_range", "dup", "dup2", "dup3", "fcntl", "fcntl64",
        "ioctl", "flock", "pipe", "pipe2", "poll", "ppoll", "select",
        "_newselect", "pselect6", "epoll_create", "epoll_create1",
        "epoll_ctl", "epoll_wait", "epoll_pwait", "epoll_pwait2",
        "eventfd", "eventfd2", "signalfd", "signalfd4", "timerfd_create",
        "timerfd_settime", "timerfd_gettime", "inotify_init", "inotify_init1",
        "inotify_add_watch", "inotify_rm_watch", "open", "openat", "openat2",
        "creat", "access", "faccessat", "faccessat2", "stat", "lstat",
        "fstat", "newfstatat", "statx", "statfs", "fstatfs", "getdents",
        "getdents64", "getcwd", "chdir", "fchdir", "readlink", "readlinkat",
        "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat", "rename",
        "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat",
        "truncate", "ftruncate", "chmod", "fchmod", "fchmodat", "chown",
        "fchown", "lchown", "fchownat", "umask", "utime", "utimes",
        "futimesat", "utimensat", "fsync", "fdatasync", "sync_file_range",
        "readahead", "sendfile", "splice", "tee", "vmsplice", "copy_file_range",
        "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
        "flistxattr", "setxattr", "lsetxattr", "fsetxattr", "removexattr",
        "lremovexattr", "fremovexattr", "memfd_create",

        "bind", "listen", "accept", "accept4", "connect", "shutdown",
        "getsockname", "getpeername", "getsockopt", "setsockopt", "sendto",
        "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    };
    scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!filter)
        fail("create seccomp filter");
    seccomp_check(seccomp_attr_set(filter, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS));
    for (size_t i = 0; i < sizeof(calls) / sizeof(*calls); ++i)
    {
        int number = seccomp_syscall_resolve_name(calls[i]);
        if (number != __NR_SCMP_ERROR)
            seccomp_check(seccomp_rule_add(filter, SCMP_ACT_ALLOW, number, 0));
    }
    seccomp_check(seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
                                   SCMP_CMP(0, SCMP_CMP_EQ, AF_UNIX)));
    seccomp_check(seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 1,
                                   SCMP_CMP(0, SCMP_CMP_EQ, AF_UNIX)));
    uint64_t forbidden = NAMESPACES | CLONE_NEWCGROUP | CLONE_NEWTIME |
                         CLONE_PTRACE | CLONE_UNTRACED | CLONE_PARENT;
    seccomp_check(seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                                   SCMP_CMP(0, SCMP_CMP_MASKED_EQ, forbidden, 0)));
    /* libc can fall back to filtered clone when clone3 is unavailable. */
    seccomp_check(seccomp_rule_add(filter, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0));
    seccomp_check(seccomp_load(filter));
    seccomp_release(filter);
}

static int child_main(void *unused)
{
    (void)unused;
    owner = -1; /* PID 1 can exist in both the parent and child namespaces. */
    signals(SIG_DFL); // set the signals to default
    close(channel[0]); // close the parent end of socker
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0L, 0L, 0L) < 0 || setpgid(0, 0) < 0) // prctl: ?? setpgid: se the id of the process group to the process id.
    // process groups are usefull because they allow termination of all processes in the group with ctrl+c
        fail("initialize child supervision");
    token(channel[1], 'R', true);
    token(channel[1], 'G', false);

    // ---
    close(channel[1]);
    if (setresgid(0, 0, 0) < 0 || setresuid(0, 0, 0) < 0 ||
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0L, 0L, 0L) < 0)
        fail("switch to mapped identity");
    if (sethostname(config.hostname, strlen(config.hostname)) < 0)
        fail("set hostname");
    umask(0022);
    // --- dk

    setup_mount_tree();
    drop_all_capabilities();
    const int resources[] = {RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_AS, RLIMIT_CORE, RLIMIT_MEMLOCK};
    const uint64_t values[] = {config.nofile, config.pids, config.memory_bytes, 0, 0};
    for (size_t i = 0; i < sizeof(resources) / sizeof(*resources); ++i)
    {
        struct rlimit limit = {.rlim_cur = values[i], .rlim_max = values[i]};
        if ((uint64_t)limit.rlim_cur != values[i])
        {
            errno = EOVERFLOW;
            fail("resource limit");
        }
        if (setrlimit(resources[i], &limit) < 0)
            fail("apply resource limit");
    }
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) < 0)
        fail("close inherited descriptors");
    install_seccomp_filter();
    execvp(config.command[0], config.command);
    fail("exec workload");
    return 125;
}

int main(int argc, char **argv)
{
    int parsed = config_parse(&config, argc, argv, stderr);
    if (parsed == CONFIG_PARSE_HELP)
    {
        config_print_usage(stdout, argv[0]);
        return 0;
    }
    if (parsed != CONFIG_PARSE_OK)
        return 2;
    char rootfs[PATH_MAX], parent[PATH_MAX], hostname[65];
    if (!realpath(config.rootfs, rootfs))
    {
        perror("contained: resolve rootfs");
        return 2;
    }
    if (!strcmp(rootfs, "/"))
    {
        fputs("contained: refusing '/' as rootfs\n", stderr);
        return 2;
    }
    if (!realpath(config.cgroup_parent, parent))
    {
        perror("contained: resolve cgroup parent");
        return 2;
    }
    struct stat status;
    if (stat(rootfs, &status) < 0 || !S_ISDIR(status.st_mode) ||
        stat(parent, &status) < 0 || !S_ISDIR(status.st_mode))
    {
        fputs("contained: rootfs and cgroup parent must be directories\n", stderr);
        return 2;
    }
    config.rootfs = rootfs;
    config.cgroup_parent = parent;
    snprintf(hostname, sizeof(hostname), "contained-%ld", (long)getpid());
    if (!config.hostname)
        config.hostname = hostname;
    owner = getpid();

    if (atexit(cleanup) != 0)
        fail("register cleanup");
    signals(forward_signal);
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) < 0) // creates a two way road for messaging
        fail("socketpair");
    long page = sysconf(_SC_PAGESIZE);

    if (page <= 0)
        fail("read page size");
    // 2 * page ebcause 
    // first guard page -> usable_stack -> last guard page
    stack_size = STACK_SIZE + 2 * (size_t)page; 
    // that gets a pointer to the stack_size but it is locked
    stack = mmap(NULL, stack_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    // that unlocks the usable_stack portion of the stack pointer after skipping guard
    if (stack == MAP_FAILED || mprotect((char *)stack + page, STACK_SIZE, PROT_READ | PROT_WRITE) < 0)
        fail("allocate guarded child stack");
    //  this gives pointer to the end of the usable_stack
    pid_t pid = clone(child_main, (char *)stack + page + STACK_SIZE, NAMESPACES | SIGCHLD, NULL);
    if (pid < 0)
        fail("clone six namespaces");
    child_pid = pid;
    // close the parent's child copy because if child exists this would still be open: causing problems when waiting because we cannot guarentee nobody will send a messafe again
    close(channel[1]);
    channel[1] = -1;
    token(channel[0], 'R', false); /* Child has installed its process group. */
    if (isatty(STDIN_FILENO))
    {
        terminal_group = tcgetpgrp(STDIN_FILENO);
        if (terminal_group < 0 || foreground(pid) < 0)
            fail("transfer foreground terminal");
    }
    configure_child(pid);
    token(channel[0], 'G', true);
    close(channel[0]);
    channel[0] = -1;
    int result;
    while (waitpid(pid, &result, 0) < 0)
        if (errno != EINTR)
            fail("wait for child");
    child_pid = 0;
    return WIFEXITED(result) ? WEXITSTATUS(result) : 128 + WTERMSIG(result);
}
