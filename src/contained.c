/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "config.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHILD_STACK_SIZE (1024U * 1024U)
#define CHILD_SETUP_FAILURE 125
#define CGROUP_CLEANUP_ATTEMPTS 50
#define ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

struct child_context {
    const struct container_config *config;
    int sync_read;
    int sync_write;
};

struct child_stack {
    void *mapping;
    size_t mapping_size;
    void *top;
};

struct cgroup_state {
    char path[PATH_MAX];
    bool created;
};

static volatile sig_atomic_t supervised_pid = -1;

static int write_text_file(const char *path, const char *text)
{
    size_t length = strlen(text);
    ssize_t written;
    int descriptor;
    int saved_errno;

    descriptor = open(path, O_WRONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return -1;
    }
    do {
        written = write(descriptor, text, length);
    } while (written < 0 && errno == EINTR);
    if (written < 0) {
        saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
        return -1;
    }
    if ((size_t)written != length) {
        close(descriptor);
        errno = EIO;
        return -1;
    }
    if (close(descriptor) < 0) {
        return -1;
    }
    return 0;
}

static int read_text_file(const char *path, char *buffer, size_t capacity)
{
    ssize_t count;
    int descriptor;
    int saved_errno;

    if (capacity < 2U) {
        errno = EINVAL;
        return -1;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return -1;
    }
    do {
        count = read(descriptor, buffer, capacity - 1U);
    } while (count < 0 && errno == EINTR);
    if (count < 0) {
        saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
        return -1;
    }
    buffer[count] = '\0';
    if (close(descriptor) < 0) {
        return -1;
    }
    return 0;
}

static int join_path(char *destination,
                     size_t capacity,
                     const char *directory,
                     const char *name)
{
    int length = snprintf(destination, capacity, "%s/%s", directory, name);

    if (length < 0 || (size_t)length >= capacity) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static bool contains_word(const char *words, const char *wanted)
{
    size_t wanted_length = strlen(wanted);
    const char *cursor = words;

    while (*cursor != '\0') {
        const char *start;
        size_t length;

        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n') {
            ++cursor;
        }
        start = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
               *cursor != '\n') {
            ++cursor;
        }
        length = (size_t)(cursor - start);
        if (length == wanted_length && strncmp(start, wanted, length) == 0) {
            return true;
        }
    }
    return false;
}

static int write_proc_map(pid_t pid, const char *file, const char *value)
{
    char path[128];
    int length = snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, file);

    if (length < 0 || (size_t)length >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (write_text_file(path, value) < 0) {
        fprintf(stderr, "contained: write %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int configure_id_maps(pid_t pid, uid_t uid, gid_t gid)
{
    char mapping[96];
    char setgroups_path[128];
    int length;

    length = snprintf(setgroups_path, sizeof(setgroups_path),
                      "/proc/%ld/setgroups", (long)pid);
    if (length < 0 || (size_t)length >= sizeof(setgroups_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (write_text_file(setgroups_path, "deny\n") < 0 && errno != ENOENT) {
        fprintf(stderr, "contained: write %s: %s\n", setgroups_path,
                strerror(errno));
        return -1;
    }

    length = snprintf(mapping, sizeof(mapping), "0 %lu 1\n",
                      (unsigned long)uid);
    if (length < 0 || (size_t)length >= sizeof(mapping)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (write_proc_map(pid, "uid_map", mapping) < 0) {
        return -1;
    }

    length = snprintf(mapping, sizeof(mapping), "0 %lu 1\n",
                      (unsigned long)gid);
    if (length < 0 || (size_t)length >= sizeof(mapping)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (write_proc_map(pid, "gid_map", mapping) < 0) {
        return -1;
    }
    return 0;
}

static int enable_cgroup_controllers(const char *parent)
{
    static const char *const required[] = {"memory", "cpu", "pids"};
    char controllers_path[PATH_MAX];
    char subtree_path[PATH_MAX];
    char available[4096];
    char enabled[4096];
    char request[128] = {0};
    size_t used = 0U;

    if (join_path(controllers_path, sizeof(controllers_path), parent,
                  "cgroup.controllers") < 0 ||
        join_path(subtree_path, sizeof(subtree_path), parent,
                  "cgroup.subtree_control") < 0) {
        return -1;
    }
    if (read_text_file(controllers_path, available, sizeof(available)) < 0) {
        fprintf(stderr,
                "contained: read %s: %s (a cgroup v2 parent is required)\n",
                controllers_path, strerror(errno));
        return -1;
    }
    if (read_text_file(subtree_path, enabled, sizeof(enabled)) < 0) {
        fprintf(stderr, "contained: read %s: %s\n", subtree_path,
                strerror(errno));
        return -1;
    }

    for (size_t i = 0; i < ARRAY_LENGTH(required); ++i) {
        int count;

        if (!contains_word(available, required[i])) {
            fprintf(stderr,
                    "contained: cgroup controller '%s' is not delegated at %s\n",
                    required[i], parent);
            errno = ENODEV;
            return -1;
        }
        if (contains_word(enabled, required[i])) {
            continue;
        }
        count = snprintf(request + used, sizeof(request) - used, "+%s%s",
                         required[i], i + 1U == ARRAY_LENGTH(required) ? "" : " ");
        if (count < 0 || (size_t)count >= sizeof(request) - used) {
            errno = EOVERFLOW;
            return -1;
        }
        used += (size_t)count;
    }

    if (used != 0U && write_text_file(subtree_path, request) < 0) {
        fprintf(stderr,
                "contained: enable cgroup controllers in %s: %s; use a writable, "
                "delegated cgroup parent\n",
                subtree_path, strerror(errno));
        return -1;
    }
    return 0;
}

static int write_cgroup_value(const char *group,
                              const char *file,
                              const char *value,
                              bool optional)
{
    char path[PATH_MAX];

    if (join_path(path, sizeof(path), group, file) < 0) {
        return -1;
    }
    if (write_text_file(path, value) < 0) {
        if (optional && errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, "contained: write %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int configure_cgroup(const struct container_config *config,
                            pid_t child,
                            struct cgroup_state *state)
{
    char template_path[PATH_MAX];
    char value[128];
    int length;

    if (enable_cgroup_controllers(config->cgroup_parent) < 0) {
        return -1;
    }
    length = snprintf(template_path, sizeof(template_path),
                      "%s/contained-%lu-%ld-XXXXXX", config->cgroup_parent,
                      (unsigned long)getuid(), (long)child);
    if (length < 0 || (size_t)length >= sizeof(template_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (mkdtemp(template_path) == NULL) {
        fprintf(stderr, "contained: create cgroup below %s: %s\n",
                config->cgroup_parent, strerror(errno));
        return -1;
    }
    memcpy(state->path, template_path, (size_t)length + 1U);
    state->created = true;

    snprintf(value, sizeof(value), "%" PRIu64 "\n", config->memory_bytes);
    if (write_cgroup_value(state->path, "memory.max", value, false) < 0 ||
        write_cgroup_value(state->path, "memory.swap.max", "0\n", true) < 0 ||
        write_cgroup_value(state->path, "memory.oom.group", "1\n", true) < 0) {
        return -1;
    }

    snprintf(value, sizeof(value), "%" PRIu64 " %" PRIu64 "\n",
             config->cpu.quota, config->cpu.period);
    if (write_cgroup_value(state->path, "cpu.max", value, false) < 0) {
        return -1;
    }

    snprintf(value, sizeof(value), "%" PRIu64 "\n", config->pids);
    if (write_cgroup_value(state->path, "pids.max", value, false) < 0) {
        return -1;
    }

    snprintf(value, sizeof(value), "%ld\n", (long)child);
    if (write_cgroup_value(state->path, "cgroup.procs", value, false) < 0) {
        return -1;
    }
    return 0;
}

static int remove_cgroup(struct cgroup_state *state)
{
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000L};
    int last_errno = 0;

    if (!state->created) {
        return 0;
    }

    /*
     * PID-namespace init exiting normally kills its remaining descendants.
     * cgroup.kill is an additional cleanup guard on kernels that provide it.
     */
    if (write_cgroup_value(state->path, "cgroup.kill", "1\n", true) < 0) {
        fprintf(stderr, "contained: warning: could not kill remaining cgroup tasks\n");
    }
    for (int attempt = 0; attempt < CGROUP_CLEANUP_ATTEMPTS; ++attempt) {
        if (rmdir(state->path) == 0) {
            state->created = false;
            state->path[0] = '\0';
            return 0;
        }
        last_errno = errno;
        if (errno != EBUSY && errno != ENOTEMPTY) {
            break;
        }
        (void)nanosleep(&pause, NULL);
    }
    errno = last_errno;
    fprintf(stderr, "contained: remove cgroup %s: %s\n", state->path,
            strerror(errno));
    return -1;
}

static int allocate_child_stack(struct child_stack *stack)
{
    long page_size = sysconf(_SC_PAGESIZE);
    size_t total;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    char *mapping;

    if (page_size <= 0 || (size_t)page_size > SIZE_MAX / 2U ||
        CHILD_STACK_SIZE > SIZE_MAX - 2U * (size_t)page_size) {
        errno = EOVERFLOW;
        return -1;
    }
    total = CHILD_STACK_SIZE + 2U * (size_t)page_size;
#ifdef MAP_STACK
    flags |= MAP_STACK;
#endif
    mapping = mmap(NULL, total, PROT_NONE, flags, -1, 0);
    if (mapping == MAP_FAILED) {
        return -1;
    }
    if (mprotect(mapping + page_size, CHILD_STACK_SIZE,
                 PROT_READ | PROT_WRITE) < 0) {
        int saved_errno = errno;
        munmap(mapping, total);
        errno = saved_errno;
        return -1;
    }
    stack->mapping = mapping;
    stack->mapping_size = total;
    stack->top = mapping + page_size + CHILD_STACK_SIZE;
    return 0;
}

static int child_failure(const char *operation)
{
    int saved_errno = errno;

    dprintf(STDERR_FILENO, "contained: child %s: %s\n", operation,
            strerror(saved_errno));
    errno = saved_errno;
    return CHILD_SETUP_FAILURE;
}

static int require_mountpoint(const char *rootfs,
                              const char *name,
                              char *path,
                              size_t capacity)
{
    struct stat status;

    if (join_path(path, capacity, rootfs, name) < 0) {
        return -1;
    }
    if (lstat(path, &status) < 0) {
        return -1;
    }
    if (!S_ISDIR(status.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

static int create_empty_file(const char *path, mode_t mode)
{
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);

    if (descriptor < 0) {
        return -1;
    }
    return close(descriptor);
}

static int bind_device(const char *dev_root,
                       const char *name,
                       bool optional)
{
    char source[PATH_MAX];
    char target[PATH_MAX];
    struct stat status;

    if (join_path(source, sizeof(source), "/dev", name) < 0 ||
        join_path(target, sizeof(target), dev_root, name) < 0) {
        return -1;
    }
    if (lstat(source, &status) < 0) {
        return optional && errno == ENOENT ? 0 : -1;
    }
    if (create_empty_file(target, 0666) < 0) {
        return -1;
    }
    if (mount(source, target, NULL, MS_BIND, NULL) < 0) {
        return -1;
    }
    return 0;
}

static int setup_minimal_dev(const char *dev_root)
{
    char path[PATH_MAX];
    static const char *const devices[] = {
        "null", "zero", "full", "random", "urandom",
    };

    if (mount("tmpfs", dev_root, "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "mode=755,size=4m") < 0) {
        return -1;
    }
    for (size_t i = 0; i < ARRAY_LENGTH(devices); ++i) {
        if (bind_device(dev_root, devices[i], false) < 0) {
            return -1;
        }
    }
    if (bind_device(dev_root, "tty", true) < 0) {
        return -1;
    }

    if (join_path(path, sizeof(path), dev_root, "pts") < 0 ||
        mkdir(path, 0755) < 0 ||
        mount("devpts", path, "devpts", MS_NOSUID | MS_NOEXEC,
              "newinstance,ptmxmode=0666,mode=0620,gid=0") < 0) {
        return -1;
    }

    if (join_path(path, sizeof(path), dev_root, "shm") < 0 ||
        mkdir(path, 01777) < 0 ||
        mount("tmpfs", path, "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "mode=1777,size=16m") < 0) {
        return -1;
    }

    if (join_path(path, sizeof(path), dev_root, "ptmx") < 0 ||
        symlink("pts/ptmx", path) < 0 ||
        join_path(path, sizeof(path), dev_root, "fd") < 0 ||
        symlink("/proc/self/fd", path) < 0 ||
        join_path(path, sizeof(path), dev_root, "stdin") < 0 ||
        symlink("/proc/self/fd/0", path) < 0 ||
        join_path(path, sizeof(path), dev_root, "stdout") < 0 ||
        symlink("/proc/self/fd/1", path) < 0 ||
        join_path(path, sizeof(path), dev_root, "stderr") < 0 ||
        symlink("/proc/self/fd/2", path) < 0) {
        return -1;
    }
    return 0;
}

static int setup_mount_tree(const struct container_config *config)
{
    char proc_path[PATH_MAX];
    char dev_path[PATH_MAX];
    unsigned long root_flags = MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV;

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        return child_failure("make mount propagation private");
    }
    if (mount(config->rootfs, config->rootfs, NULL, MS_BIND, NULL) < 0) {
        return child_failure("bind root filesystem");
    }
    if (mount(NULL, config->rootfs, NULL, MS_PRIVATE, NULL) < 0) {
        return child_failure("make root bind private");
    }
    if (require_mountpoint(config->rootfs, "proc", proc_path,
                           sizeof(proc_path)) < 0) {
        return child_failure("validate rootfs /proc mountpoint");
    }
    if (require_mountpoint(config->rootfs, "dev", dev_path,
                           sizeof(dev_path)) < 0) {
        return child_failure("validate rootfs /dev mountpoint");
    }
    if (setup_minimal_dev(dev_path) < 0) {
        return child_failure("construct minimal /dev");
    }

    if (!config->writable_rootfs) {
        root_flags |= MS_RDONLY;
    }
    if (mount(NULL, config->rootfs, NULL, root_flags, NULL) < 0) {
        return child_failure("apply rootfs mount flags");
    }

    if (chdir(config->rootfs) < 0) {
        return child_failure("enter rootfs");
    }
    if (syscall(SYS_pivot_root, ".", ".") < 0) {
        return child_failure("pivot root");
    }
    if (umount2(".", MNT_DETACH) < 0) {
        return child_failure("detach old root");
    }
    if (chdir("/") < 0) {
        return child_failure("change to new root");
    }
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) {
        return child_failure("mount isolated /proc");
    }
    return 0;
}

static int set_limit(int resource, uint64_t value, const char *name)
{
    struct rlimit limit;

    limit.rlim_cur = (rlim_t)value;
    limit.rlim_max = (rlim_t)value;
    if ((uint64_t)limit.rlim_cur != value || setrlimit(resource, &limit) < 0) {
        return child_failure(name);
    }
    return 0;
}

static int apply_resource_limits(const struct container_config *config)
{
    if (set_limit(RLIMIT_NOFILE, config->nofile, "set RLIMIT_NOFILE") != 0 ||
        set_limit(RLIMIT_NPROC, config->pids, "set RLIMIT_NPROC") != 0 ||
        set_limit(RLIMIT_AS, config->memory_bytes, "set RLIMIT_AS") != 0 ||
        set_limit(RLIMIT_CORE, 0U, "disable core dumps") != 0 ||
        set_limit(RLIMIT_MEMLOCK, 0U, "disable locked memory") != 0) {
        return CHILD_SETUP_FAILURE;
    }
    return 0;
}

static int read_last_capability(void)
{
    char buffer[32];
    char *end = NULL;
    long parsed;

    if (read_text_file("/proc/sys/kernel/cap_last_cap", buffer,
                       sizeof(buffer)) < 0) {
        return CAP_LAST_CAP;
    }
    errno = 0;
    parsed = strtol(buffer, &end, 10);
    if (errno != 0 || end == buffer || parsed < 0 || parsed > 4096) {
        return CAP_LAST_CAP;
    }
    return (int)parsed;
}

static int drop_all_capabilities(void)
{
    cap_t empty;
    int last_capability = read_last_capability();
    unsigned long securebits =
        SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
        SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED |
        SECBIT_KEEP_CAPS_LOCKED;

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L) < 0) {
        return child_failure("clear ambient capabilities");
    }
    for (int capability = 0; capability <= last_capability; ++capability) {
        if (prctl(PR_CAPBSET_DROP, capability, 0L, 0L, 0L) < 0) {
            return child_failure("drop capability bounding set");
        }
    }
    if (prctl(PR_SET_SECUREBITS, securebits, 0L, 0L, 0L) < 0) {
        return child_failure("lock securebits");
    }

    empty = cap_init();
    if (empty == NULL) {
        return child_failure("allocate empty capability set");
    }
    if (cap_set_proc(empty) < 0) {
        int saved_errno = errno;
        cap_free(empty);
        errno = saved_errno;
        return child_failure("clear permitted/effective/inheritable capabilities");
    }
    if (cap_free(empty) < 0) {
        return child_failure("release capability set");
    }
    return 0;
}

static int close_extra_descriptors(void)
{
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) == 0) {
        return 0;
    }
    if (errno != ENOSYS) {
        return -1;
    }
#endif
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    int directory_fd;

    if (directory == NULL) {
        return -1;
    }
    directory_fd = dirfd(directory);
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long descriptor = strtol(entry->d_name, &end, 10);

        if (end == entry->d_name || *end != '\0' || descriptor <= 2 ||
            descriptor == directory_fd) {
            continue;
        }
        (void)close((int)descriptor);
    }
    if (errno != 0) {
        int saved_errno = errno;
        closedir(directory);
        errno = saved_errno;
        return -1;
    }
    return closedir(directory);
}

static int allow_syscall_names(scmp_filter_ctx filter,
                               const char *const *names,
                               size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        int syscall_number = seccomp_syscall_resolve_name(names[i]);
        int result;

        if (syscall_number == __NR_SCMP_ERROR) {
            continue;
        }
        result = seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_number, 0);
        if (result < 0) {
            errno = -result;
            return -1;
        }
    }
    return 0;
}

static int allow_local_socket_creation(scmp_filter_ctx filter,
                                       const char *name)
{
    int syscall_number = seccomp_syscall_resolve_name(name);
    int result;

    if (syscall_number == __NR_SCMP_ERROR) {
        return 0;
    }
    result = seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_number, 1,
                              SCMP_CMP(0, SCMP_CMP_EQ, AF_UNIX));
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

static int allow_safe_clone(scmp_filter_ctx filter)
{
    int syscall_number = seccomp_syscall_resolve_name("clone");
    uint64_t forbidden =
        (uint64_t)CLONE_NEWUTS | (uint64_t)CLONE_NEWNS |
        (uint64_t)CLONE_NEWPID | (uint64_t)CLONE_NEWIPC |
        (uint64_t)CLONE_NEWNET | (uint64_t)CLONE_NEWUSER |
        (uint64_t)CLONE_PTRACE | (uint64_t)CLONE_UNTRACED |
        (uint64_t)CLONE_PARENT;
    int result;

#ifdef CLONE_NEWCGROUP
    forbidden |= (uint64_t)CLONE_NEWCGROUP;
#endif
#ifdef CLONE_NEWTIME
    forbidden |= (uint64_t)CLONE_NEWTIME;
#endif
    if (syscall_number == __NR_SCMP_ERROR) {
        return 0;
    }
    result = seccomp_rule_add(
        filter, SCMP_ACT_ALLOW, syscall_number, 1,
        SCMP_CMP(0, SCMP_CMP_MASKED_EQ, forbidden, 0));
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

static int install_seccomp_filter(void)
{
    /*
     * Default-deny is deliberate. The categories below permit normal
     * computation while keeping high-risk process controls (setns, unshare,
     * ptrace, bpf, perf_event_open, keyctl, mount and module loading) absent.
     */
    static const char *const process_calls[] = {
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
    };
    static const char *const memory_and_time_calls[] = {
        "brk", "mmap", "mmap2", "munmap", "mprotect", "mremap", "madvise",
        "mincore", "msync", "arch_prctl", "set_thread_area",
        "get_thread_area", "modify_ldt", "clock_gettime", "clock_getres",
        "clock_nanosleep", "nanosleep", "gettimeofday", "time", "getrandom",
    };
    static const char *const filesystem_calls[] = {
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
    };
    static const char *const event_and_network_calls[] = {
        /*
         * socket/socketpair are separately constrained to AF_UNIX. These
         * operations therefore apply only to local sockets inherited or
         * created inside the otherwise empty network namespace.
         */
        "bind", "listen", "accept", "accept4", "connect", "shutdown",
        "getsockname", "getpeername", "getsockopt", "setsockopt", "sendto",
        "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    };
    scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    int result;

    if (filter == NULL) {
        errno = ENOMEM;
        return child_failure("create seccomp filter");
    }
    result = seccomp_attr_set(filter, SCMP_FLTATR_ACT_BADARCH,
                              SCMP_ACT_KILL_PROCESS);
    if (result < 0) {
        errno = -result;
        seccomp_release(filter);
        return child_failure("configure seccomp architecture action");
    }

    if (allow_syscall_names(filter, process_calls,
                            ARRAY_LENGTH(process_calls)) < 0 ||
        allow_syscall_names(filter, memory_and_time_calls,
                            ARRAY_LENGTH(memory_and_time_calls)) < 0 ||
        allow_syscall_names(filter, filesystem_calls,
                            ARRAY_LENGTH(filesystem_calls)) < 0 ||
        allow_syscall_names(filter, event_and_network_calls,
                            ARRAY_LENGTH(event_and_network_calls)) < 0 ||
        allow_local_socket_creation(filter, "socket") < 0 ||
        allow_local_socket_creation(filter, "socketpair") < 0 ||
        allow_safe_clone(filter) < 0) {
        int saved_errno = errno;
        seccomp_release(filter);
        errno = saved_errno;
        return child_failure("build seccomp allowlist");
    }

    result = seccomp_load(filter);
    if (result < 0) {
        errno = -result;
        seccomp_release(filter);
        return child_failure("load seccomp allowlist");
    }
    seccomp_release(filter);
    return 0;
}

static int send_token(int descriptor, char token)
{
    ssize_t count;

    do {
        count = send(descriptor, &token, 1U, MSG_NOSIGNAL);
    } while (count < 0 && errno == EINTR);
    if (count != 1) {
        if (count >= 0) {
            errno = EIO;
        }
        return -1;
    }
    return 0;
}

static int receive_token(int descriptor, char *token)
{
    ssize_t count;

    do {
        count = recv(descriptor, token, 1U, 0);
    } while (count < 0 && errno == EINTR);
    if (count != 1) {
        if (count == 0) {
            errno = EPIPE;
        } else if (count > 0) {
            errno = EIO;
        }
        return -1;
    }
    return 0;
}

static void reset_forwarded_signals(void)
{
    static const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    for (size_t i = 0; i < ARRAY_LENGTH(signals); ++i) {
        (void)sigaction(signals[i], &action, NULL);
    }
}

static int child_main(void *argument)
{
    struct child_context *context = argument;
    const struct container_config *config = context->config;
    char token;
    pid_t parent;

    reset_forwarded_signals();
    (void)close(context->sync_write);

    parent = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0L, 0L, 0L) < 0) {
        return child_failure("set parent-death signal");
    }
    if (getppid() != parent) {
        return CHILD_SETUP_FAILURE;
    }
    if (setpgid(0, 0) < 0) {
        return child_failure("create process group");
    }

    /*
     * Supplementary groups must be cleared while setgroups is still allowed.
     * The ready token prevents the parent from writing \"deny\" too early.
     */
    if (setgroups(0, NULL) < 0) {
        return child_failure("clear supplementary groups");
    }
    if (send_token(context->sync_read, 'R') < 0) {
        return child_failure("signal readiness to parent");
    }
    if (receive_token(context->sync_read, &token) < 0) {
        return child_failure("wait for UID/GID maps and cgroup");
    }
    if (close(context->sync_read) < 0) {
        return child_failure("close synchronization channel");
    }
    if (token != 'G') {
        return CHILD_SETUP_FAILURE;
    }

    if (setresgid(0, 0, 0) < 0) {
        return child_failure("switch to mapped GID 0");
    }
    if (setresuid(0, 0, 0) < 0) {
        return child_failure("switch to mapped UID 0");
    }
    /* Credential changes clear PDEATHSIG; restore it after becoming UID 0. */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0L, 0L, 0L) < 0) {
        return child_failure("restore parent-death signal");
    }
    if (sethostname(config->hostname, strlen(config->hostname)) < 0) {
        return child_failure("set UTS hostname");
    }
    umask(0022);

    if (setup_mount_tree(config) != 0) {
        return CHILD_SETUP_FAILURE;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) < 0) {
        return child_failure("set no_new_privs");
    }
    if (prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) < 0) {
        return child_failure("disable dumpability");
    }
    if (drop_all_capabilities() != 0) {
        return CHILD_SETUP_FAILURE;
    }
    if (apply_resource_limits(config) != 0) {
        return CHILD_SETUP_FAILURE;
    }
    if (close_extra_descriptors() < 0) {
        return child_failure("close inherited file descriptors");
    }
    if (install_seccomp_filter() != 0) {
        return CHILD_SETUP_FAILURE;
    }

    execvp(config->command[0], config->command);
    return child_failure("exec workload");
}

static void forward_signal(int signal_number)
{
    int saved_errno = errno;
    pid_t child = (pid_t)supervised_pid;

    if (child > 0 && kill(-child, signal_number) < 0 && errno == ESRCH) {
        (void)kill(child, signal_number);
    }
    errno = saved_errno;
}

static int install_signal_forwarding(void)
{
    static const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = forward_signal;
    sigemptyset(&action.sa_mask);
    for (size_t i = 0; i < ARRAY_LENGTH(signals); ++i) {
        if (sigaction(signals[i], &action, NULL) < 0) {
            return -1;
        }
    }
    return 0;
}

static int wait_for_child(pid_t child, int *status)
{
    pid_t result;

    do {
        result = waitpid(child, status, 0);
    } while (result < 0 && errno == EINTR);
    return result == child ? 0 : -1;
}

static int status_to_exit_code(int status)
{
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return CHILD_SETUP_FAILURE;
}

static int canonicalize_directory(const char *input,
                                  char *output,
                                  size_t capacity,
                                  const char *description)
{
    char *resolved;
    struct stat status;

    errno = 0;
    resolved = realpath(input, output);
    if (resolved == NULL) {
        fprintf(stderr, "contained: resolve %s '%s': %s\n", description, input,
                strerror(errno));
        return -1;
    }
    if (strlen(resolved) >= capacity) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (stat(resolved, &status) < 0) {
        fprintf(stderr, "contained: inspect %s '%s': %s\n", description,
                resolved, strerror(errno));
        return -1;
    }
    if (!S_ISDIR(status.st_mode)) {
        errno = ENOTDIR;
        fprintf(stderr, "contained: %s '%s' is not a directory: %s\n",
                description, resolved, strerror(errno));
        return -1;
    }
    return 0;
}

static void choose_hostname(char *hostname, size_t capacity)
{
    struct timespec now = {0};

    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    (void)snprintf(hostname, capacity, "contained-%ld-%08lx", (long)getpid(),
                   (unsigned long)now.tv_nsec);
}

int main(int argc, char **argv)
{
    struct container_config config;
    struct child_context child_context;
    struct child_stack stack = {0};
    struct cgroup_state cgroup = {0};
    enum config_parse_result parse_result;
    char rootfs[PATH_MAX];
    char cgroup_parent[PATH_MAX];
    char generated_hostname[65];
    int synchronization[2] = {-1, -1};
    int child_status = 0;
    int result = CHILD_SETUP_FAILURE;
    int clone_flags = CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID |
                      CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUSER | SIGCHLD;
    pid_t child = -1;
    bool reaped = false;
    char token;

    parse_result = config_parse(&config, argc, argv, stderr);
    if (parse_result == CONFIG_PARSE_HELP) {
        config_print_usage(stdout, argv[0]);
        return 0;
    }
    if (parse_result == CONFIG_PARSE_ERROR) {
        fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);
        return 2;
    }

    if (canonicalize_directory(config.rootfs, rootfs, sizeof(rootfs),
                               "rootfs") < 0) {
        return 2;
    }
    if (strcmp(rootfs, "/") == 0) {
        fprintf(stderr,
                "contained: refusing '/' as rootfs; use a dedicated root "
                "filesystem tree\n");
        return 2;
    }
    if (canonicalize_directory(config.cgroup_parent, cgroup_parent,
                               sizeof(cgroup_parent), "cgroup parent") < 0) {
        return 2;
    }
    config.rootfs = rootfs;
    config.cgroup_parent = cgroup_parent;
    if (config.hostname == NULL) {
        choose_hostname(generated_hostname, sizeof(generated_hostname));
        config.hostname = generated_hostname;
    }

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                   synchronization) < 0) {
        fprintf(stderr, "contained: create synchronization socket: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (allocate_child_stack(&stack) < 0) {
        fprintf(stderr, "contained: allocate guarded child stack: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (install_signal_forwarding() < 0) {
        fprintf(stderr, "contained: install signal handlers: %s\n",
                strerror(errno));
        goto cleanup;
    }

    child_context.config = &config;
    child_context.sync_read = synchronization[1];
    child_context.sync_write = synchronization[0];
    child = clone(child_main, stack.top, clone_flags, &child_context);
    if (child < 0) {
        fprintf(stderr,
                "contained: clone six namespaces "
                "(uts,mount,pid,ipc,network,user): %s; check user-namespace "
                "policy and kernel support\n",
                strerror(errno));
        goto cleanup;
    }
    supervised_pid = (sig_atomic_t)child;
    (void)close(synchronization[1]);
    synchronization[1] = -1;
    if (setpgid(child, child) < 0 && errno != EACCES && errno != ESRCH &&
        errno != EPERM) {
        fprintf(stderr, "contained: set child process group: %s\n",
                strerror(errno));
        goto abort_child;
    }

    if (receive_token(synchronization[0], &token) < 0 || token != 'R') {
        fprintf(stderr, "contained: child failed before ID mapping: %s\n",
                strerror(errno));
        goto abort_child;
    }
    if (configure_id_maps(child, getuid(), getgid()) < 0) {
        goto abort_child;
    }
    if (configure_cgroup(&config, child, &cgroup) < 0) {
        goto abort_child;
    }
    if (send_token(synchronization[0], 'G') < 0) {
        fprintf(stderr, "contained: release configured child: %s\n",
                strerror(errno));
        goto abort_child;
    }
    (void)close(synchronization[0]);
    synchronization[0] = -1;

    if (wait_for_child(child, &child_status) < 0) {
        fprintf(stderr, "contained: wait for child: %s\n", strerror(errno));
        goto cleanup;
    }
    reaped = true;
    supervised_pid = -1;
    result = status_to_exit_code(child_status);
    goto cleanup;

abort_child:
    if (synchronization[0] >= 0) {
        if (send_token(synchronization[0], 'X') < 0) {
            (void)kill(child, SIGKILL);
        }
        (void)close(synchronization[0]);
        synchronization[0] = -1;
    } else {
        (void)kill(child, SIGKILL);
    }
    if (wait_for_child(child, &child_status) == 0) {
        reaped = true;
    }
    supervised_pid = -1;
    result = CHILD_SETUP_FAILURE;

cleanup:
    if (child > 0 && !reaped) {
        (void)kill(child, SIGKILL);
        if (wait_for_child(child, &child_status) == 0) {
            reaped = true;
        }
        supervised_pid = -1;
    }
    if (cgroup.created && remove_cgroup(&cgroup) < 0 && result == 0) {
        result = CHILD_SETUP_FAILURE;
    }
    if (synchronization[0] >= 0) {
        (void)close(synchronization[0]);
    }
    if (synchronization[1] >= 0) {
        (void)close(synchronization[1]);
    }
    if (stack.mapping != NULL) {
        (void)munmap(stack.mapping, stack.mapping_size);
    }
    return result;
}