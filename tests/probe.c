/* Exercise seccomp decisions, not only the Seccomp status field. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    close(fd);
    errno = 0;
    if (socket(AF_INET, SOCK_STREAM, 0) != -1 || errno != EPERM) return 2;
    errno = 0;
    if (unshare(CLONE_NEWUSER) != -1 || errno != EPERM) return 3;
    errno = 0;
    if (syscall(SYS_clone3, NULL, 0) != -1 || errno != ENOSYS) return 4;
    puts("seccomp syscall decisions passed");
    return 0;
}
