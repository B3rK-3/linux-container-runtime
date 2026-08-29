"""Drive an actual foreground terminal; fail on hangs or unread input."""
import errno
import os
import pty
import select
import signal
import sys
import time

pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], [sys.argv[1], '--rootfs', sys.argv[2], '--', '/bin/sh'])
output = b''
try:
    deadline = time.monotonic() + 10
    sent = False
    while time.monotonic() < deadline:
        if not select.select([fd], [], [], 0.1)[0]:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not data:
            break
        output += data
        if not sent and b'# ' in output:
            # The expected marker never appears literally in the echoed input.
            os.write(fd, b"printf 'TTY_%s\\n' VERIFIED\nexit 23\n")
            sent = True
    else:
        raise AssertionError(f'terminal timed out: {output!r}')
    _, status = os.waitpid(pid, 0)
    pid = 0
    assert os.waitstatus_to_exitcode(status) == 23, output
    assert b'\r\nTTY_VERIFIED\r\n' in output, output
    print('interactive terminal test passed')
finally:
    if pid:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(fd)
