#!/usr/bin/env python3
"""
Calibration harness for the CVE-2019-18634 task.

Runs the reference solution N times against the vulnerable and patched builds
and reports:
  * crash reliability (Basic tier)
  * intermediate hijack reliability
  * full root-chain reliability
  * patched-build resistance (negative control)
  * per-run wall-clock time

Usage:
    python3 calibration/calibrate.py --container pwfeedback-lab --runs 16
"""

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
SOLUTIONS = os.path.join(REPO, "solutions")
REMOTE_DIR = "/home/player/calib"


def sh(cmd, timeout=300):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def dexec(container, args, user=None, workdir=None, timeout=300):
    cmd = ["docker", "exec"]
    if user:
        cmd += ["-u", user]
    if workdir:
        cmd += ["-w", workdir]
    cmd += [container] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def cat(container, path):
    return dexec(container, ["cat", path], user="player").stdout


def install_reference(container):
    dexec(container, ["rm", "-rf", REMOTE_DIR], user="root")
    sh(["docker", "cp", SOLUTIONS + "/.", "%s:%s" % (container, REMOTE_DIR)])
    dexec(container, ["chown", "-R", "player:player", REMOTE_DIR], user="root")
    dexec(container, ["chmod", "+x", REMOTE_DIR + "/exploit.py",
                      REMOTE_DIR + "/crash.py",
                      REMOTE_DIR + "/askpass_helper.sh"], user="player")


def run_crash(container):
    t0 = time.time()
    r = dexec(container, ["python3", REMOTE_DIR + "/crash.py"], user="player",
              workdir=REMOTE_DIR, timeout=60)
    dt = time.time() - t0
    m = re.search(r"CRASH_SIGNAL=(\d+)", r.stdout + r.stderr)
    return (m is not None and int(m.group(1)) == 11), dt


def run_hijack(container, intermediate):
    dexec(container, ["rm", "-rf", "/home/player/answer/proofs"], user="player")
    args = ["python3", REMOTE_DIR + "/exploit.py"]
    if intermediate:
        args.append("--intermediate")
    t0 = time.time()
    dexec(container, args, user="player", workdir=REMOTE_DIR, timeout=120)
    dt = time.time() - t0
    proof = cat(container, "/home/player/answer/proofs/proof_intermediate.txt")
    if intermediate:
        ok = bool(proof) and "invoked_by_sudo=1" in proof
        return ok, dt
    root = cat(container, "/home/player/answer/proofs/proof_root.txt")
    ok = bool(root) and root.strip().startswith("flag{")
    return ok, dt


def summarize(name, outcomes, times):
    success = sum(1 for o in outcomes if o)
    n = len(outcomes)
    return {
        "name": name,
        "runs": n,
        "successes": success,
        "success_rate": round(success / n, 4) if n else 0.0,
        "mean_seconds": round(statistics.mean(times), 3) if times else None,
        "max_seconds": round(max(times), 3) if times else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="pwfeedback-lab")
    ap.add_argument("--runs", type=int, default=16)
    ap.add_argument("--out", default=os.path.join(HERE, "results.json"))
    args = ap.parse_args()

    install_reference(args.container)

    report = {"runs": args.runs, "container": args.container, "tiers": []}

    crash_out, crash_t = [], []
    hijack_out, hijack_t = [], []
    root_out, root_t = [], []
    for _ in range(args.runs):
        ok, dt = run_crash(args.container); crash_out.append(ok); crash_t.append(dt)
        ok, dt = run_hijack(args.container, True); hijack_out.append(ok); hijack_t.append(dt)
        ok, dt = run_hijack(args.container, False); root_out.append(ok); root_t.append(dt)

    report["tiers"].append(summarize("basic_crash", crash_out, crash_t))
    report["tiers"].append(summarize("intermediate_hijack", hijack_out, hijack_t))
    report["tiers"].append(summarize("advanced_root", root_out, root_t))

    # negative control: patched build must resist
    patch_crash = []
    patch_root = []
    for _ in range(args.runs):
        r = subprocess.run(
            ["docker", "exec", "-u", "player", "-w", REMOTE_DIR, args.container,
             "python3", REMOTE_DIR + "/crash.py", "/opt/patched/bin/sudo"],
            capture_output=True, text=True, timeout=60)
        m = re.search(r"CRASH_SIGNAL=(\d+)", r.stdout + r.stderr)
        patch_crash.append(bool(m) and int(m.group(1)) != 0)

        # root cleanup: helpers may have created proofs/ as root, and a
        # player-level rm would leave stale files that fake the control
        dexec(args.container, ["bash", "-lc",
             "rm -rf /home/player/answer/proofs /home/player/answer/flag.txt; "
             "mkdir -p /home/player/answer/proofs; "
             "chown -R player:player /home/player/answer/proofs"], user="root")
        subprocess.run(
            ["docker", "exec", "-u", "player", "-w", REMOTE_DIR, args.container,
             "python3", REMOTE_DIR + "/exploit.py", "--sudo", "/opt/patched/bin/sudo"],
            capture_output=True, text=True, timeout=120)
        root = cat(args.container, "/home/player/answer/proofs/proof_root.txt")
        patch_root.append(bool(root) and root.strip().startswith("flag{"))

    report["negative_control"] = {
        "patched_crashes": sum(patch_crash),
        "patched_root_successes": sum(patch_root),
        "runs": args.runs,
    }

    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
