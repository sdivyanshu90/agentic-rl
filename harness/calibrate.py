#!/usr/bin/env python3
"""
Per-tier calibration for the CVE-2019-18634 task.

Runs N rollouts (>=16 recommended) per agent profile, each capped at a 16-turn
budget, and reports the fraction of rollouts that reached each difficulty
tier.  The tier rates are cumulative and monotonic by construction
(Basic <= Intermediate <= Advanced reaches).

Profiles:
  expert / intermediate_only / basic_only / novice   simulated proxies
  llm                                                real model via OPENAI_* env

Usage:
    python3 harness/calibrate.py --container pwfeedback-lab --runs 16 \
        --profiles expert,intermediate_only,basic_only,novice
    OPENAI_API_KEY=... OPENAI_BASE_URL=... OPENAI_MODEL=... \
        python3 harness/calibrate.py --profiles llm --runs 16
"""

import argparse
import json
import os
import statistics
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from harness.agents import build_agent  # noqa: E402
from harness.rollout import run_rollout  # noqa: E402

SOLUTIONS = os.path.join(REPO, "solutions")


def run_profile(container, profile, runs, max_turns, out_dir):
    kw = {}
    if profile == "llm":
        kw = {"model": os.environ["OPENAI_MODEL"],
              "base_url": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
              "api_key": os.environ["OPENAI_API_KEY"]}
    results = []
    for i in range(runs):
        agent = build_agent(profile, **kw)
        res = run_rollout(container, agent, max_turns=max_turns, reference_dir=SOLUTIONS)
        results.append(res)
        print("  [%s] rollout %2d/%d turns=%d tiers=%s score=%.2f"
              % (profile, i + 1, runs, res["turns_used"], res["tiers"], res["total_score"]),
              flush=True)
    with open(os.path.join(out_dir, "rollout-%s.json" % profile), "w") as fh:
        json.dump(results, fh, indent=2)

    n = len(results)
    def rate(key):
        return round(sum(1 for r in results if r["tiers"][key]) / n, 4)
    return {
        "profile": profile,
        "runs": n,
        "basic_rate": rate("basic"),
        "intermediate_rate": rate("intermediate"),
        "advanced_rate": rate("advanced"),
        "mean_turns": round(statistics.mean(r["turns_used"] for r in results), 2),
        "min_turns_advanced": min([r["turns_used"] for r in results if r["tiers"]["advanced"]],
                                  default=None),
        "mean_score": round(statistics.mean(r["total_score"] for r in results), 4),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="pwfeedback-lab")
    ap.add_argument("--runs", type=int, default=16)
    ap.add_argument("--max-turns", type=int, default=16)
    ap.add_argument("--profiles", default="expert,intermediate_only,basic_only,novice")
    ap.add_argument("--out-dir", default=os.path.join(REPO, "harness", "artifacts"))
    ap.add_argument("--report", default=os.path.join(REPO, "harness", "calibration.json"))
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    report = {"task_id": "cve-2019-18634-sudo-pwfeedback", "turn_budget": args.max_turns,
              "runs_per_profile": args.runs, "profiles": [], "started": time.time()}

    for profile in profiles:
        print("[*] profile=%s runs=%d" % (profile, args.runs), flush=True)
        report["profiles"].append(
            run_profile(args.container, profile, args.runs, args.max_turns, args.out_dir))

    report["elapsed_seconds"] = round(time.time() - report.pop("started"), 1)
    with open(args.report, "w") as fh:
        json.dump(report, fh, indent=2)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())