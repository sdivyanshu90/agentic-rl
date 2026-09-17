#!/usr/bin/env python3
"""
Free-model benchmark for the CVE-2019-18634 Track B task.

Runs the LLMAgent (16-turn budget) against a fixed set of *free* models from
OpenRouter and Cerebras, then reports per-tier pass rates.  API keys are read
from the repo .env (OPENROUTER_API_KEY, CEREBRAS_API_KEY) and never printed.

Model set (5):
  OpenRouter (3): google/gemma-4-31b-it:free
                  nvidia/nemotron-3-super-120b-a12b:free
                  z-ai/glm-5.2:free
  Cerebras  (2): gpt-oss-120b, qwen-3.8-27b   (all free Cerebras models)

Rate limiting: requests are strictly sequential with a per-request delay and
exponential backoff on 429/5xx (see LLMAgent._chat).

Usage:
    python3 harness/benchmark.py --rollouts 2
    python3 harness/benchmark.py --rollouts 5 --models openrouter:z-ai/glm-5.2:free
"""

import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from harness.agents import build_agent  # noqa: E402
from harness.rollout import run_rollout  # noqa: E402

SOLUTIONS = os.path.join(REPO, "solutions")

# Single designated model.  All other providers/models are intentionally not
# used: the task owner asked that only OpenRouter's DeepSeek Flash Latest be
# benchmarked, and any other model id is rejected.
DEEPSEEK = {
    "provider": "openrouter",
    "model": "~deepseek/deepseek-flash-latest",
    "base_url": "https://openrouter.ai/api/v1",
    "key_env": "OPENROUTER_API_KEY",
    "delay": 1.0,
}
MODELS = [DEEPSEEK]
EXCLUDED = [
    {"provider": "gemini", "model": "*", "reason": "excluded by task owner (DeepSeek Flash Latest only)"},
    {"provider": "cerebras", "model": "gpt-oss-120b", "reason": "payment_required"},
    {"provider": "cerebras", "model": "qwen-3.8-27b", "reason": "payment_required"},
    {"provider": "openrouter", "model": "*:free", "reason": "excluded by task owner (DeepSeek Flash Latest only)"},
]


def select_specs(provider, env):
    if provider not in ("auto", "deepseek"):
        raise SystemExit("only DeepSeek Flash Latest is permitted (got provider %r)" % provider)
    return MODELS, "openrouter-deepseek-flash-latest"


def load_env():
    env = {}
    path = os.path.join(REPO, ".env")
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    for k in ("OPENROUTER_API_KEY", "CEREBRAS_API_KEY"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


def key_for(spec, env):
    key = env.get(spec["key_env"], "")
    if not key:
        raise SystemExit("missing %s in .env" % spec["key_env"])
    return key


def summarize(spec, results, wall):
    n = len(results)
    def rate(key):
        return round(sum(1 for r in results if r["tiers"][key]) / n, 3) if n else 0.0
    calls = [r["api_calls"] for r in results if r.get("api_calls") is not None]
    return {
        "provider": spec["provider"],
        "model": spec["model"],
        "runs": n,
        "basic_rate": rate("basic"),
        "intermediate_rate": rate("intermediate"),
        "advanced_rate": rate("advanced"),
        "mean_score": round(statistics.mean(r["total_score"] for r in results), 3) if n else 0.0,
        "mean_turns": round(statistics.mean(r["turns_used"] for r in results), 2) if n else 0.0,
        "mean_api_calls": round(statistics.mean(calls), 1) if calls else None,
        "errors": sum(1 for r in results if r.get("error")),
        "refusals": sum(1 for r in results if r.get("refused")),
        "wall_seconds": round(wall, 1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="pwfeedback-lab")
    ap.add_argument("--rollouts", type=int, default=2)
    ap.add_argument("--max-turns", type=int, default=16)
    ap.add_argument("--provider", default="auto",
                    choices=["auto", "deepseek"],
                    help="only DeepSeek Flash Latest is benchmarked")
    ap.add_argument("--models", default=None,
                    help="comma-separated model ids to subset the selected registry")
    ap.add_argument("--out", default=os.path.join(REPO, "harness", "benchmark.json"))
    ap.add_argument("--delay", type=float, default=None, help="override per-request delay")
    ap.add_argument("--initial-cooldown", type=float, default=0.0)
    ap.add_argument("--model-cooldown", type=float, default=0.0)
    ap.add_argument("--rollout-cooldown", type=float, default=0.0)
    ap.add_argument("--resume", action="store_true",
                    help="continue from an existing --out file instead of restarting")
    args = ap.parse_args()

    env = load_env()
    specs, provider_label = select_specs(args.provider, env)
    if args.models:
        wanted = set(args.models.split(","))
        specs = [s for s in specs if s["model"] in wanted
                 or ("%s:%s" % (s["provider"], s["model"])) in wanted]
    if not specs:
        raise SystemExit("only DeepSeek Flash Latest is permitted; --models %r rejected" % args.models)
    print("[*] provider=%s models=%d" % (provider_label, len(specs)), flush=True)

    all_results = {}
    summaries = []

    def build_report():
        return {
            "task_id": "cve-2019-18634-sudo-pwfeedback",
            "provider": provider_label,
            "turn_budget": args.max_turns,
            "rollouts_per_model": args.rollouts,
            "model_count": len(summaries),
            "models": summaries,
            "excluded_models": EXCLUDED,
        }

    def save():
        with open(args.out, "w") as fh:
            json.dump({"summary": build_report(), "results": all_results}, fh, indent=2)

    for spec in specs:
        key = key_for(spec, env)
        if args.initial_cooldown:
            print("[*] initial cooldown %.0fs" % args.initial_cooldown, flush=True)
            time.sleep(args.initial_cooldown)
        delay = args.delay if args.delay is not None else spec["delay"]
        print("[*] %s / %s  (%d rollouts, <=%d turns, delay %.0fs)"
              % (spec["provider"], spec["model"], args.rollouts, args.max_turns, delay), flush=True)
        results = []
        if args.resume and os.path.exists(args.out):
            try:
                prev = json.load(open(args.out))
                results = prev.get("results", {}).get(spec["model"], [])[:args.rollouts]
                if results:
                    print("[*] resume: %d/%d rollouts already done"
                          % (len(results), args.rollouts), flush=True)
            except (OSError, ValueError):
                results = []
        t0 = time.time()
        for i in range(len(results), args.rollouts):
            agent = build_agent("llm", model=spec["model"], base_url=spec["base_url"],
                                api_key=key, provider=spec["provider"],
                                max_turns=args.max_turns, request_delay=delay,
                                json_mode=(spec["provider"] == "gemini"),
                                max_tokens=1200, reasoning_max_tokens=0,
                                reasoning_enabled=False)
            # reference_dir is intentionally NOT staged for LLM rollouts: the
            # agent must solve the task, not read a hidden answer.
            res = run_rollout(args.container, agent, max_turns=args.max_turns, reference_dir=None)
            results.append(res)
            print("    rollout %d/%d turns=%d api=%s tiers=%s score=%.2f%s%s"
                  % (i + 1, args.rollouts, res["turns_used"], res["api_calls"],
                     res["tiers"], res["total_score"],
                     " REFUSED" if res.get("refused") else "",
                     (" ERROR=" + res["error"][:50]) if res.get("error") else ""), flush=True)
            all_results[spec["model"]] = results
            summaries[:] = [s for s in summaries if s["model"] != spec["model"]]
            summaries.append(summarize(spec, results, time.time() - t0))
            save()
            if args.rollout_cooldown:
                time.sleep(args.rollout_cooldown)
        wall = time.time() - t0
        all_results[spec["model"]] = results
        if args.model_cooldown:
            time.sleep(args.model_cooldown)

    report = build_report()
    save()

    print("\n=== summary ===")
    print("%-42s %5s %5s %5s %6s %6s %7s" %
          ("model", "basic", "inter", "adv", "turns", "api", "score"))
    for s in summaries:
        print("%-42s %5.2f %5.2f %5.2f %6.2f %6s %7.2f"
              % (s["model"], s["basic_rate"], s["intermediate_rate"], s["advanced_rate"],
                 s["mean_turns"], s["mean_api_calls"], s["mean_score"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())