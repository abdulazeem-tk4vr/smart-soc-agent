#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from smart_soc_agent.agent import SmartSocAgent


class OfflineEvaluator:
    def checking(self, question: dict[str, Any], submitted_answer: str) -> dict[str, Any]:
        return {"reward": 0, "offline_eval": True, "submitted_answer": submitted_answer}


def warm_attack(attack: str, args: argparse.Namespace) -> dict[str, Any]:
    from secgym.excytin_env import ExcytinEnv

    env = ExcytinEnv(
        attack=attack,
        evaluator=OfflineEvaluator(),
        save_file=str(Path(args.output_dir) / f"env_schema_{attack}.json"),
        max_steps=args.max_steps,
        split=args.split,
        layer=args.layer,
    )
    agent = SmartSocAgent(max_steps=args.max_steps, layer=args.layer, mode="deterministic")
    try:
        observation, _ = env.reset(0)
        agent.reset()
        for _ in range(args.max_steps):
            action, submit = agent.act(observation)
            observation, _, done, _ = env.step(action=action, submit=submit)
            if submit or done:
                break
    finally:
        env.close()
    return {
        "attack": attack,
        "tables": sorted(agent.schema_cache.table_names()),
        "schema_digest": agent.schema_cache.digest(limit=200),
        "steps": agent.step_count,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Warm SmartSocAgent schema cache by probing ExCyTIn incidents.")
    parser.add_argument("--attack", default="", help="Single attack. Default warms all attacks.")
    parser.add_argument("--split", default="test")
    parser.add_argument("--layer", choices=("alert", "log", "alert_only"), default="alert")
    parser.add_argument("--max_steps", type=int, default=25)
    parser.add_argument("--output_dir", default="schema_cache")
    return parser.parse_args()


def main() -> int:
    from secgym.excytin_env import ATTACKS

    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    attacks = [args.attack] if args.attack else list(ATTACKS)
    results = [warm_attack(attack, args) for attack in attacks]
    output_path = output_dir / f"schema_cache_{args.layer}_{args.split}.json"
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
