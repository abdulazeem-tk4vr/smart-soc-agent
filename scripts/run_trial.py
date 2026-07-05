# Ported from soc_defender.
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import autogen

from secgym.excytin_env import ATTACKS, ExcytinEnv

from smart_soc_agent.agent import SmartSocAgent
from smart_soc_agent.remote_agent import RemoteSmartSocAgent


class OfflineEvaluator:
    def checking(self, question: dict[str, Any], submitted_answer: str) -> dict[str, Any]:
        return {
            "reward": 0,
            "offline_eval": True,
            "answer": question.get("answer"),
            "submitted_answer": submitted_answer,
        }


def filter_config_list(config_list: list[dict[str, Any]], model_name: str) -> list[dict[str, Any]]:
    filtered = autogen.filter_config(config_list, {"tags": [model_name]})
    if not filtered:
        raise ValueError(f"model {model_name!r} not found in CONFIG_LIST tags")
    return filtered


def run_trial(args: argparse.Namespace) -> Path:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.offline_eval:
        evaluator = OfflineEvaluator()
    else:
        from secgym.evaluator import LLMEvaluator
        from secgym.myconfig import CONFIG_LIST

        eval_config_list = filter_config_list(CONFIG_LIST, args.eval_model)
        evaluator = LLMEvaluator(
            config_list=eval_config_list,
            cache_seed=args.cache_seed,
            ans_check_reflection=True,
            sol_check_reflection=True,
            step_checking=True,
            strict_check=False,
        )

    attack = args.attack or next(iter(ATTACKS))
    env = ExcytinEnv(
        attack=attack,
        evaluator=evaluator,
        save_file=str(output_dir / f"env_{attack}.json"),
        max_steps=args.max_steps,
        split=args.split,
        layer=args.layer,
    )
    if args.remote_agent_url:
        agent = RemoteSmartSocAgent(args.remote_agent_url, timeout=args.remote_timeout, token=args.remote_agent_token)
        agent.health()
    else:
        agent = SmartSocAgent(max_steps=args.max_steps, layer=args.layer)

    logs: list[dict[str, Any]] = []
    try:
        for question_idx in range(min(args.num_questions, env.num_questions)):
            observation, info = env.reset(question_idx)
            agent.reset()
            reward = 0
            done = False
            step_info: dict[str, Any] = {}

            for _ in range(args.max_steps):
                action, submit = agent.act(observation)
                observation, reward, done, step_info = env.step(action=action, submit=submit)
                if submit or done:
                    break

            logs.append(
                {
                    "question_idx": question_idx,
                    "env_info": info,
                    "reward": reward,
                    "done": done,
                    "step_info": step_info,
                    "agent": agent.get_logging(),
                }
            )
    finally:
        env.close()

    output_path = output_dir / f"smart_soc_trial_{attack}.json"
    output_path.write_text(json.dumps(logs, indent=2, default=str), encoding="utf-8")
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SmartSocAgent against a small SecRL/ExCyTIn trial.")
    parser.add_argument("--attack", default="", help="Attack name from secgym.excytin_env. Defaults to the first attack.")
    parser.add_argument("--eval_model", default="gpt-4.1", help="Evaluator model tag from SecRL CONFIG_LIST.")
    parser.add_argument("--cache_seed", type=int, default=131)
    parser.add_argument("--max_steps", type=int, default=15)
    parser.add_argument("--layer", choices=("alert", "log", "alert_only"), default="alert")
    parser.add_argument("--split", default="test")
    parser.add_argument("--num_questions", type=int, default=2)
    parser.add_argument("--output_dir", default="trial_results")
    parser.add_argument("--offline_eval", action="store_true", help="Use a local zero-reward evaluator for wiring checks.")
    parser.add_argument("--remote_agent_url", default="", help="HTTP URL for a SmartSocAgent server running on RunPod.")
    parser.add_argument("--remote_agent_token", default="", help="Optional bearer token for the remote agent server.")
    parser.add_argument("--remote_timeout", type=float, default=300.0)
    return parser.parse_args()


if __name__ == "__main__":
    print(run_trial(parse_args()))
