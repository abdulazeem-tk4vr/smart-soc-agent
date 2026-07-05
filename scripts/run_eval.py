#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from smart_soc_agent.agent import SmartSocAgent
from smart_soc_agent.env import load_env_file
from smart_soc_agent.llm import build_llm_client_from_env
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
    import autogen

    filtered = autogen.filter_config(config_list, {"tags": [model_name]})
    if not filtered:
        raise ValueError(f"model {model_name!r} not found in CONFIG_LIST tags")
    return filtered


def build_evaluator(args: argparse.Namespace):
    if args.offline_eval:
        return OfflineEvaluator()
    from secgym.evaluator import LLMEvaluator
    from secgym.myconfig import CONFIG_LIST

    eval_config_list = filter_config_list(CONFIG_LIST, args.eval_model)
    return LLMEvaluator(
        config_list=eval_config_list,
        cache_seed=args.cache_seed,
        ans_check_reflection=True,
        sol_check_reflection=True,
        step_checking=True,
        strict_check=False,
    )


def build_agent(arm: str, args: argparse.Namespace):
    if arm == "baseline":
        if args.remote_agent_url:
            raise ValueError("baseline arm cannot run through SmartSocAgent remote HTTP service")
        from secgym.agents import BaselineAgent
        from secgym.myconfig import CONFIG_LIST

        agent_config_list = filter_config_list(CONFIG_LIST, args.model)
        return BaselineAgent(
            config_list=agent_config_list,
            cache_seed=args.cache_seed,
            temperature=args.temperature,
            max_steps=args.max_steps,
        )

    mode = "deterministic" if arm in {"B1_backbone", "B2_schema"} else "agentic"
    if args.remote_agent_url:
        agent = RemoteSmartSocAgent(args.remote_agent_url, timeout=args.remote_timeout, token=args.remote_agent_token)
        agent.health()
        return agent
    agent = SmartSocAgent(
        max_steps=args.max_steps,
        layer=args.layer,
        mode=mode,
        llm=build_llm_client_from_env(args.llm_backend),
        rag_enabled=arm in {"B4_rag", "full"},
        scanner_enabled=arm == "full",
    )
    agent.usage_summary["ablation_arm"] = arm
    agent.usage_summary["rag_enabled"] = arm in {"B4_rag", "full"}
    agent.usage_summary["scanner_enabled"] = arm == "full"
    return agent


def run_episode(env: Any, agent: Any, question_idx: int, max_steps: int) -> dict[str, Any]:
    observation, info = env.reset(question_idx)
    if hasattr(agent, "reset"):
        agent.reset()
    reward = 0
    done = False
    step_info: dict[str, Any] = {}
    steps = 0
    submitted = False
    started = time.time()

    for steps in range(1, max_steps + 1):
        action, submit = agent.act(observation)
        submitted = bool(submit)
        observation, reward, done, step_info = env.step(action=action, submit=submit)
        if submit or done:
            break

    logging = agent.get_logging() if hasattr(agent, "get_logging") else {}
    return {
        "question_idx": question_idx,
        "env_info": info,
        "reward": reward,
        "done": done,
        "submitted": submitted,
        "steps": steps,
        "seconds": round(time.time() - started, 3),
        "step_info": step_info,
        "agent": logging,
    }


def run_arm(args: argparse.Namespace, arm: str, attack: str, evaluator: Any) -> Path:
    from secgym.excytin_env import ExcytinEnv

    output_dir = Path(args.output_dir) / arm
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"agent_{attack}.json"
    env = ExcytinEnv(
        attack=attack,
        evaluator=evaluator,
        save_file=str(output_dir / f"env_{attack}.json"),
        max_steps=args.max_steps,
        split=args.split,
        layer=args.layer,
    )
    agent = build_agent(arm, args)
    logs: list[dict[str, Any]] = []
    try:
        question_count = env.num_questions if args.num_questions < 0 else min(args.num_questions, env.num_questions)
        for question_idx in range(question_count):
            logs.append(run_episode(env, agent, question_idx, args.max_steps))
            output_path.write_text(json.dumps(logs, indent=2, default=str), encoding="utf-8")
            if args.trial_run and len(logs) >= 2:
                break
    finally:
        env.close()
    return output_path


def parse_arms(raw: str) -> list[str]:
    aliases = {
        "all": ["baseline", "B1_backbone", "B2_schema", "B3_gate", "B4_rag", "full"],
        "smart": ["B1_backbone", "B2_schema", "B3_gate", "B4_rag", "full"],
    }
    if raw in aliases:
        return aliases[raw]
    return [part.strip() for part in raw.split(",") if part.strip()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SmartSocAgent evaluation/ablation arms on ExCyTIn-Bench.")
    parser.add_argument("--arms", default="full", help="Comma list or alias: baseline, smart, all.")
    parser.add_argument("--attack", default="", help="Single attack. Default runs all attacks.")
    parser.add_argument("--model", default="gpt-4.1-nano")
    parser.add_argument("--eval_model", default="gpt-4o")
    parser.add_argument("--cache_seed", type=int, default=131)
    parser.add_argument("--temperature", type=float, default=0)
    parser.add_argument("--max_steps", type=int, default=25)
    parser.add_argument("--layer", choices=("alert", "log", "alert_only"), default="alert")
    parser.add_argument("--split", default="test")
    parser.add_argument("--num_questions", type=int, default=-1)
    parser.add_argument("--output_dir", default="final_results")
    parser.add_argument("--trial_run", action="store_true")
    parser.add_argument("--offline_eval", action="store_true")
    parser.add_argument("--remote_agent_url", default="", help="HTTP URL for a SmartSocAgent server running on RunPod.")
    parser.add_argument("--remote_agent_token", default="", help="Optional bearer token for the remote agent server.")
    parser.add_argument("--remote_timeout", type=float, default=300.0)
    parser.add_argument("--llm_backend", default="", help="Internal smart-agent LLM backend: ollama, none. Defaults to SMART_SOC_LLM_BACKEND.")
    parser.add_argument("--env_file", default=".env", help="Load environment variables from this file if it exists.")
    return parser.parse_args()


def main() -> int:
    from secgym.excytin_env import ATTACKS

    args = parse_args()
    load_env_file(args.env_file)
    args.remote_agent_url = args.remote_agent_url or os.getenv("REMOTE_AGENT_URL", "")
    args.remote_agent_token = args.remote_agent_token or os.getenv("REMOTE_AGENT_TOKEN", "")
    evaluator = build_evaluator(args)
    attacks = [args.attack] if args.attack else list(ATTACKS)
    written: list[str] = []
    for arm in parse_arms(args.arms):
        for attack in attacks:
            written.append(str(run_arm(args, arm, attack, evaluator)))
            if args.trial_run:
                break
    print(json.dumps({"written": written}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
