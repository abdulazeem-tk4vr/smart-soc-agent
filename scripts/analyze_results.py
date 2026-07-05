#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import mean
from typing import Any


def load_logs(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def iter_result_files(root: Path):
    for path in root.rglob("agent_*.json"):
        if path.name.startswith("agent_"):
            arm = path.parent.name
            attack = path.stem.removeprefix("agent_")
            yield arm, attack, path


def episode_metrics(log: dict[str, Any]) -> dict[str, Any]:
    agent = log.get("agent") if isinstance(log.get("agent"), dict) else {}
    trace = agent.get("action_trace") if isinstance(agent, dict) else []
    trace = trace if isinstance(trace, list) else []
    query_steps = [item for item in trace if isinstance(item, dict) and not item.get("submit")]
    submitted = bool(log.get("submitted") or any(item.get("submit") for item in trace if isinstance(item, dict)))
    sqls = [str(item.get("action") or "").strip().lower() for item in query_steps]
    gate_rejections = 0
    schema_steps = 0
    rag_calls = 0
    scanner_annotations = 0
    for item in trace:
        if not isinstance(item, dict):
            continue
        action = str(item.get("action") or "")
        if action.lower().startswith(("show tables", "describe ")):
            schema_steps += 1
        for node in item.get("graph_traces") or []:
            output = node.get("output_summary") if isinstance(node, dict) else {}
            if node.get("node") == "responder":
                decision = (output.get("verifier_candidate") or {}).get("gate_decision") or {}
                if decision and decision.get("approved") is False:
                    gate_rejections += 1
            if node.get("node") == "rag" and output.get("documents", 0):
                rag_calls += 0 if output.get("cache_hit") else 1
            if node.get("node") == "scanner":
                scanner_annotations += len(output.get("annotations") or [])
    return {
        "reward": float(log.get("reward") or 0),
        "success": 1 if float(log.get("reward") or 0) == 1 else 0,
        "steps": int(log.get("steps") or len(trace) or 0),
        "submitted": 1 if submitted else 0,
        "query_count": len(query_steps),
        "unique_query_count": len(set(sqls)),
        "repeated_query_rate": 0.0 if not sqls else 1.0 - (len(set(sqls)) / len(sqls)),
        "schema_steps": schema_steps,
        "gate_rejections": gate_rejections,
        "rag_calls": rag_calls,
        "scanner_annotations": scanner_annotations,
    }


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    keys = (
        "reward",
        "success",
        "steps",
        "submitted",
        "query_count",
        "unique_query_count",
        "repeated_query_rate",
        "schema_steps",
        "gate_rejections",
        "rag_calls",
        "scanner_annotations",
    )
    return {"episodes": len(rows), **{key: round(mean(float(row[key]) for row in rows), 4) for key in keys}}


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def analyze(root: Path, output_dir: Path) -> dict[str, Any]:
    episode_rows: list[dict[str, Any]] = []
    for arm, attack, path in iter_result_files(root):
        for idx, log in enumerate(load_logs(path)):
            episode_rows.append({"arm": arm, "attack": attack, "question_idx": log.get("question_idx", idx), **episode_metrics(log)})

    summary_rows: list[dict[str, Any]] = []
    for arm in sorted({row["arm"] for row in episode_rows}):
        rows = [row for row in episode_rows if row["arm"] == arm]
        summary_rows.append({"arm": arm, **aggregate(rows)})
    breakdown_rows: list[dict[str, Any]] = []
    for arm in sorted({row["arm"] for row in episode_rows}):
        for attack in sorted({row["attack"] for row in episode_rows if row["arm"] == arm}):
            rows = [row for row in episode_rows if row["arm"] == arm and row["attack"] == attack]
            breakdown_rows.append({"arm": arm, "attack": attack, **aggregate(rows)})

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "summary.csv", summary_rows)
    write_csv(output_dir / "per_incident.csv", breakdown_rows)
    write_csv(output_dir / "episodes.csv", episode_rows)
    payload = {"summary": summary_rows, "per_incident": breakdown_rows, "episodes": len(episode_rows)}
    (output_dir / "summary.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze SmartSocAgent/SecRL evaluation JSON logs.")
    parser.add_argument("--input_dir", default="final_results")
    parser.add_argument("--output_dir", default="analysis_results")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = analyze(Path(args.input_dir), Path(args.output_dir))
    print(json.dumps(payload["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
