#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from smart_soc_agent.agent import SmartSocAgent
from smart_soc_agent.env import load_env_file
from smart_soc_agent.llm import build_llm_client_from_env


class AgentHTTPServer(ThreadingHTTPServer):
    agent: SmartSocAgent
    token: str


class AgentRequestHandler(BaseHTTPRequestHandler):
    server: AgentHTTPServer

    def do_GET(self) -> None:
        if not self._authorized():
            self._json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        if self.path == "/health":
            self._json({"ok": True, "agent": self.server.agent.name, "mode": self.server.agent.mode})
            return
        if self.path == "/logging":
            self._json(self.server.agent.get_logging())
            return
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if not self._authorized():
            self._json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        try:
            payload = self._read_json()
            if self.path == "/reset":
                self.server.agent.reset(change_seed=bool(payload.get("change_seed", True)))
                self._json({"ok": True})
                return
            if self.path == "/act":
                observation = str(payload.get("observation") or "")
                action, submit = self.server.agent.act(observation)
                self._json({"action": action, "submit": submit})
                return
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._json({"error": str(exc), "type": type(exc).__name__}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def log_message(self, format: str, *args: Any) -> None:
        if getattr(self.server, "quiet", False):
            return
        super().log_message(format, *args)

    def _authorized(self) -> bool:
        token = getattr(self.server, "token", "")
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        return header == f"Bearer {token}"

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        data = json.loads(raw or "{}")
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        return data

    def _json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve SmartSocAgent over HTTP for remote SecRL gym control.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--mode", choices=("deterministic", "agentic", "full", "graph"), default="full")
    parser.add_argument("--max_steps", type=int, default=25)
    parser.add_argument("--layer", choices=("alert", "log", "alert_only"), default="alert")
    parser.add_argument("--disable_rag", action="store_true")
    parser.add_argument("--disable_scanner", action="store_true")
    parser.add_argument("--llm_backend", default="", help="Internal smart-agent LLM backend: ollama, none. Defaults to SMART_SOC_LLM_BACKEND.")
    parser.add_argument("--env_file", default=".env", help="Load environment variables from this file if it exists.")
    parser.add_argument("--token", default="", help="Optional bearer token required from local proxy.")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    load_env_file(args.env_file)
    server = AgentHTTPServer((args.host, args.port), AgentRequestHandler)
    server.agent = SmartSocAgent(
        max_steps=args.max_steps,
        layer=args.layer,
        mode=args.mode,
        llm=build_llm_client_from_env(args.llm_backend),
        rag_enabled=not args.disable_rag,
        scanner_enabled=not args.disable_scanner,
    )
    server.token = args.token
    server.quiet = args.quiet
    print(f"SmartSocAgent HTTP server listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
