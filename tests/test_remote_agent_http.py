from __future__ import annotations

from threading import Thread

from scripts.agent_http_server import AgentHTTPServer, AgentRequestHandler, _llm_info
from smart_soc_agent.agent import SmartSocAgent
from smart_soc_agent.llm import OllamaConfig, OllamaLLMClient
from smart_soc_agent.remote_agent import RemoteSmartSocAgent


def test_remote_agent_http_round_trip():
    server = AgentHTTPServer(("127.0.0.1", 0), AgentRequestHandler)
    server.agent = SmartSocAgent(max_steps=5)
    server.token = "secret"
    server.quiet = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        client = RemoteSmartSocAgent(f"http://{host}:{port}", token="secret", timeout=5)

        assert client.health()["ok"] is True
        client.reset()
        action, submit = client.act("Question: What IP address was involved?")

        assert action == "SHOW TABLES"
        assert submit is False
        assert client.get_logging()["action_trace"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_llm_info_reports_ollama_runtime_controls():
    llm = OllamaLLMClient(
        OllamaConfig(
            base_url="https://runpod.example",
            model="qwen2.5:14b",
            timeout=45,
            num_predict=512,
        )
    )

    assert _llm_info(llm) == {
        "backend": "ollama",
        "model": "qwen2.5:14b",
        "base_url": "https://runpod.example",
        "timeout": 45,
        "num_predict": 512,
    }
