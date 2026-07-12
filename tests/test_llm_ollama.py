import pytest

from smart_soc_agent.llm import OllamaConfig, OllamaLLMClient, build_llm_client_from_env


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, json, timeout):
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeResponse(self.responses.pop(0))


def test_build_llm_client_from_env_ollama(monkeypatch):
    monkeypatch.setenv("SMART_SOC_LLM_BACKEND", "ollama")
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://runpod.example/ollama/")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:14b")
    monkeypatch.setenv("OLLAMA_TIMEOUT", "120")
    monkeypatch.setenv("OLLAMA_NUM_PREDICT", "384")

    client = build_llm_client_from_env()

    assert isinstance(client, OllamaLLMClient)
    assert client.config.base_url == "https://runpod.example/ollama"
    assert client.config.model == "qwen2.5:14b"
    assert client.config.timeout == 120
    assert client.config.num_predict == 384


def test_build_llm_client_from_env_none(monkeypatch):
    monkeypatch.delenv("SMART_SOC_LLM_BACKEND", raising=False)
    monkeypatch.delenv("SOC_DEFENDER_LLM_BACKEND", raising=False)
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)

    assert build_llm_client_from_env() is None
    assert build_llm_client_from_env("none") is None


def test_build_llm_client_from_env_auto_detects_ollama_url(monkeypatch):
    monkeypatch.delenv("SMART_SOC_LLM_BACKEND", raising=False)
    monkeypatch.delenv("SOC_DEFENDER_LLM_BACKEND", raising=False)
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://runpod.example")

    assert isinstance(build_llm_client_from_env(), OllamaLLMClient)


def test_ollama_client_repairs_non_json_response():
    session = FakeSession(
        [
            {"response": "not json"},
            {"response": '{"intent_type": "query_logs", "sql": "SHOW TABLES"}'},
        ]
    )
    client = OllamaLLMClient(
        OllamaConfig(base_url="https://runpod.example", model="llama3.1:8b", timeout=30),
        session=session,
    )

    parsed = client.complete_json([{"role": "user", "content": "Return JSON"}], schema_hint={"sql": "string"})

    assert parsed["sql"] == "SHOW TABLES"
    assert len(session.calls) == 2
    assert session.calls[0]["url"] == "https://runpod.example/api/generate"
    assert session.calls[0]["json"]["format"] == "json"
    assert session.calls[0]["json"]["options"]["num_predict"] == 512


def test_build_llm_client_from_env_rejects_unknown_backend():
    with pytest.raises(ValueError):
        build_llm_client_from_env("not-real")
