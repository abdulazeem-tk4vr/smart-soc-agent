import os

from smart_soc_agent.env import load_env_file


def test_load_env_file_reads_basic_values_without_overriding(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "# comment",
                "OLLAMA_BASE_URL=https://runpod.example",
                'OLLAMA_MODEL="qwen2.5:7b-instruct"',
                "EXISTING=value-from-file",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("EXISTING", "already-set")

    loaded = load_env_file(env_path)

    assert loaded == 2
    assert os.environ["OLLAMA_BASE_URL"] == "https://runpod.example"
    assert os.environ["OLLAMA_MODEL"] == "qwen2.5:7b-instruct"
    assert os.environ["EXISTING"] == "already-set"


def test_load_env_file_can_override(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("OLLAMA_TIMEOUT=120\n", encoding="utf-8")
    monkeypatch.setenv("OLLAMA_TIMEOUT", "60")

    loaded = load_env_file(env_path, override=True)

    assert loaded == 1
    assert os.environ["OLLAMA_TIMEOUT"] == "120"
