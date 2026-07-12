# Remote Agent Reproduction Runbook

This is the intended final setup:

- Linux/RunPod runs Ollama, `scripts/rag_server.py`, and `scripts/agent_http_server.py`.
- Windows runs SecRL/ExCyTIn and calls the Linux SmartSocAgent over HTTP.
- Acting model: `qwen2.5:14b`
- Eval model: `gpt-4o`

## Frozen Protocol

- Split: `test`
- Layer: `alert`
- Max steps: `25`
- Evaluator: `gpt-4o`
- Cache seed: `131`
- Default smart arm: `full`

## Linux Terminal A: RAG Server

```bash
cd /workspace/smart-soc-agent

python scripts/rag_server.py \
  --qdrant-path data/rag/qdrant \
  --device cuda \
  --host 127.0.0.1 \
  --port 8765
```

The RAG index is assumed to already exist at `data/rag/qdrant`.

## Linux Terminal B: SmartSocAgent HTTP Server

```bash
cd /workspace/smart-soc-agent

export SOC_DEFENDER_RAG_URL=http://127.0.0.1:8765
export SMART_SOC_RAG_BACKEND=http
export SMART_SOC_LLM_BACKEND=ollama
export OLLAMA_BASE_URL=https://<runpod-ollama-host>
export OLLAMA_MODEL=qwen2.5:14b
export OLLAMA_TIMEOUT=45
export OLLAMA_NUM_PREDICT=512

python scripts/agent_http_server.py \
  --host 0.0.0.0 \
  --port 8080 \
  --mode full \
  --max_steps 25 \
  --layer alert \
  --llm_backend ollama
```

Check the server from Windows:

```powershell
Invoke-RestMethod http://<linux-host>:8080/health
```

The `llm` object should show `model: qwen2.5:14b`, `timeout: 45`, and `num_predict: 512`.

## Windows Quick Wiring Check

```powershell
python scripts/run_eval.py `
  --arms full `
  --trial_run `
  --offline_eval `
  --max_steps 25 `
  --layer alert `
  --split test `
  --remote_agent_url http://<linux-host>:8080
```

## Windows Judged Full Eval

```powershell
python scripts/run_eval.py `
  --arms full `
  --max_steps 25 `
  --layer alert `
  --split test `
  --eval_model gpt-4o `
  --cache_seed 131 `
  --remote_agent_url http://<linux-host>:8080
```

## Remote-Safe Ablations

Do not run `--arms all --remote_agent_url`. The baseline runs locally in Windows, while smart-agent ablations depend on how the Linux HTTP server was launched.

Baseline, local Windows only:

```powershell
python scripts/run_eval.py `
  --arms baseline `
  --max_steps 25 `
  --layer alert `
  --split test `
  --eval_model gpt-4o `
  --cache_seed 131
```

Full remote agent, with the Linux server launched normally:

```powershell
python scripts/run_eval.py `
  --arms full `
  --max_steps 25 `
  --layer alert `
  --split test `
  --eval_model gpt-4o `
  --cache_seed 131 `
  --remote_agent_url http://<linux-host>:8080
```

No-RAG/gate ablation: restart the Linux server with `--disable_rag`, then run:

```powershell
python scripts/run_eval.py `
  --arms B3_gate `
  --max_steps 25 `
  --layer alert `
  --split test `
  --eval_model gpt-4o `
  --cache_seed 131 `
  --remote_agent_url http://<linux-host>:8080
```

RAG-enabled ablation: restart the Linux server with RAG enabled, then run:

```powershell
python scripts/run_eval.py `
  --arms B4_rag `
  --max_steps 25 `
  --layer alert `
  --split test `
  --eval_model gpt-4o `
  --cache_seed 131 `
  --remote_agent_url http://<linux-host>:8080
```

## Analysis

```bash
python scripts/analyze_results.py --input_dir final_results --output_dir analysis_results
```
