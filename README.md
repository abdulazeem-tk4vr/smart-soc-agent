# smart-soc-agent

A standalone SOC investigation agent for evaluating evidence-gated threat hunting workflows on SecRL/ExCyTIn-Bench.

## Compatibility

- Runtime code is self-contained in this repository and imports through `smart_soc_agent`.
- Benchmark wrappers expect `secgym` to be installed as an environment dependency; they do not add sibling repo paths to `sys.path`.
- Python code uses portable `pathlib` paths and is intended to run on Windows PowerShell and Linux/Ubuntu shells.

## Quick Checks

Windows PowerShell:

```powershell
python -m pytest tests -q
```

Linux/Ubuntu:

```bash
python -m pytest tests -q
```

## SecRL Trial Wrapper

After installing SecRL/ExCyTIn-Bench as `secgym` in the active environment and ensuring its containers/config are available:

```bash
python scripts/run_trial.py --num_questions 2 --max_steps 15 --layer alert
```

Offline wiring check:

```bash
python scripts/run_trial.py --num_questions 2 --max_steps 25 --layer alert --offline_eval
```

## RAG

The default `full`/`agentic` graph uses SOC Defender RAG. It prefers an HTTP service when `SOC_DEFENDER_RAG_URL` is set, which is the expected mode when running against a remote server that already hosts the RAG content. If local generated assets exist under `data/rag`, it can also use the local Qdrant vector index. Keyword retrieval remains available as an explicit fallback with:

```bash
SMART_SOC_RAG_BACKEND=keyword python scripts/run_eval.py --arms full
```

RAG corpora, chunks, and Qdrant indexes are generated/external artifacts and are intentionally not tracked in git. To rebuild local assets:

```bash
python scripts/fetch_rag_corpora.py
python scripts/build_rag_chunks.py
python scripts/build_qdrant_index.py --chunks data/rag/chunks.jsonl --output-dir data/rag/qdrant
```

## Ollama

The smart-agent LLM hooks are compatible with an Ollama server hosted on RunPod GPU. Set the Ollama endpoint and model, then enable the backend:

```bash
export OLLAMA_BASE_URL=https://<runpod-ollama-host>
export OLLAMA_MODEL=qwen2.5:7b-instruct
export SMART_SOC_LLM_BACKEND=ollama
python scripts/run_eval.py --arms full --llm_backend ollama
```

The endpoint should be the Ollama base URL that serves `/api/generate`. `OLLAMA_BASE_URL` auto-enables the Ollama backend; the explicit backend flag is useful for reproducibility. Use `.env.example` as the template for local RunPod/Ollama settings and keep actual values in `.env`, which is git-ignored. `run_eval.py` and `agent_http_server.py` load `.env` automatically when it exists.

## Evaluation

Frozen-protocol full arm:

```bash
python scripts/run_eval.py --arms full --max_steps 25 --layer alert --split test --eval_model gpt-4o --cache_seed 131
```

Ablations plus baseline:

```bash
python scripts/run_eval.py --arms all --max_steps 25 --layer alert --split test --eval_model gpt-4o --cache_seed 131
python scripts/analyze_results.py --input_dir final_results --output_dir analysis_results
```

See `REPRODUCE.md` for complete reproduction notes.
