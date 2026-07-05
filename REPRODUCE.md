# Reproducing Smart SOC Agent Experiments

This repository is a standalone Smart SOC Agent artifact. It expects `secgym` from SecRL/ExCyTIn-Bench to be installed in the active Python environment and the ExCyTIn database containers/configuration to be available. Runtime code does not add sibling repository paths.

## Frozen Protocol

- Split: `test`
- Layer: `alert`
- Noise: `0` through the default ExCyTIn test setup
- Max steps: `25`
- Evaluator: `gpt-4o`
- Cache seed: `131`
- Agent temperature: `0`
- Default smart arm: `full` with registry, planner, schema cache, answer gate, Qdrant vector RAG, and scanner enabled

The frozen config is recorded in `configs/smart_agent.yaml`.

## Ollama on RunPod

The default smart-agent LLM backend is Ollama-compatible for RunPod GPU deployments. Point the agent at the RunPod Ollama base URL that serves `/api/generate`:

Windows PowerShell:

```powershell
$env:OLLAMA_BASE_URL = "https://<runpod-ollama-host>"
$env:OLLAMA_MODEL = "qwen2.5:7b-instruct"
$env:SMART_SOC_LLM_BACKEND = "ollama"
```

Linux/Ubuntu:

```bash
export OLLAMA_BASE_URL=https://<runpod-ollama-host>
export OLLAMA_MODEL=qwen2.5:7b-instruct
export SMART_SOC_LLM_BACKEND=ollama
```

`OLLAMA_BASE_URL` auto-enables the Ollama backend. You can also pass `--llm_backend ollama` to `scripts/run_eval.py` or `scripts/agent_http_server.py` for explicit reproducibility, or `--llm_backend none` to disable internal LLM calls. The repository includes `.env.example` with the Ollama, Qdrant RAG, and optional remote-agent variables; put real local values in `.env`, which is intentionally ignored. `run_eval.py` and `agent_http_server.py` load `.env` automatically when it exists.

## Install

Windows PowerShell:

```powershell
python -m pip install -e .
python -m pytest tests -q
```

Linux/Ubuntu:

```bash
python -m pip install -e .
python -m pytest tests -q
```

## RAG Assets

RAG assets are external/generated and are intentionally not tracked in git. The default smart arm prefers a remote SOC Defender RAG service when `SOC_DEFENDER_RAG_URL` is set; use that mode when the remote server already hosts the RAG content.

Local RAG assets, when rebuilt, live under `data/rag/`:

- Raw corpus: ATT&CK Enterprise, Sigma, D3FEND, CWE
- Chunks: `data/rag/chunks.jsonl`
- Qdrant index: `data/rag/qdrant/`

To rebuild the local assets:

```bash
python scripts/fetch_rag_corpora.py
python scripts/build_rag_chunks.py
python scripts/build_qdrant_index.py --chunks data/rag/chunks.jsonl --output-dir data/rag/qdrant
```

Local Qdrant retrieval uses the SecureBERT embedding model recorded in `data/rag/qdrant/build_manifest.json`. The build command defaults to `device: cuda`, so RunPod GPU runs use CUDA by default. To force the lightweight keyword fallback, set:

Windows PowerShell:

```powershell
$env:SMART_SOC_RAG_BACKEND = "keyword"
```

Linux/Ubuntu:

```bash
export SMART_SOC_RAG_BACKEND=keyword
```

## Wiring Check

Offline evaluator, two questions:

```bash
python scripts/run_trial.py --num_questions 2 --max_steps 25 --layer alert --offline_eval
```

## Evaluation

Full smart-agent arm under the frozen protocol:

```bash
python scripts/run_eval.py --arms full --max_steps 25 --layer alert --split test --eval_model gpt-4o --cache_seed 131
```

All ablations plus baseline:

```bash
python scripts/run_eval.py --arms all --max_steps 25 --layer alert --split test --eval_model gpt-4o --cache_seed 131
```

Trial run without LLM judging:

```bash
python scripts/run_eval.py --arms full --trial_run --offline_eval --max_steps 25 --layer alert
```

## Analysis Tables

```bash
python scripts/analyze_results.py --input_dir final_results --output_dir analysis_results
```

Outputs:

- `analysis_results/summary.csv`
- `analysis_results/per_incident.csv`
- `analysis_results/episodes.csv`
- `analysis_results/summary.json`

## Figures

Source figures are:

- `docs/figures/fig1_baseline_excytin.svg`
- `docs/figures/fig2_smart_soc_agent.svg`

Convert to PDF with either `rsvg-convert` or Inkscape.

Linux/Ubuntu:

```bash
rsvg-convert -f pdf -o docs/figures/fig1_baseline_excytin.pdf docs/figures/fig1_baseline_excytin.svg
rsvg-convert -f pdf -o docs/figures/fig2_smart_soc_agent.pdf docs/figures/fig2_smart_soc_agent.svg
```

Windows PowerShell with Inkscape on `PATH`:

```powershell
inkscape docs\figures\fig1_baseline_excytin.svg --export-type=pdf --export-filename=docs\figures\fig1_baseline_excytin.pdf
inkscape docs\figures\fig2_smart_soc_agent.svg --export-type=pdf --export-filename=docs\figures\fig2_smart_soc_agent.pdf
```

## Known External Blocker

Live judged runs require valid SecRL evaluator credentials. Earlier live trials reached the ExCyTIn environment but failed at evaluator authentication with OpenAI `401 User not found`; offline evaluator runs remain available for wiring checks.
