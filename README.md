# Federated Learning Project (Simple Guide)

This repo runs a small federated learning setup in Python.
It also saves logs and metrics so you can compare runs.

## What you need

- Python 3.10+
- A virtual environment (optional but recommended)

## Install

From the project root:

```bash
pip install -e .
```

## Run a basic experiment

```bash
flwr run .
```

## Launch the Dashboard

The dashboard keeps the current `pyproject.toml` defaults and launches experiments
through `./run.sh`, then streams live progress and exposes artifacts in the browser.

Install the optional dashboard dependencies:

```bash
pip install -e ".[dashboard]"
```

Start the app:

```bash
dynamic-fl-dashboard
```

Then open:

```text
http://127.0.0.1:8000
```

## Save logs and metrics per run

This script runs a training job and writes a folder under `logs/`.

```bash
python scripts/run_simulation_and_log.py
```

Optional options:

```bash
python scripts/run_simulation_and_log.py --federation local-simulation-gpu
python scripts/run_simulation_and_log.py --run-config "num-server-rounds=5 local-epochs=2"
```


## Run a sweep (multiple strategies, automated analysis)

The main workflow is automated with `run_thesis_sweep.sh`:

```bash
./run_thesis_sweep.sh --name my_sweep
```

Key options:
- `--strategies "bulyan,multikrum,fedtrimmedavg"` (comma-separated list)
- `--sweeps-file docs/thesis_sweeps.conf` (custom sweep scenarios)
- `--llm-analysis` (run LLM analysis after each strategy)
- `--llm-model claude-opus-4-6` (specify LLM model)

Example (all strategies, with LLM analysis):

```bash
./run_thesis_sweep.sh --name thesis --strategies "bulyan,multikrum,fedtrimmedavg" --llm-analysis --llm-model claude-opus-4-6
```

For each strategy, the script writes:
- `sweep_settings.csv` (run configs)
- `sweep_summary.txt` (metrics summary)
- `llm_comprehensive_payload.json` (LLM input)
- `llm_comprehensive_analysis.md` (LLM markdown report)

See all options with:
```bash
./run_thesis_sweep.sh --help
```

## LLM Vulnerability Analysis

You can generate comprehensive, vulnerability-focused reports from all sweep results using an LLM (Claude via Anthropic/Azure).

**Setup:**
1. Install the SDK:
  ```bash
  pip install anthropic
  ```
2. Fill your credentials in `.env` at the project root:
  ```bash
  ANTHROPIC_API_KEY=...
  ANTHROPIC_BASE_URL=...
  ANTHROPIC_MODEL=claude-opus-4-6
  ```

**Manual analysis:**
```bash
python scripts/llm_sweep_analysis.py --sweeps-root logs/sweeps/FEMNIST_2026-04-02 --call-api
```
Replace the path with your sweep folder as needed.

**Automatic analysis:**
Add `--llm-analysis` to your sweep command (see above). This will run the LLM analysis after each strategy completes.

**Outputs:**
- `llm_comprehensive_payload.json` (per-strategy LLM input)
- `llm_comprehensive_analysis.md` (per-strategy LLM markdown report)
- `llm_global_analysis.md` (cross-strategy synthesis, if multiple strategies)

**How it works:**
- The script aggregates all metrics, summaries, and attack logs for each strategy.
- It sends a single request per strategy to the LLM (Claude), with a max token limit (default 7000 output tokens).
- Only strategies that support explicit malicious client selection (e.g., MultiKrum, Krum) will report `malicious_selected_fraction`.
- All results are written as markdown for easy review.

**Tip:** You can preview markdown files in VS Code by right-clicking the file and selecting "Open Preview" or pressing `Cmd+Shift+V` (Mac) or `Ctrl+Shift+V` (Windows/Linux).

See also: [docs/how_to_run_llm_sweep_analysis.md](docs/how_to_run_llm_sweep_analysis.md)

## Change settings

Most settings live in `pyproject.toml`. That file has the knobs for runs,
data, attacks, and training.

## Where outputs go

Each run creates a folder like this:

```text
logs/<run-name>/
  stdout.log
  stderr.log
  meta.json
  metrics/
  graphs/
  summaries/
```

## Project layout

```text
dynamic_fl/
  pytorchexample/
    client_app.py
    server_app.py
    task.py
  scripts/
    run_simulation_and_log.py
  pyproject.toml
  run_thesis_sweep.sh
  README.md
```
