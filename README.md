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

## Run a sweep (multiple runs)

```bash
./run_thesis_sweep.sh --name my_sweep
```

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
