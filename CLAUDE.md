# Read This Before Every Session

Before making changes, read the following documentation to understand the current state:

1. **This file (CLAUDE.md)** — project rules, priorities, and operating constraints
2. **docs/DATABASE_WORKFLOW.md** — the end-to-end database-backed vulnerability discovery workflow, including schema documentation, CSV-to-table mapping, testing status, and remaining tests
3. **db/schema.sql** — the SQLite schema (13 tables) with source-data comments explaining which CSV produces each table
4. **db/queries.py** — example vulnerability discovery queries the agent should be able to run
5. **docs/FEMNIST_VULNERABILITY_UPDATE.md** — current ATLAS-mapped research findings and candidate failure modes
6. **docs/vulnerability_pilot_once.conf** — the pilot sweep config

Key rules for database and workflow work:
- Do not assume the schema works against real CSV outputs until tested. Only dummy data validation has passed so far.
- Do not invent database fields unless they are supported by real run artifacts or clearly needed for the agent workflow.
- Keep the system SQLite-compatible unless there is a strong reason not to.
- If schema changes are made, update docs/DATABASE_WORKFLOW.md and db/validate.py too.
- Always distinguish dummy validation from real sweep validation.
- Always preserve the main goal: plug-and-play vulnerability discovery for federated learning strategies.

# Project Context

This is a federated learning research codebase focused on adversarial robustness and vulnerability-discovery-style testing.

The current research goal is not only to compare final accuracy across defenses, but to test whether adaptive and staged attacks can discover defense-specific weaknesses in federated aggregation methods.

The framework supports:
- multiple aggregation defenses
- multiple attack types
- adaptive attack selection (epsilon-greedy MAB)
- client/cohort selection behavior
- sticky, churn, and per-round-random malicious client scheduling
- delayed-onset attacks
- intensity ramping
- layered/composite attacks (single, fixed, sample_k)
- IID and non-IID data
- FEMNIST, MNIST, CIFAR-10, and possibly CIFAR-100
- clean baseline runs
- metrics logging (accuracy, loss, F1, precision, recall, backdoor ASR, per-class accuracy)
- attack timeline logging
- defense/trust/reputation logging
- structured database storage of all results
- agent-queryable vulnerability discovery
- reproducible experiment runs
- web dashboard for experiment monitoring and control

# Core Code Files

The main implementation lives in `pytorchexample/` (a Flower app) and `scripts/` (orchestration/analysis).

## pytorchexample/ — Flower Application

| File | Lines | Purpose |
|------|-------|---------|
| `task.py` | ~4821 | Largest file. Model definitions (LeNet CNN, ResNet-18, TextClassifier), configurable model dispatch (`_create_vision_model`), dataset loading/partitioning (vision/text/tabular/audio), `AttackEngine` class (all attack types, adaptive MAB, layered/composite attacks, scheduling), data poisoning, backdoor injection, label normalization, metric computation. |
| `server_app.py` | ~1361 | All aggregation strategy implementations: FedAvg, Bulyan, MultiKrum, FedTrimmedAvg, FedMedian, FLTrust, FoolsGold, FLRAM, MAB-RFL. Contains `AttackInjectedStrategyMixin`, trust/reputation scoring, defense selection logging, per-round CSV writing. |
| `client_app.py` | ~333 | Flower client: training loop with attack injection, evaluation with F1/precision/recall metrics, client-side metric reporting. |
| `__init__.py` | 1 | Package marker. |

## scripts/ — Orchestration and Analysis

| File | Lines | Purpose |
|------|-------|---------|
| `run_simulation_and_log.py` | ~3124 | Main simulation runner. Wraps `flwr run`, produces per-run output directories with metrics CSVs, summaries, graphs, configs, and meta.json. This is the script that `run_thesis_sweep.sh` calls for each run. |
| `llm_sweep_analysis.py` | ~575 | LLM-based (Claude API) vulnerability analysis over sweep artifacts. Generates per-strategy and global analysis markdown reports. |
| `generate_sweep_summary.py` | ~570 | Generates compact sweep summary tables from per-run metrics. |
| `vulnerability_analysis.py` | ~530 | Cross-defense, cross-dataset vulnerability analysis. Extracts final accuracy and pivots by attack dimensions. |
| `primitive_attack_rank.py` | ~130 | Ranks primitive attacks by effectiveness across strategies. |
| `adaptive_takeover_summary.py` | ~60 | Summarizes adaptive attack takeover patterns (which attack the MAB converges to). |
| `prefetch_datasets.py` | ~95 | Downloads HF datasets to local cache for offline use. |
| `measure_srv_norm.py` | ~10 | Quick utility to measure server model parameter norm. |
| `__init__.py` | 2 | Package marker. |

## Top-Level Shell Scripts

| File | Purpose |
|------|---------|
| `run_thesis_sweep.sh` | Main sweep runner. Parses sweep config files, iterates strategies × scenarios × seeds, calls `run_simulation_and_log.py` for each. |
| `run.sh` | Quick single-run launcher for development/debugging. |

## Dashboard — Web UI

The `dashboard/` directory contains a web-based experiment control center.

| File | Lines | Purpose |
|------|-------|---------|
| `dashboard/app.py` | ~798 | HTTP server (built-in Python, no Flask dependency). Serves the web UI, provides JSON APIs for experiment status, run history, and live monitoring. |
| `dashboard/static/index.html` | ~306 | Main page — "Dynamic FL Control Center" layout with sidebar navigation. |
| `dashboard/static/app.js` | ~876 | Frontend logic: experiment listing, run status, metric visualization. |
| `dashboard/static/app.css` | ~727 | Styling for the dashboard. |
| `dashboard/__init__.py` | — | Package marker. |

Status: The dashboard exists and is functional but "dashboard persistence" is lower priority.

## Tests

| File | Tests | Purpose |
|------|-------|---------|
| `tests/test_smoke.py` | 37 | TOML config parsing, strategy name registry, model creation, text pipeline, label normalization |
| `tests/test_framework_plumbing.py` | 52 | TOML round-trip, dataset specs (5 vision + text + tabular + audio), model factory (8 combos), attack config parsing (11 overrides), strategy dispatch (8 strategies + mixin check), AttackEngine instantiation |
| `tests/test_trust_strategies.py` | 13 | Trust-weighted aggregation for FLTrust, FoolsGold, FLRAM, MAB-RFL |

**Total: 102 tests, 0 failures, 0 skips** (with venv Python + torch)

Run with: `../myenv/bin/python -m pytest tests/ -v`

# Current Research Framing

The project is being framed as MITRE ATLAS-style adversarial ML threat mapping for federated learning.

Use MITRE ATLAS as a threat-model checklist, not as proof of novelty.

Relevant ATLAS-style categories for this project include:
- data poisoning
- label flipping
- backdoor poisoning
- model poisoning
- gradient/update manipulation
- defense evasion
- stealthy update crafting
- adaptive attack selection
- delayed-onset attacks
- composite/layered attacks
- client/cohort manipulation
- non-IID exploitation
- robust aggregation assumption exploitation
- trust/reputation manipulation
- impact through accuracy degradation, loss increase, backdoor ASR, model collapse, or malicious clients passing aggregation

ATLAS categories that are currently out of scope unless explicitly added later:
- phishing
- credential access
- RAG poisoning
- prompt injection
- LLM jailbreak
- model extraction/theft
- exfiltration
- lateral movement
- infrastructure compromise
- AI agent tool abuse
- supply chain compromise

When writing summaries, use conservative language:
- candidate vulnerability
- potential failure mode
- observed weakness
- needs confirmation across more seeds
- not yet a confirmed novel vulnerability

Do not claim a new vulnerability unless evidence includes clean baselines, attacked runs, multiple seeds, defense-specific failure metrics, and comparison against known literature.

# Current Defenses

Older completed FEMNIST sweeps mainly tested:
- FedTrimmedAvg
- FedMedian
- Bulyan
- MultiKrum

Newer implemented defenses being piloted/tested:
- FLTrust
- FoolsGold
- FLRAM
- MAB-RFL

Plain English explanations:
- FLTrust uses a trusted/root server update and cosine-similarity-based trust weighting.
- FoolsGold uses historical client update similarity to detect Sybil-like clients.
- FLRAM uses multi-signal reliability scoring such as norm, direction, and sign agreement if implemented.
- MAB-RFL uses reputation or bandit-style adaptive reliability scoring over time.

# Current Attack Capabilities

The framework supports or has discussed:
- Gaussian/noise attacks
- sign flip
- ALIE
- mean shift
- label flip
- backdoor
- adaptive attack selection
- weighted/random attack selection
- sticky malicious clients
- churn-based malicious client rotation
- per-round-random malicious client selection
- delayed-onset attacks
- intensity ramping
- layered/composite attacks
- stealth/norm-capping behavior if implemented

For vulnerability analysis, always connect attack behavior to:
- the defense being tested
- the assumption it may exploit
- the metric that shows success or failure
- whether clean baseline comparison exists

# Important Experiment Design Decisions

Clean baselines are required.
For each attacked run, there should be a matching no-attack baseline with the same:
- dataset
- partitioner
- Dirichlet alpha
- strategy
- seed
- number of clients
- number of rounds
- training hyperparameters

Do not compare only absolute attacked accuracy across defenses.
Prefer:
- baseline accuracy
- attacked accuracy
- accuracy drop in percentage points
- accuracy retention
- macro F1 drop
- weighted F1 drop
- backdoor ASR when applicable
- defense-specific logs such as selected malicious fraction, trust scores, reputation scores, or excluded count

For pilots:
- do not use the old full thesis sweep config unless explicitly requested
- use a small custom pilot config first
- one clean baseline and one attacked run per strategy is enough to verify the pipeline
- do not run the full sweep before verifying output files and metrics

The pilot config created or intended for this purpose is:
docs/vulnerability_pilot_once.conf

It should contain one attacked scenario:
PILOT_ALL_ADAPTIVE_CHURN|0|30|3.0|adaptive|churn|0.5|single|||

The intended pilot command is approximately:
```
./run_thesis_sweep.sh \
  --name pilot_vuln \
  --dataset "flwrlabs/femnist" \
  --dirichlet-alpha 0.5 \
  --sweeps-file docs/vulnerability_pilot_once.conf \
  --strategies "bulyan,multikrum,fedtrimmedavg,fedmedian,fltrust,foolsgold,flram,mab-rfl" \
  --repeats 1 \
  --seeds "1337" \
  --trust-level full
```

Before running, always confirm:
- docs/vulnerability_pilot_once.conf is used, not docs/thesis_sweeps.conf
- exactly one attacked scenario is used
- clean BASELINE_clean runs are included
- expected total runs are correct
- output goes under logs/sweeps with the pilot name
- attack_timeline.csv will identify which attack was selected each round
- sweep_settings.csv shows baseline and attacked rows

# Dataset and Model Decisions

## Vision Models (configurable via `model` key in pyproject.toml)

| Model | Config value | Parameters (FEMNIST) | Parameters (CIFAR-10) | Best for |
|-------|-------------|---------------------|----------------------|----------|
| LeNet-style CNN | `simple-cnn` (default) | 66K | 62K | Fast iteration, debugging, FEMNIST/MNIST |
| ResNet-18 (small-image variant) | `resnet18` | 11.2M | 11.2M | Stronger baseline, CIFAR-10 |

Override per run: `--run-config 'model="resnet18"'`

Non-vision modalities (text, tabular) ignore this field and use their own models.

## Text Models

Text datasets use `TextClassifier` — a 2-layer MLP (32768 → 128 → num_classes).
Input features are hash-based bag-of-words vectors (CRC32, dim=32768).
Verified end-to-end with Sentiment140 (3 classes).

## Vision Dataset Mapping

- MNIST uses 1 channel, 10 classes
- FEMNIST uses 1 channel, 62 classes
- CIFAR-10 uses 3 channels, 10 classes
- CIFAR-100 uses 3 channels, 100 classes if supported

## Text Dataset Mapping

- Sentiment140: 3 classes (neg/neutral/pos), labels {0,2,4} auto-normalized to {0,1,2}
- financial_phrasebank, twitter-financial-news-sentiment: cataloged but not yet end-to-end validated

Current recommendation:
- FEMNIST and CIFAR-10 are reasonable for thesis robustness comparisons.
- CIFAR-100 is technically possible only if supported, but the small CNN is likely too weak and may make results noisy.
- Sentiment140 is verified for text modality smoke tests.
- For first pilot, prefer FEMNIST with Dirichlet alpha=0.5.
- Later stress tests can use FEMNIST Dirichlet alpha=0.1.
- Use IID as a control condition later so non-IID failure can be separated from attack failure.

Dirichlet alpha guidance:
- alpha=0.5 means moderate non-IID and is better for pilot/debugging
- alpha=0.1 means severe non-IID and is better for stress testing after the pipeline works

# Metrics Decisions

Accuracy and loss are not enough.

The project now logs (confirmed present in pilot run outputs):
- accuracy
- loss
- macro F1 (`f1_macro`)
- weighted F1 (`f1_weighted`)
- macro precision (`precision_macro`)
- weighted precision (`precision_weighted`)
- macro recall (`recall_macro`)
- weighted recall (`recall_weighted`)
- backdoor ASR (`backdoor_asr`) when backdoor is active
- per-class accuracy (`class_0_accuracy` through `class_61_accuracy` for FEMNIST)
- backdoor loss (`backdoor_loss`)

Per-class accuracy CSVs are already produced (62 for FEMNIST, 10 for MNIST/CIFAR-10). Confusion matrices are not yet logged.

If using sklearn:
- use sklearn.metrics.precision_recall_fscore_support
- use zero_division=0
- make sure it works for FEMNIST with 62 classes

When modifying metrics:
- do not refactor training
- do not change attack logic
- do not change defense logic
- keep existing accuracy/loss behavior
- add scalar metrics to the same Flower MetricRecord flow so CSVs are automatically created

# Reproducibility Decisions

Important reproducibility issues identified:
- global random, NumPy, and PyTorch seeds should be set
- DirichletPartitioner should use an explicit seed
- package/runtime versions should be logged
- config snapshots should be saved
- git commit hash is useful if easy to log
- multiple seeds are required before statistical claims

Minimum thesis-quality validation:
- at least 3 seeds for key configurations
- clean baseline for every attacked run
- mean and standard deviation or confidence intervals
- avoid claiming novelty from one seed or one run

# Current Known Research Findings / Summary Direction

The old FEMNIST sweep should be summarized cautiously.

Observed or reported patterns from previous FEMNIST analysis include:
- older FEMNIST runs tested FedTrimmedAvg, FedMedian, Bulyan, and MultiKrum
- adaptive attack selection often selected different dominant attacks depending on the defense
- this suggests each defense may have a different candidate weakness profile
- coordinate-wise defenses may be sensitive to ALIE, mean shift, or distribution-aware update manipulation
- distance-based defenses such as MultiKrum may be sensitive to ALIE or stealthy updates that remain close to honest distributions
- Bulyan and FedTrimmedAvg may have convergence issues under non-IID data and should be compared against clean baselines and IID controls
- delayed onset and churn/sticky client scheduling are important axes
- layered/composite attacks may cause stronger collapse behavior than single attacks

Important:
Do not treat these as confirmed new vulnerabilities unless the current logs support them and the results are replicated.

# Current Documentation Files

All files verified as of 2026-07-29:

| File | Status | Purpose |
|------|--------|---------|
| `docs/DATABASE_WORKFLOW.md` | EXISTS | End-to-end database-backed vulnerability discovery workflow |
| `docs/FEMNIST_VULNERABILITY_UPDATE.md` | EXISTS | ATLAS-mapped research findings and candidate failure modes |
| `docs/vulnerability_pilot_once.conf` | EXISTS | Minimal pilot sweep config (1 attacked scenario) |
| `docs/thesis_sweeps.conf` | EXISTS | Original thesis sweep config |
| `docs/thesis_sweeps2.conf` | EXISTS | Full factorial 63-scenario sweep config |
| `docs/datasets_catalog.md` | EXISTS | Dataset catalog from Flower Datasets — lists supported and future datasets |
| `docs/how_to_run_llm_sweep_analysis.md` | EXISTS | Instructions for running LLM-based vulnerability analysis |
| `docs/paper_draft.tex` | EXISTS | IEEE conference paper draft (LaTeX) |
| `docs/todo.txt` | EXISTS | Thesis experiment and writing plan with status tracking |
| `docs/reports/vulnerability_report_atlas.md` | EXISTS | Full ATLAS vulnerability report (584 findings from 600 runs) |
| `docs/updates/` | EXISTS | Date-stamped progress updates (see list below) |

Progress updates (in `docs/updates/`):

| File | Date | Summary |
|------|------|---------|
| `2026-06-25.md` | Jun 25 | Initial project setup and architecture |
| `2026-06-25_model_architecture.md` | Jun 25 | ResNet-18 addition, model dispatch system |
| `2026-06-26_text_pipeline.md` | Jun 26 | Text modality pipeline (Sentiment140) |
| `2026-07-01_database_ingestion.md` | Jul 1 | DB ingestion pipeline for real sweep data |
| `2026-07-14_atlas_analysis.md` | Jul 14 | MITRE ATLAS analysis pipeline + vulnerability report |
| `2026-07-26_plumbing_audit.md` | Jul 26 | Framework plumbing audit, 52-test suite, data ingestion (600 runs), ATLAS findings (584), research citations |
| `2026-07-29.md` | Jul 29 | Test hardening (102/102 pass), baseline validation, ATLAS expansion (11 techniques), plug-and-play strategy params, new literature |

Database files:

| File | Status | Purpose |
|------|--------|---------|
| `db/schema.sql` | EXISTS | SQLite DDL with source-data comments (13 tables) |
| `db/create_db.py` | EXISTS | Creates DB + inserts dummy data |
| `db/ingest.py` | EXISTS | Ingests real sweep CSV outputs into the database |
| `db/analyze.py` | EXISTS | ATLAS-mapped vulnerability analysis engine |
| `db/atlas_mapping.py` | EXISTS | MITRE ATLAS technique registry (11 techniques), finding classifier, literature cross-reference |
| `db/queries.py` | EXISTS | 11 vulnerability discovery query functions |
| `db/validate.py` | EXISTS | End-to-end smoke test (WARNING: destructively recreates DB — do NOT run after ingesting real data) |
| `db/dynamic_fl.sqlite` | EXISTS | Database with 600 real runs (252 FEMNIST + 320 MNIST + 22 pilot + 6 dummy) |

Other top-level files:

| File | Purpose |
|------|---------|
| `pyproject.toml` | Build config, Flower federation settings, all experiment parameters |
| `README.md` | Project readme |
| `femnist_sweep_analysis.ipynb` | Jupyter notebook — FEMNIST sweep analysis and visualization |
| `thesis_sweep_analysis.ipynb` | Jupyter notebook — thesis-wide sweep analysis |
| `sweep_run.log` | ~25MB log from a previous full sweep run |
| `final_model.pt` | Saved model checkpoint |
| `.env` | Environment variables (API keys, etc. — gitignored) |
| `.gitignore` | Ignores: logs/, .env, final_model.pt, paper_draft.tex, sweep configs, notebooks |

If asked to update professor-facing status, update docs/FEMNIST_VULNERABILITY_UPDATE.md or create a concise new update file.

## Progress Updates

When the user asks to "update the progress" or "write an update":
1. Create a new file in `docs/updates/` named `YYYY-MM-DD.md` using today's date.
2. Audit the codebase (git diff, file changes, sweep results, new features) to write an accurate summary.
3. Structure the update as: project goal, what was implemented (with tables), existing data, next steps, and architecture summary.
4. Use conservative language — do not overclaim. Mark pilot failures, dummy-only validation, and untested items.
5. Previous updates live in `docs/updates/` for reference.

# Database-Backed Vulnerability Discovery

The project uses a SQLite database to support agent-driven vulnerability discovery. Full documentation is in `docs/DATABASE_WORKFLOW.md`.

## Workflow Summary

1. Run experiment sweeps via `run_thesis_sweep.sh`
2. Sweeps produce CSV/log artifacts per run (metrics, attack timelines, trust scores, defense selection)
3. Ingestion scripts (to be built) read those artifacts into the database
4. Agent queries the database to identify weakness patterns
5. Agent maps findings to MITRE ATLAS categories when possible
6. Agent generates an analysis report
7. Agent suggests next sweeps or follow-up experiments

## Database Schema

13 tables in `db/schema.sql`:
- `sweeps` — one row per sweep execution
- `runs` — one row per run (includes attack/defense config at run level)
- `run_config` — EAV overflow for extra config keys
- `round_metrics` — server-level metrics per round (EAV: run, round, metric_name, value)
- `client_metrics` — per-client per-round metrics (EAV)
- `attack_events` — one row per round, round-level attack state with norm/stealth data
- `attack_event_layers` — per-layer detail for stacked attacks (from JSONL)
- `adaptive_attack_scores` — MAB bandit state per round (**placeholder, not yet logged**)
- `client_attack_events` — per-client per-round attack assignment with full parameters
- `trust_metrics` — per-client per-round trust/reputation scores (trust strategies only)
- `defense_selection` — per-client per-round aggregation selection decisions
- `baseline_comparisons` — pre-computed attacked vs clean drops
- `agent_recommendations` — agent-generated experiment suggestions

## Key Design Facts

- Attack names for layered attacks are `+`-joined strings (e.g. `"gaussian_noise+sign_flip"`), matching the source CSVs
- `attack_mode`, `selection_mode`, `layering_mode` are run-level config in the `runs` table, not per-round
- Trust metrics have common flat columns plus `details_json` for strategy-specific fields
- `defense_selection` is unified across krum-family and trust strategies
- The `adaptive_attack_scores` table requires logging changes to `AttackEngine` before it can be populated from real runs

## Database Files

| File | Purpose |
|------|---------|
| `db/schema.sql` | SQLite DDL with source-data comments |
| `db/create_db.py` | Creates DB + inserts dummy data |
| `db/queries.py` | 11 vulnerability discovery query functions |
| `db/validate.py` | End-to-end smoke test |
| `db/dynamic_fl.sqlite` | Dummy database (regenerated by create_db.py) |

## CSV-to-Table Mapping

This is the mapping from run output files to database tables. Critical for building the ingestion script.

| CSV / Source File | Database Table | Granularity |
|---|---|---|
| sweep directory metadata + `sweep_settings.csv` | `sweeps` | One row per sweep |
| `meta.json` + `sweep_settings.csv` row | `runs` | One row per run |
| `meta.json` → `resolved_config_for_naming` | `run_config` | Key-value pairs per run |
| `metrics/evaluate_server__*.csv` | `round_metrics` | One row per (run, round, metric) |
| `metrics/evaluate_client__*.csv`, `train_client__*.csv` | `client_metrics` | One row per (run, round, client, metric) |
| `summaries/attack_timeline.csv` + `round_attack_stats.csv` | `attack_events` | One row per (run, round) |
| `summaries/attack_log.jsonl` → `attack_details.layer_details` | `attack_event_layers` | One row per (run, round, layer) |
| **NOT YET LOGGED** — needs AttackEngine changes | `adaptive_attack_scores` | Placeholder |
| `summaries/attack_by_client_round.csv` | `client_attack_events` | One row per (run, round, client) |
| `summaries/trust_strategy_by_round.csv` | `trust_metrics` | One row per (run, round, client) — trust strategies only |
| `defense_selection_by_round.csv` (krum/bulyan) + trust CSV `selected_for_aggregation` | `defense_selection` | One row per (run, round, client) |
| Computed from `round_metrics` pairs | `baseline_comparisons` | One row per (attacked_run, baseline_run) |
| Agent output | `agent_recommendations` | One row per recommendation |

All server metric CSVs have 2 columns: `round, value`. One file per metric name (e.g. `evaluate_server__accuracy.csv`, `evaluate_server__f1_macro.csv`).

The `trust_strategy_by_round.csv` columns: `round, strategy, client_id, trust_score, selected_for_aggregation, update_norm, cosine_to_center, history_score, reputation, num_examples, details_json`. The `details_json` column has commas replaced with semicolons to avoid CSV breakage — must reverse this before JSON parsing.

The `defense_selection_by_round.csv` is only written for krum/multikrum/bulyan. Its `selected_client_ids` and `selected_client_numbers` columns are semicolon-separated lists that must be expanded into individual rows during ingestion.

Client IDs: `trust_strategy_by_round.csv` uses raw Flower node IDs. `attack_by_client_round.csv` uses both `client_number` (1-based) and `src_node_id`. Use `client_number_map.csv` for mapping.

## Run Directory Layout

Each run (when launched through a sweep) produces this structure:

```
logs/sweeps/<sweep_name>/
  sweep_settings.csv                     # one row per run in the sweep
  sweep_summary.txt                      # text summary of sweep results
  <scenario>__<strategy>__<dataset>__<iid|noniid>__<timestamp>/
    meta.json                            # full resolved config
    stdout.log                           # captured stdout
    stderr.log                           # captured stderr
    configs/
      activated_overrides.toml           # override settings for this run
      activated_run_config.txt           # resolved run config
      pyproject.snapshot.toml            # frozen pyproject.toml at run time
    metrics/
      evaluate_server__accuracy.csv      # round, value (2-column format)
      evaluate_server__loss.csv
      evaluate_server__f1_macro.csv
      evaluate_server__f1_weighted.csv
      evaluate_server__precision_macro.csv
      evaluate_server__precision_weighted.csv
      evaluate_server__recall_macro.csv
      evaluate_server__recall_weighted.csv
      evaluate_server__backdoor_asr.csv
      evaluate_server__backdoor_loss.csv
      evaluate_server__class_*_accuracy.csv  # per-class (62 for FEMNIST)
      evaluate_client__eval_acc.csv
      evaluate_client__eval_loss.csv
      train_client__train_loss.csv
      train_client__attack_is_malicious.csv
      train_client__poisoned_examples.csv
      train_client__poisoned_backdoor_examples.csv
      train_client__poisoned_label_flip_examples.csv
      train_client__poison_examples_seen.csv
      metrics.json                       # aggregated metrics JSON
      per_client_color_key.csv           # color assignments for plots
      per_client_color_key.json
      per_client_metrics.json
      rounds.json                        # per-round metric history
      sampling.csv                       # client sampling record
    summaries/
      attack_timeline.csv
      attack_by_client_round.csv
      attack_log.jsonl
      attack_summary.md                  # human-readable attack summary
      round_attack_stats.csv
      malicious_clients_by_round.csv
      round_poison_stats.csv
      poisoning_by_client_round.csv
      defense_filter_by_round.csv
      defense_selection_by_round.csv     # krum/bulyan only
      trust_strategy_by_round.csv        # trust strategies only
      defense_malicious_selected_vs_sampled.png  # visualization
      client_number_map.csv
      run_config_and_summary.json
      plots/                             # additional summary plots
    graphs/
      aggregated_client/                 # aggregated client metric plots
      aggregated_server/                 # aggregated server metric plots
      diagnostics/                       # diagnostic visualizations
      per_client/                        # per-client metric plots
      summaries/                         # summary visualizations
    rounds/
      round_001.json                     # per-round state snapshots
      round_002.json
      ...
```

Standalone dev/debug runs (launched directly, not through a sweep) go under `logs/` directly with the same internal structure but without the sweep wrapper.

## Existing Sweep Data Inventory

As of 2026-06-25:

| Sweep | Location | Strategies | Runs per Strategy | Status |
|-------|----------|------------|-------------------|--------|
| FEMNIST full | `logs/sweeps/FEMNIST_2026-04-02/` | bulyan, fedmedian, fedtrimmedavg, fltrust, multikrum | ~67 each | Completed. Contains `llm_global_analysis.md`. |
| MNIST full | `logs/sweeps/MNIST_2026-04-02/` | bulyan, fedmedian, fedtrimmedavg, fltrust, multikrum | varies | Completed. Contains analysis CSVs and `llm_global_analysis.md`. |
| Pilot v1 (bulyan) | `logs/sweeps/bulyan_pilot_vuln__2026-05-01_03-46-10/` | bulyan | 2 (baseline + attacked) | Completed |
| Pilot v1 (fedmedian) | `logs/sweeps/fedmedian_pilot_vuln__*03-46-10/` | fedmedian | 2 | Completed |
| Pilot v1 (fedtrimmedavg) | `logs/sweeps/fedtrimmedavg_pilot_vuln__*03-46-10/` | fedtrimmedavg | 2 | Completed |
| Pilot v1 (fltrust) | `logs/sweeps/fltrust_pilot_vuln__*03-46-10/` | fltrust | 2 | Completed |
| Pilot v1 (foolsgold) | `logs/sweeps/foolsgold_pilot_vuln__*03-46-10/` | foolsgold | 2 | Completed |
| Pilot v1 (flram) | `logs/sweeps/flram_pilot_vuln__*03-46-10/` | flram | 2 | Completed |
| Pilot v1 (mab-rfl) | `logs/sweeps/mab-rfl_pilot_vuln__*03-46-10/` | mab-rfl | 2 | Completed |
| Pilot v1 (multikrum) | `logs/sweeps/multikrum_pilot_vuln__*03-46-10/` | multikrum | 2 | Completed |
| Pilot v2 (fedmedian) | `logs/sweeps/fedmedian_pilot_vuln_v2__*09-25-22/` | fedmedian | 2 | Completed |
| Pilot v2 (fedtrimmedavg) | `logs/sweeps/fedtrimmedavg_pilot_vuln_v2__*09-25-22/` | fedtrimmedavg | 2 | Completed |
| Pilot v2 (fltrust) | `logs/sweeps/fltrust_pilot_vuln_v2__*09-25-22/` | fltrust | 2 | Completed |
| Pilot v2 (flram) | `logs/sweeps/flram_pilot_vuln_v2__*09-25-22/` | flram | 0 runs | FAILED/EMPTY |
| Pilot v2 (foolsgold) | `logs/sweeps/foolsgold_pilot_vuln_v2__*09-25-22/` | foolsgold | 0 runs | FAILED/EMPTY |
| Pilot v2 (mab-rfl) | `logs/sweeps/mab-rfl_pilot_vuln_v2__*09-25-22/` | mab-rfl | 0 runs | FAILED/EMPTY |

Additionally, ~35 standalone dev/debug runs exist directly under `logs/` (mostly flram, fltrust, foolsgold, mab-rfl FEMNIST runs from April-May 2026, plus one MNIST fedavg run).

## Testing Status

**Unit tests (2026-07-29): 102 passed, 0 failed, 0 skipped**
- Run with `../myenv/bin/python -m pytest tests/ -v`
- Covers: TOML config, dataset specs, model factories, attack config parsing, strategy dispatch, trust aggregation

**Database — Real data ingestion DONE (2026-07-26):**
- 600 runs ingested (252 FEMNIST + 320 MNIST + 22 pilot + 6 dummy)
- 116,160 round metric rows, 17,490 attack event rows, 1,736,400 client attack rows
- 622 baseline comparison pairs computed
- ATLAS vulnerability analysis run: 584 findings, 11 candidate novel

**Database — dummy validation PASSED (2026-05-22):**
- Schema creation, dummy insertion, 11 queries, FK integrity — all passed

**WARNING:** Never run `db/validate.py` after ingesting real data — it destructively recreates the DB with dummy data.

## Remaining Work

Experiment gaps:
1. **MNIST clean baselines** — 320 attacked runs, 0 baselines. Must run clean baseline sweeps.
2. **Multi-seed replication** — All runs single-seed (1337). Need 3+ seeds for statistical claims.
3. **FLTrust stress test** — Increase malicious fraction beyond 30%.
4. **IID control experiments** — Separate non-IID effects from attack effects.
5. **More rounds** — Current runs use 30 rounds; 100-200 would improve convergence and clean accuracy.

Infrastructure:
6. Add MAB bandit state logging to AttackEngine (adaptive_attack_scores table is placeholder)
7. Test with a new FL strategy not in the database (plug-and-play validation)
8. Multi-seed confidence intervals in baseline_comparisons

## Vulnerability Discovery Patterns

The agent should query the database looking for these patterns:

| Pattern | What to query | Key tables |
|---|---|---|
| Attack effectiveness | Largest accuracy/F1 drops per attack | baseline_comparisons, round_metrics |
| Defense failure | Defense with worst drops under specific attacks | baseline_comparisons, attack_events |
| Malicious client survival | Malicious clients with selected_for_aggregation = 1 | defense_selection, client_attack_events |
| Trust score failure | Malicious clients with high trust_score or effective_weight | trust_metrics, client_attack_events |
| Slipthrough rate | Fraction of malicious clients selected vs total malicious | defense_selection |
| Adaptive convergence | Which attack the MAB converged to per defense | attack_events grouped by strategy |
| Collapse | attacked_final_accuracy < 0.05 | baseline_comparisons |
| Failed recovery | Accuracy drops and never recovers within round budget | round_metrics time series |
| Non-IID sensitivity | Defense failure even on clean baselines | round_metrics for baseline runs |
| Strategy-specific weakness | Different dominant attacks per defense | attack_events grouped by strategy |

Each finding should be classified as: known weakness, repeated/confirmed vulnerability, new or previously unobserved failure, or hypothesis needing more testing.

## MITRE ATLAS Mapping Rules

When the agent maps a finding to a MITRE ATLAS category:
- Do not claim a mapping if it does not clearly fit
- If uncertain, mark as tentative
- If project-specific, label as candidate vulnerability or observed weakness
- Distinguish known adversarial ML behavior from new evidence
- Never say "new MITRE ATLAS vulnerability discovered"

## Plug-and-Play Strategy Testing

To test a new FL strategy:
1. Implement it in server_app.py (extend AttackInjectedStrategyMixin)
2. Run adversarial sweeps with run_thesis_sweep.sh
3. Strategy produces the same CSV output columns as existing strategies
4. Ingest CSVs into the database
5. Agent analyzes the new strategy alongside existing ones
6. Receive a vulnerability report

The schema, ingestion, queries, and analysis workflow stay the same. Only the strategy implementation changes.

## Rules

- Never delete original CSVs
- Never move results unless explicitly asked
- Do not modify the schema without updating docs/DATABASE_WORKFLOW.md
- Do not assume the schema is correct against real CSVs until ingestion is tested
- Keep SQLite-compatible unless there is a strong reason to change

# How Claude Should Help

Before editing code, inspect the relevant files and explain what they do.

Do not rewrite the whole project unless explicitly asked.

Prefer simple, readable code over clever code.

When suggesting changes, explain:
1. What file changes
2. Why it changes
3. What could break
4. How to verify it

When editing code:
- Make small, focused changes
- Keep existing working behavior unless there is a clear reason to change it
- Avoid deleting files unless explicitly approved
- Do not invent experiment results
- Do not fake metrics, logs, or paper claims
- Do not hide errors by suppressing exceptions
- Prefer fixing the root cause

# Claude Code Operating Rules

Always inspect before editing.

Do not:
- run full sweeps unless explicitly requested
- use old thesis_sweeps.conf by accident
- refactor task.py unless explicitly requested
- split files before tests exist
- rewrite strategy code without a clear bug
- change model architecture unless explicitly requested
- delete result files
- invent results
- invent citations
- claim novelty prematurely
- hide exceptions with silent pass
- stop or interfere with another currently running experiment

When a run is active in another terminal:
- do not kill it
- do not edit files being used by that run
- prefer read-only inspection
- use a second terminal/session for documentation or analysis tasks

For any proposed change, first show:
1. files to change
2. exact section/function
3. why the change matters
4. risk level
5. verification command

After editing, show:
1. git diff
2. verification results
3. expected output files
4. what remains next

# Verification

When possible, verify changes by running:
- import checks
- small smoke tests
- unit tests if available
- quick experiment configs instead of full expensive runs

# Current Priority Order

Research-validity priority order:
1. ~~Verify clean baselines exist and are matched to attacked runs.~~ **DONE** — 26 FEMNIST baselines across all 8 strategies verified in DB. MNIST has 0 baselines (gap).
2. ~~Verify trust/reputation defenses use explicit fair settings.~~ **DONE**
3. ~~Add scalar F1/precision/recall metrics.~~ **DONE** — all scalar metrics confirmed in pilot run outputs.
4. ~~Fix small reproducibility issues such as global seeding and Dirichlet seed.~~ **DONE** — DirichletPartitioner seed configurable via `data-seed`.
5. ~~Run small pilot sweeps before full sweeps.~~ **DONE** — pilot v1 completed for all 8 strategies.
6. ~~Analyze baseline vs attacked drops.~~ **DONE** — 622 baseline comparisons in DB, ATLAS analysis run (584 findings).
7. **Add multiple seeds** — still single-seed (1337). Need 3+ seeds for statistical claims.
8. ~~Build CSV ingestion script.~~ **DONE** — `db/ingest.py` ingested 600 runs.
9. ~~Test database schema against real CSV outputs.~~ **DONE** — all CSV columns mapped.
10. ~~Build agent analysis report generation.~~ **DONE** — `db/analyze.py` + `db/atlas_mapping.py`.
11. **Run MNIST clean baselines** — 320 attacked runs have 0 baselines.
12. **Run experiments with more rounds** (100-200) to improve clean accuracy (currently 30 rounds).
13. **IID control experiments** — separate non-IID effects from attack effects.

Database/workflow priority:
1. ~~Build ingestion script~~ **DONE**
2. ~~Test ingestion on real sweeps~~ **DONE** — 600 runs ingested
3. ~~Build report generation~~ **DONE** — ATLAS analysis pipeline
4. Add MAB bandit state logging to AttackEngine
5. Test multi-seed baseline comparisons

Lower priority / do later:
- splitting task.py
- strategy registry refactor
- dashboard persistence
- ~~text/audio model improvements~~ **Text pipeline DONE**. Audio still scaffolded only.
- CIFAR-100 experiments
- ~~ResNet or larger model additions~~ **DONE**
- ~~Plug-and-play strategy params~~ **DONE** — auto-compute num-malicious-nodes and num-nodes-to-select

# Communication Style

Explain things in plain English.
Avoid heavy jargon unless necessary.
When the code is confusing, say so directly and explain why.

Keep explanations plain English and practical.
When giving research summaries, separate:
- what is confirmed by logs
- what is a candidate finding
- what is speculation
- what still needs testing

When summarizing for my professor, be concise, careful, and avoid overclaiming.
