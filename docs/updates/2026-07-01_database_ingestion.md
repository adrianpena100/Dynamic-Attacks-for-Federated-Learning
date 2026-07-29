# Update: Database Ingestion Pipeline — July 1, 2026

## What Changed

Built `db/ingest.py` — the ingestion script that reads real experiment CSV/JSON outputs from `logs/` and inserts them into the SQLite database. This closes the gap between running experiments and querying results: the pipeline now goes from sweep → logs → database → queries.

### 1. New File: `db/ingest.py` (~800 lines)

A CLI tool that walks sweep or standalone run directories, reads all artifacts, and populates the 13-table database.

**Entry points:**
- `ingest_sweep(sweep_dir)` — walks a sweep directory, ingests all runs, computes baseline comparisons
- `ingest_standalone_run(run_dir)` — ingests a single dev/debug run outside a sweep
- CLI: `python db/ingest.py <path> [<path> ...]` — auto-detects sweep vs standalone

**Per-run ingestion reads:**

| Source File | → DB Table | Notes |
|---|---|---|
| `meta.json` | `runs` + `run_config` | Strategy, dataset, model, attack config. Overflow keys → EAV table. |
| `metrics/evaluate_server__*.csv` | `round_metrics` | 2-column format (round, value). One file per metric. |
| `metrics/evaluate_client__*.csv` | `client_metrics` | Multi-column unpivot where columns are client IDs. |
| `summaries/attack_timeline.csv` + `round_attack_stats.csv` | `attack_events` | Joined on (run, round). Includes stealth/norm stats. |
| `summaries/attack_log.jsonl` | `attack_event_layers` | Parses `attack_details.layer_details` dict per round. |
| `summaries/attack_by_client_round.csv` | `client_attack_events` | Direct column mapping with large node ID handling. |
| `summaries/trust_strategy_by_round.csv` | `trust_metrics` | Semicolon→comma restoration in `details_json`. |
| `summaries/defense_selection_by_round.csv` | `defense_selection` | Expands semicolon-separated client ID lists into rows. |

**Baseline comparison computation:**
After all runs are ingested, pairs attacked runs with clean baselines by matching (strategy, dataset, dirichlet_alpha, seed) and computes accuracy/F1 drops, collapse detection, and ASR increase.

**Edge cases handled:**
- Missing files (baselines have no attack CSVs) → skip gracefully
- Header-only CSVs (trust CSV for non-trust strategies) → skip
- `details_json` semicolons → restored to commas before storing
- Flower node IDs (uint64, up to 18 digits) → stored as TEXT to avoid overflow
- Duplicate detection: re-running ingestion skips already-ingested runs
- Standalone dev runs (no `sweep_settings.csv`) → creates synthetic sweep wrapper

### 2. Schema Updates: `db/schema.sql`

| Change | Reason |
|--------|--------|
| Added `model_architecture TEXT` to `runs` | Distinguish simple-cnn vs resnet18 runs |
| Added `dataset_modality TEXT` to `runs` | Distinguish vision vs text vs tabular experiments |
| Changed `src_node_id` in `client_attack_events` from INTEGER to TEXT | Flower node IDs are uint64, overflow SQLite int64 |
| Changed `client_id` in `trust_metrics` from INTEGER to TEXT | Same — trust CSVs use raw Flower node IDs |

### 3. Query Fixes: `db/queries.py`

Fixed trust-related join queries (queries 4 and 5) to match trust metric client IDs (raw Flower node IDs) with attack event client IDs via `src_node_id` instead of `client_id`.

### 4. Updated: `db/create_db.py` and `db/validate.py`

- Dummy data INSERT statements updated for 31-column `runs` table (added `model_architecture`, `dataset_modality`)
- Validation checks added for new columns: verifies all runs have both fields populated
- All dummy data validation passes

## Ingestion Test Results

Tested on real experiment outputs:

| Source | Runs | Server Metrics | Attack Events | Layers | Trust | Defense Selection |
|--------|------|---------------|---------------|--------|-------|-------------------|
| FLTrust pilot sweep (baseline + attacked) | 2 | 4,320 | 30 | 30 | 1,800 | 0 |
| Bulyan pilot sweep (baseline + attacked) | 2 | 4,320 | 30 | 30 | 0 | 3,000 |
| Sentiment140 text smoke test | 1 | 39 | 0 | 0 | 0 | 0 |
| ResNet-18 MNIST smoke test | 1 | 60 | 0 | 0 | 0 | 0 |
| **Total** | **6** | **8,739** | **60** | **60** | **1,800** | **3,000** |

Model/modality correctly populated:

| Run | model_architecture | dataset_modality |
|-----|-------------------|-----------------|
| FEMNIST pilot runs | simple-cnn | vision |
| Sentiment140 smoke test | simple-cnn | text |
| ResNet-18 MNIST smoke test | resnet18 | vision |

All 11 vulnerability discovery queries executed successfully on real data.

## Key Findings from Real Data (Queries on Ingested Pilot Runs)

| Finding | Detail |
|---------|--------|
| Bulyan collapsed under adaptive attack | 1.6% final accuracy vs 35.7% baseline (collapse detected) |
| FLTrust resilient | 53.6% attacked vs 53.1% baseline — essentially no accuracy drop |
| Bulyan slipthrough rate | 81.8% of malicious clients passed aggregation |
| Trust separation (FLTrust) | Malicious avg trust = 0.028 vs benign avg trust = 0.051 |
| No trust failures detected | No malicious client had trust score > 0.5 |
| Stealth evasion | Some ALIE attacks evaded norm-based detection (post-stealth norm ≤ honest p90) |
| Adaptive switching | Both strategies show attack switching patterns across 30 rounds |

## Files Modified

| File | Change |
|------|--------|
| `db/ingest.py` | **New** — full ingestion script |
| `db/schema.sql` | Added `model_architecture`, `dataset_modality` to `runs`; changed node ID types to TEXT |
| `db/create_db.py` | Updated INSERT for 31-column `runs` table |
| `db/validate.py` | Added validation checks for new columns |
| `db/queries.py` | Fixed trust join queries (queries 4, 5) for node ID matching |

## How to Use

```bash
# Ingest a pilot sweep
python db/ingest.py logs/sweeps/fltrust_pilot_vuln__2026-05-01_03-46-10

# Ingest a standalone run
python db/ingest.py logs/resnet18_smoke__ylecun_mnist__noniid__2026-06-25_23-54-32

# Ingest multiple paths at once
python db/ingest.py logs/sweeps/bulyan_pilot_vuln__* logs/text_smoke_fixed__*

# Run queries on the ingested data
python db/queries.py

# Full dummy validation (creates fresh DB with dummy data)
cd db && python validate.py
```

## What Remains

1. **Ingest all existing sweeps** — 14 pilot sweeps + 2 full sweeps (~400+ runs) not yet ingested
2. **Build agent analysis report** — query the database and generate structured vulnerability findings
3. **Multi-seed sweeps** — need 3+ seeds per config for statistical claims
4. **Add MAB bandit state logging** — `adaptive_attack_scores` table is a placeholder (requires AttackEngine changes)
5. **Test ingestion on old FEMNIST full sweep** — 67 runs per strategy, will exercise edge cases
