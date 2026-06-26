# Database-Backed Vulnerability Discovery Workflow

**Date:** 2026-05-22
**Status:** Schema validated with dummy data. Real CSV ingestion not yet tested.

---

## What This Is

This document describes how the project uses a SQLite database to support AI-agent-driven vulnerability discovery across federated learning strategies.

The database is not just a results store. It exists so an agent can query structured experiment data, identify weakness patterns in FL defenses, map findings to MITRE ATLAS-style adversarial ML categories, and suggest what to test next.

---

## End-to-End Workflow

The vulnerability discovery pipeline works in this order:

```
1. Run experiment sweeps
       |
       v
2. Sweeps produce CSV/log artifacts per run
       |
       v
3. Ingestion scripts read those artifacts
       |
       v
4. Parsed results are inserted into SQLite tables
       |
       v
5. Agent queries database tables
       |
       v
6. Agent identifies weakness patterns
       |
       v
7. Agent maps findings to MITRE ATLAS categories when possible
       |
       v
8. Agent generates an analysis page/report
       |
       v
9. Agent suggests next sweeps or follow-up experiments
```

### Step 1: Run Experiment Sweeps

Sweeps are launched via `run_thesis_sweep.sh`. Each sweep iterates over a set of attack configurations, strategies, and seeds. For each combination, the sweep runner calls `scripts/run_simulation_and_log.py`, which runs the Flower simulation and parses the output into structured files.

A sweep produces one directory per run under `logs/sweeps/<sweep_name>/`.

### Step 2: Sweeps Produce CSV/Log Artifacts

Each run directory contains:

| Directory | Key files | What they contain |
|-----------|-----------|-------------------|
| `metrics/` | `evaluate_server__accuracy.csv`, `evaluate_server__f1_macro.csv`, etc. | Per-round server-level metrics (2 columns: `round, value`) |
| `metrics/` | `evaluate_client__eval_acc.csv`, `train_client__train_loss.csv`, etc. | Per-round client-level metrics (aggregated across clients) |
| `summaries/` | `attack_timeline.csv` | Per-round attack events (attack name, intensity, malicious clients, norms) |
| `summaries/` | `attack_by_client_round.csv` | Per-client per-round attack assignment (layers, intensities, label flip/backdoor params) |
| `summaries/` | `round_attack_stats.csv` | Per-round stealth info, honest/malicious norm distributions, assumption gap |
| `summaries/` | `trust_strategy_by_round.csv` | Per-client per-round trust scores (trust strategies only) |
| `summaries/` | `defense_selection_by_round.csv` | Per-round aggregation selection (krum/bulyan only) |
| `summaries/` | `attack_log.jsonl` | Full per-round JSON with all attack details including per-layer parameters |
| `summaries/` | `malicious_clients_by_round.csv`, `round_poison_stats.csv`, `poisoning_by_client_round.csv` | Poisoning details |
| `summaries/` | `defense_filter_by_round.csv` | Pre-aggregation norm-based filtering |
| root | `meta.json` | Full resolved config for the run |
| sweep root | `sweep_settings.csv` | One row per run with sweep-level config |

### Step 3: Ingestion Scripts Read Artifacts

An ingestion script (to be built) walks a sweep directory, reads `meta.json` and the CSV/JSONL files for each run, and converts them into database rows.

The mapping from CSV files to database tables is documented in `db/schema.sql` (header comments).

**Current status:** Ingestion from real CSVs has NOT been implemented yet. Only dummy data insertion has been tested.

### Step 4: Parsed Results Go Into SQLite Tables

The database has 13 tables:

| Table | Granularity | Source |
|-------|-------------|--------|
| `sweeps` | One row per sweep | Sweep directory metadata |
| `runs` | One row per run | `meta.json` + `sweep_settings.csv` |
| `run_config` | Key-value pairs per run | `meta.json` overflow config |
| `round_metrics` | One row per (run, round, metric) | `metrics/evaluate_server__*.csv` |
| `client_metrics` | One row per (run, round, client, metric) | `metrics/evaluate_client__*.csv`, `train_client__*.csv` |
| `attack_events` | One row per (run, round) | `attack_timeline.csv` + `round_attack_stats.csv` |
| `attack_event_layers` | One row per (run, round, layer) | `attack_log.jsonl` layer_details |
| `adaptive_attack_scores` | One row per (run, round, attack) | **Not yet logged** (placeholder) |
| `client_attack_events` | One row per (run, round, client) | `attack_by_client_round.csv` |
| `trust_metrics` | One row per (run, round, client) | `trust_strategy_by_round.csv` |
| `defense_selection` | One row per (run, round, client) | `defense_selection_by_round.csv` + trust CSV |
| `baseline_comparisons` | One row per (attacked_run, baseline_run) pair | Computed from `round_metrics` |
| `agent_recommendations` | One row per recommendation | Agent output |

Schema DDL: `db/schema.sql`
Creation script: `db/create_db.py`
Query examples: `db/queries.py`

### Step 5: Agent Queries the Database

Instead of manually parsing hundreds of CSV files across dozens of run directories, the agent queries the database using SQL. The database pre-joins run metadata, attack config, round metrics, trust scores, and defense selection so the agent can answer questions in a single query.

### Step 6: Agent Identifies Weakness Patterns

The agent looks for evidence of:

- **Attack effectiveness:** Which attacks cause the biggest accuracy drop, F1 drop, or backdoor ASR increase for a given defense?
- **Defense failure:** Which defenses consistently perform worst under specific attacks or attack modes?
- **Malicious client survival:** Which malicious clients were selected for aggregation despite being active attackers?
- **Trust score failure:** Which malicious clients received high trust scores or effective weights?
- **Aggregation selection failure:** Which defenses failed to exclude any malicious clients (slipthrough rate)?
- **Adaptive attack success:** Which rounds show the MAB bandit switching attacks, and what did it converge to?
- **Collapse or poor recovery:** Which configurations caused accuracy to drop below 5% and stay there?
- **Non-IID sensitivity:** Which defenses degrade under non-IID data even without attacks (defense-induced failure)?
- **Strategy-specific weak points:** Which attack is dominant against each specific defense?

### Step 7: MITRE ATLAS Mapping

When the agent identifies a weakness pattern, it should attempt to map it to a MITRE ATLAS-style adversarial ML category. See the MITRE ATLAS Mapping section below.

### Step 8: Agent Generates Analysis Report

The agent generates a report from the database. See the Agent Analysis Page section below.

### Step 9: Agent Suggests Next Experiments

Based on the analysis, the agent writes rows to the `agent_recommendations` table with:
- which defense/attack combination to test next
- priority score
- evidence strength
- suggested config (JSON)
- plain English rationale

---

## Purpose of the Database

The database transforms raw experiment outputs into structured evidence.

Without the database, analyzing results requires:
- navigating dozens of run directories
- opening individual CSV files
- manually matching attacked runs to their baselines
- cross-referencing attack timelines with trust scores with defense selection logs

With the database, the agent can:
- **Compare attacks** across all defenses in one query
- **Compare defenses** under the same attack configuration
- **Compare strategies** by their accuracy drop, F1 drop, or collapse rate
- **Compare baseline vs attacked runs** with pre-computed drops
- **Identify malicious clients that bypassed defenses** by joining attack events with trust metrics and defense selection
- **Detect collapse and recovery behavior** from round-level accuracy curves
- **Support reproducible vulnerability claims** by tracking seeds, repetitions, and statistical flags
- **Generate agent-readable summaries** without parsing raw files

---

## Plug-and-Play FL Strategy Testing

This system should eventually work for any federated learning strategy, not just the ones currently implemented.

The workflow for testing a new strategy:

1. **Plug in the strategy.** Implement it in `server_app.py` following the existing pattern (extend `AttackInjectedStrategyMixin`). The strategy must produce the same CSV output columns as existing strategies.
2. **Run adversarial sweeps.** Use `run_thesis_sweep.sh` with the new strategy name. The sweep runner, attack engine, and logging code are strategy-agnostic.
3. **Produce the expected CSV outputs.** As long as the strategy uses the mixin's `aggregate_train` and logging methods, it will produce the same CSV structure.
4. **Ingest CSVs into the database.** The ingestion script reads files by path convention and column names. It does not hard-code strategy names.
5. **Let the agent analyze.** The agent queries the database for the new strategy's runs and compares them against baselines and other strategies.
6. **Receive a vulnerability report.** The analysis report covers the new strategy alongside existing ones.

**What stays the same:** The database schema, ingestion script, query library, and analysis workflow.

**What changes:** Only the strategy implementation in `server_app.py` and potentially new trust-metric columns in `details_json` if the strategy uses a novel trust scoring mechanism.

**Current limitation:** Trust strategies store strategy-specific detail in the `details_json` column. If a new strategy introduces metrics not captured by the common flat columns (`trust_score`, `update_norm`, `cosine_to_center`, `history_score`, `reputation`, `effective_weight`), those metrics will only be accessible through JSON parsing of `details_json`. This is by design — the flat columns cover the most-queried fields, and `details_json` is the escape hatch for everything else.

---

## Vulnerability Discovery Goal

The point of this system is not only to report metrics. It is to discover weaknesses in federated learning strategies.

The agent should treat the database as an evidence base and look for patterns like:

| Pattern | What to look for | Key tables |
|---------|-------------------|------------|
| Attack effectiveness | Large accuracy/F1 drops in `baseline_comparisons` | `baseline_comparisons`, `round_metrics` |
| Defense failure | A defense consistently performs worst under a specific attack | `baseline_comparisons`, `attack_events` |
| Malicious client survival | Malicious clients with `selected_for_aggregation = 1` | `defense_selection`, `client_attack_events` |
| Trust score failure | Malicious clients with high `trust_score` or `effective_weight` | `trust_metrics`, `client_attack_events` |
| Aggregation selection failure | High slipthrough rate (malicious selected / total malicious) | `defense_selection` |
| Adaptive attack success | MAB bandit converging to a specific attack per defense | `attack_events` (adaptive_switched, attack_name) |
| Accuracy collapse | `attacked_final_accuracy < 0.05` | `baseline_comparisons` |
| Failed recovery | Accuracy drops and never recovers within the round budget | `round_metrics` time series |
| Non-IID sensitivity | Defense-induced failure even on clean baseline runs | `round_metrics` for baseline runs |
| Strategy-specific weak points | Different dominant attacks per defense | `attack_events` grouped by strategy |

The agent should classify each finding as one of:
- **Known weakness:** Matches published literature or prior ATLAS mapping
- **Repeated/confirmed vulnerability:** Observed across multiple seeds and configurations
- **New or previously unobserved failure pattern:** Not explained by known literature
- **Hypothesis that needs more testing:** Observed once or in limited conditions

---

## MITRE ATLAS Mapping

Findings should be mapped to MITRE ATLAS-style adversarial ML categories when possible.

### Rules for Mapping

- Do not claim a MITRE mapping exists if it does not clearly fit.
- If the mapping is uncertain, mark it as **tentative**.
- If a finding appears new or project-specific, label it as a **candidate vulnerability** or **observed weakness** rather than pretending it is a known MITRE vulnerability.
- Distinguish between known adversarial ML behavior and new evidence discovered by this framework.

### Relevant ATLAS Categories

These ATLAS categories are relevant to this project's federated learning threat model:

| ATLAS Tactic | How it maps to this project |
|---|---|
| Reconnaissance (Discover AI Model Outputs) | Adaptive MAB observes accuracy to learn which attack works best |
| Resource Development (Develop/Stage Capabilities) | Attack engine pre-configures 6 attack types with layering and scheduling |
| Initial Access (Valid Accounts) | Compromised FL clients participate normally then attack |
| Execution (Poison Training Data) | Label flip, backdoor inject poisoned data |
| Execution (Manipulate AI Model) | Sign flip, gaussian noise, ALIE, mean shift modify updates directly |
| Persistence (Repeated Poisoning) | Sticky scheduling maintains persistent malicious pressure |
| Defense Evasion (Evade AI Model) | Norm-capping matches honest distribution; ALIE stays within statistical bounds |
| AI Attack Staging (Layered/Composite) | sample_k mode rotates attack combinations each round |
| AI Attack Staging (Cohort Manipulation) | Churn/sticky/per-round scheduling changes client identity patterns |
| Impact (Accuracy Degradation) | Measured by accuracy drop and collapse rate |
| Impact (Targeted Backdoor) | Measured by backdoor ASR |
| Impact (Model Collapse) | Measured by non-finite updates and accuracy < 5% |

### Out-of-Scope ATLAS Categories

Not tested by this project: phishing, credential access, RAG poisoning, prompt injection, LLM jailbreak, model extraction/theft, exfiltration, lateral movement, infrastructure compromise, AI agent tool abuse, supply chain compromise.

### Example Mapping Output

A finding in the agent report should look like:

```
Finding: Bulyan collapsed under adaptive ALIE within 10 rounds.
ATLAS mapping: Defense Evasion → Evade AI Model (distribution-aware crafting)
Confidence: High — ALIE is a known distribution-aware attack.
Status: Observed weakness. Needs multi-seed replication before claiming confirmed vulnerability.
```

Not like:

```
Finding: New MITRE ATLAS vulnerability discovered!
```

---

## Agent Analysis Page

The agent should generate an analysis page or report from the database after each sweep is ingested.

### Report Structure

1. **Sweep summary:** Sweep name, date, dataset, partitioning, number of runs, seeds used.
2. **Strategies tested:** List of defense strategies in this sweep.
3. **Dataset and partitioning setup:** Dataset name, Dirichlet alpha, IID/non-IID, number of clients, rounds.
4. **Attacks tested:** Attack modes, layering modes, scheduling modes, individual attack types.
5. **Baseline comparison results:** Table showing clean vs attacked accuracy, F1, backdoor ASR, and computed drops per strategy.
6. **Strongest attacks:** Which attacks caused the most damage, ranked by accuracy drop or F1 drop.
7. **Weakest defenses:** Which defenses had the highest collapse rate, worst accuracy retention, or highest slipthrough rate.
8. **Suspicious client behavior:** Malicious clients that were selected for aggregation despite active attacks.
9. **Trust/selection failures:** Malicious clients with high trust scores, high effective weights, or that were not downweighted.
10. **Adaptive attack patterns:** Which attacks the MAB bandit converged to per defense. Rounds where switching occurred.
11. **MITRE ATLAS-style mapping:** Each finding mapped to an ATLAS category with confidence and status.
12. **Finding classification:** For each finding, whether it is known, repeated, new, or needs more testing.
13. **Recommended next experiments:** Priority-ranked list of suggested configurations with rationale.

### Report Generation Status

**Not yet implemented.** The query library (`db/queries.py`) demonstrates the SQL patterns needed. A report generation script that formats query results into a markdown analysis page has not been built yet.

---

## Testing Status

### What Has Been Tested

**Dummy SQLite validation (PASSED):**
- Schema creation from `db/schema.sql` — all 13 tables created successfully
- Dummy data insertion via `db/create_db.py` — 6 runs across 3 strategies (bulyan, fltrust, mab-rfl), baselines and attacked, covering adaptive/single, weighted_random/sample_k, trust and non-trust strategies
- Example queries via `db/queries.py` — all 11 queries executed without errors
- Foreign key integrity — no violations detected
- Basic joins across attack events, trust metrics, defense selection, baseline comparisons
- Layered attack data (sample_k with 5 distinct layers) correctly stored and queried
- Adaptive switching detection across rounds
- Trust score separation between benign and malicious clients
- Slipthrough rate calculation (malicious clients selected for aggregation)
- Collapse detection (accuracy < 5%)
- End-to-end validation via `db/validate.py` — all checks passed

### What Has NOT Been Tested

**Real CSV ingestion — NOT TESTED:**
- No ingestion script exists yet to read actual sweep directories
- No verification that real CSV column names match the database schema
- No handling of missing or partial CSV files
- No handling of the semicolon-escaped `details_json` in trust CSVs
- No handling of the client_number vs node_id mapping
- No testing with multi-run or multi-seed sweeps
- No testing with the old 252-run FEMNIST sweep
- No testing with the new pilot sweep outputs

**Agent analysis report — NOT TESTED:**
- No report generation script exists
- No markdown analysis page has been generated from real data
- No MITRE mapping logic has been coded (mappings are currently manual/human-written)

**Reproducibility validation — NOT TESTED:**
- No multi-seed comparisons computed from real data
- No confidence intervals or significance tests
- No validation that baseline matching works correctly with real sweep_settings.csv

---

## Remaining Tests Needed

### Ingestion

1. Write a CSV ingestion script that walks `logs/sweeps/<sweep>/` and imports real run data
2. Test ingestion on the old FEMNIST sweep (`logs/sweeps/FEMNIST_2026-04-02/`)
3. Test ingestion on completed pilot sweeps
4. Verify every required CSV column exists in real outputs (some columns may be missing in older runs)
5. Handle missing or partial CSV files gracefully (some runs may have failed mid-way)
6. Handle the `details_json` semicolon-to-comma restoration for trust CSVs
7. Handle client_number vs src_node_id mapping via `client_number_map.csv`
8. Validate that `sweep_settings.csv` rows match the actual run directories

### Baseline Matching

9. Validate that baseline matching logic correctly pairs each attacked run with its clean baseline using strategy + dataset + alpha + seed
10. Handle cases where a baseline run is missing or failed

### Multi-Seed

11. Validate multi-seed comparisons by ingesting 3+ seeds of the same configuration
12. Compute mean, standard deviation, and confidence intervals from multi-seed data
13. Set `is_replicated = 1` only when 3+ seeds are present

### Joins and Queries

14. Test the join between `client_attack_events`, `trust_metrics`, and `defense_selection` on real data (these use different client ID conventions)
15. Verify the adaptive switching detection query works with real attack_timeline.csv data
16. Verify the dominant attack query correctly counts attack frequencies from real data
17. Test queries with layered attacks (real sample_k runs produce different composite names than dummy data)

### Agent Report

18. Build a report generation script that queries the database and produces a markdown analysis page
19. Test the report on real ingested data
20. Verify MITRE ATLAS mapping outputs are accurate and conservative
21. Verify finding classification (known/repeated/new/needs testing) is reasonable

### Plug-and-Play

22. Test the workflow end-to-end with a new FL strategy not currently in the database
23. Verify that ingestion handles unknown strategy names gracefully
24. Verify that queries and reports work with mixed old and new strategies

### Adaptive Attack Scores

25. Add logging to `AttackEngine` so MAB bandit state (reward, estimated_value, times_selected) is written to `attack_log.jsonl` or a separate CSV
26. Test ingestion of adaptive attack scores from real adaptive runs
27. Verify the `adaptive_attack_scores` table is populated correctly

---

## Database Files

| File | Purpose |
|------|---------|
| `db/schema.sql` | SQLite DDL — 13 tables with indexes, FKs, source-data comments |
| `db/create_db.py` | Creates the database and inserts dummy data |
| `db/queries.py` | 11 vulnerability discovery query functions |
| `db/validate.py` | End-to-end smoke test (create + insert + query + integrity check) |
| `db/dynamic_fl.sqlite` | The dummy database (regenerated by `create_db.py`) |

---

## Key Design Decisions

### Why SQLite instead of DuckDB

The earlier CLAUDE.md recommended DuckDB for CSV-heavy analytical workflows. SQLite was chosen instead because:
- The agent workflow needs a persistent structured database, not ad-hoc CSV querying
- SQLite is universally available with no extra dependencies
- The database is small enough (thousands to tens of thousands of rows) that SQLite performance is not a concern
- If the project scales to millions of rows or needs columnar analytics, DuckDB can be added later without changing the schema

### Why EAV for metrics

`round_metrics` and `client_metrics` use an Entity-Attribute-Value pattern (run_id, round, metric_name, metric_value) rather than one column per metric. This is because:
- The set of metric names grows over time (per-class accuracy alone adds 62 columns for FEMNIST)
- New metrics can be added without schema changes
- The source CSVs already have this shape (one file per metric, `round, value` columns)

The tradeoff is that pivoting metrics into columns requires SQL aggregation, but this is straightforward and the query library demonstrates how.

### Why attack names are stored as composite strings

Layered attacks are stored as `+`-joined strings (e.g. `"gaussian_noise+sign_flip"`) rather than normalized into a junction table. This matches the source data format and keeps queries simple. The `attack_event_layers` table provides per-layer detail when needed.

### Why trust metrics keep flat columns plus details_json

The most-queried trust fields (`trust_score`, `effective_weight`, `update_norm`, `cosine_to_center`, `reputation`) are flat columns for indexing and easy querying. Strategy-specific fields that vary by defense go in `details_json`. This avoids a wide sparse table while keeping the common fields fast.

---

## Questions the Agent Should Be Able to Answer

After ingestion, the agent should be able to answer these questions from the database:

1. Which attacks consistently weaken this FL strategy?
2. Which defenses fail under specific attack modes?
3. Which malicious clients bypass trust or reputation scoring?
4. Which malicious clients are still selected for aggregation?
5. Which rounds show adaptive MAB attack switching?
6. Which attacks cause accuracy collapse, F1 collapse, backdoor success, or poor recovery?
7. Which strategy is most vulnerable under non-IID data?
8. Which vulnerabilities are already known or MITRE-mappable?
9. Which findings look new, unusual, or worth deeper testing?
10. What sweep configuration should be tested next?

Example queries for all of these are in `db/queries.py`.
