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
| `post_run_analysis.py` | ~947 | Post-run terminal analysis. Detects 8 vulnerability patterns, generates defense-specific suggestions with parameter changes, saves structured JSON. Runs automatically via `run.sh`. |
| `llm_sweep_analysis.py` | ~575 | LLM-based (Claude API) vulnerability analysis over sweep artifacts. Generates per-strategy and global analysis markdown reports. |
| `generate_sweep_summary.py` | ~570 | Generates compact sweep summary tables from per-run metrics. |
| `vulnerability_analysis.py` | ~530 | Cross-defense, cross-dataset vulnerability analysis. Extracts final accuracy and pivots by attack dimensions. |
| `primitive_attack_rank.py` | ~130 | Ranks primitive attacks by effectiveness across strategies. |
| `adaptive_takeover_summary.py` | ~60 | Summarizes adaptive attack takeover patterns (which attack the MAB converges to). |
| `prefetch_datasets.py` | ~95 | Downloads HF datasets to local cache for offline use. |
| `generate_run_report.py` | ~889 | Auto-generates a Jupyter notebook report per run. Reads CSVs/JSONs and builds `report.ipynb` with accuracy/loss/F1 charts, attack analysis, defense behavior, per-class heatmap, findings/suggestions. Runs automatically via `run.sh`. |
| `query_run.py` | ~194 | CLI to query the SQLite database for a specific run's results. Prints run info, final metrics, baseline comparison, attack summary, trust summary. |
| `measure_srv_norm.py` | ~10 | Quick utility to measure server model parameter norm. |
| `__init__.py` | 2 | Package marker. |

## Top-Level Shell Scripts

| File | Purpose |
|------|---------|
| `run_thesis_sweep.sh` | Main sweep runner. Parses sweep config files, iterates strategies × scenarios × seeds, calls `run_simulation_and_log.py` for each. |
| `run.sh` | Quick single-run launcher. Runs simulation, then post-run analysis, then notebook report generation, then LLM analysis (opt-out via `CALL_LLM_ANALYSIS=0`). |

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
| `tests/test_analysis_semantics.py` | 8 | Telemetry availability, research-validity gates, conservative report semantics |
| `tests/test_knowledge_base.py` | 5 | Literature KB integrity, Markdown synchronization, exact-pair retrieval, conservative novelty wording |

**Total: 115 tests, 0 failures, 0 skips** (with venv Python + torch; verified 2026-08-27)

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

Key docs an agent needs to find (see also `db/` for the schema/ingestion scripts):

| File | Purpose |
|------|---------|
| `docs/DATABASE_WORKFLOW.md` | End-to-end database workflow, schema, CSV mapping, run layout |
| `docs/EXPERIMENT_PLAN.md` | 6-phase experiment plan (thesis proposal) |
| `docs/FEMNIST_VULNERABILITY_UPDATE.md` | ATLAS-mapped findings and candidate failure modes |
| `docs/NOVELTY_MAP.md` | Literature/novelty snapshot of the 205-paper KB |
| `docs/paper_draft.tex` | IEEE conference paper draft |
| `docs/vulnerability_pilot_once.conf` | Minimal pilot sweep config (1 attacked scenario) |
| `docs/thesis_sweeps.conf`, `thesis_sweeps2.conf` | Full sweep configs (do not use for pilots) |
| `docs/reports/vulnerability_report_atlas.md` | Global ATLAS vulnerability report |

Date-stamped progress updates live in `docs/updates/` (`ls` to see them; read the
latest to catch up). Top-level artifacts: `pyproject.toml` (all experiment params),
`README.md`, the two analysis notebooks, and `final_model.pt` (legacy fallback;
runner-managed runs save `checkpoints/final_model.pt` per run dir).

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

## Schema, Workflow, and CSV Mapping

The full 9-step workflow, the 13-table schema, the CSV-to-table ingestion mapping,
the run-directory layout, and the sweep-data inventory all live in
**`docs/DATABASE_WORKFLOW.md`** (and `db/schema.sql`). Do not duplicate them here —
update that doc if the schema or mapping changes.

Ingestion gotchas that are easy to miss (also in DATABASE_WORKFLOW.md):
- Layered attack names are `+`-joined strings (e.g. `"gaussian_noise+sign_flip"`).
- `trust_strategy_by_round.csv` `details_json` has commas replaced with semicolons — reverse before JSON parsing.
- `defense_selection_by_round.csv` (krum/bulyan only) has semicolon-separated client-ID lists that expand into one row per client.
- Client IDs differ across CSVs; use `client_number_map.csv` to map `client_number` ↔ `src_node_id`.

Current sweep data: FEMNIST full + MNIST full (Apr 2026), pilot v1 (all 8 strategies)
and partial pilot v2 under `logs/sweeps/`, plus ~35 standalone dev runs under `logs/`.
See `docs/updates/2026-08-13.md` for the inventory. MNIST full has 0 clean baselines.

## Testing Status

- **Unit tests: 115 passed, 0 failed, 0 skipped** (venv Python + torch). Run with `../myenv/bin/python -m pytest tests/ -v`.
- **Real data ingestion DONE:** 606 run rows (324 MNIST + 282 FEMNIST), 622 baseline comparison pairs, 1,452 adaptive-score rows.
- **Dummy validation PASSED:** schema creation, dummy insertion, 11 queries, FK integrity.
- **WARNING:** Never run `db/validate.py` after ingesting real data — it destructively recreates the DB with dummy data.

## Remaining Work

Experiment gaps (research-critical, tracked in `docs/EXPERIMENT_PLAN.md`):
1. **MNIST clean baselines** — 320 attacked runs, 0 baselines.
2. **Multi-seed replication** — all runs single-seed (1337); need 3+ seeds.
3. **Fixed-primitive controls** (`attack_mode=phase`) — 0 exist; required for the adaptive-vs-static claim.
4. **Re-run FEMNIST baselines** — old ones used wrong `num-malicious-nodes`.
5. **IID controls** and **more rounds** (100–200 vs current 30).

Infrastructure: plug-and-play validation with a strategy not in the DB; multi-seed confidence intervals in `baseline_comparisons`.

## Discovery Patterns, ATLAS Mapping, Plug-and-Play

The vulnerability-discovery query patterns, MITRE ATLAS mapping rules, and the
plug-and-play new-strategy workflow are documented in **`docs/DATABASE_WORKFLOW.md`**.
Core rule that always applies: never say "new MITRE ATLAS vulnerability discovered" —
mark uncertain mappings tentative and label project-specific results as candidate
vulnerabilities or observed weaknesses.

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

Research-validity (open items — completed steps are recorded in `docs/updates/`):
1. **Re-run FEMNIST baselines with fixed params** — old baselines used hardcoded `num-malicious-nodes=25`, causing filter defenses (Bulyan/MultiKrum/FedTrimmedAvg/FedMedian) to exclude honest clients. Auto-compute fix is in place; baselines need re-running.
2. **Add multiple seeds** — still single-seed (1337); need 3+ for statistical claims.
3. **Run MNIST clean baselines** — 320 attacked runs have 0 baselines.
4. **Add fixed-primitive controls** (`attack_mode=phase`) — required for the adaptive-vs-static comparison.
5. **More rounds** (100–200 vs current 30) and **IID controls** to separate non-IID effects from attack effects.

Database/workflow: add multi-seed confidence intervals to `baseline_comparisons`; validate plug-and-play with a strategy not yet in the DB.

Lower priority / do later: splitting `task.py`, strategy-registry refactor, dashboard persistence, CIFAR-100 experiments, audio model (still scaffolded only), and testing the suggestion loop end-to-end (apply suggested params, re-run, verify improvement).

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
