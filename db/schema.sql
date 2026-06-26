-- =============================================================================
-- Dynamic FL Vulnerability Discovery Database — SQLite Schema
-- =============================================================================
-- Designed to store federated learning experiment results and enable an AI agent
-- to query for vulnerability patterns, defense weaknesses, and recommended
-- follow-up experiments.
--
-- Data sources per table:
--   SWEEPS              → sweep_settings.csv (sweep-level)
--   RUNS                → meta.json + sweep_settings.csv row
--   RUN_CONFIG          → meta.json resolved_config_for_naming (overflow)
--   ROUND_METRICS       → metrics/evaluate_server__*.csv
--   CLIENT_METRICS      → metrics/evaluate_client__*.csv, train_client__*.csv
--   ATTACK_EVENTS       → summaries/attack_timeline.csv, round_attack_stats.csv
--   ATTACK_EVENT_LAYERS → summaries/attack_log.jsonl → attack_details.layer_details
--   ADAPTIVE_ATTACK_SCORES → NOT YET LOGGED (placeholder, needs AttackEngine changes)
--   CLIENT_ATTACK_EVENTS   → summaries/attack_by_client_round.csv
--   TRUST_METRICS       → summaries/trust_strategy_by_round.csv
--   DEFENSE_SELECTION   → summaries/defense_selection_by_round.csv (krum/bulyan)
--                        + trust_strategy_by_round.csv selected_for_aggregation
--   BASELINE_COMPARISONS → computed from ROUND_METRICS pairs
--   AGENT_RECOMMENDATIONS → agent-generated output
-- =============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- -----------------------------------------------------------------------------
-- SWEEPS: one row per sweep execution (a batch of related runs)
-- Source: sweep directory metadata + sweep_settings.csv
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sweeps (
    sweep_id          TEXT PRIMARY KEY,
    sweep_name        TEXT NOT NULL,
    created_at        TEXT NOT NULL,  -- ISO 8601
    dataset           TEXT,
    partitioner       TEXT,
    dirichlet_alpha   REAL,
    config_file       TEXT,           -- e.g. "docs/vulnerability_pilot_once.conf"
    num_runs          INTEGER,
    strategies        TEXT,           -- comma-separated strategy names
    seeds             TEXT,           -- comma-separated seed values
    notes             TEXT
);

-- -----------------------------------------------------------------------------
-- RUNS: one row per experiment run
-- Source: meta.json + sweep_settings.csv row
-- Includes attack/defense config that is FIXED for the entire run.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS runs (
    run_id              TEXT PRIMARY KEY,
    sweep_id            TEXT REFERENCES sweeps(sweep_id),
    label               TEXT,           -- sweep scenario label, e.g. "S00_A_adp_churn_single"
    run_name            TEXT,
    run_folder          TEXT,           -- relative path to run output directory
    strategy            TEXT NOT NULL,  -- defense strategy name
    dataset             TEXT NOT NULL,
    partitioner         TEXT,
    dirichlet_alpha     REAL,
    is_iid              INTEGER NOT NULL DEFAULT 0,  -- boolean
    seed                INTEGER,
    num_clients         INTEGER,
    num_rounds          INTEGER,
    fraction_train      REAL,           -- fraction of clients sampled per round
    local_epochs        INTEGER,
    learning_rate       REAL,
    batch_size          INTEGER,
    -- Attack configuration (run-level, does NOT change per round)
    is_baseline         INTEGER NOT NULL DEFAULT 0,
    attack_enabled      INTEGER NOT NULL DEFAULT 0,
    attack_mode         TEXT,           -- "adaptive", "weighted_random", "phase", NULL for baselines
    selection_mode      TEXT,           -- "churn", "sticky", "per_round_random"
    layering_mode       TEXT,           -- "single", "fixed", "sample_k"
    churn_fraction      REAL,
    attack_window_start INTEGER,        -- first round attacks are active
    attack_window_end   INTEGER,        -- last round attacks are active
    ramp_end            REAL,           -- intensity ramp endpoint
    malicious_fraction  REAL,           -- configured fraction of malicious clients
    -- Run status
    status              TEXT DEFAULT 'completed',  -- "completed", "failed", "running"
    created_at          TEXT            -- ISO 8601 timestamp
);

CREATE INDEX idx_runs_sweep ON runs(sweep_id);
CREATE INDEX idx_runs_strategy ON runs(strategy);
CREATE INDEX idx_runs_baseline ON runs(is_baseline);

-- -----------------------------------------------------------------------------
-- RUN_CONFIG: EAV table for overflow/non-standard config keys from meta.json
-- Source: meta.json → resolved_config_for_naming
-- Use this for config keys not already captured as columns in RUNS.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS run_config (
    run_id       TEXT NOT NULL REFERENCES runs(run_id),
    config_key   TEXT NOT NULL,
    config_value TEXT,
    PRIMARY KEY (run_id, config_key)
);

-- -----------------------------------------------------------------------------
-- ROUND_METRICS: server-level metrics per round (EAV)
-- Source: metrics/evaluate_server__*.csv (each file = one metric, columns: round, value)
-- Metric names: accuracy, loss, f1_macro, f1_weighted, precision_macro,
--   precision_weighted, recall_macro, recall_weighted, backdoor_asr, backdoor_loss,
--   class_0_accuracy .. class_61_accuracy
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS round_metrics (
    run_id       TEXT NOT NULL REFERENCES runs(run_id),
    round        INTEGER NOT NULL,
    metric_name  TEXT NOT NULL,
    metric_value REAL,
    PRIMARY KEY (run_id, round, metric_name)
);

CREATE INDEX idx_round_metrics_metric ON round_metrics(metric_name);
CREATE INDEX idx_round_metrics_run_round ON round_metrics(run_id, round);

-- -----------------------------------------------------------------------------
-- CLIENT_METRICS: per-client per-round metrics (EAV)
-- Source: metrics/evaluate_client__*.csv, metrics/train_client__*.csv
-- Metric names: eval_acc, eval_loss, train_loss, attack_is_malicious,
--   poison_examples_seen, poisoned_examples, poisoned_label_flip_examples,
--   poisoned_backdoor_examples, {strategy}_avg_trust, etc.
-- Note: client_id here is the client_number (1-based), not the raw node_id.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS client_metrics (
    run_id       TEXT NOT NULL REFERENCES runs(run_id),
    round        INTEGER NOT NULL,
    client_id    INTEGER NOT NULL,
    metric_name  TEXT NOT NULL,
    metric_value REAL,
    PRIMARY KEY (run_id, round, client_id, metric_name)
);

CREATE INDEX idx_client_metrics_run_round ON client_metrics(run_id, round);

-- -----------------------------------------------------------------------------
-- ATTACK_EVENTS: one row per round, round-level attack state
-- Source: summaries/attack_timeline.csv + summaries/round_attack_stats.csv
-- For layered attacks, attack_name is "+"-joined (e.g. "gaussian_noise+sign_flip")
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_events (
    run_id                  TEXT NOT NULL REFERENCES runs(run_id),
    round                   INTEGER NOT NULL,
    attack_name             TEXT,       -- "+"-joined composite, e.g. "alie" or "mean_shift+sign_flip+backdoor"
    attack_active           INTEGER,    -- boolean: is attack active this round?
    mechanism               TEXT,       -- "gaussian_noise", "sign_flip", "multi_layer", "-", etc.
    intensity               REAL,       -- base intensity before per-layer multipliers
    malicious_fraction_used REAL,
    num_selected_clients    INTEGER,    -- total clients sampled this round
    num_malicious           INTEGER,    -- malicious clients active this round
    -- Norm statistics (from round_attack_stats.csv)
    max_norm                REAL,       -- largest update norm across all clients
    max_mal_norm_pre        REAL,       -- largest malicious norm before stealth capping
    max_mal_norm_post       REAL,       -- largest malicious norm after stealth capping
    honest_norm_p50         REAL,
    honest_norm_p90         REAL,
    honest_norm_max         REAL,
    -- Stealth info
    stealth_applied         INTEGER,    -- boolean
    stealth_cap             REAL,
    stealth_scale           REAL,
    -- Defense assumption gap
    defense_assumed_malicious INTEGER,  -- n_malicious the defense was configured to expect
    assumption_gap          INTEGER,    -- actual - assumed
    -- Adaptive switching detection
    adaptive_switched       INTEGER,    -- boolean: did the MAB switch attacks this round?
    previous_attack         TEXT,       -- attack name from previous round (for switch detection)
    PRIMARY KEY (run_id, round)
);

CREATE INDEX idx_attack_events_attack ON attack_events(attack_name);

-- -----------------------------------------------------------------------------
-- ATTACK_EVENT_LAYERS: per-layer detail for layered/stacked attacks
-- Source: summaries/attack_log.jsonl → attack_details.layer_details
-- Only populated when layer_details are available (typically from JSONL import).
-- For single-attack rounds, there is one row. For stacked, one row per layer.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_event_layers (
    run_id         TEXT NOT NULL REFERENCES runs(run_id),
    round          INTEGER NOT NULL,
    layer_name     TEXT NOT NULL,   -- individual attack name, e.g. "gaussian_noise"
    layer_type     TEXT,            -- "update_poisoning" or "data_poisoning"
    mechanism      TEXT,            -- same as layer_name for single-mechanism layers
    intensity      REAL,            -- per-layer effective intensity
    -- Attack-type-specific parameters (NULL when not applicable)
    sigma_effective     REAL,       -- gaussian_noise
    alpha_effective     REAL,       -- sign_flip
    z_effective         REAL,       -- alie
    beta_effective      REAL,       -- mean_shift
    flip_rate_effective REAL,       -- label_flip
    targeted            INTEGER,    -- label_flip: boolean
    source_class        INTEGER,    -- label_flip
    target_class        INTEGER,    -- label_flip / backdoor
    poison_rate_effective REAL,     -- backdoor
    blend_alpha_effective REAL,     -- backdoor
    trigger_type        TEXT,       -- backdoor
    patch_size          INTEGER,    -- backdoor
    PRIMARY KEY (run_id, round, layer_name)
);

-- -----------------------------------------------------------------------------
-- ADAPTIVE_ATTACK_SCORES: MAB bandit state per attack per round
-- Source: NOT YET LOGGED. Requires adding logging to AttackEngine._adaptive_rewards_by_attack.
-- This table is a PLACEHOLDER for future use. The columns match the internal
-- bandit state that exists in memory but is not written to any file.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS adaptive_attack_scores (
    run_id              TEXT NOT NULL REFERENCES runs(run_id),
    round               INTEGER NOT NULL,
    attack_name         TEXT NOT NULL,   -- individual attack name (not composite)
    reward              REAL,            -- reward signal this round (e.g. accuracy drop)
    cumulative_reward   REAL,            -- sum of all rewards for this attack
    estimated_value     REAL,            -- running average reward
    times_selected      INTEGER,         -- how many times this attack has been chosen
    selected_this_round INTEGER,         -- boolean: was this attack chosen this round?
    PRIMARY KEY (run_id, round, attack_name)
);

-- -----------------------------------------------------------------------------
-- CLIENT_ATTACK_EVENTS: per-client per-round attack assignment
-- Source: summaries/attack_by_client_round.csv
-- One row per (round, client). For layered attacks, attack_layers contains
-- semicolon-separated layer names; attack_layer_intensities has key=value pairs.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS client_attack_events (
    run_id                   TEXT NOT NULL REFERENCES runs(run_id),
    round                    INTEGER NOT NULL,
    client_id                INTEGER NOT NULL,  -- client_number (1-based)
    src_node_id              INTEGER,            -- raw Flower node ID
    is_malicious             INTEGER NOT NULL,   -- boolean
    attack_active            INTEGER,            -- boolean
    attack_name              TEXT,               -- "+"-joined composite
    attack_layers            TEXT,               -- semicolon-separated layer names
    intensity                REAL,
    attack_layer_intensities TEXT,               -- semicolon-separated "layer=value" pairs
    -- Label flip parameters
    label_flip_rate          REAL,
    label_flip_rate_effective REAL,
    label_flip_targeted      INTEGER,            -- boolean
    label_flip_source_class  INTEGER,
    label_flip_target_class  INTEGER,
    -- Backdoor parameters
    backdoor_poison_rate     REAL,
    backdoor_poison_rate_effective REAL,
    backdoor_blend_alpha     REAL,
    backdoor_blend_alpha_effective REAL,
    backdoor_target_label    INTEGER,
    backdoor_trigger_type    TEXT,
    backdoor_patch_size      INTEGER,
    -- Poisoning counts (from poisoning_by_client_round.csv)
    examples_seen            INTEGER,
    poisoned_examples        INTEGER,
    poisoned_label_flip      INTEGER,
    poisoned_backdoor        INTEGER,
    PRIMARY KEY (run_id, round, client_id)
);

CREATE INDEX idx_client_attack_malicious ON client_attack_events(is_malicious);
CREATE INDEX idx_client_attack_run_round ON client_attack_events(run_id, round);

-- -----------------------------------------------------------------------------
-- TRUST_METRICS: per-client per-round trust/reputation scores
-- Source: summaries/trust_strategy_by_round.csv
-- Only populated for trust-based strategies (fltrust, foolsgold, flram, mab-rfl).
-- Common columns are flat; strategy-specific detail is in details_json.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS trust_metrics (
    run_id                TEXT NOT NULL REFERENCES runs(run_id),
    round                 INTEGER NOT NULL,
    client_id             INTEGER NOT NULL,  -- raw client_id from trust CSV
    strategy              TEXT NOT NULL,      -- "fltrust", "foolsgold", "flram", "mab-rfl"
    trust_score           REAL,
    selected_for_aggregation INTEGER,         -- boolean
    update_norm           REAL,
    cosine_to_center      REAL,
    history_score         REAL,              -- FoolsGold: max_history_cosine; MAB-RFL: old_reputation
    reputation            REAL,              -- MAB-RFL only
    num_examples          INTEGER,
    effective_weight      REAL,              -- from details_json, pulled out for easy querying
    details_json          TEXT,              -- full strategy-specific detail (JSON)
    PRIMARY KEY (run_id, round, client_id)
);

CREATE INDEX idx_trust_strategy ON trust_metrics(strategy);
CREATE INDEX idx_trust_run_round ON trust_metrics(run_id, round);

-- -----------------------------------------------------------------------------
-- DEFENSE_SELECTION: per-client per-round aggregation selection decision
-- Source: defense_selection_by_round.csv (krum/multikrum/bulyan — expanded from
--         semicolon-separated lists) + trust_strategy_by_round.csv
--         selected_for_aggregation column (trust strategies)
-- Unified view: for any strategy, did this client end up in the aggregation?
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS defense_selection (
    run_id                    TEXT NOT NULL REFERENCES runs(run_id),
    round                     INTEGER NOT NULL,
    client_id                 INTEGER NOT NULL,
    defense_strategy          TEXT,              -- strategy that made the selection
    selected_for_aggregation  INTEGER NOT NULL,  -- boolean
    is_malicious              INTEGER,           -- boolean (joined from attack data)
    rejection_reason          TEXT,              -- NULL if selected; reason string if rejected
    PRIMARY KEY (run_id, round, client_id)
);

CREATE INDEX idx_defense_sel_run_round ON defense_selection(run_id, round);
CREATE INDEX idx_defense_sel_malicious ON defense_selection(is_malicious, selected_for_aggregation);

-- -----------------------------------------------------------------------------
-- BASELINE_COMPARISONS: pre-computed attacked-vs-clean comparison metrics
-- Source: computed from ROUND_METRICS by pairing attacked runs with their
--         matching clean baseline (same strategy, dataset, alpha, seed, etc.)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS baseline_comparisons (
    comparison_id          TEXT PRIMARY KEY,
    attacked_run_id        TEXT NOT NULL REFERENCES runs(run_id),
    baseline_run_id        TEXT NOT NULL REFERENCES runs(run_id),
    strategy               TEXT,
    -- Final-round accuracy
    clean_final_accuracy   REAL,
    attacked_final_accuracy REAL,
    accuracy_drop          REAL,    -- clean - attacked (positive = attack hurt)
    accuracy_retention     REAL,    -- attacked / clean (1.0 = no damage)
    -- Final-round F1
    clean_final_f1_macro   REAL,
    attacked_final_f1_macro REAL,
    f1_macro_drop          REAL,
    clean_final_f1_weighted REAL,
    attacked_final_f1_weighted REAL,
    f1_weighted_drop       REAL,
    -- Backdoor
    clean_final_backdoor_asr  REAL,
    attacked_final_backdoor_asr REAL,
    backdoor_asr_increase  REAL,
    -- Loss
    clean_final_loss       REAL,
    attacked_final_loss    REAL,
    loss_increase          REAL,
    -- Flags
    collapse_detected      INTEGER,  -- boolean: attacked accuracy < 5%
    recovery_detected      INTEGER,  -- boolean: accuracy recovered after mid-run dip
    has_matching_baseline  INTEGER NOT NULL DEFAULT 1,
    num_seeds              INTEGER DEFAULT 1,
    is_replicated          INTEGER DEFAULT 0,  -- boolean: tested with 3+ seeds
    is_preliminary         INTEGER DEFAULT 1   -- boolean: needs more validation
);

CREATE INDEX idx_baseline_attacked ON baseline_comparisons(attacked_run_id);
CREATE INDEX idx_baseline_strategy ON baseline_comparisons(strategy);

-- -----------------------------------------------------------------------------
-- AGENT_RECOMMENDATIONS: AI agent-generated experiment suggestions
-- Source: agent output — the agent writes here after analyzing the DB
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_recommendations (
    recommendation_id        TEXT PRIMARY KEY,
    created_at               TEXT NOT NULL,  -- ISO 8601
    run_id                   TEXT REFERENCES runs(run_id),  -- which run prompted this
    strategy                 TEXT,           -- defense under test
    attack_name              TEXT,           -- attack or composite attack
    dataset                  TEXT,
    attack_mode              TEXT,           -- adaptive, weighted_random, etc.
    selection_mode           TEXT,           -- churn, sticky, per_round_random
    layering_mode            TEXT,           -- single, fixed, sample_k
    defense_weakness_score   REAL,           -- 0-1, how weak the defense looked
    attack_effectiveness_score REAL,         -- 0-1, how effective the attack was
    evidence_strength        REAL,           -- 0-1, how much data supports this
    priority_score           REAL,           -- 0-1, overall priority for next experiment
    suggested_next_config    TEXT,           -- JSON or human-readable config suggestion
    rationale                TEXT            -- plain English explanation
);

CREATE INDEX idx_recommendations_priority ON agent_recommendations(priority_score DESC);
CREATE INDEX idx_recommendations_strategy ON agent_recommendations(strategy);
