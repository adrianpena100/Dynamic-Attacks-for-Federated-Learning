"""
Ingest real experiment run outputs into the Dynamic FL SQLite database.

Usage:
    python db/ingest.py logs/sweeps/fltrust_pilot_vuln__2026-05-01_03-46-10
    python db/ingest.py logs/resnet18_smoke__ylecun_mnist__*
    python db/ingest.py logs/sweeps/*   # ingest all sweeps
"""

import csv
import json
import math
import sqlite3
import sys
import uuid
from pathlib import Path

DB_DIR = Path(__file__).parent
DB_PATH = DB_DIR / "dynamic_fl.sqlite"
SCHEMA_PATH = DB_DIR / "schema.sql"

KNOWN_RUN_COLUMNS = {
    "strategy", "dataset", "partitioner", "dirichlet-alpha", "seed",
    "num-server-rounds", "fraction-train", "local-epochs", "learning-rate",
    "batch-size", "attack-mode", "attack-selection-mode", "attack-layering-mode",
    "attack-churn-fraction", "attack-window-start-round", "attack-window-end-round",
    "attack-intensity-ramp-multiplier-end", "attack-malicious-fraction",
    "attack-malicious-fraction-mode", "attack-seed", "model",
    "dataset-modality", "num-clients",
}

VISION_DATASETS = {
    "uoft-cs/cifar10", "uoft-cs/cifar100", "ylecun/mnist",
    "zalando-datasets/fashion_mnist", "flwrlabs/femnist",
    "zh-plus/tiny-imagenet", "flwrlabs/usps", "flwrlabs/pacs",
    "flwrlabs/cinic10", "flwrlabs/caltech101", "flwrlabs/office-home",
    "flwrlabs/fed-isic2019", "ufldl-stanford/svhn",
}
TEXT_DATASETS = {
    "sentiment140", "takala/financial_phrasebank", "pauri32/fiqa-2018",
    "zeroshot/twitter-financial-news-sentiment", "bigbio/pubmed_qa",
    "openlifescienceai/medmcqa", "bigbio/med_qa",
    "google-research-datasets/mbpp",
}


def _uid():
    return uuid.uuid4().hex[:12]


def _safe_float(v):
    if v is None or v == "" or v == "nan" or v == "NaN":
        return None
    try:
        f = float(v)
        return None if (math.isnan(f) or math.isinf(f)) else f
    except (ValueError, TypeError):
        return None


def _safe_int(v):
    if v is None or v == "":
        return None
    try:
        return int(float(v))
    except (ValueError, TypeError):
        return None


def _read_csv(path):
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _infer_modality(dataset, resolved_config):
    explicit = str(resolved_config.get("dataset-modality", "auto")).strip().lower()
    if explicit and explicit != "auto":
        return explicit
    ds = str(dataset).strip().lower()
    if ds in TEXT_DATASETS:
        return "text"
    if ds in VISION_DATASETS:
        return "vision"
    if resolved_config.get("text-key"):
        return "text"
    if resolved_config.get("audio-key"):
        return "audio"
    return "vision"


def _ensure_db(db_path):
    db_path = Path(db_path)
    if not db_path.exists():
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA foreign_keys = ON")
        with open(SCHEMA_PATH) as f:
            conn.executescript(f.read())
        conn.commit()
        print(f"  Created new database: {db_path}")
        return conn
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    # Add new columns if missing (for DBs created before schema update)
    try:
        conn.execute("SELECT model_architecture FROM runs LIMIT 0")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE runs ADD COLUMN model_architecture TEXT")
        conn.execute("ALTER TABLE runs ADD COLUMN dataset_modality TEXT")
        conn.commit()
    try:
        conn.execute("SELECT atlas_technique_id FROM agent_recommendations LIMIT 0")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE agent_recommendations ADD COLUMN atlas_technique_id TEXT")
        conn.execute("ALTER TABLE agent_recommendations ADD COLUMN novelty_status TEXT")
        conn.commit()
    return conn


def _run_already_ingested(conn, run_folder):
    row = conn.execute(
        "SELECT run_id FROM runs WHERE run_folder = ?", (run_folder,)
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# Ingest server-level metrics (evaluate_server__*.csv)
# ---------------------------------------------------------------------------
def _ingest_server_metrics(conn, run_id, metrics_dir):
    rows = []
    for csv_path in sorted(metrics_dir.glob("evaluate_server__*.csv")):
        metric_name = csv_path.stem.replace("evaluate_server__", "")
        for row in _read_csv(csv_path):
            rnd = _safe_int(row.get("round"))
            val = _safe_float(row.get("value"))
            if rnd is not None:
                rows.append((run_id, rnd, metric_name, val))
    if rows:
        conn.executemany(
            "INSERT OR IGNORE INTO round_metrics VALUES (?,?,?,?)", rows
        )
    return len(rows)


# ---------------------------------------------------------------------------
# Ingest client-level metrics (evaluate_client__*.csv, train_client__*.csv)
# ---------------------------------------------------------------------------
def _ingest_client_metrics(conn, run_id, metrics_dir):
    rows = []
    patterns = ["evaluate_client__*.csv", "train_client__*.csv"]
    for pattern in patterns:
        for csv_path in sorted(metrics_dir.glob(pattern)):
            stem = csv_path.stem
            if stem.startswith("evaluate_client__"):
                metric_name = stem.replace("evaluate_client__", "")
            elif stem.startswith("train_client__"):
                metric_name = stem.replace("train_client__", "")
            else:
                continue
            data = _read_csv(csv_path)
            if not data:
                continue
            cols = [c for c in data[0].keys() if c != "round"]
            for row in data:
                rnd = _safe_int(row.get("round"))
                if rnd is None:
                    continue
                for col in cols:
                    val = _safe_float(row[col])
                    client_id = _safe_int(col)
                    if client_id is not None:
                        rows.append((run_id, rnd, client_id, metric_name, val))
    if rows:
        conn.executemany(
            "INSERT OR IGNORE INTO client_metrics VALUES (?,?,?,?,?)", rows
        )
    return len(rows)


# ---------------------------------------------------------------------------
# Ingest attack events (attack_timeline + round_attack_stats)
# ---------------------------------------------------------------------------
def _ingest_attack_events(conn, run_id, summaries_dir):
    timeline_path = summaries_dir / "attack_timeline.csv"
    stats_path = summaries_dir / "round_attack_stats.csv"
    timeline = _read_csv(timeline_path)
    if not timeline:
        return 0

    stats_by_round = {}
    for row in _read_csv(stats_path):
        rnd = _safe_int(row.get("round"))
        if rnd is not None:
            stats_by_round[rnd] = row

    rows = []
    prev_attack = None
    for tl_row in timeline:
        rnd = _safe_int(tl_row.get("round"))
        if rnd is None:
            continue
        attack_name = tl_row.get("attack_name", "")
        mechanism = tl_row.get("mechanism", "")
        intensity = _safe_float(tl_row.get("intensity"))
        mal_frac = _safe_float(tl_row.get("malicious_fraction_used"))
        attack_active = _safe_int(tl_row.get("attack_active"))
        num_selected = _safe_int(tl_row.get("num_selected_clients"))
        num_malicious = _safe_int(tl_row.get("num_malicious"))
        max_norm = _safe_float(tl_row.get("max_norm"))
        max_mal_pre = _safe_float(tl_row.get("max_mal_norm_pre"))
        max_mal_post = _safe_float(tl_row.get("max_mal_norm_post"))

        st = stats_by_round.get(rnd, {})
        honest_p50 = _safe_float(st.get("honest_norm_p50"))
        honest_p90 = _safe_float(st.get("honest_norm_p90"))
        honest_max = _safe_float(st.get("honest_norm_max"))
        stealth_applied = _safe_int(st.get("stealth_applied"))
        stealth_cap = _safe_float(st.get("stealth_cap"))
        stealth_scale = _safe_float(st.get("stealth_scale"))
        defense_assumed = _safe_int(st.get("defense_assumed_num_malicious_nodes"))
        assumption_gap = _safe_int(st.get("assumption_gap"))

        switched = 1 if (prev_attack is not None and prev_attack != attack_name) else 0

        rows.append((
            run_id, rnd, attack_name, attack_active, mechanism,
            intensity, mal_frac, num_selected, num_malicious,
            max_norm, max_mal_pre, max_mal_post,
            honest_p50, honest_p90, honest_max,
            stealth_applied, stealth_cap, stealth_scale,
            defense_assumed, assumption_gap,
            switched, prev_attack,
        ))
        prev_attack = attack_name

    if rows:
        conn.executemany(
            "INSERT OR IGNORE INTO attack_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


# ---------------------------------------------------------------------------
# Ingest attack event layers from attack_log.jsonl
# ---------------------------------------------------------------------------
def _ingest_attack_event_layers(conn, run_id, summaries_dir):
    jsonl_path = summaries_dir / "attack_log.jsonl"
    if not jsonl_path.exists():
        return 0

    rows = []
    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            rnd = entry.get("round") or entry.get("server_round")
            if rnd is None:
                continue
            details = entry.get("attack_details", {})
            raw_layers = details.get("layer_details", {})

            if isinstance(raw_layers, dict) and raw_layers:
                layer_items = [
                    (name, info) for name, info in raw_layers.items()
                    if isinstance(info, dict)
                ]
            elif isinstance(raw_layers, list) and raw_layers:
                layer_items = [
                    (ld.get("layer_name", ""), ld) for ld in raw_layers
                ]
            else:
                layer_name = details.get("attack_name") or entry.get("attack_name", "")
                if layer_name:
                    layer_items = [(layer_name, details)]
                else:
                    layer_items = []

            for ln, ld in layer_items:
                if not ln:
                    continue
                lt = ld.get("type", ld.get("layer_type", ""))
                mechanism = ld.get("mechanism", ln)
                rows.append((
                    run_id, rnd, ln, lt, mechanism,
                    _safe_float(ld.get("layer_intensity") or ld.get("intensity")),
                    _safe_float(ld.get("sigma_effective") or ld.get("sigma_eff") or ld.get("sigma")),
                    _safe_float(ld.get("alpha_effective") or ld.get("alpha_eff") or ld.get("alpha")),
                    _safe_float(ld.get("z_effective") or ld.get("z_eff") or ld.get("z")),
                    _safe_float(ld.get("beta_effective") or ld.get("beta_eff") or ld.get("beta")),
                    _safe_float(ld.get("flip_rate_effective") or ld.get("flip_rate")),
                    _safe_int(ld.get("targeted")),
                    _safe_int(ld.get("source_class")),
                    _safe_int(ld.get("target_class") or ld.get("target_label")),
                    _safe_float(ld.get("poison_rate_effective") or ld.get("poison_rate")),
                    _safe_float(ld.get("blend_alpha_effective") or ld.get("blend_alpha")),
                    ld.get("trigger_type"),
                    _safe_int(ld.get("patch_size")),
                ))

    if rows:
        conn.executemany(
            "INSERT OR IGNORE INTO attack_event_layers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


# ---------------------------------------------------------------------------
# Ingest client attack events
# ---------------------------------------------------------------------------
def _ingest_client_attack_events(conn, run_id, summaries_dir):
    csv_path = summaries_dir / "attack_by_client_round.csv"
    data = _read_csv(csv_path)
    if not data:
        return 0

    rows = []
    for row in data:
        rnd = _safe_int(row.get("round"))
        client_num = _safe_int(row.get("client_number"))
        if rnd is None or client_num is None:
            continue
        rows.append((
            run_id, rnd, client_num,
            row.get("src_node_id", ""),
            _safe_int(row.get("is_malicious")),
            _safe_int(row.get("attack_active")),
            row.get("attack_name", ""),
            row.get("attack_layers", ""),
            _safe_float(row.get("intensity")),
            row.get("attack_layer_intensities", ""),
            _safe_float(row.get("label_flip_flip_rate")),
            _safe_float(row.get("label_flip_flip_rate_effective")),
            _safe_int(row.get("label_flip_targeted")),
            _safe_int(row.get("label_flip_source_class")),
            _safe_int(row.get("label_flip_target_class")),
            _safe_float(row.get("backdoor_poison_rate")),
            _safe_float(row.get("backdoor_poison_rate_effective")),
            _safe_float(row.get("backdoor_blend_alpha")),
            _safe_float(row.get("backdoor_blend_alpha_effective")),
            _safe_int(row.get("backdoor_target_label")),
            row.get("backdoor_trigger_type"),
            _safe_int(row.get("backdoor_patch_size")),
            None, None, None, None,  # poisoning counts (from separate file)
        ))

    if rows:
        conn.executemany(
            "INSERT OR IGNORE INTO client_attack_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


# ---------------------------------------------------------------------------
# Ingest trust metrics
# ---------------------------------------------------------------------------
def _ingest_trust_metrics(conn, run_id, summaries_dir, client_map):
    csv_path = summaries_dir / "trust_strategy_by_round.csv"
    data = _read_csv(csv_path)
    if not data:
        return 0

    rows = []
    for row in data:
        rnd = _safe_int(row.get("round"))
        if rnd is None:
            continue
        raw_client_id = row.get("client_id", "")
        strategy = row.get("strategy", "")
        details_raw = row.get("details_json", "")
        details = details_raw.replace(";", ",") if details_raw else ""

        eff_weight = None
        if details:
            try:
                d = json.loads(details)
                eff_weight = _safe_float(d.get("effective_weight"))
            except (json.JSONDecodeError, TypeError):
                pass

        rows.append((
            run_id, rnd, raw_client_id, strategy,
            _safe_float(row.get("trust_score")),
            _safe_int(row.get("selected_for_aggregation")),
            _safe_float(row.get("update_norm")),
            _safe_float(row.get("cosine_to_center")),
            _safe_float(row.get("history_score")),
            _safe_float(row.get("reputation")),
            _safe_int(row.get("num_examples")),
            eff_weight,
            details,
        ))

    if rows:
        conn.executemany(
            "INSERT OR IGNORE INTO trust_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


# ---------------------------------------------------------------------------
# Ingest defense selection
# ---------------------------------------------------------------------------
def _ingest_defense_selection(conn, run_id, summaries_dir, client_map,
                              attack_client_data):
    csv_path = summaries_dir / "defense_selection_by_round.csv"
    data = _read_csv(csv_path)
    if not data:
        return 0

    malicious_by_round = {}
    for row in attack_client_data:
        rnd = _safe_int(row.get("round"))
        cn = _safe_int(row.get("client_number"))
        is_mal = _safe_int(row.get("is_malicious"))
        if rnd is not None and cn is not None:
            malicious_by_round.setdefault(rnd, {})[cn] = is_mal

    rows = []
    for row in data:
        rnd = _safe_int(row.get("round"))
        if rnd is None:
            continue
        strategy = row.get("defense_strategy", "")
        if strategy == "-" or not strategy:
            continue

        selected_ids_str = row.get("selected_client_numbers", "")
        if not selected_ids_str:
            selected_ids_str = row.get("selected_client_ids", "")

        if not selected_ids_str:
            continue

        selected_nums = set()
        for part in selected_ids_str.split(";"):
            n = _safe_int(part.strip())
            if n is not None:
                selected_nums.add(n)

        all_clients_this_round = malicious_by_round.get(rnd, {})
        all_nums = set(all_clients_this_round.keys()) | selected_nums

        for cn in sorted(all_nums):
            is_mal = all_clients_this_round.get(cn)
            selected = 1 if cn in selected_nums else 0
            reason = None if selected else "not_selected"
            rows.append((run_id, rnd, cn, strategy, selected, is_mal, reason))

    if rows:
        conn.executemany(
            "INSERT OR IGNORE INTO defense_selection VALUES (?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


# ---------------------------------------------------------------------------
# Load client number map
# ---------------------------------------------------------------------------
def _load_client_map(summaries_dir):
    csv_path = summaries_dir / "client_number_map.csv"
    data = _read_csv(csv_path)
    fwd = {}
    rev = {}
    for row in data:
        cn = _safe_int(row.get("client_number"))
        nid = row.get("src_node_id", "")
        if cn is not None:
            fwd[cn] = nid
            rev[nid] = cn
    return fwd, rev


# ---------------------------------------------------------------------------
# Ingest one run
# ---------------------------------------------------------------------------
def _ingest_one_run(conn, run_dir, sweep_id, sweep_row=None):
    run_dir = Path(run_dir)
    meta_path = run_dir / "meta.json"
    if not meta_path.exists():
        print(f"  SKIP {run_dir.name} — no meta.json")
        return None

    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)

    run_folder = str(run_dir)
    if _run_already_ingested(conn, run_folder):
        print(f"  SKIP {run_dir.name} — already ingested")
        return None

    rc = meta.get("resolved_config_for_naming", {})
    dataset = str(meta.get("dataset", rc.get("dataset", "")))
    strategy = str(meta.get("strategy", rc.get("strategy", "")))
    timestamp = meta.get("timestamp", "")

    attack_mode = str(rc.get("attack-mode", "")).strip()
    if attack_mode in ("", "off", "none"):
        attack_mode = None
    selection_mode = str(rc.get("attack-selection-mode", "")).strip() or None
    if selection_mode in ("", "none"):
        selection_mode = None
    layering_mode = str(rc.get("attack-layering-mode", "")).strip() or None
    if layering_mode in ("", "none"):
        layering_mode = None

    is_baseline = 1 if attack_mode is None else 0
    attack_enabled = 0 if is_baseline else 1

    if sweep_row:
        label = sweep_row.get("label", "")
        if "BASELINE" in label.upper() or "clean" in label.lower():
            is_baseline = 1
            attack_enabled = 0
            attack_mode = None
        seed = _safe_int(sweep_row.get("seed"))
    else:
        label = run_dir.name
        seed = _safe_int(rc.get("attack-seed"))

    model_arch = str(rc.get("model", "simple-cnn")).strip() or "simple-cnn"
    modality = _infer_modality(dataset, rc)
    partitioner = str(rc.get("partitioner", "")).strip() or None
    dirichlet_alpha = _safe_float(rc.get("dirichlet-alpha"))
    is_iid = 1 if partitioner == "iid" else 0

    run_id = f"run_{_uid()}"

    conn.execute(
        """INSERT INTO runs VALUES
           (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            run_id, sweep_id, label, run_dir.name, run_folder,
            strategy, dataset, partitioner, dirichlet_alpha, is_iid,
            seed,
            _safe_int(rc.get("num-clients")) or 100,
            _safe_int(rc.get("num-server-rounds")),
            _safe_float(rc.get("fraction-train")),
            _safe_int(rc.get("local-epochs")),
            _safe_float(rc.get("learning-rate")),
            _safe_int(rc.get("batch-size")),
            is_baseline, attack_enabled,
            attack_mode, selection_mode, layering_mode,
            _safe_float(rc.get("attack-churn-fraction")),
            _safe_int(rc.get("attack-window-start-round")),
            _safe_int(rc.get("attack-window-end-round")),
            _safe_float(rc.get("attack-intensity-ramp-multiplier-end")),
            _safe_float(rc.get("attack-malicious-fraction")),
            model_arch, modality,
            "completed", timestamp,
        ),
    )

    overflow_keys = set(rc.keys()) - KNOWN_RUN_COLUMNS
    for key in sorted(overflow_keys):
        val = rc[key]
        if val is None or val == "" or val == -1 or val == -1.0:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO run_config VALUES (?,?,?)",
            (run_id, key, str(val)),
        )

    metrics_dir = run_dir / "metrics"
    summaries_dir = run_dir / "summaries"

    n_srv = 0
    n_cli = 0
    if metrics_dir.exists():
        n_srv = _ingest_server_metrics(conn, run_id, metrics_dir)
        n_cli = _ingest_client_metrics(conn, run_id, metrics_dir)

    n_atk = 0
    n_layers = 0
    n_cli_atk = 0
    n_trust = 0
    n_def = 0

    if summaries_dir.exists():
        client_fwd, client_rev = _load_client_map(summaries_dir)

        n_atk = _ingest_attack_events(conn, run_id, summaries_dir)
        n_layers = _ingest_attack_event_layers(conn, run_id, summaries_dir)

        attack_client_csv = summaries_dir / "attack_by_client_round.csv"
        attack_client_data = _read_csv(attack_client_csv)
        n_cli_atk = _ingest_client_attack_events(conn, run_id, summaries_dir)
        n_trust = _ingest_trust_metrics(conn, run_id, summaries_dir, client_fwd)
        n_def = _ingest_defense_selection(
            conn, run_id, summaries_dir, client_fwd, attack_client_data
        )

    bl_tag = "baseline" if is_baseline else "attacked"
    print(
        f"  {bl_tag:8s} {strategy:14s} {dataset:25s} "
        f"srv={n_srv} cli={n_cli} atk={n_atk} layers={n_layers} "
        f"cli_atk={n_cli_atk} trust={n_trust} def={n_def}"
    )
    return run_id


# ---------------------------------------------------------------------------
# Compute baseline comparisons
# ---------------------------------------------------------------------------
def _compute_baseline_comparisons(conn):
    attacked = conn.execute(
        "SELECT run_id, strategy, dataset, dirichlet_alpha, seed FROM runs WHERE is_baseline = 0"
    ).fetchall()
    baselines = conn.execute(
        "SELECT run_id, strategy, dataset, dirichlet_alpha, seed FROM runs WHERE is_baseline = 1"
    ).fetchall()

    bl_index = {}
    for rid, strat, ds, alpha, seed in baselines:
        key = (strat, ds, alpha, seed)
        bl_index[key] = rid

    count = 0
    for atk_id, strat, ds, alpha, seed in attacked:
        bl_id = bl_index.get((strat, ds, alpha, seed))
        if bl_id is None:
            continue

        already = conn.execute(
            "SELECT 1 FROM baseline_comparisons WHERE attacked_run_id = ? AND baseline_run_id = ?",
            (atk_id, bl_id),
        ).fetchone()
        if already:
            continue

        def _get_final(run_id, metric):
            row = conn.execute(
                """SELECT metric_value FROM round_metrics
                   WHERE run_id=? AND metric_name=?
                   ORDER BY round DESC LIMIT 1""",
                (run_id, metric),
            ).fetchone()
            return row[0] if row else None

        bl_acc = _get_final(bl_id, "accuracy")
        atk_acc = _get_final(atk_id, "accuracy")
        bl_f1m = _get_final(bl_id, "f1_macro")
        atk_f1m = _get_final(atk_id, "f1_macro")
        bl_f1w = _get_final(bl_id, "f1_weighted")
        atk_f1w = _get_final(atk_id, "f1_weighted")
        bl_asr = _get_final(bl_id, "backdoor_asr")
        atk_asr = _get_final(atk_id, "backdoor_asr")
        bl_loss = _get_final(bl_id, "loss")
        atk_loss = _get_final(atk_id, "loss")

        def _drop(a, b):
            return round(a - b, 6) if a is not None and b is not None else None

        def _ratio(num, den):
            return round(num / den, 6) if num is not None and den and den > 0 else None

        acc_drop = _drop(bl_acc, atk_acc)
        acc_ret = _ratio(atk_acc, bl_acc)
        collapse = 1 if atk_acc is not None and atk_acc < 0.05 else 0

        conn.execute(
            """INSERT OR IGNORE INTO baseline_comparisons VALUES
               (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f"cmp_{_uid()}", atk_id, bl_id, strat,
                bl_acc, atk_acc, acc_drop, acc_ret,
                bl_f1m, atk_f1m, _drop(bl_f1m, atk_f1m),
                bl_f1w, atk_f1w, _drop(bl_f1w, atk_f1w),
                bl_asr, atk_asr,
                _drop(atk_asr, bl_asr) if atk_asr is not None and bl_asr is not None else None,
                bl_loss, atk_loss,
                _drop(atk_loss, bl_loss) if atk_loss is not None and bl_loss is not None else None,
                collapse, 0,
                1, 1, 0, 1,
            ),
        )
        count += 1

    return count


# ---------------------------------------------------------------------------
# Ingest a sweep directory
# ---------------------------------------------------------------------------
def ingest_sweep(sweep_dir, db_path=None):
    sweep_dir = Path(sweep_dir)
    db_path = Path(db_path or DB_PATH)
    conn = _ensure_db(db_path)

    settings_path = sweep_dir / "sweep_settings.csv"
    settings = _read_csv(settings_path)

    sweep_id = f"sweep_{_uid()}"
    sweep_name = sweep_dir.name

    run_dirs = [
        d for d in sorted(sweep_dir.iterdir())
        if d.is_dir() and (d / "meta.json").exists()
    ]

    strategies_set = set()
    seeds_set = set()
    dataset_val = None

    for row in settings:
        if row.get("seed"):
            seeds_set.add(row["seed"])

    print(f"\nIngesting sweep: {sweep_name} ({len(run_dirs)} runs)")

    conn.execute(
        "INSERT OR IGNORE INTO sweeps VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (sweep_id, sweep_name, "", None, None, None, None, 0, "", "", None),
    )

    run_ids = []
    settings_by_folder = {row.get("run_folder", ""): row for row in settings}

    for run_dir in run_dirs:
        sweep_row = settings_by_folder.get(run_dir.name)
        rid = _ingest_one_run(conn, run_dir, sweep_id, sweep_row)
        if rid:
            run_ids.append(rid)
            r = conn.execute("SELECT strategy, dataset, seed FROM runs WHERE run_id=?", (rid,)).fetchone()
            if r:
                strategies_set.add(r[0])
                dataset_val = r[1]
                if r[2]:
                    seeds_set.add(str(r[2]))

    conn.execute(
        """UPDATE sweeps SET dataset=?, num_runs=?, strategies=?, seeds=?
           WHERE sweep_id=?""",
        (dataset_val, len(run_ids),
         ",".join(sorted(strategies_set)),
         ",".join(sorted(seeds_set)),
         sweep_id),
    )

    n_cmp = _compute_baseline_comparisons(conn)
    print(f"  Computed {n_cmp} baseline comparisons")

    conn.commit()
    conn.close()
    print(f"  Done. Ingested {len(run_ids)} runs into {db_path}")
    return len(run_ids)


# ---------------------------------------------------------------------------
# Ingest a standalone run (not in a sweep)
# ---------------------------------------------------------------------------
def ingest_standalone_run(run_dir, db_path=None):
    run_dir = Path(run_dir)
    db_path = Path(db_path or DB_PATH)
    conn = _ensure_db(db_path)

    sweep_id = f"sweep_standalone_{_uid()}"
    sweep_name = f"standalone__{run_dir.name}"

    print(f"\nIngesting standalone run: {run_dir.name}")

    conn.execute(
        "INSERT OR IGNORE INTO sweeps VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (sweep_id, sweep_name, "", None, None, None, None, 0, "", None, "standalone run"),
    )

    rid = _ingest_one_run(conn, run_dir, sweep_id, sweep_row=None)

    if rid:
        r = conn.execute("SELECT strategy, dataset FROM runs WHERE run_id=?", (rid,)).fetchone()
        conn.execute(
            "UPDATE sweeps SET dataset=?, num_runs=1, strategies=? WHERE sweep_id=?",
            (r[1] if r else None, r[0] if r else None, sweep_id),
        )
        n_cmp = _compute_baseline_comparisons(conn)
        if n_cmp:
            print(f"  Computed {n_cmp} baseline comparison(s)")
        conn.commit()
        print(f"  Done. Ingested 1 run into {db_path}")
    else:
        print("  No run ingested.")

    conn.close()
    return 1 if rid else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python db/ingest.py <path> [<path> ...]")
        print("  path can be a sweep directory or a standalone run directory")
        sys.exit(1)

    total = 0
    for path_str in sys.argv[1:]:
        p = Path(path_str)
        if not p.exists():
            print(f"SKIP: {p} does not exist")
            continue

        if (p / "sweep_settings.csv").exists():
            total += ingest_sweep(p)
        elif (p / "meta.json").exists():
            total += ingest_standalone_run(p)
        else:
            print(f"SKIP: {p} — not a sweep dir or run dir (no sweep_settings.csv or meta.json)")

    print(f"\nTotal runs ingested: {total}")


if __name__ == "__main__":
    main()
