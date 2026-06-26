"""
Create the Dynamic FL vulnerability discovery database and populate with dummy data.

Dummy data covers:
  - 1 sweep with 6 runs (3 strategies x baseline + attacked)
  - Strategies: bulyan (krum-family), fltrust (trust-based), mab-rfl (reputation-based)
  - Attack modes: adaptive/single, adaptive/single, weighted_random/sample_k
  - Scheduling: churn, sticky, churn
  - 30 rounds, 10 clients per run
  - Realistic metric curves (accuracy ramps up for baselines, degrades under attack)
  - Trust scores, defense selection, attack events with layering
"""

import json
import math
import random
import sqlite3
import uuid
from pathlib import Path

DB_DIR = Path(__file__).parent
DB_PATH = DB_DIR / "dynamic_fl.sqlite"
SCHEMA_PATH = DB_DIR / "schema.sql"

random.seed(42)


def create_database():
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA foreign_keys = ON")
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    return conn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uid():
    return uuid.uuid4().hex[:12]


def _accuracy_curve(num_rounds, final_acc, noise=0.01, warmup=5):
    """Generate a realistic accuracy curve that ramps up then plateaus."""
    vals = []
    for r in range(1, num_rounds + 1):
        t = min(r / warmup, 1.0)
        base = final_acc * (1 - math.exp(-3 * t))
        vals.append(max(0.0, min(1.0, base + random.gauss(0, noise))))
    return vals


def _attacked_accuracy_curve(num_rounds, clean_final, attack_start, collapse=False):
    """Accuracy that converges then degrades when attack starts."""
    vals = []
    for r in range(1, num_rounds + 1):
        if r < attack_start:
            t = min(r / 5, 1.0)
            base = clean_final * (1 - math.exp(-3 * t))
        else:
            rounds_since = r - attack_start
            if collapse:
                base = clean_final * math.exp(-0.15 * rounds_since)
            else:
                drop = clean_final * 0.4 * (1 - math.exp(-0.2 * rounds_since))
                base = clean_final * (1 - math.exp(-3 * min(r / 5, 1.0))) - drop
        vals.append(max(0.01, min(1.0, base + random.gauss(0, 0.01))))
    return vals


def _loss_from_accuracy(acc_vals):
    return [max(0.01, -math.log(max(a, 0.01)) + random.gauss(0, 0.05)) for a in acc_vals]


def _f1_from_accuracy(acc_vals, offset=-0.03):
    return [max(0.0, min(1.0, a + offset + random.gauss(0, 0.005))) for a in acc_vals]


ATTACK_POOL = ["gaussian_noise", "sign_flip", "alie", "mean_shift", "label_flip", "backdoor"]


# ---------------------------------------------------------------------------
# Insert functions
# ---------------------------------------------------------------------------

def insert_sweep(conn):
    sweep_id = f"sweep_{_uid()}"
    conn.execute(
        "INSERT INTO sweeps VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (sweep_id, "pilot_vuln_dummy", "2026-05-22T10:00:00",
         "flwrlabs/femnist", "dirichlet", 0.5,
         "docs/vulnerability_pilot_once.conf", 6,
         "bulyan,fltrust,mab-rfl", "1337", "Dummy data for schema validation"),
    )
    return sweep_id


def insert_runs(conn, sweep_id):
    """Insert 6 runs: 3 strategies x (baseline + attacked)."""
    configs = [
        # (strategy, is_baseline, attack_mode, selection_mode, layering_mode, churn_frac)
        ("bulyan",  True,  None,              None,     None,       None),
        ("bulyan",  False, "adaptive",        "churn",  "single",   0.5),
        ("fltrust", True,  None,              None,     None,       None),
        ("fltrust", False, "adaptive",        "sticky", "single",   None),
        ("mab-rfl", True,  None,              None,     None,       None),
        ("mab-rfl", False, "weighted_random", "churn",  "sample_k", 0.5),
    ]
    run_ids = []
    for strategy, is_bl, atk_mode, sel_mode, lay_mode, churn in configs:
        rid = f"run_{strategy}_{'bl' if is_bl else 'atk'}_{_uid()}"
        label = f"BASELINE_clean" if is_bl else f"PILOT_ALL_ADAPTIVE_CHURN"
        conn.execute(
            """INSERT INTO runs VALUES
               (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rid, sweep_id, label,
             f"{strategy}__femnist__noniid__2026-05-22",
             f"logs/sweeps/pilot_vuln_dummy/{rid}",
             strategy, "flwrlabs/femnist", "dirichlet", 0.5, 0,
             1337, 10, 30, 1.0, 1, 0.01, 32,
             1 if is_bl else 0, 0 if is_bl else 1,
             atk_mode, sel_mode, lay_mode, churn,
             0 if not is_bl else None, 30 if not is_bl else None,
             3.0 if not is_bl else None,
             0.3 if not is_bl else None,
             "completed", "2026-05-22T10:00:00"),
        )
        run_ids.append((rid, strategy, is_bl))
    return run_ids


def insert_run_config(conn, run_ids):
    for rid, strategy, is_bl in run_ids:
        conn.execute(
            "INSERT INTO run_config VALUES (?,?,?)",
            (rid, "dataset-eval-split", "test"),
        )
        if strategy in ("fltrust", "mab-rfl", "flram", "foolsgold"):
            conn.execute(
                "INSERT INTO run_config VALUES (?,?,?)",
                (rid, "trust-level", "full"),
            )


def insert_round_metrics(conn, run_ids):
    clean_finals = {"bulyan": 0.35, "fltrust": 0.53, "mab-rfl": 0.31}

    for rid, strategy, is_bl in run_ids:
        final = clean_finals[strategy]
        if is_bl:
            acc = _accuracy_curve(30, final)
        else:
            collapse = (strategy == "bulyan")
            acc = _attacked_accuracy_curve(30, final, attack_start=1, collapse=collapse)

        loss = _loss_from_accuracy(acc)
        f1_macro = _f1_from_accuracy(acc, -0.03)
        f1_weighted = _f1_from_accuracy(acc, -0.01)
        prec_macro = _f1_from_accuracy(acc, -0.02)
        recall_macro = _f1_from_accuracy(acc, -0.04)
        backdoor_asr = [0.0] * 30
        if not is_bl:
            for r in range(30):
                backdoor_asr[r] = min(1.0, 0.02 * r * random.uniform(0.5, 1.5))

        metrics = {
            "accuracy": acc, "loss": loss,
            "f1_macro": f1_macro, "f1_weighted": f1_weighted,
            "precision_macro": prec_macro, "recall_macro": recall_macro,
            "backdoor_asr": backdoor_asr,
        }
        rows = []
        for name, vals in metrics.items():
            for r, v in enumerate(vals, 1):
                rows.append((rid, r, name, round(v, 6)))
        conn.executemany(
            "INSERT INTO round_metrics VALUES (?,?,?,?)", rows,
        )


def insert_client_metrics(conn, run_ids):
    rows = []
    for rid, strategy, is_bl in run_ids:
        for r in range(1, 31):
            for cid in range(1, 11):
                base_acc = 0.3 + 0.02 * r + random.gauss(0, 0.05)
                if not is_bl and cid <= 3:
                    base_acc -= 0.1
                rows.append((rid, r, cid, "eval_acc", round(max(0, min(1, base_acc)), 4)))
                rows.append((rid, r, cid, "eval_loss",
                             round(max(0.01, -math.log(max(base_acc, 0.01))), 4)))
    conn.executemany("INSERT INTO client_metrics VALUES (?,?,?,?,?)", rows)


def insert_attack_events(conn, run_ids):
    """Insert per-round attack events for attacked runs only."""
    rows = []
    layer_rows = []
    prev_attack = {}

    for rid, strategy, is_bl in run_ids:
        if is_bl:
            continue

        if strategy == "mab-rfl":
            # sample_k layering: 2-of-5 pool each round
            pool = ["gaussian_noise", "sign_flip", "alie", "mean_shift", "backdoor"]
        else:
            pool = None

        for r in range(1, 31):
            if pool:
                layers = sorted(random.sample(pool, 2))
                attack_name = "+".join(layers)
                mechanism = "multi_layer"
            elif strategy == "bulyan":
                # Adaptive: converges to alie by round ~10
                if r < 5:
                    attack_name = random.choice(ATTACK_POOL[:4])
                elif r < 10:
                    attack_name = random.choice(["alie", "mean_shift", "alie"])
                else:
                    attack_name = "alie"
                layers = [attack_name]
                mechanism = attack_name
            else:
                # fltrust adaptive: converges to sign_flip
                if r < 7:
                    attack_name = random.choice(ATTACK_POOL[:4])
                else:
                    attack_name = random.choice(["sign_flip", "sign_flip", "gaussian_noise"])
                layers = [attack_name]
                mechanism = attack_name

            prev = prev_attack.get(rid)
            switched = 1 if (prev is not None and prev != attack_name) else 0
            prev_attack[rid] = attack_name

            intensity = min(3.0, 0.5 + 0.08 * r)
            n_malicious = 3  # 3 of 10 clients
            honest_p50 = random.uniform(0.5, 2.0)

            rows.append((
                rid, r, attack_name, 1, mechanism,
                round(intensity, 3),
                0.3,  # malicious_fraction_used
                10, n_malicious,
                round(random.uniform(5, 50), 2),       # max_norm
                round(random.uniform(10, 100), 2),      # max_mal_norm_pre
                round(random.uniform(1, 10), 2),        # max_mal_norm_post
                round(honest_p50, 3),
                round(honest_p50 * 1.8, 3),
                round(honest_p50 * 3.0, 3),
                round(random.uniform(0.1, 0.5), 3),     # stealth_cap
                round(random.uniform(0.5, 1.0), 3),     # stealth_scale
                1 if r > 3 else 0,                       # stealth_applied
                24,     # defense_assumed_malicious
                -21,    # assumption_gap (24 assumed, 3 actual)
                switched, prev if prev else None,
            ))

            for layer in layers:
                layer_rows.append((
                    rid, r, layer,
                    "data_poisoning" if layer in ("label_flip", "backdoor") else "update_poisoning",
                    layer, round(intensity * random.uniform(0.8, 1.2), 3),
                    round(random.uniform(0.1, 0.5), 3) if layer == "gaussian_noise" else None,
                    round(random.uniform(0.5, 2.0), 3) if layer == "sign_flip" else None,
                    round(random.uniform(0.5, 1.5), 3) if layer == "alie" else None,
                    round(random.uniform(1.0, 5.0), 3) if layer == "mean_shift" else None,
                    round(random.uniform(0.3, 0.8), 3) if layer == "label_flip" else None,
                    1 if layer == "label_flip" else None,
                    3 if layer == "label_flip" else None,
                    7 if layer in ("label_flip", "backdoor") else None,
                    round(random.uniform(0.1, 0.5), 3) if layer == "backdoor" else None,
                    round(random.uniform(0.3, 0.8), 3) if layer == "backdoor" else None,
                    "pixel_pattern" if layer == "backdoor" else None,
                    5 if layer == "backdoor" else None,
                ))

    conn.executemany(
        """INSERT INTO attack_events VALUES
           (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    conn.executemany(
        """INSERT INTO attack_event_layers VALUES
           (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        layer_rows,
    )


def insert_adaptive_attack_scores(conn, run_ids):
    """Insert placeholder MAB bandit scores for the adaptive runs."""
    rows = []
    cumulative = {}
    for rid, strategy, is_bl in run_ids:
        if is_bl or strategy == "mab-rfl":  # mab-rfl run uses weighted_random
            continue
        cumulative[rid] = {a: 0.0 for a in ATTACK_POOL}
        times = {a: 0 for a in ATTACK_POOL}

        for r in range(1, 31):
            # Figure out which attack was selected this round from attack_events
            selected = None
            for a in ATTACK_POOL:
                reward = random.uniform(-0.05, 0.1)
                was_selected = 0
                if r <= 5:
                    was_selected = 1 if random.random() < 0.3 else 0
                elif a == "alie" and strategy == "bulyan":
                    was_selected = 1 if r >= 10 else (1 if random.random() < 0.5 else 0)
                elif a == "sign_flip" and strategy == "fltrust":
                    was_selected = 1 if r >= 7 else (1 if random.random() < 0.3 else 0)

                if was_selected:
                    reward = random.uniform(0.01, 0.15)
                    times[a] += 1
                    cumulative[rid][a] += reward

                est_val = cumulative[rid][a] / max(times[a], 1)
                rows.append((
                    rid, r, a, round(reward, 4),
                    round(cumulative[rid][a], 4),
                    round(est_val, 4),
                    times[a], was_selected,
                ))

    conn.executemany(
        "INSERT INTO adaptive_attack_scores VALUES (?,?,?,?,?,?,?,?)", rows,
    )


def insert_client_attack_events(conn, run_ids):
    """Per-client per-round attack assignments."""
    rows = []
    for rid, strategy, is_bl in run_ids:
        if is_bl:
            continue
        malicious_ids = [1, 2, 3]  # clients 1-3 are malicious

        for r in range(1, 31):
            # Get attack name for this round (simplified — recompute)
            if strategy == "mab-rfl":
                pool = ["gaussian_noise", "sign_flip", "alie", "mean_shift", "backdoor"]
                random.seed(42 + r + hash(rid))
                layers = sorted(random.sample(pool, 2))
                attack_name = "+".join(layers)
            elif strategy == "bulyan":
                attack_name = "alie" if r >= 10 else "mean_shift"
            else:
                attack_name = "sign_flip" if r >= 7 else "gaussian_noise"

            for cid in range(1, 11):
                is_mal = 1 if cid in malicious_ids else 0
                rows.append((
                    rid, r, cid, 1000 + cid,
                    is_mal, 1 if is_mal else 0,
                    attack_name if is_mal else "none",
                    attack_name.replace("+", ";") if is_mal else None,
                    round(0.5 + 0.08 * r, 3) if is_mal else 0.0,
                    None,  # attack_layer_intensities
                    # label flip params
                    0.5 if (is_mal and "label_flip" in attack_name) else None,
                    0.3 if (is_mal and "label_flip" in attack_name) else None,
                    1 if (is_mal and "label_flip" in attack_name) else None,
                    3 if (is_mal and "label_flip" in attack_name) else None,
                    7 if (is_mal and "label_flip" in attack_name) else None,
                    # backdoor params
                    0.3 if (is_mal and "backdoor" in attack_name) else None,
                    0.2 if (is_mal and "backdoor" in attack_name) else None,
                    0.5 if (is_mal and "backdoor" in attack_name) else None,
                    0.4 if (is_mal and "backdoor" in attack_name) else None,
                    7 if (is_mal and "backdoor" in attack_name) else None,
                    "pixel_pattern" if (is_mal and "backdoor" in attack_name) else None,
                    5 if (is_mal and "backdoor" in attack_name) else None,
                    # poisoning counts
                    48 if is_mal else 48,
                    random.randint(5, 20) if is_mal else 0,
                    random.randint(0, 10) if (is_mal and "label_flip" in attack_name) else 0,
                    random.randint(0, 5) if (is_mal and "backdoor" in attack_name) else 0,
                ))

    random.seed(42)  # reset
    conn.executemany(
        """INSERT INTO client_attack_events VALUES
           (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )


def insert_trust_metrics(conn, run_ids):
    """Trust scores for trust-based strategies only."""
    rows = []
    for rid, strategy, is_bl in run_ids:
        if strategy not in ("fltrust", "mab-rfl"):
            continue
        malicious_ids = [1, 2, 3]

        for r in range(1, 31):
            for cid in range(1, 11):
                is_mal = cid in malicious_ids
                if strategy == "fltrust":
                    trust = random.uniform(0.0, 0.3) if is_mal else random.uniform(0.6, 1.0)
                    if is_bl:
                        trust = random.uniform(0.5, 1.0)
                    cosine = trust * random.uniform(0.8, 1.0)
                    reputation = None
                    history = None
                    eff_weight = trust
                    details = json.dumps({
                        "server_update_norm": round(random.uniform(0.5, 2.0), 3),
                        "trust_strength": 1.0,
                        "min_weight": 0.0,
                        "warmup_rounds": 0,
                        "effective_weight": round(eff_weight, 4),
                    })
                else:  # mab-rfl
                    base_rep = 0.3 if is_mal else 0.7
                    reputation = max(0, min(1, base_rep + 0.01 * r * (1 if not is_mal else -1)
                                            + random.gauss(0, 0.05)))
                    if is_bl:
                        reputation = max(0, min(1, 0.7 + 0.005 * r + random.gauss(0, 0.03)))
                    trust = reputation * random.uniform(0.8, 1.0)
                    cosine = random.uniform(0.3, 0.9)
                    history = round(reputation * 0.8 + random.gauss(0, 0.05), 4)
                    eff_weight = trust
                    details = json.dumps({
                        "old_reputation": round(reputation - 0.01, 4),
                        "current_score": round(trust, 4),
                        "norm_score": round(random.uniform(0.5, 1.0), 4),
                        "direction_score": round(cosine, 4),
                        "reputation_decay": 0.8,
                        "current_weight": 0.5,
                        "trust_strength": 1.0,
                        "min_weight": 0.0,
                        "warmup_rounds": 0,
                        "effective_weight": round(eff_weight, 4),
                    })

                selected = 1 if trust > 0.2 else 0
                if is_mal and not is_bl and r > 10:
                    selected = 1 if random.random() < 0.3 else 0

                rows.append((
                    rid, r, cid, strategy,
                    round(trust, 4), selected,
                    round(random.uniform(0.5, 5.0), 3),
                    round(cosine, 4),
                    history,
                    round(reputation, 4) if reputation is not None else None,
                    48,
                    round(eff_weight, 4),
                    details,
                ))

    conn.executemany(
        "INSERT INTO trust_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows,
    )


def insert_defense_selection(conn, run_ids):
    """Defense selection for all strategies."""
    rows = []
    for rid, strategy, is_bl in run_ids:
        malicious_ids = [1, 2, 3]
        for r in range(1, 31):
            for cid in range(1, 11):
                is_mal = 1 if cid in malicious_ids else 0

                if strategy == "bulyan":
                    # Bulyan: krum-based, selects ~7 of 10, poor at excluding malicious
                    selected = 1 if cid <= 7 else 0
                    if is_mal and not is_bl:
                        selected = 1  # bulyan fails to exclude
                    reason = None if selected else "krum_distance_outlier"
                elif strategy in ("fltrust", "mab-rfl"):
                    if is_bl:
                        selected = 1
                        reason = None
                    elif is_mal and r > 10:
                        selected = 1 if random.random() < 0.3 else 0
                        reason = None if selected else "low_trust_score"
                    elif is_mal:
                        selected = 1 if random.random() < 0.6 else 0
                        reason = None if selected else "low_trust_score"
                    else:
                        selected = 1
                        reason = None
                else:
                    selected = 1
                    reason = None

                rows.append((rid, r, cid, strategy, selected, is_mal, reason))

    conn.executemany(
        "INSERT INTO defense_selection VALUES (?,?,?,?,?,?,?)", rows,
    )


def insert_baseline_comparisons(conn, run_ids):
    """Pair each attacked run with its baseline and compute drops."""
    pairs = {}
    for rid, strategy, is_bl in run_ids:
        pairs.setdefault(strategy, {})
        if is_bl:
            pairs[strategy]["baseline"] = rid
        else:
            pairs[strategy]["attacked"] = rid

    rows = []
    for strategy, p in pairs.items():
        if "baseline" not in p or "attacked" not in p:
            continue
        bl_id = p["baseline"]
        atk_id = p["attacked"]

        # Fetch final round metrics
        cur = conn.cursor()

        def _get_final(run_id, metric):
            cur.execute(
                "SELECT metric_value FROM round_metrics WHERE run_id=? AND round=30 AND metric_name=?",
                (run_id, metric),
            )
            row = cur.fetchone()
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

        acc_drop = round(bl_acc - atk_acc, 6) if bl_acc and atk_acc else None
        acc_ret = round(atk_acc / bl_acc, 6) if bl_acc and atk_acc and bl_acc > 0 else None
        f1m_drop = round(bl_f1m - atk_f1m, 6) if bl_f1m and atk_f1m else None
        f1w_drop = round(bl_f1w - atk_f1w, 6) if bl_f1w and atk_f1w else None
        asr_inc = round(atk_asr - bl_asr, 6) if atk_asr and bl_asr else None
        loss_inc = round(atk_loss - bl_loss, 6) if atk_loss and bl_loss else None
        collapse = 1 if atk_acc and atk_acc < 0.05 else 0

        rows.append((
            f"cmp_{_uid()}", atk_id, bl_id, strategy,
            bl_acc, atk_acc, acc_drop, acc_ret,
            bl_f1m, atk_f1m, f1m_drop,
            bl_f1w, atk_f1w, f1w_drop,
            bl_asr, atk_asr, asr_inc,
            bl_loss, atk_loss, loss_inc,
            collapse, 0,  # no recovery detected in dummy
            1, 1, 0, 1,
        ))

    conn.executemany(
        """INSERT INTO baseline_comparisons VALUES
           (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )


def insert_agent_recommendations(conn, run_ids):
    recs = [
        ("bulyan", "alie", 0.85, 0.9, 0.7, 0.82,
         '{"strategy":"bulyan","attack_mode":"adaptive","layering_mode":"single","attack":"alie","seeds":[1337,42,7]}',
         "Bulyan collapsed under adaptive ALIE within 10 rounds. ALIE evades Bulyan's coordinate-wise "
         "trimming by staying within the honest distribution. Recommend multi-seed replication."),
        ("fltrust", "sign_flip", 0.4, 0.6, 0.5, 0.5,
         '{"strategy":"fltrust","attack_mode":"adaptive","selection_mode":"sticky","attack":"sign_flip","seeds":[1337,42,7]}',
         "FLTrust showed moderate degradation under sign_flip with sticky scheduling. "
         "Cosine similarity to root may be partially bypassed by direction-aligned flips."),
        ("mab-rfl", "gaussian_noise+sign_flip", 0.6, 0.7, 0.4, 0.55,
         '{"strategy":"mab-rfl","attack_mode":"weighted_random","layering_mode":"sample_k","seeds":[1337,42,7]}',
         "MAB-RFL reputation scores failed to separate malicious and benign clients under layered "
         "attacks with churn scheduling. Churn resets reputation history."),
    ]
    for strategy, attack, weakness, effectiveness, evidence, priority, config, rationale in recs:
        atk_run = None
        for rid, s, is_bl in run_ids:
            if s == strategy and not is_bl:
                atk_run = rid
                break
        conn.execute(
            """INSERT INTO agent_recommendations VALUES
               (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (f"rec_{_uid()}", "2026-05-22T12:00:00", atk_run,
             strategy, attack, "flwrlabs/femnist",
             "adaptive" if strategy != "mab-rfl" else "weighted_random",
             "churn" if strategy != "fltrust" else "sticky",
             "single" if strategy != "mab-rfl" else "sample_k",
             weakness, effectiveness, evidence, priority,
             config, rationale),
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_dummy_database():
    print(f"Creating database at {DB_PATH}")
    conn = create_database()

    print("  Inserting sweep...")
    sweep_id = insert_sweep(conn)

    print("  Inserting runs...")
    run_ids = insert_runs(conn, sweep_id)

    print("  Inserting run config...")
    insert_run_config(conn, run_ids)

    print("  Inserting round metrics...")
    insert_round_metrics(conn, run_ids)

    print("  Inserting client metrics...")
    insert_client_metrics(conn, run_ids)

    print("  Inserting attack events...")
    insert_attack_events(conn, run_ids)

    print("  Inserting adaptive attack scores...")
    insert_adaptive_attack_scores(conn, run_ids)

    print("  Inserting client attack events...")
    insert_client_attack_events(conn, run_ids)

    print("  Inserting trust metrics...")
    insert_trust_metrics(conn, run_ids)

    print("  Inserting defense selection...")
    insert_defense_selection(conn, run_ids)

    print("  Computing baseline comparisons...")
    insert_baseline_comparisons(conn, run_ids)

    print("  Inserting agent recommendations...")
    insert_agent_recommendations(conn, run_ids)

    conn.commit()

    # Print summary
    cur = conn.cursor()
    tables = cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    print(f"\nDatabase created with {len(tables)} tables:")
    for (t,) in tables:
        count = cur.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
        print(f"  {t:30s} {count:>6} rows")

    conn.close()
    print(f"\nDone. Database: {DB_PATH}")
    return str(DB_PATH)


if __name__ == "__main__":
    build_dummy_database()
