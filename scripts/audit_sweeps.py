#!/usr/bin/env python3
"""
Audit one sweep directory and produce the standard experiment CSV set.

Usage:
    python scripts/audit_sweeps.py --dataset femnist
    python scripts/audit_sweeps.py --dataset cifar100

Outputs land in analysis/sep16/ (femnist) or analysis/sep21/ (cifar100).
Files produced:
    experiment_audit.csv      one row per run
    fixed_attack_matrix.csv   defense x attack x seed metrics
    mab_arm_summary.csv       per MAB run arm-selection shares
    multi_metric_summary.csv  per run final metrics
    cohort_summary.csv        per MAB run cohort-churn stats
"""
import argparse
import csv
import glob
import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))

ATTACKS = ["gaussian_noise", "sign_flip", "label_flip", "backdoor", "alie", "mean_shift"]
SCHEDULES = ["sticky", "random", "churn"]

FIXED_MAP = {
    "GAUSSIAN": "gaussian_noise", "SIGN_FLIP": "sign_flip",
    "LABEL_FLIP": "label_flip", "BACKDOOR": "backdoor",
    "ALIE": "alie", "MEAN_SHIFT": "mean_shift",
}

DATASET_CONFIG = {
    "femnist": {
        "src": os.path.join(REPO, "logs", "sweeps", "sep16sweeps"),
        "out": os.path.join(REPO, "analysis", "sep16"),
        "chance": 1.0 / 62,
        "expected_rounds": 50,
        "min_valid_rounds": 45,
        "glob_pattern": "*_fixed_vs_mab_full__*",
        "label": "femnist",
    },
    "cifar100": {
        "src": os.path.join(REPO, "logs", "sweeps", "sep21sweeps"),
        "out": os.path.join(REPO, "analysis", "sep21"),
        "chance": 1.0 / 100,
        "expected_rounds": 100,
        "min_valid_rounds": 90,
        "glob_pattern": "*_fixed_vs_mab_cifar100__*",
        "label": "cifar100",
    },
}


# ------------------------------------------------------------------ helpers

def read_series(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path) as f:
        r = csv.DictReader(f)
        cols = r.fieldnames or []
        if not cols:
            return []
        rc = "round" if "round" in cols else cols[0]
        vc = "value" if "value" in cols else (cols[1] if len(cols) > 1 else cols[0])
        for row in r:
            try:
                out.append((int(float(row[rc])), float(row[vc])))
            except (ValueError, TypeError, KeyError):
                continue
    return out


def final_of(series):
    return series[-1][1] if series else None


def parse_condition(folder):
    base = os.path.basename(folder)
    if base.startswith("BASELINE"):
        return "baseline", "", ""
    if base.startswith("FIXED_"):
        tok = base.split("__", 1)[0][len("FIXED_"):]
        return "fixed", FIXED_MAP.get(tok, tok.lower()), ""
    if base.startswith("MAB_ADAPTIVE_"):
        tok = base.split("__", 1)[0][len("MAB_ADAPTIVE_"):]
        return "mab", "", tok.lower()
    return "other", "", ""


def load_meta(rundir):
    p = os.path.join(rundir, "meta.json")
    if not os.path.exists(p):
        return {}
    try:
        m = json.load(open(p))
    except Exception:
        return {}
    return m.get("resolved_config_for_naming", {}) or {}


def metric_final(rundir, name):
    return final_of(read_series(os.path.join(rundir, "metrics", f"evaluate_server__{name}.csv")))


def timeline_arms(cond):
    p = os.path.join(cond, "summaries", "attack_timeline.csv")
    if not os.path.exists(p):
        return []
    seq = []
    with open(p) as f:
        for row in csv.DictReader(f):
            a = row.get("attack_name", "").strip()
            if a and a != "-":
                try:
                    seq.append((int(float(row["round"])), a))
                except (ValueError, KeyError):
                    pass
    seq.sort()
    return [a for _, a in seq]


def warmup_cutoff(seq):
    seen = set()
    for i, a in enumerate(seq, 1):
        seen.add(a)
        if len(seen) >= len(set(seq)):
            return i
    return len(seq)


def bandit_final_values(cond):
    p = os.path.join(cond, "summaries", "adaptive_bandit_state.csv")
    if not os.path.exists(p):
        return {}
    rows_ = list(csv.DictReader(open(p)))
    if not rows_:
        return {}
    last = max(int(float(x["round"])) for x in rows_)
    out = {}
    for x in rows_:
        if int(float(x["round"])) == last:
            try:
                out[x["attack_name"]] = (float(x["estimated_value"]), int(float(x["times_selected"])))
            except (ValueError, KeyError):
                pass
    return out


def cohort_churn(cond):
    p = os.path.join(cond, "summaries", "malicious_clients_by_round.csv")
    if not os.path.exists(p):
        return "", ""
    sets = []
    with open(p) as f:
        for row in csv.DictReader(f):
            for k in row:
                if "client" in k and ("number" in k or "id" in k):
                    raw = row[k]
                    if raw and raw not in ("-", ""):
                        parts = [x for x in raw.replace(";", ",").replace("|", ",").split(",") if x.strip()]
                        sets.append(frozenset(p.strip() for p in parts))
                        break
    if len(sets) < 2:
        return "", len(sets)
    j = []
    for a, b in zip(sets, sets[1:]):
        if a or b:
            j.append(len(a & b) / len(a | b))
    return (round(sum(j) / len(j), 4) if j else ""), len(sets)


# ------------------------------------------------------------------ main audit

def run_audit(dataset):
    cfg = DATASET_CONFIG[dataset]
    SRC = cfg["src"]
    OUT = cfg["out"]
    CHANCE = cfg["chance"]
    EXPECTED_ROUNDS = cfg["expected_rounds"]
    MIN_VALID_ROUNDS = cfg["min_valid_rounds"]
    NEAR_ZERO = 0.05

    os.makedirs(OUT, exist_ok=True)

    rows = []

    top = sorted(glob.glob(os.path.join(SRC, cfg["glob_pattern"])))
    if not top:
        print(f"[WARN] No sweep dirs found matching {cfg['glob_pattern']} in {SRC}", file=sys.stderr)

    for topdir in top:
        defense = os.path.basename(topdir).split("_fixed_vs_mab_", 1)[0]
        dated = os.path.basename(topdir).split("__", 1)[1] if "__" in os.path.basename(topdir) else ""
        for cond in sorted(glob.glob(os.path.join(topdir, "*", ""))):
            cond = cond.rstrip("/")
            if not os.path.isdir(cond):
                continue
            run_type, fixed_attack, cohort = parse_condition(cond)
            if run_type == "other":
                continue
            meta = load_meta(cond)
            seed = str(meta.get("attack-seed", ""))
            acc = read_series(os.path.join(cond, "metrics", "evaluate_server__accuracy.csv"))
            completed = len(acc)
            final_acc = final_of(acc)
            min_acc = min((v for _, v in acc), default=None)

            row = {
                "source_path": cond,
                "defense": defense,
                "dated_dir": dated,
                "seed": seed,
                "run_type": run_type,
                "fixed_attack": fixed_attack,
                "cohort_schedule": cohort,
                "attack_mode": meta.get("attack-mode", ""),
                "attack_selection_mode": meta.get("attack-selection-mode", ""),
                "malicious_fraction": meta.get("attack-malicious-fraction", ""),
                "completed_rounds": completed,
                "final_accuracy": final_acc,
                "min_accuracy": min_acc,
                "final_f1_macro": metric_final(cond, "f1_macro"),
                "final_recall_macro": metric_final(cond, "recall_macro"),
                "final_precision_macro": metric_final(cond, "precision_macro"),
                "final_loss": metric_final(cond, "loss"),
                "final_backdoor_asr": metric_final(cond, "backdoor_asr"),
                "near_zero": (final_acc is not None and final_acc < NEAR_ZERO),
                "incomplete": (0 < completed < EXPECTED_ROUNDS),
                "has_bandit_state": os.path.exists(os.path.join(cond, "summaries", "adaptive_bandit_state.csv")),
                "has_timeline": os.path.exists(os.path.join(cond, "summaries", "attack_timeline.csv")),
            }

            reasons = []
            if completed == 0:
                reasons.append("no_accuracy_series")
            elif completed < MIN_VALID_ROUNDS:
                reasons.append(f"too_short_{completed}r")
            if seed == "":
                reasons.append("no_seed_in_meta")
            row["valid"] = (len(reasons) == 0)
            row["invalid_reason"] = ";".join(reasons)
            rows.append(row)

    # baseline lookup + acc_drop_pp
    baseline = {}
    for r in rows:
        if r["run_type"] == "baseline" and r["valid"]:
            baseline[(r["defense"], r["seed"])] = r

    for r in rows:
        b = baseline.get((r["defense"], r["seed"]))
        if b and r["final_accuracy"] is not None and b["final_accuracy"] is not None:
            r["baseline_accuracy"] = b["final_accuracy"]
            r["acc_drop_pp"] = 100.0 * (b["final_accuracy"] - r["final_accuracy"])
            r["f1_drop"] = (
                (b["final_f1_macro"] - r["final_f1_macro"])
                if (b["final_f1_macro"] is not None and r["final_f1_macro"] is not None)
                else ""
            )
        else:
            r["baseline_accuracy"] = ""
            r["acc_drop_pp"] = ""
            r["f1_drop"] = ""

    # experiment_audit.csv
    AUDIT_COLS = [
        "source_path", "defense", "dated_dir", "seed", "run_type",
        "fixed_attack", "cohort_schedule", "attack_mode", "attack_selection_mode",
        "malicious_fraction", "completed_rounds", "valid", "invalid_reason",
        "baseline_accuracy", "final_accuracy", "min_accuracy", "acc_drop_pp",
        "final_f1_macro", "f1_drop", "final_recall_macro", "final_precision_macro",
        "final_loss", "final_backdoor_asr", "near_zero", "incomplete",
        "has_bandit_state", "has_timeline",
    ]
    with open(os.path.join(OUT, "experiment_audit.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=AUDIT_COLS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

    valid = [r for r in rows if r["valid"]]

    # multi_metric_summary.csv
    with open(os.path.join(OUT, "multi_metric_summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "source_path", "defense", "seed", "run_type",
            "fixed_attack", "cohort_schedule",
            "final_accuracy", "final_f1_macro", "final_recall_macro",
            "final_precision_macro", "final_loss", "final_backdoor_asr",
        ], extrasaction="ignore")
        w.writeheader()
        for r in valid:
            w.writerow(r)

    # fixed_attack_matrix.csv
    with open(os.path.join(OUT, "fixed_attack_matrix.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["defense", "seed", "fixed_attack", "final_accuracy", "acc_drop_pp",
                    "final_f1_macro", "final_loss", "final_backdoor_asr", "source_path"])
        for r in valid:
            if r["run_type"] == "fixed":
                w.writerow([r["defense"], r["seed"], r["fixed_attack"], r["final_accuracy"],
                            r["acc_drop_pp"], r["final_f1_macro"], r["final_loss"],
                            r["final_backdoor_asr"], r["source_path"]])

    # mab_arm_summary.csv
    with open(os.path.join(OUT, "mab_arm_summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        header = ["defense", "seed", "cohort_schedule", "n_rounds", "warmup_len",
                  "top_arm_all", "top_arm_postwarmup", "top_arm_by_value"]
        header += [f"share_all__{a}" for a in ATTACKS]
        header += [f"share_post__{a}" for a in ATTACKS]
        header += [f"value__{a}" for a in ATTACKS]
        header += ["source_path"]
        w.writerow(header)
        for r in valid:
            if r["run_type"] != "mab":
                continue
            cond = r["source_path"]
            seq = timeline_arms(cond)
            if not seq:
                continue
            wl = warmup_cutoff(seq)
            post = seq[wl:]
            c_all = Counter(seq)
            c_post = Counter(post)
            vals = bandit_final_values(cond)
            n = len(seq)
            share_all = {a: c_all.get(a, 0) / n for a in ATTACKS}
            share_post = {a: (c_post.get(a, 0) / len(post) if post else 0.0) for a in ATTACKS}
            top_all = max(ATTACKS, key=lambda a: share_all[a])
            top_post = max(ATTACKS, key=lambda a: share_post[a]) if post else ""
            top_val = max(vals, key=lambda a: vals[a][0]) if vals else ""
            rowout = [r["defense"], r["seed"], r["cohort_schedule"], n, wl,
                      top_all, top_post, top_val]
            rowout += [round(share_all[a], 4) for a in ATTACKS]
            rowout += [round(share_post[a], 4) for a in ATTACKS]
            rowout += [(round(vals[a][0], 4) if a in vals else "") for a in ATTACKS]
            rowout += [cond]
            w.writerow(rowout)

    # cohort_summary.csv
    with open(os.path.join(OUT, "cohort_summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["defense", "seed", "cohort_schedule", "mean_consecutive_jaccard",
                    "n_cohort_rounds", "final_accuracy", "acc_drop_pp", "source_path"])
        for r in valid:
            if r["run_type"] == "mab":
                jac, nr = cohort_churn(r["source_path"])
                w.writerow([r["defense"], r["seed"], r["cohort_schedule"], jac, nr,
                            r["final_accuracy"], r["acc_drop_pp"], r["source_path"]])

    # summary report
    invalid = [r for r in rows if not r["valid"]]
    by_type = Counter(r["run_type"] for r in valid)
    defenses = sorted(set(r["defense"] for r in rows))

    print(f"\n{'='*60}")
    print(f"AUDIT: {dataset.upper()}  ({cfg['label']})")
    print(f"{'='*60}")
    print(f"  total dirs parsed : {len(rows)}")
    print(f"  valid (>={MIN_VALID_ROUNDS}r, seed known): {len(valid)}")
    print(f"  invalid/incomplete: {len(invalid)}")
    print(f"  by type: {dict(sorted(by_type.items()))}")
    print(f"\n  Per-defense (valid baseline/fixed/mab ; invalid):")
    for d in defenses:
        dv = [r for r in valid if r["defense"] == d]
        di = [r for r in invalid if r["defense"] == d]
        seeds = sorted(set(r["seed"] for r in dv if r["seed"]))
        print(f"    {d:<14} base={sum(1 for r in dv if r['run_type']=='baseline')} "
              f"fixed={sum(1 for r in dv if r['run_type']=='fixed'):2d} "
              f"mab={sum(1 for r in dv if r['run_type']=='mab'):2d}  "
              f"invalid={len(di):2d}  seeds={{{','.join(seeds)}}}")

    print(f"\n  Files written to {OUT}:")
    for fn in ["experiment_audit.csv", "multi_metric_summary.csv",
               "fixed_attack_matrix.csv", "mab_arm_summary.csv", "cohort_summary.csv"]:
        p = os.path.join(OUT, fn)
        n = sum(1 for _ in open(p)) - 1
        print(f"    {fn:<30} rows={n}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["femnist", "cifar100"], required=True)
    args = parser.parse_args()
    run_audit(args.dataset)
