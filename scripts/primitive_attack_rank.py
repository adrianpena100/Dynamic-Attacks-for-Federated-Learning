import json
from pathlib import Path

import pandas as pd


base = Path("/Users/adrianpena/Documents/Thesis/Experimental/dynamic_fl/logs/sweeps")
rows = []

for sweep in base.glob("*_thesis_full__2026-03-05_15-38-03"):
    strat = sweep.name.split("_thesis_full__")[0]
    settings_path = sweep / "sweep_settings.csv"
    if not settings_path.exists():
        continue

    settings = pd.read_csv(settings_path)
    if "label" not in settings.columns:
        continue

    for _, srow in settings.iterrows():
        run_label = str(srow["label"])
        run_folder = srow.get("run_folder")
        if isinstance(run_folder, str) and run_folder:
            run_dir = sweep / run_folder
            if not run_dir.exists():
                run_dirs = [p for p in sweep.glob(f"{run_label}__*") if p.is_dir()]
                if not run_dirs:
                    continue
                run_dir = max(run_dirs, key=lambda p: p.stat().st_mtime)
        else:
            run_dirs = [p for p in sweep.glob(f"{run_label}__*") if p.is_dir()]
            if not run_dirs:
                continue
            run_dir = max(run_dirs, key=lambda p: p.stat().st_mtime)

        summary_json = run_dir / "summaries" / "run_config_and_summary.json"
        final_acc = None
        final_asr = None

        if summary_json.exists():
            try:
                obj = json.loads(summary_json.read_text())
                final_acc = obj.get("final_acc")
                final_asr = obj.get("final_asr")
                if final_acc is None:
                    final_acc = obj.get("summary", {}).get("final_acc")
                if final_asr is None:
                    final_asr = obj.get("summary", {}).get("final_asr")
            except Exception:
                pass

        mdir = run_dir / "metrics"
        if final_acc is None and (mdir / "evaluate_server__accuracy.csv").exists():
            try:
                df_acc = pd.read_csv(mdir / "evaluate_server__accuracy.csv")
                if len(df_acc):
                    final_acc = float(df_acc.iloc[-1]["value"])
            except Exception:
                pass
        if final_asr is None and (mdir / "evaluate_server__backdoor_asr.csv").exists():
            try:
                df_asr = pd.read_csv(mdir / "evaluate_server__backdoor_asr.csv")
                if len(df_asr):
                    final_asr = float(df_asr.iloc[-1]["value"])
            except Exception:
                pass

        attacks = set()
        attack_file = run_dir / "summaries" / "attack_log.jsonl"
        if attack_file.exists():
            with attack_file.open("r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue

                    name = rec.get("attack_name")
                    if name and name != "none":
                        attacks.add(name)
                    details = rec.get("attack_details") or {}
                    dname = details.get("attack_name")
                    if dname and dname != "none":
                        attacks.add(dname)

        if not attacks:
            attacks = {"none"}

        for aname in sorted(attacks):
            rows.append(
                {
                    "strategy": strat,
                    "run_label": run_label,
                    "attack_name": aname,
                    "final_acc": final_acc,
                    "final_asr": final_asr,
                }
            )

out = pd.DataFrame(rows)
if out.empty:
    print("NO_ROWS")
    raise SystemExit(0)

prim = out[out["attack_name"] != "none"].copy()
print("rows_total", len(out), "rows_primitive", len(prim))
print("distinct_attacks", sorted(prim["attack_name"].dropna().unique().tolist()))

if prim.empty:
    print("NO_PRIMITIVE_ATTACKS_FOUND")
    raise SystemExit(0)

run_level = prim.dropna(subset=["final_acc"]).copy()

agg = (
    run_level.groupby("attack_name", as_index=False)
    .agg(
        runs=("run_label", "nunique"),
        mean_final_acc=("final_acc", "mean"),
        median_final_acc=("final_acc", "median"),
        min_final_acc=("final_acc", "min"),
        mean_final_asr=("final_asr", "mean"),
    )
    .sort_values(["mean_final_acc", "median_final_acc", "min_final_acc"])
)

print("\nTop primitives by LOWEST mean final_acc (most damaging):")
print(agg.head(15).to_string(index=False))

best_run = run_level.sort_values("final_acc").head(15)
print("\nTop runs (lowest final_acc) with primitive attack names:")
print(best_run[["strategy", "run_label", "attack_name", "final_acc", "final_asr"]].to_string(index=False))

out_path = base / "primitive_attack_summary.csv"
agg_path = base / "primitive_attack_ranking.csv"
out.to_csv(out_path, index=False)
agg.to_csv(agg_path, index=False)
print("\nWROTE", out_path)
print("WROTE", agg_path)
