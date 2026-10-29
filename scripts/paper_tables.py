#!/usr/bin/env python3
"""Aggregate the audit CSVs in analysis/sep16 and analysis/sep21 into clean,
table-ready numbers for the paper. Every number printed here comes straight from
experiment_audit.csv (one row per run) so tables can only contain real values.

Usage: python3.9 scripts/paper_tables.py
"""
import csv, os, statistics as st
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFENSES = ["multikrum","fedtrimmedavg","fedmedian","foolsgold","flram","mab-rfl","bulyan","fltrust"]
ATTACKS  = ["gaussian_noise","sign_flip","label_flip","backdoor","alie","mean_shift"]
SCHEDULES = ["sticky","churn","random","per_round_random"]

def load(ds):
    p = os.path.join(ROOT,"analysis",ds,"experiment_audit.csv")
    rows=[]
    with open(p) as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows

def fnum(x):
    try: return float(x)
    except: return None

def norm_sched(s):
    if s in ("per_round_random","random"): return "random"
    return s

def summarize(ds, label):
    rows = load(ds)
    print("="*78)
    print(f"{label}  ({ds})   total rows={len(rows)}")
    print("="*78)
    # validity counts
    valid = [r for r in rows if r.get("valid","").lower()=="true"]
    print(f"valid rows={len(valid)}  invalid={len(rows)-len(valid)}")
    by_type=defaultdict(int)
    for r in valid: by_type[r["run_type"]]+=1
    print("valid by run_type:", dict(by_type))
    print()

    # --- baselines per defense (mean clean accuracy across seeds) ---
    print("--- CLEAN BASELINE accuracy per defense (mean [min,max] across seeds) ---")
    base=defaultdict(list)
    for r in valid:
        if r["run_type"]=="baseline":
            a=fnum(r["final_accuracy"])
            if a is not None: base[r["defense"]].append((r["seed"],a))
    for d in DEFENSES:
        if base[d]:
            vals=[a for _,a in base[d]]
            seeds=",".join(s for s,_ in base[d])
            print(f"  {d:14} n={len(vals)} mean={st.mean(vals):.4f} range=[{min(vals):.4f},{max(vals):.4f}] seeds={seeds}")
    print()

    # --- fixed-attack damage matrix: defense x attack -> mean acc_drop_pp across seeds ---
    print("--- FIXED-ATTACK mean damage (acc_drop_pp), averaged across seeds ---")
    cell=defaultdict(list)
    for r in valid:
        if r["run_type"]=="fixed":
            dmg=fnum(r["acc_drop_pp"]);
            if dmg is not None: cell[(r["defense"],r["fixed_attack"])].append(dmg)
    hdr="  {:14}".format("defense")+"".join(f"{a[:9]:>10}" for a in ATTACKS)+f"{'BEST':>18}"
    print(hdr)
    for d in DEFENSES:
        if not any((d,a) in cell for a in ATTACKS): continue
        line="  {:14}".format(d)
        best=None
        for a in ATTACKS:
            v=cell.get((d,a))
            if v:
                m=st.mean(v); line+=f"{m:>10.1f}"
                if best is None or m>best[1]: best=(a,m)
            else:
                line+=f"{'--':>10}"
        line+=f"{(best[0]+' '+format(best[1],'.1f')):>18}" if best else f"{'--':>18}"
        print(line)
    print()

    # --- adaptive damage: defense x schedule -> mean acc_drop_pp ---
    print("--- ADAPTIVE (bandit) mean damage (acc_drop_pp) by cohort schedule ---")
    acell=defaultdict(list)
    for r in valid:
        if r["run_type"]=="adaptive" or r["attack_mode"]=="adaptive":
            dmg=fnum(r["acc_drop_pp"])
            sch=norm_sched(r["cohort_schedule"])
            if dmg is not None: acell[(r["defense"],sch)].append(dmg)
    print("  {:14}{:>10}{:>10}{:>10}{:>18}".format("defense","sticky","churn","random","BEST-sched"))
    for d in DEFENSES:
        if not any((d,s) in acell for s in ["sticky","churn","random"]): continue
        line="  {:14}".format(d); best=None
        for s in ["sticky","churn","random"]:
            v=acell.get((d,s))
            if v:
                m=st.mean(v); line+=f"{m:>10.1f}"
                if best is None or m>best[1]: best=(s,m)
            else: line+=f"{'--':>10}"
        line+=f"{(best[0]+' '+format(best[1],'.1f')):>18}" if best else f"{'--':>18}"
        print(line)
    print()

    # --- per-seed detail for adaptive (shows seed variability) ---
    print("--- ADAPTIVE per-seed final_accuracy (shows seed spread) ---")
    seedcell=defaultdict(dict)
    for r in valid:
        if r["run_type"]=="adaptive" or r["attack_mode"]=="adaptive":
            a=fnum(r["final_accuracy"]); sch=norm_sched(r["cohort_schedule"])
            if a is not None: seedcell[(r["defense"],sch)][r["seed"]]=a
    for d in DEFENSES:
        for s in ["sticky","churn","random"]:
            if (d,s) in seedcell:
                dd=seedcell[(d,s)]
                print(f"  {d:14} {s:8} " + " ".join(f"{k}={v:.3f}" for k,v in sorted(dd.items())))
    print()

    # --- collapse counts (<5% final acc) ---
    coll=defaultdict(int); tot=defaultdict(int)
    for r in valid:
        a=fnum(r["final_accuracy"])
        if a is None: continue
        tot[r["run_type"]]+=1
        if a<0.05: coll[r["run_type"]]+=1
    print("--- COLLAPSE counts (final_accuracy < 5%) by run_type ---")
    for t in ["baseline","fixed","adaptive"]:
        print(f"  {t:10} {coll[t]}/{tot[t]}")
    print()

for ds,label in [("sep16","FEMNIST"),("sep21","CIFAR-100")]:
    summarize(ds,label)
