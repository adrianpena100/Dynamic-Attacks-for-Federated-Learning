#!/usr/bin/env python3
"""Extract VERIFIED mechanistic series from the raw sep16 (FEMNIST) logs so the
paper's figures and tables share one real source. Writes CSVs to
analysis/mechanistic/ and prints a summary. Nothing here is hardcoded or
estimated: every value is read from a run artifact.

Run:  python3.9 scripts/paper_mechanistic.py
"""
import os, csv, glob, json, re
from collections import defaultdict, Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEP16 = os.path.join(ROOT, "logs", "sweeps", "sep16sweeps")
OUT = os.path.join(ROOT, "analysis", "mechanistic")
os.makedirs(OUT, exist_ok=True)

ARMS = ["gaussian_noise","sign_flip","label_flip","backdoor","alie","mean_shift"]

def seed_of(rundir):
    try:
        d = json.load(open(os.path.join(rundir,"meta.json")))
        m = re.search(r"attack-seed=?\s*[\"']?(\d+)", str(d))
        return m.group(1) if m else "?"
    except Exception:
        return "?"

def folders(defense):
    return sorted(glob.glob(os.path.join(SEP16, f"{defense}_fixed_vs_mab_full__*")))

def find_run(defense, cond_prefix, want_seed=None):
    """Return (rundir, seed) for the first run matching cond_prefix (optionally seed)."""
    hits=[]
    for fdr in folders(defense):
        for rd in glob.glob(os.path.join(fdr, f"{cond_prefix}*")):
            if os.path.isdir(rd):
                hits.append((rd, seed_of(rd)))
    if want_seed:
        for rd,s in hits:
            if s==want_seed: return rd,s
    return hits[0] if hits else (None,None)

def read_rounds_csv(path, rcol="round", vcols=None):
    rows=[]
    if not path or not os.path.exists(path): return rows
    with open(path) as f:
        rd=csv.DictReader(f)
        for row in rd:
            rows.append(row)
    return rows

# ---------------------------------------------------------------- 1. NORMS
def extract_norms():
    """FedTrimmedAvg seed-42: honest vs malicious update norms per round."""
    print("\n### 1. FedTrimmedAvg update norms (seed 42) ###")
    out_rows=[]
    for attack,cond in [("alie","FIXED_ALIE"),("gaussian","FIXED_GAUSSIAN")]:
        rd,seed = find_run("fedtrimmedavg", cond, want_seed="42")
        stats = os.path.join(rd,"summaries","round_attack_stats.csv") if rd else None
        rows = read_rounds_csv(stats)
        print(f"  {cond} seed={seed} rows={len(rows)} file={stats}")
        for r in rows:
            try:
                rnd=int(float(r["round"]))
                out_rows.append({
                    "attack":attack,"round":rnd,
                    "honest_p50":float(r["honest_norm_p50"]),
                    "honest_max":float(r["honest_norm_max"]),
                    "mal_pre":float(r["max_mal_norm_pre"]),
                    "mal_post":float(r["max_mal_norm_post"]),
                })
            except Exception:
                continue
    with open(os.path.join(OUT,"fedtrimmedavg_norms.csv"),"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["attack","round","honest_p50","honest_max","mal_pre","mal_post"])
        w.writeheader(); w.writerows(out_rows)
    # print representative rows (skip r1 init outlier)
    for attack in ("alie","gaussian"):
        sel=[r for r in out_rows if r["attack"]==attack and r["round"] in (2,10,25,50)]
        for r in sel:
            print(f"    {attack:8} r{r['round']:<3} honest_p50={r['honest_p50']:.1f} "
                  f"honest_max={r['honest_max']:.1f} mal_pre={r['mal_pre']:.1f} mal_post={r['mal_post']:.1f}")
    return out_rows

# ---------------------------------------------------------------- 2. TRUST
def extract_trust():
    """FoolsGold aggregate trust (avg/min/max) per round, each schedule."""
    print("\n### 2. FoolsGold trust trajectory ###")
    out_rows=[]
    for sched,cond in [("sticky","MAB_ADAPTIVE_STICKY"),("churn","MAB_ADAPTIVE_CHURN"),("random","MAB_ADAPTIVE_RANDOM")]:
        # prefer the seed with the most rounds of trust logging
        best=None
        for fdr in folders("foolsgold"):
            for rd in glob.glob(os.path.join(fdr, f"{cond}*")):
                if not os.path.isdir(rd): continue
                avg=os.path.join(rd,"metrics","evaluate_client__foolsgold_avg_trust.csv")
                mn =os.path.join(rd,"metrics","evaluate_client__foolsgold_min_trust.csv")
                mx =os.path.join(rd,"metrics","evaluate_client__foolsgold_max_trust.csv")
                rows=read_rounds_csv(avg)
                if best is None or len(rows)>len(best[1]):
                    best=(rd,rows,mn,mx,seed_of(rd),avg)
        if not best:
            print(f"  {sched}: NO trust files"); continue
        rd,rows,mn,mx,seed,avgpath=best
        mnrows={int(float(r['round'])):float(r['value']) for r in read_rounds_csv(mn) if r.get('value') not in (None,'')}
        mxrows={int(float(r['round'])):float(r['value']) for r in read_rounds_csv(mx) if r.get('value') not in (None,'')}
        print(f"  {sched} seed={seed} rounds_logged={len(rows)} file={avgpath}")
        for r in rows:
            try:
                rnd=int(float(r["round"])); v=float(r["value"])
            except Exception:
                continue
            out_rows.append({"schedule":sched,"seed":seed,"round":rnd,"avg_trust":v,
                             "min_trust":mnrows.get(rnd,""),"max_trust":mxrows.get(rnd,"")})
    with open(os.path.join(OUT,"foolsgold_trust.csv"),"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["schedule","seed","round","avg_trust","min_trust","max_trust"])
        w.writeheader(); w.writerows(out_rows)
    # print summary (first/last logged value per schedule)
    for sched in ("sticky","churn","random"):
        s=[r for r in out_rows if r["schedule"]==sched]
        if s:
            print(f"    {sched:7} avg_trust r{s[0]['round']}={s[0]['avg_trust']:.3f} ... "
                  f"r{s[-1]['round']}={s[-1]['avg_trust']:.3f}  (min seen={min(r['avg_trust'] for r in s):.3f})")
    return out_rows

# ---------------------------------------------------------------- 3. ARM SHARES
def extract_arm_shares():
    """Per defense x schedule: attack-selection distribution, aggregated across seeds."""
    print("\n### 3. Bandit arm shares (aggregated across seeds) ###")
    defenses=["multikrum","fedtrimmedavg","fedmedian","foolsgold","mab-rfl"]
    out_rows=[]
    for d in defenses:
        for sched,cond in [("sticky","MAB_ADAPTIVE_STICKY"),("churn","MAB_ADAPTIVE_CHURN"),("random","MAB_ADAPTIVE_RANDOM")]:
            counts=Counter(); total=0; seeds=set()
            for fdr in folders(d):
                for rd in glob.glob(os.path.join(fdr, f"{cond}*")):
                    tl=os.path.join(rd,"summaries","attack_timeline.csv")
                    rows=read_rounds_csv(tl)
                    if not rows: continue
                    seeds.add(seed_of(rd))
                    for r in rows:
                        a=(r.get("attack_name") or "").strip()
                        if a and a!="-" and a!="none":
                            counts[a]+=1; total+=1
            if total==0:
                continue
            dom,domc=counts.most_common(1)[0]
            out_rows.append({"defense":d,"schedule":sched,"dominant_arm":dom,
                             "dominant_share":round(domc/total,3),"total_rounds":total,
                             "n_seeds":len(seeds),
                             **{f"share_{a}":round(counts.get(a,0)/total,3) for a in ARMS}})
            print(f"  {d:14} {sched:7} dom={dom:14} share={domc/total:.2f} "
                  f"(n_rounds={total}, seeds={len(seeds)})")
    with open(os.path.join(OUT,"arm_shares.csv"),"w",newline="") as f:
        cols=["defense","schedule","dominant_arm","dominant_share","total_rounds","n_seeds"]+[f"share_{a}" for a in ARMS]
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader(); w.writerows(out_rows)
    return out_rows

# ---------------------------------------------------------------- 4. MULTIKRUM BANDIT
def extract_multikrum_bandit():
    """Multi-Krum seed-42 adaptive-sticky: final per-arm estimated value + count."""
    print("\n### 4. Multi-Krum bandit final state (seed 42, adaptive sticky) ###")
    rd,seed=find_run("multikrum","MAB_ADAPTIVE_STICKY",want_seed="42")
    bs=os.path.join(rd,"summaries","adaptive_bandit_state.csv") if rd else None
    rows=read_rounds_csv(bs)
    # take last occurrence per arm
    last={}
    for r in rows:
        a=(r.get("attack_name") or "").strip()
        if a in ARMS:
            last[a]=r
    out=[]
    for a in ARMS:
        if a in last:
            r=last[a]
            out.append({"arm":a,"estimated_value":float(r["estimated_value"]),
                        "times_selected":int(float(r["times_selected"]))})
    out.sort(key=lambda x:-x["estimated_value"])
    with open(os.path.join(OUT,"multikrum_bandit.csv"),"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["arm","estimated_value","times_selected"])
        w.writeheader(); w.writerows(out)
    print(f"  file={bs}")
    for r in out:
        print(f"    {r['arm']:14} est_value={r['estimated_value']:+.4f} times_selected={r['times_selected']}")
    return out

if __name__=="__main__":
    extract_norms()
    extract_trust()
    extract_arm_shares()
    extract_multikrum_bandit()
    print(f"\nWrote CSVs to {OUT}")
