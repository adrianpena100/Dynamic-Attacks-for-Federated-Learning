"""
Generate mechanistic analysis figures for draft.tex FROM VERIFIED LOG DATA.

All numbers are read from analysis/mechanistic/*.csv, which are produced by
scripts/paper_mechanistic.py directly from the raw sep16 (FEMNIST) run logs.
Nothing in this file is hardcoded or estimated. Run paper_mechanistic.py first.

Produces:
  fig_norm_comparison.pdf/png   — FedTrimmedAvg honest vs malicious update norms over rounds
  fig_trust_trajectory.pdf/png  — FoolsGold mean client trust over rounds, by cohort schedule
  fig_mab_defense_heatmap.pdf/png — dominant bandit arm per defense x cohort schedule

Run from the repo root:
    python3.9 scripts/paper_mechanistic.py
    python3.9 scripts/generate_mechanistic_figures.py
"""

import os, csv
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import ListedColormap

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FIGDIR = os.path.join(REPO, "figures", "preliminary_results")
MECH = os.path.join(REPO, "analysis", "mechanistic")
os.makedirs(FIGDIR, exist_ok=True)

OK = {"gray":"#999999","orange":"#E69F00","sky":"#56B4E9","green":"#009E73",
      "yellow":"#F0E442","blue":"#0072B2","vermillion":"#D55E00","purple":"#CC79A7","black":"#000000"}

plt.rcParams.update({
    "font.size": 8, "axes.titlesize": 8.5, "axes.labelsize": 8,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
    "axes.grid": True, "grid.alpha": 0.25, "figure.dpi": 150,
    "savefig.bbox": "tight", "pdf.fonttype": 42, "font.family": "DejaVu Sans",
})
COL1, COL2 = 3.5, 7.16

def save(fig, stem):
    for ext in ("pdf","png"):
        p=os.path.join(FIGDIR,f"{stem}.{ext}"); fig.savefig(p); print(f"  Saved {p}")
    plt.close(fig)

def load_csv(name):
    with open(os.path.join(MECH,name)) as f:
        return list(csv.DictReader(f))

# --------------------------------------------------------------------------
# Figure A: FedTrimmedAvg honest vs malicious update norms over rounds
# --------------------------------------------------------------------------
def fig_norm_comparison():
    rows=load_csv("fedtrimmedavg_norms.csv")
    def series(attack,col):
        xs=[];ys=[]
        for r in rows:
            if r["attack"]==attack and int(r["round"])>=2:  # skip r1 init outlier
                xs.append(int(r["round"])); ys.append(float(r[col]))
        return np.array(xs),np.array(ys)
    hx,hp50=series("alie","honest_p50")
    _,hmax=series("alie","honest_max")
    ax_,alie=series("alie","mal_post")
    gx,gauss=series("gaussian","mal_post")

    fig, ax = plt.subplots(figsize=(COL2*0.6, 2.7))
    # honest range band (p50..max)
    ax.fill_between(hx, hp50, hmax, color=OK["blue"], alpha=0.15, label="Honest range (p50 to max)")
    ax.plot(hx, hp50, color=OK["blue"], lw=1.6, label="Honest median")
    ax.plot(ax_, alie, color=OK["vermillion"], lw=1.5, marker="o", ms=2.5, label="ALIE malicious")
    ax.plot(gx, gauss, color=OK["orange"], lw=1.5, marker="s", ms=2.5, label="Gaussian malicious")
    ax.set_yscale("log")
    ax.set_xlabel("Round"); ax.set_ylabel("L2 update norm (log scale)")
    ax.set_title("FedTrimmedAvg: malicious norms stay inside\nthe honest range (FEMNIST, seed 42)")
    ax.legend(loc="upper right", framealpha=0.9)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    fig.tight_layout(pad=0.5)
    save(fig,"fig_norm_comparison")

# --------------------------------------------------------------------------
# Figure B: FoolsGold mean client trust over rounds, by cohort schedule
# --------------------------------------------------------------------------
def fig_trust_trajectory():
    rows=load_csv("foolsgold_trust.csv")
    fig, ax = plt.subplots(figsize=(COL2*0.6, 2.7))
    style={"sticky":(OK["blue"],"o","Sticky cohort"),
           "churn":(OK["vermillion"],"s","Churn cohort"),
           "random":(OK["purple"],"^","Per-round random cohort")}
    for sched,(c,mk,lbl) in style.items():
        s=[(int(r["round"]),float(r["avg_trust"])) for r in rows if r["schedule"]==sched]
        if not s: continue
        s.sort()
        xs=[a for a,_ in s]; ys=[b for _,b in s]
        ax.plot(xs,ys,color=c,lw=1.6,marker=mk,ms=2.5,label=lbl)
    ax.axhline(1.0,color=OK["gray"],ls=":",lw=0.8)
    ax.text(2,1.01,"full weight (no discrimination)",fontsize=6,color=OK["gray"])
    ax.set_xlabel("Round"); ax.set_ylabel("Mean client trust weight")
    ax.set_title("FoolsGold trust under rotation (FEMNIST, seed 42):\nchurn and random cohorts reach full weight")
    ax.set_ylim(0.0,1.08)
    ax.legend(loc="lower right", framealpha=0.9)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    fig.tight_layout(pad=0.5)
    save(fig,"fig_trust_trajectory")

# --------------------------------------------------------------------------
# Figure C: dominant bandit arm per defense x schedule
# --------------------------------------------------------------------------
def fig_mab_defense_heatmap():
    rows=load_csv("arm_shares.csv")
    ARMS=["gaussian_noise","sign_flip","label_flip","backdoor","alie","mean_shift"]
    arm_names=["Gaussian","Sign flip","Label flip","Backdoor","ALIE","Mean shift"]
    arm_colors=[OK["gray"],OK["blue"],OK["green"],OK["orange"],OK["vermillion"],OK["purple"]]
    defenses=["multikrum","fedtrimmedavg","fedmedian","foolsgold","mab-rfl"]
    dlabels=["Multi-Krum","FedTrimmedAvg","FedMedian","FoolsGold","MAB-RFL"]
    scheds=["sticky","churn","random"]; slabels=["Sticky","Churn","Random"]
    idx={(r["defense"],r["schedule"]):(r["dominant_arm"],float(r["dominant_share"])) for r in rows}
    grid=np.full((len(defenses),len(scheds)),-1,dtype=int)
    share=np.zeros((len(defenses),len(scheds)))
    for i,d in enumerate(defenses):
        for j,s in enumerate(scheds):
            if (d,s) in idx:
                arm,sh=idx[(d,s)]; grid[i,j]=ARMS.index(arm); share[i,j]=sh
    cmap=ListedColormap(arm_colors)
    fig,ax=plt.subplots(figsize=(COL1*1.15,2.5))
    ax.imshow(np.where(grid<0,np.nan,grid),cmap=cmap,vmin=0,vmax=5,aspect="auto")
    for i in range(len(defenses)):
        for j in range(len(scheds)):
            if grid[i,j]<0: continue
            dark=grid[i,j] in (1,3,4,5)
            ax.text(j,i,f"{arm_names[grid[i,j]]}\n{share[i,j]:.0%}",ha="center",va="center",
                    fontsize=5.8,color="white" if dark else "black",fontweight="bold")
    ax.set_xticks(range(len(scheds))); ax.set_xticklabels(slabels,fontsize=7)
    ax.set_yticks(range(len(defenses))); ax.set_yticklabels(dlabels,fontsize=7)
    ax.set_title("Dominant bandit arm by defense and schedule\n(FEMNIST, aggregated across seeds)",fontsize=8)
    patches=[mpatches.Patch(color=arm_colors[i],label=arm_names[i]) for i in range(6)]
    ax.legend(handles=patches,loc="upper left",bbox_to_anchor=(1.02,1),fontsize=6,borderaxespad=0,frameon=True)
    ax.spines[:].set_visible(False)
    ax.set_xticks(np.arange(-.5,len(scheds),1),minor=True)
    ax.set_yticks(np.arange(-.5,len(defenses),1),minor=True)
    ax.grid(which="minor",color="white",linewidth=1.5); ax.tick_params(which="minor",bottom=False,left=False)
    fig.tight_layout(pad=0.5)
    save(fig,"fig_mab_defense_heatmap")

if __name__=="__main__":
    print("Generating mechanistic figures from verified log data...")
    fig_norm_comparison(); fig_trust_trajectory(); fig_mab_defense_heatmap()
    print("Done. Files written to figures/preliminary_results/")
