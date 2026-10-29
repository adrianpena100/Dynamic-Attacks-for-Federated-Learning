#!/usr/bin/env python3
"""
Build comparison figures from audited sep16 (FEMNIST) and sep21 (CIFAR-100) sweeps.

Reads from:
    analysis/sep16/experiment_audit.csv   (FEMNIST)
    analysis/sep21/experiment_audit.csv   (CIFAR-100)
    analysis/sep16/mab_arm_summary.csv
    Raw per-round metrics via source_path in the audit CSVs.

Outputs:
    figures/preliminary_results/fig_landscape_combined.pdf/png  -- new stacked heatmap
    figures/preliminary_results/fig_temporal.pdf/png            -- FEMNIST only (unchanged)
    figures/preliminary_results/fig_arms.pdf/png                -- FEMNIST only
    figures/preliminary_results/fig_multimetric.pdf/png         -- FEMNIST only (trimmed)
    figures/preliminary_results/fig_cases.pdf/png               -- FEMNIST only
    figures/preliminary_results/fig_backdoor.pdf/png            -- FEMNIST only

Run after audit_sweeps.py has been run for both datasets.
"""
import csv
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Rectangle
from matplotlib.colors import ListedColormap
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
FIGDIR = os.path.join(REPO, "figures", "preliminary_results")
os.makedirs(FIGDIR, exist_ok=True)

SEP16_DIR = os.path.join(REPO, "analysis", "sep16")
SEP21_DIR = os.path.join(REPO, "analysis", "sep21")

# ---------------------------------------------------------- valid sets / style
DEF_ORDER = ["multikrum", "fedtrimmedavg", "fedmedian", "flram", "foolsgold", "mab-rfl"]
DEF_LABEL = {
    "multikrum": "Multi-Krum", "fedtrimmedavg": "Trimmed Mean",
    "fedmedian": "FedMedian", "flram": "FLRAM",
    "foolsgold": "FoolsGold", "mab-rfl": "MAB-RFL",
}
EXCLUDE = {"bulyan", "fltrust"}
ATT_ORDER = ["gaussian_noise", "sign_flip", "label_flip", "backdoor", "alie", "mean_shift"]
ATT_LABEL = {
    "gaussian_noise": "Gaussian", "sign_flip": "Sign-flip", "label_flip": "Label-flip",
    "backdoor": "Backdoor", "alie": "ALIE", "mean_shift": "Mean-shift",
}
SCHED = ["sticky", "random", "churn"]
SCHED_LABEL = {"sticky": "Sticky", "random": "Random", "churn": "Churn"}

OK = {
    "gray": "#999999", "orange": "#E69F00", "sky": "#56B4E9", "green": "#009E73",
    "yellow": "#F0E442", "blue": "#0072B2", "vermillion": "#D55E00", "purple": "#CC79A7",
    "black": "#000000",
}
SCHED_C = {"sticky": OK["blue"], "random": OK["green"], "churn": OK["purple"]}
ARM_C = {
    "gaussian_noise": OK["gray"], "sign_flip": OK["blue"], "label_flip": OK["green"],
    "backdoor": OK["orange"], "alie": OK["vermillion"], "mean_shift": OK["purple"],
}
SEED_C = {"1337": OK["vermillion"], "42": OK["blue"], "2024": OK["green"]}
CLEAN_C, FIXED_C = OK["black"], OK["vermillion"]

CHANCE_FEMNIST = 100.0 / 62
CHANCE_CIFAR = 100.0 / 100
COL1, COL2 = 3.5, 7.16

plt.rcParams.update({
    "font.size": 8, "axes.titlesize": 8.5, "axes.labelsize": 8,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
    "axes.grid": True, "grid.alpha": 0.25, "grid.linewidth": 0.5,
    "axes.axisbelow": True, "figure.dpi": 150, "savefig.bbox": "tight",
    "pdf.fonttype": 42, "ps.fonttype": 42, "font.family": "DejaVu Sans",
})


# ----------------------------------------------------------------- load

def load_csv(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def fnum(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def read_series(source_path, metric="accuracy"):
    p = os.path.join(source_path, "metrics", f"evaluate_server__{metric}.csv")
    if not os.path.exists(p):
        return [], []
    xs, ys = [], []
    with open(p) as f:
        r = csv.DictReader(f)
        cols = r.fieldnames or []
        rc = "round" if "round" in cols else cols[0]
        vc = "value" if "value" in cols else cols[-1]
        for row in r:
            try:
                xs.append(int(float(row[rc]))); ys.append(float(row[vc]))
            except (ValueError, KeyError):
                pass
    return xs, ys


# load both audit tables
f_audit = [r for r in load_csv(os.path.join(SEP16_DIR, "experiment_audit.csv"))
           if r.get("valid") == "True" and r.get("defense") not in EXCLUDE]
c_audit = [r for r in load_csv(os.path.join(SEP21_DIR, "experiment_audit.csv"))
           if r.get("valid") == "True" and r.get("defense") not in EXCLUDE]

f_arm = load_csv(os.path.join(SEP16_DIR, "mab_arm_summary.csv"))
c_arm = load_csv(os.path.join(SEP21_DIR, "mab_arm_summary.csv"))


def rows_for(audit, defense, run_type=None, schedule=None, attack=None):
    out = []
    for r in audit:
        if r["defense"] != defense:
            continue
        if run_type and r["run_type"] != run_type:
            continue
        if schedule is not None and r.get("cohort_schedule") != schedule:
            continue
        if attack is not None and r.get("fixed_attack") != attack:
            continue
        out.append(r)
    return out


def mean_of(rows, key, scale=1.0):
    vals = [fnum(r[key]) * scale for r in rows if fnum(r[key]) is not None]
    return (sum(vals) / len(vals)) if vals else None


def fixed_drop(audit, defense, attack):
    return mean_of(rows_for(audit, defense, "fixed", attack=attack), "acc_drop_pp")


def mab_drop(audit, defense, schedule):
    return mean_of(rows_for(audit, defense, "mab", schedule=schedule), "acc_drop_pp")


def strongest_fixed(audit, defense):
    best, bv = None, -1e9
    for a in ATT_ORDER:
        d = fixed_drop(audit, defense, a)
        if d is not None and d > bv:
            bv, best = d, a
    return best, bv


def worst_mab_schedule(audit, defense):
    best, bv = None, -1e9
    for s in SCHED:
        d = mab_drop(audit, defense, s)
        if d is not None and d > bv:
            bv, best = d, s
    return best, bv


def seed_aggregate(rows, metric="accuracy", scale=100.0):
    per_seed, byround = [], defaultdict(list)
    for r in sorted(rows, key=lambda r: r.get("seed", "")):
        xs, ys = read_series(r["source_path"], metric)
        if not xs:
            continue
        ys = [y * scale for y in ys]
        per_seed.append((r.get("seed", ""), xs, ys))
        for x, y in zip(xs, ys):
            byround[x].append(y)
    if not byround:
        return per_seed, [], []
    ax = sorted(byround)
    ay = [sum(byround[x]) / len(byround[x]) for x in ax]
    return per_seed, ax, ay


def pick_median_seed(rows):
    rs = [r for r in rows if fnum(r.get("final_accuracy")) is not None]
    if not rs:
        return None
    rs.sort(key=lambda r: fnum(r["final_accuracy"]))
    return rs[len(rs) // 2]


def timeline_seq(source_path):
    p = os.path.join(source_path, "summaries", "attack_timeline.csv")
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
    return seq


def reward_series(source_path):
    p = os.path.join(source_path, "summaries", "adaptive_bandit_state.csv")
    if not os.path.exists(p):
        return [], []
    xs, ys = [], []
    with open(p) as f:
        for row in csv.DictReader(f):
            try:
                if int(float(row.get("selected_this_round", 0))) == 1:
                    xs.append(int(float(row["round"]))); ys.append(float(row["reward"]))
            except (ValueError, KeyError):
                pass
    order = np.argsort(xs)
    return [xs[i] for i in order], [ys[i] for i in order]


def rolling(xs, ys, w):
    out = []
    for i in range(len(ys)):
        lo = max(0, i - w + 1)
        seg = ys[lo:i + 1]
        out.append(sum(seg) / len(seg))
    return xs, out


def save(fig, name):
    fig.savefig(os.path.join(FIGDIR, name + ".pdf"))
    fig.savefig(os.path.join(FIGDIR, name + ".png"), dpi=200)
    plt.close(fig)
    print("  wrote", name)


def build_drop_matrix(audit):
    cols = ATT_ORDER + SCHED
    M = np.full((len(DEF_ORDER), len(cols)), np.nan)
    for i, d in enumerate(DEF_ORDER):
        for j, a in enumerate(ATT_ORDER):
            v = fixed_drop(audit, d, a)
            if v is not None:
                M[i, j] = v
        for k, s in enumerate(SCHED):
            v = mab_drop(audit, d, s)
            if v is not None:
                M[i, len(ATT_ORDER) + k] = v
    return M


def draw_heatmap(ax, M, vmax, col_labels, show_yticklabels=True, title=""):
    im = ax.imshow(M, cmap="RdBu_r", aspect="auto", vmin=-vmax, vmax=vmax)
    ax.set_xticks(range(len(col_labels)))
    ax.set_xticklabels(col_labels, rotation=35, ha="right")
    if show_yticklabels:
        ax.set_yticks(range(len(DEF_ORDER)))
        ax.set_yticklabels([DEF_LABEL[d] for d in DEF_ORDER])
    else:
        ax.set_yticks(range(len(DEF_ORDER)))
        ax.set_yticklabels([])
    # annotate cells
    for i in range(len(DEF_ORDER)):
        for j in range(len(col_labels)):
            if not np.isnan(M[i, j]):
                v = 0.0 if abs(M[i, j]) < 0.5 else M[i, j]
                ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=6,
                        color="white" if abs(M[i, j]) > vmax * 0.55 else "black")
            else:
                # mark missing cells gray
                ax.add_patch(Rectangle((j - 0.5, i - 0.5), 1, 1,
                                       facecolor="#cccccc", edgecolor="none"))
        # outline strongest fixed + strongest MAB
        fixed_row = M[i, :len(ATT_ORDER)]
        mab_row = M[i, len(ATT_ORDER):]
        if not np.all(np.isnan(fixed_row)):
            jf = int(np.nanargmax(fixed_row))
            ax.add_patch(Rectangle((jf - 0.5, i - 0.5), 1, 1, fill=False,
                                   edgecolor=OK["black"], lw=2.0))
        if not np.all(np.isnan(mab_row)):
            jm = len(ATT_ORDER) + int(np.nanargmax(mab_row))
            ax.add_patch(Rectangle((jm - 0.5, i - 0.5), 1, 1, fill=False,
                                   edgecolor=OK["green"], lw=2.0, linestyle=(0, (2, 1))))
    ax.axvline(len(ATT_ORDER) - 0.5, color="black", lw=1.6)
    if title:
        ax.set_title(title, fontsize=8.5, pad=4)
    return im


# =====================================================================
# FIG 1  LANDSCAPE COMBINED  (stacked: FEMNIST top, CIFAR-100 bottom)
# =====================================================================
def fig_landscape_combined():
    col_labels = [ATT_LABEL[a] for a in ATT_ORDER] + [SCHED_LABEL[s] for s in SCHED]
    Mf = build_drop_matrix(f_audit)
    Mc = build_drop_matrix(c_audit)
    vmax = max(np.nanmax(np.abs(Mf)) if not np.all(np.isnan(Mf)) else 0,
               np.nanmax(np.abs(Mc)) if not np.all(np.isnan(Mc)) else 0)

    # Taller figure so cells are readable in the PDF; each panel ~3.4" → total 7.5"
    fig, (ax_f, ax_c) = plt.subplots(2, 1, figsize=(COL2, 7.5),
                                      gridspec_kw={"hspace": 0.62})

    # Use slightly larger fonts inside the heatmap for readability
    _cell_fs = 7.5   # annotation numbers
    _tick_fs = 8     # axis tick labels

    def _draw(ax, M, title):
        im = ax.imshow(M, cmap="RdBu_r", aspect="auto", vmin=-vmax, vmax=vmax)
        ax.set_xticks(range(len(col_labels)))
        ax.set_xticklabels(col_labels, rotation=35, ha="right", fontsize=_tick_fs)
        ax.set_yticks(range(len(DEF_ORDER)))
        ax.set_yticklabels([DEF_LABEL[d] for d in DEF_ORDER], fontsize=_tick_fs)
        for i in range(len(DEF_ORDER)):
            for j in range(len(col_labels)):
                if not np.isnan(M[i, j]):
                    v = 0.0 if abs(M[i, j]) < 0.5 else M[i, j]
                    ax.text(j, i, f"{v:.0f}", ha="center", va="center",
                            fontsize=_cell_fs,
                            color="white" if abs(M[i, j]) > vmax * 0.55 else "black",
                            fontweight="bold")
                else:
                    ax.add_patch(Rectangle((j - 0.5, i - 0.5), 1, 1,
                                           facecolor="#cccccc", edgecolor="none"))
            fixed_row = M[i, :len(ATT_ORDER)]
            mab_row   = M[i, len(ATT_ORDER):]
            if not np.all(np.isnan(fixed_row)):
                jf = int(np.nanargmax(fixed_row))
                ax.add_patch(Rectangle((jf - 0.5, i - 0.5), 1, 1, fill=False,
                                       edgecolor="black", lw=2.2))
            if not np.all(np.isnan(mab_row)):
                jm = len(ATT_ORDER) + int(np.nanargmax(mab_row))
                ax.add_patch(Rectangle((jm - 0.5, i - 0.5), 1, 1, fill=False,
                                       edgecolor=OK["green"], lw=2.2,
                                       linestyle=(0, (2, 1))))
        ax.axvline(len(ATT_ORDER) - 0.5, color="black", lw=1.8)
        # arrows sit right at the axes frame; title padded well above them
        ax.annotate("← Fixed attacks", xy=(0.01, 1.005), xycoords="axes fraction",
                    fontsize=7, fontweight="bold", va="bottom", ha="left")
        ax.annotate("Adaptive MAB →", xy=(0.99, 1.005), xycoords="axes fraction",
                    fontsize=7, fontweight="bold", va="bottom", ha="right")
        ax.set_title(title, fontsize=9, pad=24)  # pad pushes title above the arrows
        return im

    im = _draw(ax_f, Mf, "(a) FEMNIST — 62 classes, Dir(0.5), 50 rounds")
    _draw(ax_c, Mc, "(b) CIFAR-100 — 100 classes, Dir(1.0), 100 rounds  (MAB partial†)")

    cb = fig.colorbar(im, ax=[ax_f, ax_c], fraction=0.022, pad=0.02)
    cb.set_label("Accuracy drop vs matched clean baseline (pp)", fontsize=8)
    cb.ax.tick_params(labelsize=7)
    fig.text(0.01, 0.005,
             "† Gray = MAB in progress. Black box = strongest fixed attack; "
             "dashed green = strongest MAB schedule. Negative pp = attacked run exceeded its clean baseline (seed artifact).",
             fontsize=6, color=OK["gray"], ha="left", wrap=True)
    save(fig, "fig_landscape_combined")


TRIM_DEFS = ["multikrum", "fedmedian", "foolsgold", "mab-rfl"]


# =====================================================================
# FIG 6  CASE STUDIES  -- FEMNIST only
# =====================================================================
CASES = [
    ("multikrum", "sticky", "Rediscovery"),
    ("foolsgold", "random", "Adaptive gain"),
    ("mab-rfl", "churn", "Learning failure"),
]


def fig_cases():
    fig, axes = plt.subplots(3, 3, figsize=(COL2, 5.4), sharex=True)
    w = 8
    for c, (d, s, tag) in enumerate(CASES):
        rrows = rows_for(f_audit, d, "mab", schedule=s)
        r = pick_median_seed(rrows)
        if r is None:
            continue
        sa, _ = strongest_fixed(f_audit, d)
        seq = timeline_seq(r["source_path"])
        rounds = [rd for rd, _ in seq]
        # (top) rolling arm share
        axt = axes[0][c]
        for a in ATT_ORDER:
            ind = [1.0 if nm == a else 0.0 for _, nm in seq]
            _, rs = rolling(rounds, ind, w)
            axt.plot(rounds, rs, color=ARM_C[a], lw=1.3 if a == sa else 0.9,
                     label=ATT_LABEL[a], alpha=0.95 if a == sa else 0.7)
        axt.set_ylim(0, 1)
        axt.set_title(f"{DEF_LABEL[d]} · {SCHED_LABEL[s]}\n{tag}", fontsize=7.5)
        if c == 0:
            axt.set_ylabel("Arm share\n(8-round roll)", fontsize=7)
        # (mid) reward
        axm = axes[1][c]
        rx, ry = reward_series(r["source_path"])
        if rx:
            axm.plot(rx, ry, color=OK["gray"], lw=0.6, alpha=0.7)
            _, rr = rolling(rx, ry, w)
            axm.plot(rx, rr, color=OK["black"], lw=1.4)
        axm.axhline(0, color="black", lw=0.6, ls=":")
        if c == 0:
            axm.set_ylabel("Selected-arm\nreward", fontsize=7)
        # (bottom) accuracy
        axb = axes[2][c]
        xs, ys = read_series(r["source_path"])
        axb.plot(xs, [y * 100 for y in ys], color=SCHED_C[s], lw=1.5, label="MAB run")
        bm = mean_of(rows_for(f_audit, d, "baseline"), "final_accuracy")
        if bm is not None:
            axb.axhline(bm * 100, color=CLEAN_C, ls="--", lw=1.0, label="Clean")
        axb.axhline(CHANCE_FEMNIST, color="black", ls=":", lw=0.7)
        axb.set_ylim(0, 100)
        axb.set_xlabel("Round")
        if c == 0:
            axb.set_ylabel("Accuracy (%)", fontsize=7)
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, ncol=6, loc="upper center", bbox_to_anchor=(0.5, 1.03),
               frameon=False, columnspacing=0.9, handletextpad=0.3, fontsize=6.5)
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    save(fig, "fig_cases_femnist")


# =====================================================================
# CIFAR-100 variants of per-dataset figures
# =====================================================================

def _temporal_dataset(audit, chance, label, note=""):
    fig, axes = plt.subplots(2, 3, figsize=(COL2, 4.2), sharex=True, sharey=True)
    for idx, d in enumerate(DEF_ORDER):
        ax = axes[idx // 3][idx % 3]
        _, bx, by = seed_aggregate(rows_for(audit, d, "baseline"))
        if bx:
            ax.plot(bx, by, color=CLEAN_C, lw=1.8, label="Clean", zorder=6)
        sa, _ = strongest_fixed(audit, d)
        if sa:
            ps, fx, fy = seed_aggregate(rows_for(audit, d, "fixed", attack=sa))
            for _, xs, ys in ps:
                ax.plot(xs, ys, color=FIXED_C, lw=0.5, alpha=0.35, zorder=2)
            if fx:
                ax.plot(fx, fy, color=FIXED_C, lw=1.8, label="Strongest Fixed", zorder=5)
        for s in SCHED:
            ps, mx, my = seed_aggregate(rows_for(audit, d, "mab", schedule=s))
            for _, xs, ys in ps:
                ax.plot(xs, ys, color=SCHED_C[s], lw=0.5, alpha=0.30, zorder=2)
            if mx:
                ax.plot(mx, my, color=SCHED_C[s], lw=1.5, label=f"MAB {SCHED_LABEL[s]}", zorder=4)
        ax.axhline(chance, color="black", ls=":", lw=0.7)
        ax.set_title(DEF_LABEL[d], fontsize=8)
        ax.set_ylim(0, 100)
        if idx % 3 == 0:
            ax.set_ylabel("Accuracy (%)")
        if idx // 3 == 1:
            ax.set_xlabel("Round")
    handles, labels_l = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels_l, ncol=5, loc="upper center", bbox_to_anchor=(0.5, 1.04),
               frameon=False, columnspacing=1.1, handletextpad=0.4)
    if note:
        fig.text(0.5, -0.01, note, ha="center", fontsize=6, color=OK["gray"])
    fig.tight_layout(rect=(0, 0, 1, 0.98))
    save(fig, f"fig_temporal_{label}")


def _multimetric_dataset(audit, label, note=""):
    panels = [
        ("f1_macro", "Macro-F1 (%)", 100.0, (0, 100)),
        ("recall_macro", "Macro-recall (%)", 100.0, (0, 100)),
        ("loss", "Test loss (nats)", 1.0, None),
    ]
    fig, axes = plt.subplots(len(TRIM_DEFS), 3, figsize=(COL2, 4.8), sharex=True)
    for i, d in enumerate(TRIM_DEFS):
        sa, _ = strongest_fixed(audit, d)
        ws, _ = worst_mab_schedule(audit, d)
        for j, (metric, ylab, scale, ylim) in enumerate(panels):
            ax = axes[i][j]
            _, bx, by = seed_aggregate(rows_for(audit, d, "baseline"), metric, scale)
            if bx:
                ax.plot(bx, by, color=CLEAN_C, lw=1.5, label="Clean")
            if sa:
                _, fx, fy = seed_aggregate(rows_for(audit, d, "fixed", attack=sa), metric, scale)
                if fx:
                    ax.plot(fx, fy, color=FIXED_C, lw=1.4, label=f"Fixed {ATT_LABEL[sa]}")
            if ws:
                _, mx, my = seed_aggregate(rows_for(audit, d, "mab", schedule=ws), metric, scale)
                if mx:
                    ax.plot(mx, my, color=SCHED_C[ws], lw=1.4, label=f"MAB {SCHED_LABEL[ws]}")
            if ylim:
                ax.set_ylim(*ylim)
            if i == 0:
                ax.set_title(ylab, fontsize=8)
            if j == 0:
                ax.set_ylabel(DEF_LABEL[d], fontsize=7.5)
            if i == len(TRIM_DEFS) - 1:
                ax.set_xlabel("Round")
    leg = [
        Line2D([0], [0], color=CLEAN_C, lw=1.6, label="Clean baseline"),
        Line2D([0], [0], color=FIXED_C, lw=1.6, label="Strongest fixed attack"),
        Line2D([0], [0], color=SCHED_C["sticky"], lw=1.6, label="MAB sticky"),
        Line2D([0], [0], color=SCHED_C["random"], lw=1.6, label="MAB random"),
        Line2D([0], [0], color=SCHED_C["churn"], lw=1.6, label="MAB churn"),
    ]
    fig.legend(handles=leg, ncol=5, loc="upper center", bbox_to_anchor=(0.5, 1.02),
               frameon=False, columnspacing=1.2)
    if note:
        fig.text(0.5, -0.01, note, ha="center", fontsize=6, color=OK["gray"])
    fig.tight_layout(rect=(0, 0, 1, 0.98))
    save(fig, f"fig_multimetric_{label}")


def _backdoor_dataset(audit, label, note=""):
    fig, axes = plt.subplots(2, 3, figsize=(COL2, 4.0), sharex=True, sharey=True)
    for idx, d in enumerate(DEF_ORDER):
        ax = axes[idx // 3][idx % 3]
        _, fx, fy = seed_aggregate(rows_for(audit, d, "fixed", attack="backdoor"), "backdoor_asr", 100.0)
        if fx:
            ax.plot(fx, fy, color=FIXED_C, lw=1.7, label="Fixed backdoor")
        for s in SCHED:
            _, mx, my = seed_aggregate(rows_for(audit, d, "mab", schedule=s), "backdoor_asr", 100.0)
            if mx:
                ax.plot(mx, my, color=SCHED_C[s], lw=1.2, label=f"MAB {SCHED_LABEL[s]}")
        ax.set_title(DEF_LABEL[d], fontsize=8)
        ax.set_ylim(0, 50)
        if idx % 3 == 0:
            ax.set_ylabel("Backdoor ASR (%)")
        if idx // 3 == 1:
            ax.set_xlabel("Round")
    handles, labels_l = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels_l, ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.04),
               frameon=False, columnspacing=1.1)
    if note:
        fig.text(0.5, -0.01, note, ha="center", fontsize=6, color=OK["gray"])
    fig.tight_layout(rect=(0, 0, 1, 0.98))
    save(fig, f"fig_backdoor_{label}")


def _arm_matrix(arm_summary, audit, schedule):
    """Build arm-share matrix from a pre-computed mab_arm_summary table."""
    acc = defaultdict(lambda: defaultdict(list))
    valid_defs = {r["defense"] for r in audit if r["valid"] == "True"}
    for r in arm_summary:
        if r.get("defense") in EXCLUDE or r.get("cohort_schedule") != schedule:
            continue
        if r.get("defense") not in valid_defs:
            continue
        for a in ATT_ORDER:
            v = fnum(r.get(f"share_post__{a}"))
            if v is not None:
                acc[r["defense"]][a].append(v)
    M = np.full((len(DEF_ORDER), len(ATT_ORDER)), np.nan)
    for i, d in enumerate(DEF_ORDER):
        for j, a in enumerate(ATT_ORDER):
            if acc[d][a]:
                M[i, j] = sum(acc[d][a]) / len(acc[d][a])
    return M


def _arms_dataset(arm_summary, audit, label, note=""):
    mats = {s: _arm_matrix(arm_summary, audit, s) for s in SCHED}
    all_vals = [m for m in mats.values() if not np.all(np.isnan(m))]
    if not all_vals:
        print(f"  skipping fig_arms_{label} — no MAB arm data")
        return
    vmax = max(np.nanmax(m) for m in all_vals)
    fig, axes = plt.subplots(1, 3, figsize=(COL2, 2.9), sharey=True,
                             gridspec_kw={"wspace": 0.12})
    for k, s in enumerate(SCHED):
        ax = axes[k]
        M = mats[s]
        im = ax.imshow(M, cmap="Purples", aspect="auto", vmin=0, vmax=vmax)
        ax.set_xticks(range(len(ATT_ORDER)))
        ax.set_xticklabels([ATT_LABEL[a] for a in ATT_ORDER], rotation=40, ha="right", fontsize=6.5)
        ax.set_title(f"({chr(97+k)}) {SCHED_LABEL[s]}", fontsize=8)
        if k == 0:
            ax.set_yticks(range(len(DEF_ORDER)))
            ax.set_yticklabels([DEF_LABEL[d] for d in DEF_ORDER])
        for i, d in enumerate(DEF_ORDER):
            sa, _ = strongest_fixed(audit, d)
            if sa:
                ja = ATT_ORDER.index(sa)
                ax.add_patch(Rectangle((ja - 0.5, i - 0.5), 1, 1, fill=False,
                                       edgecolor=OK["vermillion"], lw=1.8))
            for j in range(len(ATT_ORDER)):
                v = M[i, j]
                if not np.isnan(v):
                    ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=5.5,
                            color="white" if v > vmax * 0.6 else "black")
                else:
                    ax.add_patch(Rectangle((j - 0.5, i - 0.5), 1, 1,
                                           facecolor="#dddddd", edgecolor="none"))
    cb = fig.colorbar(im, ax=axes, fraction=0.03, pad=0.02)
    cb.set_label("Post-warmup selection share", fontsize=7)
    fig.text(0.5, 1.0, "red box = empirically strongest fixed attack for that defense",
             ha="center", fontsize=6.2, color=OK["gray"])
    if note:
        fig.text(0.5, -0.01, note, ha="center", fontsize=6, color=OK["gray"])
    save(fig, f"fig_arms_{label}")


# =====================================================================
# FIG  COHORT COMBINED  (grouped bars: adaptive damage by schedule, both datasets)
# =====================================================================
DISP_SCHED = ["sticky", "churn", "random"]  # match the paper tables' column order


def fig_cohort_combined():
    """Adaptive damage (pp) by cohort schedule, FEMNIST vs CIFAR-100.

    One panel per dataset (independent y-axes, since absolute damage differs a lot).
    Three bars per defense (sticky / churn / random). A star marks the worst schedule
    for that defense. Directly visualizes Tables tab:cohort and tab:cifarcohort.
    """
    datasets = [("FEMNIST", f_audit), ("CIFAR-100", c_audit)]
    fig, axes = plt.subplots(2, 1, figsize=(COL2, 4.9))
    width = 0.26
    offs = {"sticky": -width, "churn": 0.0, "random": width}
    for ax, (name, audit) in zip(axes, datasets):
        for s in DISP_SCHED:
            xs, ys = [], []
            for i, d in enumerate(DEF_ORDER):
                v = mab_drop(audit, d, s)
                if v is not None:
                    xs.append(i + offs[s]); ys.append(v)
            ax.bar(xs, ys, width=width, color=SCHED_C[s], label=SCHED_LABEL[s],
                   edgecolor="black", linewidth=0.4, zorder=3)
        # star the worst (most damaging) schedule per defense
        for i, d in enumerate(DEF_ORDER):
            ws, wv = worst_mab_schedule(audit, d)
            if ws is not None:
                dy = 1.2 if wv >= 0 else -2.4
                ax.text(i + offs[ws], wv + dy, "*", ha="center",
                        va="bottom" if wv >= 0 else "top", fontsize=12, color="black")
        ax.axhline(0, color="black", lw=0.8, zorder=2)
        ax.set_xticks(range(len(DEF_ORDER)))
        ax.set_xticklabels([DEF_LABEL[d] for d in DEF_ORDER])
        ax.set_ylabel("Damage vs clean (pp)")
        ax.set_title(name, fontsize=8.5, pad=2)
        ax.grid(axis="x", visible=False)
        ax.margins(y=0.18)  # headroom so bars/stars clear the title and legend
    handles = [Rectangle((0, 0), 1, 1, facecolor=SCHED_C[s]) for s in DISP_SCHED]
    fig.legend(handles, [SCHED_LABEL[s] for s in DISP_SCHED], ncol=3,
               loc="upper center", frameon=False, title="Cohort schedule (star = worst)",
               bbox_to_anchor=(0.5, 1.0))
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    save(fig, "fig_cohort_combined")


# =====================================================================
# FIG  ARMS COMBINED  (dominant-attack fingerprint per defense x schedule, both datasets)
# =====================================================================
ATT_ABBR = {
    "gaussian_noise": "Gau", "sign_flip": "Sign", "label_flip": "Label",
    "backdoor": "Back", "alie": "ALIE", "mean_shift": "Mean",
}
ATT_TEXT_C = {  # readable text color on each categorical cell
    "gaussian_noise": "black", "backdoor": "black",
    "sign_flip": "white", "label_flip": "white", "alie": "white", "mean_shift": "white",
}


def _dominant_arm_grid(arm_summary, audit):
    """grid[defense, schedule] = index in ATT_ORDER of the most-selected post-warmup arm."""
    G = np.full((len(DEF_ORDER), len(DISP_SCHED)), -1)
    for k, s in enumerate(DISP_SCHED):
        M = _arm_matrix(arm_summary, audit, s)
        for i in range(len(DEF_ORDER)):
            if not np.all(np.isnan(M[i])):
                G[i, k] = int(np.nanargmax(M[i]))
    return G


def fig_arms_combined():
    """Which attack the selector concentrates on, per defense x schedule, both datasets.

    Each cell is colored and labeled by the dominant post-warmup attack. Shows that the
    selector specializes to the defense, and that the preferred attack shifts between the
    two data regimes (sign-flip heavy on FEMNIST, ALIE/mean-shift heavy on CIFAR-100).
    """
    cmap = ListedColormap([ARM_C[a] for a in ATT_ORDER])
    datasets = [("FEMNIST", f_arm, f_audit), ("CIFAR-100", c_arm, c_audit)]
    fig, axes = plt.subplots(1, 2, figsize=(COL2, 2.8), sharey=True,
                             gridspec_kw={"wspace": 0.08})
    for ax, (name, arm, audit) in zip(axes, datasets):
        G = _dominant_arm_grid(arm, audit)
        Gm = np.ma.masked_where(G < 0, G)
        ax.imshow(Gm, cmap=cmap, aspect="auto", vmin=0, vmax=len(ATT_ORDER) - 1)
        ax.set_xticks(range(len(DISP_SCHED)))
        ax.set_xticklabels([SCHED_LABEL[s] for s in DISP_SCHED])
        ax.set_title(name, fontsize=8.5)
        ax.set_yticks(range(len(DEF_ORDER)))
        ax.set_yticklabels([DEF_LABEL[d] for d in DEF_ORDER])
        ax.grid(False)
        for i in range(len(DEF_ORDER)):
            for k in range(len(DISP_SCHED)):
                if G[i, k] >= 0:
                    a = ATT_ORDER[G[i, k]]
                    ax.text(k, i, ATT_ABBR[a], ha="center", va="center",
                            fontsize=6.8, color=ATT_TEXT_C[a])
                else:
                    ax.add_patch(Rectangle((k - 0.5, i - 0.5), 1, 1,
                                           facecolor="#dddddd", edgecolor="none"))
    handles = [Rectangle((0, 0), 1, 1, facecolor=ARM_C[a]) for a in ATT_ORDER]
    fig.legend(handles, [ATT_LABEL[a] for a in ATT_ORDER], ncol=6, loc="lower center",
               frameon=False, fontsize=6.5, bbox_to_anchor=(0.5, -0.02))
    fig.tight_layout(rect=[0, 0.05, 1, 1])
    save(fig, "fig_arms_combined")


# ------------------------------------------------------------------ run all
print("Building figures...")
print(f"  FEMNIST audit rows: {len(f_audit)}")
print(f"  CIFAR-100 audit rows: {len(c_audit)}")

fig_landscape_combined()
fig_cohort_combined()
fig_arms_combined()

# FEMNIST figures
_temporal_dataset(f_audit, CHANCE_FEMNIST, "femnist")
_arms_dataset(f_arm, f_audit, "femnist")
_multimetric_dataset(f_audit, "femnist")
_backdoor_dataset(f_audit, "femnist")
fig_cases()  # FEMNIST only — needs multi-seed MAB data CIFAR-100 doesn't have yet

# CIFAR-100 figures (full set as of this run; gray cells = any missing seed/schedule)
MAB_NOTE = ""
_temporal_dataset(c_audit, CHANCE_CIFAR, "cifar100", note=MAB_NOTE)
_arms_dataset(c_arm, c_audit, "cifar100", note=MAB_NOTE)
_multimetric_dataset(c_audit, "cifar100", note=MAB_NOTE)
_backdoor_dataset(c_audit, "cifar100", note=MAB_NOTE)

print("\nAll figures written to", FIGDIR)
