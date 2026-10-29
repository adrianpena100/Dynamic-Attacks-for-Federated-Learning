#!/usr/bin/env python3
"""
Framework architecture figure for the paper.

Draws the verified end-to-end flow of one federated round in the configurable
evaluation framework. Every block corresponds to a configurable component, and
the dashed arrow is the feedback path the adaptive attack selector observes.

Flow (verified against pytorchexample/{server_app,client_app,task}.py and
scripts/run_simulation_and_log.py):

  config -> data/model/federation setup
         -> per round: [attack selector] + [cohort scheduler]
         -> per-client attack config
         -> client train + data poison
         -> server update poison + stealth cap
         -> aggregation defense
         -> central + client eval metrics
         -> feedback (malicious-client accuracy) back to selector

Output: figures/preliminary_results/fig_framework.pdf/png and a copy in figures/.
Run with python3.9 (matplotlib 3.9).
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
FIGDIR = os.path.join(REPO, "figures", "preliminary_results")
FIGDIR2 = os.path.join(REPO, "figures")
os.makedirs(FIGDIR, exist_ok=True)
os.makedirs(FIGDIR2, exist_ok=True)

# Okabe-Ito palette, consistent with the other figures
C_CONFIG = "#0072B2"   # blue    (configuration)
C_SETUP  = "#56B4E9"   # sky     (data/model/federation)
C_ATTACK = "#D55E00"   # vermillion (attack-side, the two studied dimensions)
C_DEF    = "#009E73"   # green   (defense/aggregation)
C_EVAL   = "#555555"   # gray    (metrics/logs)
C_FB     = "#CC79A7"   # purple  (feedback)
C_TEXT   = "#000000"

plt.rcParams.update({
    "font.size": 8.2, "axes.titlesize": 9, "font.family": "DejaVu Sans",
})


def box(ax, x, y, w, h, text, fc, tc="white", fs=8.2, bold=False, ec="none"):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.03",
        linewidth=1.0, edgecolor=ec, facecolor=fc, mutation_aspect=1.0, zorder=2))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            color=tc, fontsize=fs, fontweight="bold" if bold else "normal",
            zorder=3, linespacing=1.15)


def arrow(ax, p0, p1, color="#333333", style="-", lw=1.4, rad=0.0):
    ax.add_patch(FancyArrowPatch(
        p0, p1, arrowstyle="-|>", mutation_scale=11, linewidth=lw,
        color=color, linestyle=style,
        connectionstyle=f"arc3,rad={rad}", zorder=1))


fig, ax = plt.subplots(figsize=(7.16, 4.5))
ax.set_xlim(0, 10)
ax.set_ylim(0, 6.6)
ax.axis("off")

# Row 1: configuration -> setup
box(ax, 0.2, 5.55, 2.7, 0.8,
    "Experiment configuration\n(one file + CLI overrides)", C_CONFIG, bold=True)
box(ax, 3.4, 5.55, 3.1, 0.8,
    "Dataset, model, partition,\nfederation setup", C_SETUP, tc="black")
box(ax, 7.0, 5.55, 2.8, 0.8,
    "Aggregation defense\n(10 strategies)", C_DEF, bold=True)

# Per-round band label
ax.text(5.0, 4.95, "Per communication round", ha="center", va="center",
        fontsize=8.0, style="italic", color="#444444")

# Row 2: the two studied dimensions (attack selector + cohort scheduler)
box(ax, 0.2, 3.75, 4.6, 1.0,
    "Attack selector  (Dimension 1)\nphase, weighted-random,\nadaptive bandit",
    C_ATTACK, bold=True, fs=7.8)
box(ax, 5.2, 3.75, 4.6, 1.0,
    "Cohort scheduler  (Dimension 2)\nsticky, windowed, churn,\nper-round-random (+cooldown)",
    C_ATTACK, bold=True, fs=7.8)

# Row 3: per-client config
box(ax, 2.6, 2.65, 4.8, 0.72,
    "Per-client attack configuration", "#E69F00", tc="black")

# Row 4: client train + server poison
box(ax, 0.2, 1.45, 4.6, 0.82,
    "Client training + data poison\n(label flip, backdoor)", C_SETUP, tc="black", fs=8.0)
box(ax, 5.2, 1.45, 4.6, 0.82,
    "Server update poison + stealth cap\n(Gaussian, sign flip, ALIE, mean shift)",
    C_ATTACK, fs=7.8)

# Row 5: eval + logs
box(ax, 0.2, 0.3, 5.6, 0.72,
    "Central + client evaluation metrics, per-round logs", C_EVAL)
box(ax, 6.1, 0.3, 3.7, 0.72,
    "Reproducible traces\n(config, selections, rewards)", C_EVAL, fs=7.6)

# ---- arrows (forward flow) ----
arrow(ax, (2.9, 5.95), (3.4, 5.95))                      # config -> setup
arrow(ax, (1.55, 5.55), (2.3, 4.75))                     # config -> attack selector
arrow(ax, (4.8, 4.25), (5.2, 4.25))                      # selector -> scheduler
arrow(ax, (5.0, 3.75), (5.0, 3.37))                      # dims -> per-client config
arrow(ax, (3.4, 2.65), (2.6, 2.27))                      # per-client -> client train
arrow(ax, (6.6, 2.65), (7.4, 2.27))                      # per-client -> server poison
arrow(ax, (4.8, 1.86), (5.2, 1.86))                      # client -> server poison
arrow(ax, (9.0, 2.27), (8.3, 5.55), rad=0.18)            # server poison -> defense (up, bows right)
arrow(ax, (7.2, 5.55), (5.5, 1.02), rad=0.16)            # defense -> eval metrics (down, bows left)
arrow(ax, (3.0, 1.45), (3.0, 1.02))                      # client -> eval
arrow(ax, (5.8, 0.66), (6.1, 0.66))                      # eval -> traces

# ---- feedback arrow (dashed, purple) ----
arrow(ax, (0.9, 1.02), (0.9, 3.75), color=C_FB, style=(0, (4, 2)), lw=1.6, rad=0.0)
ax.text(0.55, 2.5, "feedback\n(malicious-client\naccuracy)", ha="center", va="center",
        fontsize=6.8, color=C_FB, rotation=90)

# caption-style note inside the figure
ax.text(5.0, 0.03, "Every block is a configuration field. Shaded attack-side blocks are the two dimensions this paper varies.",
        ha="center", va="top", fontsize=6.6, color="#555555")

fig.tight_layout(pad=0.3)
for d in (FIGDIR, FIGDIR2):
    fig.savefig(os.path.join(d, "fig_framework.pdf"))
    fig.savefig(os.path.join(d, "fig_framework.png"), dpi=200)
plt.close(fig)
print("wrote fig_framework.pdf/png to", FIGDIR, "and", FIGDIR2)
