"""
Auto-generate a Jupyter notebook report for a completed FL experiment run.

Reads the run directory's CSVs, JSONs, and analysis output to produce a
self-contained report.ipynb with executable chart cells.

Usage:
    python scripts/generate_run_report.py <run_dir>
"""

import argparse
import json
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

import nbformat
from nbformat.v4 import new_notebook, new_markdown_cell, new_code_cell

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from scripts.post_run_analysis import load_run_data

TRUST_STRATEGIES = {"fltrust", "foolsgold", "flram", "mab-rfl"}
FILTER_STRATEGIES = {"bulyan", "multikrum", "krum"}

ATTACK_COLORS = {
    "gaussian_noise": "#7570b3",
    "sign_flip": "#e7298a",
    "alie": "#66a61e",
    "mean_shift": "#e6ab02",
    "label_flip": "#a6761d",
    "backdoor": "#d95f02",
}

SEVERITY_LABELS = {
    "critical": "**CRITICAL**",
    "high": "**HIGH**",
    "medium": "MEDIUM",
    "low": "low",
}


# ── Helpers ──────────────────────────────────────────────────────────────────


def _load_analysis_json(run_dir: Path) -> Dict:
    p = run_dir / "summaries" / "run_analysis.json"
    if not p.exists():
        return {}
    with open(p) as f:
        return json.load(f)


def _count_classes(run_dir: Path) -> int:
    metrics = run_dir / "metrics"
    if not metrics.is_dir():
        return 0
    return len(list(metrics.glob("evaluate_server__class_*_accuracy.csv")))


def _has_file(run_dir: Path, relpath: str) -> bool:
    return (run_dir / relpath).exists()


def _strategy_type(strategy: str) -> str:
    s = strategy.lower().replace("_", "-")
    if s in TRUST_STRATEGIES:
        return "trust"
    if s in FILTER_STRATEGIES:
        return "filter"
    return "coordinate"


def _esc(s: str) -> str:
    """Escape a string for safe embedding in a Python string literal."""
    return s.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')


# ── Cell builders ────────────────────────────────────────────────────────────


def _cell_title(rc: Dict, meta: Dict, analysis: Dict) -> List:
    strategy = rc.get("strategy", meta.get("strategy", "unknown"))
    dataset = rc.get("dataset", meta.get("dataset", "unknown"))
    ts = meta.get("timestamp", analysis.get("meta", {}).get("timestamp", ""))
    trajectory = analysis.get("accuracy", {}).get("trajectory", "")
    traj_badge = f" | Trajectory: **{trajectory}**" if trajectory else ""

    title = f"# FL Experiment Report: {strategy.upper()} on {dataset}\n"
    title += f"*Run timestamp: {ts}{traj_badge}*\n"

    toc = textwrap.dedent("""\
    ---
    **Contents**

    1. [Overview](#1-overview)
    2. [Accuracy & Loss](#2-accuracy--loss)
    3. [Classification Metrics](#3-classification-metrics)
    4. [Attack Analysis](#4-attack-analysis)
    5. [Defense Behavior](#5-defense-behavior)
    6. [Per-Class Accuracy](#6-per-class-accuracy)
    7. [Backdoor ASR](#7-backdoor-asr)
    8. [Findings & Suggestions](#8-findings--suggestions)
    9. [Database Lookup](#9-database-lookup)
    """)

    return [new_markdown_cell(title), new_markdown_cell(toc)]


def _cell_setup(run_dir: Path) -> List:
    run_dir_str = str(run_dir)
    code = textwrap.dedent(f"""\
    import csv, json, glob, os, warnings
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import seaborn as sns
    from pathlib import Path

    warnings.filterwarnings("ignore", category=FutureWarning)

    RUN_DIR = Path(r"{run_dir_str}")

    # Style
    plt.rcParams.update({{
        "figure.dpi": 140,
        "savefig.dpi": 220,
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.labelsize": 11,
        "legend.fontsize": 9,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "axes.grid": True,
        "grid.alpha": 0.25,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "lines.linewidth": 2.2,
        "axes.edgecolor": "#111111",
        "axes.linewidth": 1.1,
    }})

    COLORS = {{
        "accuracy": "#2166ac",
        "loss": "#b2182b",
        "f1": "#1b7837",
        "precision": "#762a83",
        "recall": "#e66101",
        "honest": "#31a354",
        "malicious": "#de2d26",
        "neutral": "#636363",
    }}

    ATTACK_COLORS = {{
        "gaussian_noise": "#7570b3",
        "sign_flip": "#e7298a",
        "alie": "#66a61e",
        "mean_shift": "#e6ab02",
        "label_flip": "#a6761d",
        "backdoor": "#d95f02",
    }}

    FIG_DIR = RUN_DIR / "report_figures"
    FIG_DIR.mkdir(exist_ok=True)


    def load_server_metric(name):
        \"\"\"Load a 2-column server metric CSV (round, value).\"\"\"
        p = RUN_DIR / "metrics" / f"evaluate_server__{{name}}.csv"
        if not p.exists():
            return None
        df = pd.read_csv(p)
        return df

    def load_csv(relpath):
        p = RUN_DIR / relpath
        if not p.exists():
            return None
        return pd.read_csv(p)

    def load_json(relpath):
        p = RUN_DIR / relpath
        if not p.exists():
            return None
        with open(p) as f:
            return json.load(f)

    analysis = load_json("summaries/run_analysis.json") or {{}}
    config = load_json("summaries/run_config_and_summary.json") or {{}}
    meta = load_json("meta.json") or {{}}
    malicious_ids = set(str(x) for x in config.get("ever_malicious_client_ids", []))
    print(f"Report for: {{RUN_DIR.name}}")
    print(f"Figures will be saved to: {{FIG_DIR}}")
    """)
    return [new_code_cell(code)]


def _cell_overview(rc: Dict, meta: Dict, analysis: Dict) -> List:
    strategy = rc.get("strategy", "unknown")
    dataset = rc.get("dataset", "unknown")
    partitioner = rc.get("partitioner", "unknown")
    alpha = rc.get("dirichlet-alpha", "N/A")
    rounds = rc.get("num-server-rounds", "?")

    acc = analysis.get("accuracy", {})
    atk = analysis.get("attack", {})
    findings = analysis.get("findings", [])

    final_acc = f"{acc.get('final', 'N/A'):.4f}" if isinstance(acc.get("final"), (int, float)) else "N/A"
    peak_acc = f"{acc.get('peak', 'N/A'):.4f}" if isinstance(acc.get("peak"), (int, float)) else "N/A"
    trajectory = acc.get("trajectory", "N/A")

    f1_final = analysis.get("f1_macro", {}).get("final")
    f1_str = f"{f1_final:.4f}" if isinstance(f1_final, (int, float)) else "N/A"

    if atk.get("active"):
        attack_line = f"{atk.get('mode', '?')} ({atk.get('selection_mode', '?')}, {atk.get('malicious_fraction', '?'):.0%} malicious)"
        dominant = atk.get("dominant_attack", "N/A")
        dominant_frac = atk.get("dominant_fraction", 0)
        dominant_str = f"{dominant} ({dominant_frac:.0%} of rounds)"
    else:
        attack_line = "Clean Baseline — No attacks"
        dominant_str = "N/A"

    verdict = "No vulnerability findings"
    for f in findings:
        if f.get("severity") == "critical":
            verdict = f"CRITICAL: {f.get('description', 'Defense collapse detected')}"
            break
        if f.get("severity") == "high":
            verdict = f"HIGH: {f.get('description', 'Significant vulnerability')}"

    md = textwrap.dedent(f"""\
    ## 1. Overview

    | Parameter | Value |
    |-----------|-------|
    | **Strategy** | {strategy} |
    | **Dataset** | {dataset} |
    | **Partitioner** | {partitioner} (alpha={alpha}) |
    | **Rounds** | {rounds} |
    | **Attack** | {attack_line} |
    | **Dominant Attack** | {dominant_str} |
    | **Final Accuracy** | {final_acc} |
    | **Peak Accuracy** | {peak_acc} |
    | **Trajectory** | {trajectory} |
    | **Final F1 (macro)** | {f1_str} |
    | **Verdict** | {verdict} |
    """)

    return [new_markdown_cell(md)]


def _cell_accuracy_loss(run_dir: Path, analysis: Dict) -> List:
    cells = [new_markdown_cell("## 2. Accuracy & Loss")]
    has_attacks = analysis.get("attack", {}).get("active", False)

    attack_overlay_code = ""
    if has_attacks and _has_file(run_dir, "summaries/attack_timeline.csv"):
        attack_overlay_code = textwrap.dedent("""\
        timeline = load_csv("summaries/attack_timeline.csv")
        if timeline is not None and not timeline.empty:
            for _, row in timeline.iterrows():
                r = row.get("round", None)
                aname = str(row.get("attack_name", ""))
                if r is not None and aname:
                    color = ATTACK_COLORS.get(aname, "#cccccc")
                    ax.axvspan(r - 0.5, r + 0.5, alpha=0.15, color=color, linewidth=0)
            used = timeline["attack_name"].dropna().unique()
            patches = [mpatches.Patch(color=ATTACK_COLORS.get(a, "#ccc"), alpha=0.4, label=a)
                       for a in used if a in ATTACK_COLORS]
            if patches:
                ax.legend(handles=patches, loc="upper right", fontsize=8, framealpha=0.8)
        """)

    acc_code = textwrap.dedent(f"""\
    acc = load_server_metric("accuracy")
    if acc is not None:
        fig, ax = plt.subplots(figsize=(12, 5))
        ax.plot(acc["round"], acc["value"], color=COLORS["accuracy"], label="Accuracy")
        ax.set_xlabel("Round")
        ax.set_ylabel("Accuracy")
        ax.set_title("Global Accuracy with Attack Overlay")
        ax.set_ylim(bottom=0)
    {textwrap.indent(attack_overlay_code, "    ")}
        plt.tight_layout()
        plt.savefig(FIG_DIR / "accuracy_trajectory.png", bbox_inches="tight")
        plt.show()
    else:
        print("Accuracy data not available.")
    """)
    cells.append(new_code_cell(acc_code))

    loss_code = textwrap.dedent(f"""\
    loss = load_server_metric("loss")
    if loss is not None:
        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(loss["round"], loss["value"], color=COLORS["loss"], label="Loss")
        ax.set_xlabel("Round")
        ax.set_ylabel("Loss")
        ax.set_title("Server Loss")
    {textwrap.indent(attack_overlay_code, "    ")}
        plt.tight_layout()
        plt.savefig(FIG_DIR / "loss_trajectory.png", bbox_inches="tight")
        plt.show()
    else:
        print("Loss data not available.")
    """)
    cells.append(new_code_cell(loss_code))

    return cells


def _cell_classification_metrics(run_dir: Path) -> List:
    cells = [new_markdown_cell("## 3. Classification Metrics")]

    code = textwrap.dedent("""\
    metric_pairs = [
        ("F1 Score", "f1_macro", "f1_weighted", COLORS["f1"]),
        ("Precision", "precision_macro", "precision_weighted", COLORS["precision"]),
        ("Recall", "recall_macro", "recall_weighted", COLORS["recall"]),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    axes = axes.flatten()

    for idx, (label, macro_name, weighted_name, color) in enumerate(metric_pairs):
        ax = axes[idx]
        macro = load_server_metric(macro_name)
        weighted = load_server_metric(weighted_name)
        if macro is not None:
            ax.plot(macro["round"], macro["value"], color=color, linestyle="-",
                    label=f"{label} (macro)")
        if weighted is not None:
            ax.plot(weighted["round"], weighted["value"], color=color, linestyle="--",
                    alpha=0.6, label=f"{label} (weighted)")
        ax.set_title(label)
        ax.set_xlabel("Round")
        ax.set_ylabel(label)
        ax.set_ylim(bottom=0)
        ax.legend(fontsize=8)

    ax = axes[3]
    for label, macro_name, _, color in metric_pairs:
        macro = load_server_metric(macro_name)
        if macro is not None:
            ax.plot(macro["round"], macro["value"], color=color, label=f"{label} (macro)")
    ax.set_title("All Metrics (Macro)")
    ax.set_xlabel("Round")
    ax.set_ylabel("Score")
    ax.set_ylim(bottom=0)
    ax.legend(fontsize=8)

    plt.suptitle("Classification Metrics Over Rounds", fontsize=14, y=1.01)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "classification_metrics.png", bbox_inches="tight")
    plt.show()
    """)
    cells.append(new_code_cell(code))

    return cells


def _cell_attack_analysis(run_dir: Path, rc: Dict, analysis: Dict) -> List:
    atk = analysis.get("attack", {})
    if not atk.get("active"):
        return [new_markdown_cell(
            "## 4. Attack Analysis\n\n*This is a clean baseline run — no attacks were applied.*"
        )]

    cells = [new_markdown_cell("## 4. Attack Analysis")]

    counts = atk.get("all_attack_counts", {})
    counts_repr = repr(counts)
    bar_code = textwrap.dedent(f"""\
    attack_counts = {counts_repr}
    if attack_counts:
        sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
        names = [a[0] for a in sorted_attacks]
        vals = [a[1] for a in sorted_attacks]
        colors = [ATTACK_COLORS.get(n, "#999999") for n in names]

        fig, ax = plt.subplots(figsize=(8, max(3, len(names) * 0.6)))
        bars = ax.barh(names, vals, color=colors, edgecolor="white", linewidth=0.5)
        ax.set_xlabel("Number of Rounds")
        ax.set_title("Attack Type Frequency")
        ax.invert_yaxis()
        for bar, v in zip(bars, vals):
            ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                    str(v), va="center", fontsize=9)
        plt.tight_layout()
        plt.savefig(FIG_DIR / "attack_frequency.png", bbox_inches="tight")
        plt.show()
    """)
    cells.append(new_code_cell(bar_code))

    if _has_file(run_dir, "summaries/attack_timeline.csv"):
        timeline_code = textwrap.dedent("""\
        timeline = load_csv("summaries/attack_timeline.csv")
        if timeline is not None and not timeline.empty:
            fig, ax = plt.subplots(figsize=(14, 4))
            unique_attacks = timeline["attack_name"].dropna().unique()
            attack_to_y = {a: i for i, a in enumerate(sorted(unique_attacks))}

            for _, row in timeline.iterrows():
                r = row.get("round")
                aname = str(row.get("attack_name", ""))
                intensity = float(row.get("intensity", 0.5))
                if r is not None and aname in attack_to_y:
                    color = ATTACK_COLORS.get(aname, "#999999")
                    ax.scatter(r, attack_to_y[aname], c=color, s=80 + 120 * intensity,
                               alpha=0.7, edgecolors="white", linewidth=0.5, zorder=3)

            ax.set_yticks(list(attack_to_y.values()))
            ax.set_yticklabels(list(attack_to_y.keys()))
            ax.set_xlabel("Round")
            ax.set_title("Attack Timeline (size = intensity)")
            ax.set_xlim(0.5, timeline["round"].max() + 0.5)
            plt.tight_layout()
            plt.savefig(FIG_DIR / "attack_timeline.png", bbox_inches="tight")
            plt.show()
        """)
        cells.append(new_code_cell(timeline_code))

    if _has_file(run_dir, "summaries/round_attack_stats.csv"):
        norm_code = textwrap.dedent("""\
        stats = load_csv("summaries/round_attack_stats.csv")
        if stats is not None and not stats.empty:
            fig, ax = plt.subplots(figsize=(12, 5))
            rounds = stats["round"]

            if "honest_norm_p50" in stats.columns:
                ax.plot(rounds, stats["honest_norm_p50"], color=COLORS["honest"],
                        label="Honest median norm", linewidth=2)
            if "honest_norm_p90" in stats.columns:
                ax.plot(rounds, stats["honest_norm_p90"], color=COLORS["honest"],
                        linestyle="--", alpha=0.5, label="Honest p90 norm")
            if "honest_norm_p50" in stats.columns and "honest_norm_p90" in stats.columns:
                ax.fill_between(rounds, stats["honest_norm_p50"], stats["honest_norm_p90"],
                                color=COLORS["honest"], alpha=0.1)

            if "max_mal_norm_pre" in stats.columns:
                pre = pd.to_numeric(stats["max_mal_norm_pre"], errors="coerce")
                ax.plot(rounds, pre, color=COLORS["malicious"],
                        label="Malicious max norm (pre-stealth)", linewidth=2)
            if "max_mal_norm_post" in stats.columns:
                post = pd.to_numeric(stats["max_mal_norm_post"], errors="coerce")
                valid = post.notna()
                if valid.any():
                    ax.plot(rounds[valid], post[valid], color=COLORS["malicious"],
                            linestyle="--", alpha=0.7, label="Malicious max norm (post-stealth)")

            ax.set_xlabel("Round")
            ax.set_ylabel("Update Norm")
            ax.set_title("Update Norm Comparison: Honest vs. Malicious")
            ax.legend(fontsize=8)
            plt.tight_layout()
            plt.savefig(FIG_DIR / "norm_comparison.png", bbox_inches="tight")
            plt.show()
        """)
        cells.append(new_code_cell(norm_code))

    return cells


def _cell_defense_behavior(run_dir: Path, rc: Dict, analysis: Dict) -> List:
    strategy = rc.get("strategy", "").lower().replace("_", "-")
    stype = _strategy_type(strategy)

    cells = [new_markdown_cell(f"## 5. Defense Behavior: {strategy}")]

    if stype == "trust":
        if _has_file(run_dir, "summaries/trust_strategy_by_round.csv"):
            trust_avg_code = textwrap.dedent("""\
            trust_df = load_csv("summaries/trust_strategy_by_round.csv")
            if trust_df is not None and not trust_df.empty and "trust_score" in trust_df.columns:
                trust_df["trust_score"] = pd.to_numeric(trust_df["trust_score"], errors="coerce")
                trust_df["client_id"] = trust_df["client_id"].astype(str)
                trust_df["is_malicious"] = trust_df["client_id"].isin(malicious_ids)

                grouped = trust_df.groupby(["round", "is_malicious"])["trust_score"]
                avg = grouped.mean().unstack(fill_value=np.nan)
                lo = grouped.min().unstack(fill_value=np.nan)
                hi = grouped.max().unstack(fill_value=np.nan)

                fig, ax = plt.subplots(figsize=(12, 5))
                if True in avg.columns:
                    ax.plot(avg.index, avg[True], color=COLORS["malicious"],
                            label="Malicious (avg)", linewidth=2)
                    ax.fill_between(avg.index, lo[True], hi[True],
                                    color=COLORS["malicious"], alpha=0.1)
                if False in avg.columns:
                    ax.plot(avg.index, avg[False], color=COLORS["honest"],
                            label="Benign (avg)", linewidth=2)
                    ax.fill_between(avg.index, lo[False], hi[False],
                                    color=COLORS["honest"], alpha=0.1)

                ax.set_xlabel("Round")
                ax.set_ylabel("Trust Score")
                ax.set_title("Trust Scores Over Time: Malicious vs. Benign")
                ax.legend(fontsize=9)
                plt.tight_layout()
                plt.savefig(FIG_DIR / "trust_over_time.png", bbox_inches="tight")
                plt.show()
            """)
            cells.append(new_code_cell(trust_avg_code))

            trust_heat_code = textwrap.dedent("""\
            trust_df = load_csv("summaries/trust_strategy_by_round.csv")
            if trust_df is not None and not trust_df.empty and "trust_score" in trust_df.columns:
                trust_df["trust_score"] = pd.to_numeric(trust_df["trust_score"], errors="coerce")
                trust_df["client_id"] = trust_df["client_id"].astype(str)

                pivot = trust_df.pivot_table(index="client_id", columns="round",
                                             values="trust_score", aggfunc="first")
                pivot = pivot.sort_index()

                n_clients = len(pivot)
                n_rounds = len(pivot.columns)
                fig_h = max(4, n_clients * 0.12)
                fig_w = max(10, n_rounds * 0.4)

                fig, ax = plt.subplots(figsize=(min(fig_w, 18), min(fig_h, 14)))
                sns.heatmap(pivot.astype(float), cmap="viridis", vmin=0, vmax=1,
                            ax=ax, cbar_kws={"label": "Trust Score"}, linewidths=0)

                yticks = ax.get_yticklabels()
                for t in yticks:
                    if t.get_text() in malicious_ids:
                        t.set_color(COLORS["malicious"])
                        t.set_fontweight("bold")
                ax.set_yticklabels(yticks, fontsize=6)
                ax.set_xlabel("Round")
                ax.set_ylabel("Client ID")
                ax.set_title("Per-Client Trust Heatmap (red labels = malicious)")
                plt.tight_layout()
                plt.savefig(FIG_DIR / "trust_heatmap.png", bbox_inches="tight")
                plt.show()
            """)
            cells.append(new_code_cell(trust_heat_code))
        else:
            cells.append(new_markdown_cell(
                "*Trust score data not available for this run.*"
            ))

    elif stype == "filter":
        if _has_file(run_dir, "summaries/defense_selection_by_round.csv"):
            filter_code = textwrap.dedent("""\
            sel_df = load_csv("summaries/defense_selection_by_round.csv")
            if sel_df is not None and not sel_df.empty:
                rounds = sel_df["round"].values
                total_sel = sel_df["num_selected_by_defense"].values
                mal_sel = sel_df["num_malicious_selected_by_defense"].values
                honest_sel = total_sel - mal_sel
                slip_rate = sel_df["malicious_selected_fraction"].values

                fig, ax1 = plt.subplots(figsize=(12, 5))
                ax1.bar(rounds, honest_sel, color=COLORS["honest"], label="Honest selected",
                        alpha=0.8, edgecolor="white", linewidth=0.5)
                ax1.bar(rounds, mal_sel, bottom=honest_sel, color=COLORS["malicious"],
                        label="Malicious selected", alpha=0.8, edgecolor="white", linewidth=0.5)
                ax1.set_xlabel("Round")
                ax1.set_ylabel("Clients Selected")
                ax1.set_title("Defense Filtering: Honest vs. Malicious Selection")

                ax2 = ax1.twinx()
                ax2.plot(rounds, slip_rate, color="#333333", linestyle="--",
                         linewidth=1.5, label="Slipthrough rate", marker="o", markersize=3)
                ax2.set_ylabel("Slipthrough Rate")
                ax2.set_ylim(0, 1)

                lines1, labels1 = ax1.get_legend_handles_labels()
                lines2, labels2 = ax2.get_legend_handles_labels()
                ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right", fontsize=8)

                plt.tight_layout()
                plt.savefig(FIG_DIR / "defense_filtering.png", bbox_inches="tight")
                plt.show()
            """)
            cells.append(new_code_cell(filter_code))
        else:
            cells.append(new_markdown_cell(
                "*Defense selection data not available for this run.*"
            ))

    else:
        cells.append(new_markdown_cell(
            f"*{strategy} is a coordinate-wise aggregation method and does not produce "
            f"per-client selection or trust data. See the norm comparison in Section 4 "
            f"for insight into how honest vs. malicious updates compared.*"
        ))

    return cells


def _cell_per_class(run_dir: Path, rc: Dict) -> List:
    n_classes = _count_classes(run_dir)
    if n_classes == 0:
        return [new_markdown_cell(
            "## 6. Per-Class Accuracy\n\n*Per-class accuracy data not available.*"
        )]

    cells = [new_markdown_cell("## 6. Per-Class Accuracy")]

    code = textwrap.dedent(f"""\
    n_classes = {n_classes}
    class_data = {{}}
    for i in range(n_classes):
        df = load_server_metric(f"class_{{i}}_accuracy")
        if df is not None:
            class_data[i] = df.set_index("round")["value"]

    if class_data:
        combined = pd.DataFrame(class_data)
        combined = combined.sort_index()

        fig_h = max(4, n_classes * 0.15)
        fig_w = max(10, len(combined) * 0.4)

        fig, ax = plt.subplots(figsize=(min(fig_w, 18), min(fig_h, 16)))
        sns.heatmap(combined.T, cmap="RdYlGn", vmin=0, vmax=1, ax=ax,
                    cbar_kws={{"label": "Accuracy"}}, linewidths=0)
        ax.set_xlabel("Round")
        ax.set_ylabel("Class")
        ax.set_title(f"Per-Class Accuracy Over Rounds ({{n_classes}} classes)")

        if n_classes > 30:
            ax.set_yticklabels(ax.get_yticklabels(), fontsize=5)
        plt.tight_layout()
        plt.savefig(FIG_DIR / "per_class_heatmap.png", bbox_inches="tight")
        plt.show()
    else:
        print("No per-class accuracy data found.")
    """)
    cells.append(new_code_cell(code))

    return cells


def _cell_backdoor_asr(run_dir: Path, analysis: Dict) -> List:
    asr_data = analysis.get("backdoor_asr", {})
    peak_asr = asr_data.get("peak", 0)
    if peak_asr <= 0 and not _has_file(run_dir, "metrics/evaluate_server__backdoor_asr.csv"):
        return [new_markdown_cell(
            "## 7. Backdoor ASR\n\n*No backdoor attack data in this run.*"
        )]

    cells = [new_markdown_cell("## 7. Backdoor ASR")]

    code = textwrap.dedent("""\
    asr = load_server_metric("backdoor_asr")
    acc = load_server_metric("accuracy")
    if asr is not None and acc is not None:
        fig, ax1 = plt.subplots(figsize=(12, 5))
        ax1.plot(acc["round"], acc["value"], color=COLORS["accuracy"],
                 label="Accuracy", linewidth=2)
        ax1.set_xlabel("Round")
        ax1.set_ylabel("Accuracy", color=COLORS["accuracy"])
        ax1.set_ylim(bottom=0)
        ax1.tick_params(axis="y", labelcolor=COLORS["accuracy"])

        ax2 = ax1.twinx()
        ax2.plot(asr["round"], asr["value"], color=COLORS["malicious"],
                 label="Backdoor ASR", linewidth=2, linestyle="--")
        ax2.set_ylabel("Backdoor ASR", color=COLORS["malicious"])
        ax2.set_ylim(0, 1)
        ax2.tick_params(axis="y", labelcolor=COLORS["malicious"])

        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right", fontsize=9)
        ax1.set_title("Accuracy vs. Backdoor Attack Success Rate")
        plt.tight_layout()
        plt.savefig(FIG_DIR / "backdoor_asr.png", bbox_inches="tight")
        plt.show()
    elif asr is not None:
        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(asr["round"], asr["value"], color=COLORS["malicious"], label="Backdoor ASR")
        ax.set_xlabel("Round")
        ax.set_ylabel("ASR")
        ax.set_title("Backdoor Attack Success Rate")
        ax.set_ylim(0, 1)
        plt.tight_layout()
        plt.savefig(FIG_DIR / "backdoor_asr.png", bbox_inches="tight")
        plt.show()
    else:
        print("Backdoor ASR data not available.")
    """)
    cells.append(new_code_cell(code))

    return cells


def _cell_findings_suggestions(analysis: Dict) -> List:
    cells = [new_markdown_cell("## 8. Findings & Suggestions")]

    findings = analysis.get("findings", [])
    if findings:
        lines = ["### Findings\n"]
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "unknown")
            sev_label = SEVERITY_LABELS.get(sev, sev)
            pattern = f.get("pattern", "unknown").replace("_", " ").title()
            desc = f.get("description", "")
            atlas = f.get("atlas_technique_ids", [])
            novelty = f.get("novelty_status", "")

            lines.append(f"**{i}. {pattern}** — Severity: {sev_label}\n")
            lines.append(f"> {desc}\n")
            if atlas:
                lines.append(f"> ATLAS: {', '.join(atlas)}\n")
            if novelty:
                lines.append(f"> Novelty: {novelty.replace('_', ' ')}\n")
            lines.append("")
        cells.append(new_markdown_cell("\n".join(lines)))
    else:
        cells.append(new_markdown_cell(
            "*No vulnerability findings were detected in this run.*"
        ))

    suggestions = analysis.get("suggestions", [])
    if suggestions:
        lines = ["### Suggestions\n"]
        for i, s in enumerate(suggestions, 1):
            lines.append(f"**{i}.** {s.get('text', '')}\n")
            pchanges = s.get("param_changes", [])
            if pchanges:
                lines.append("| Parameter | Current | Suggested |")
                lines.append("|-----------|---------|-----------|")
                for pc in pchanges:
                    lines.append(
                        f"| `{pc.get('param', '')}` | {pc.get('current', '')} | {pc.get('suggested', '')} |"
                    )
                lines.append("")
        cells.append(new_markdown_cell("\n".join(lines)))
    else:
        cells.append(new_markdown_cell(
            "*No specific parameter changes suggested.*"
        ))

    return cells


def _cell_db_lookup(run_dir: Path) -> List:
    cells = [new_markdown_cell("## 9. Database Lookup")]

    run_basename = run_dir.name
    db_path = str(_PROJECT_ROOT / "db" / "dynamic_fl.sqlite")

    code = textwrap.dedent(f"""\
    import sqlite3

    DB_PATH = r"{db_path}"
    RUN_BASENAME = "{_esc(run_basename)}"

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT * FROM runs WHERE run_folder LIKE ?", (f"%{{RUN_BASENAME}}%",))
        row = cur.fetchone()

        if row:
            print("=== Run Found in Database ===")
            for key in ["run_id", "strategy", "dataset", "attack_mode",
                        "selection_mode", "layering_mode", "malicious_fraction"]:
                if key in row.keys():
                    print(f"  {{key:25s}}: {{row[key]}}")

            run_id = row["run_id"]

            cur.execute(\"\"\"
                SELECT metric_name, metric_value FROM round_metrics
                WHERE run_id = ? AND round = (
                    SELECT MAX(round) FROM round_metrics WHERE run_id = ?
                )
                AND metric_name IN ('accuracy', 'loss', 'f1_macro')
            \"\"\", (run_id, run_id))
            final_metrics = cur.fetchall()
            if final_metrics:
                print("\\n  Final Metrics:")
                for m in final_metrics:
                    print(f"    {{m['metric_name']:25s}}: {{m['metric_value']:.4f}}")

            cur.execute(\"\"\"
                SELECT accuracy_drop, f1_macro_drop, clean_final_accuracy,
                       attacked_final_accuracy
                FROM baseline_comparisons WHERE attacked_run_id = ?
            \"\"\", (run_id,))
            bc = cur.fetchone()
            if bc:
                print("\\n  Baseline Comparison:")
                print(f"    Baseline accuracy     : {{bc['clean_final_accuracy']:.4f}}")
                print(f"    Attacked accuracy     : {{bc['attacked_final_accuracy']:.4f}}")
                print(f"    Accuracy drop         : {{bc['accuracy_drop']:.4f}}")
                if bc['f1_macro_drop'] is not None:
                    print(f"    F1 macro drop         : {{bc['f1_macro_drop']:.4f}}")

        else:
            print("Run not found in database.")
            print(f"To ingest, run: python db/ingest.py <sweep_dir>")

        conn.close()
    except Exception as e:
        print(f"Database lookup failed: {{e}}")
        print("This is expected if the run has not been ingested into the database yet.")
        print(f"To ingest, run: python db/ingest.py <sweep_dir>")
    """)
    cells.append(new_code_cell(code))

    md = textwrap.dedent("""\
    **How to use the database:**
    - **Ingest a sweep:** `python db/ingest.py <sweep_dir>`
    - **Query a run:** `python scripts/query_run.py <run_dir>`
    - **Full docs:** See `docs/DATABASE_WORKFLOW.md`
    """)
    cells.append(new_markdown_cell(md))

    return cells


# ── Main ─────────────────────────────────────────────────────────────────────


def build_notebook(run_dir: Path) -> nbformat.NotebookNode:
    data = load_run_data(run_dir)
    analysis = _load_analysis_json(run_dir)
    meta = data["meta"]
    rc = data["run_config"]

    nb = new_notebook()
    nb.metadata["kernelspec"] = {
        "display_name": "Python 3",
        "language": "python",
        "name": "python3",
    }
    nb.metadata["language_info"] = {
        "name": "python",
        "version": "3.10.0",
    }

    cells: List = []
    cells += _cell_title(rc, meta, analysis)
    cells += _cell_setup(run_dir)
    cells += _cell_overview(rc, meta, analysis)
    cells += _cell_accuracy_loss(run_dir, analysis)
    cells += _cell_classification_metrics(run_dir)
    cells += _cell_attack_analysis(run_dir, rc, analysis)
    cells += _cell_defense_behavior(run_dir, rc, analysis)
    cells += _cell_per_class(run_dir, rc)
    cells += _cell_backdoor_asr(run_dir, analysis)
    cells += _cell_findings_suggestions(analysis)
    cells += _cell_db_lookup(run_dir)

    nb.cells = cells
    return nb


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Jupyter notebook report for a completed FL run."
    )
    parser.add_argument("run_dir", type=Path, help="Path to the run output directory")
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    if not run_dir.is_dir():
        print(f"Error: {run_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    try:
        nb = build_notebook(run_dir)
        out_path = run_dir / "report.ipynb"
        nbformat.write(nb, str(out_path))
        print(f"Notebook report saved: {out_path}")
        print(f"Open in Jupyter/VS Code and run all cells to render charts.")
    except Exception as exc:
        print(f"Warning: notebook generation failed: {exc}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
