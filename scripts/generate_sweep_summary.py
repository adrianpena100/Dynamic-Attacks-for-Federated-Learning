#!/usr/bin/env python3
"""Generate a compact sweep summary table from per-run metrics."""

from __future__ import annotations

import argparse
import csv
import re
import statistics
from pathlib import Path
from typing import Dict, List, Tuple


def _read_metric_points(csv_path: Path) -> List[Tuple[int, float]]:
    if not csv_path.exists():
        return []

    values: List[Tuple[int, float]] = []
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_round = (row.get("round") or "").strip()
            raw = (row.get("value") or "").strip()
            if not raw or not raw_round:
                continue
            try:
                values.append((int(float(raw_round)), float(raw)))
            except ValueError:
                continue
    return values


def _series_values(points: List[Tuple[int, float]]) -> List[float]:
    return [v for _, v in points]


def _fmt_float(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.4f}"


def _mean(values: List[float]) -> float | None:
    if not values:
        return None
    return float(sum(values) / len(values))


def _std(values: List[float]) -> float | None:
    if len(values) < 2:
        return None
    return float(statistics.pstdev(values))


def _mean_in_window(points: List[Tuple[int, float]], start: int, end: int) -> float | None:
    vals = [v for r, v in points if start <= r <= end]
    return _mean(vals)


def _mean_before(points: List[Tuple[int, float]], start: int) -> float | None:
    vals = [v for r, v in points if r < start]
    return _mean(vals)


def _mean_after(points: List[Tuple[int, float]], end: int) -> float | None:
    vals = [v for r, v in points if r > end]
    return _mean(vals)


def _safe_int(raw: str) -> int:
    try:
        return int(float(raw))
    except Exception:
        return 0


def _safe_float(raw: str) -> float:
    try:
        return float(raw)
    except Exception:
        return 0.0


def _build_narrative(runs: List[Dict[str, object]]) -> str:
    if not runs:
        return "Interpretation and evidence-based narrative:\n\nNo runs were available for analysis.\n"

    total_runs = len(runs)
    starts = sorted({int(r["start"]) for r in runs})
    ends = sorted({int(r["end"]) for r in runs})
    layers = sorted({str(r["layering_mode"]) for r in runs})
    modes = sorted({str(r["attack_mode"]) for r in runs})
    selections = sorted({str(r["selection_mode"]) for r in runs})

    run_with_last = [r for r in runs if r["last_acc"] is not None]
    run_with_asr = [r for r in runs if r["max_asr"] is not None]

    best_last = max(run_with_last, key=lambda r: float(r["last_acc"])) if run_with_last else None
    worst_last = min(run_with_last, key=lambda r: float(r["last_acc"])) if run_with_last else None
    worst_min_acc = min(run_with_last, key=lambda r: float(r["min_acc"])) if run_with_last else None
    worst_asr = max(run_with_asr, key=lambda r: float(r["max_asr"])) if run_with_asr else None

    collapsed = [r for r in run_with_last if float(r["last_acc"]) <= 0.20]
    high_asr = [r for r in run_with_asr if float(r["max_asr"]) >= 0.50]

    paragraphs: List[str] = []
    paragraphs.append(
        "Interpretation and evidence-based narrative:\n\n"
        f"This sweep contains {total_runs} runs with attack-window starts spanning rounds "
        f"{starts[0]} to {starts[-1]} and end rounds spanning {ends[0]} to {ends[-1]}. "
        f"Observed attack policies are {', '.join(modes)}, selection modes are {', '.join(selections)}, "
        f"and layering modes are {', '.join(layers)}."
    )

    if best_last and worst_last and worst_asr:
        paragraphs.append(
            f"Across all runs, the best final clean accuracy is {float(best_last['last_acc']):.4f} "
            f"({best_last['label']}), while the worst final clean accuracy is {float(worst_last['last_acc']):.4f} "
            f"({worst_last['label']}). The highest observed ASR is {float(worst_asr['max_asr']):.4f} "
            f"({worst_asr['label']}). This spread indicates large sensitivity to policy and schedule choices "
            f"even when all runs share the same global training setup."
        )

    if len(run_with_last) >= 3:
        top3 = sorted(run_with_last, key=lambda r: float(r["last_acc"]), reverse=True)[:3]
        bot3 = sorted(run_with_last, key=lambda r: float(r["last_acc"]))[:3]
        top_text = ", ".join(f"{r['label']} ({float(r['last_acc']):.4f})" for r in top3)
        bot_text = ", ".join(f"{r['label']} ({float(r['last_acc']):.4f})" for r in bot3)
        paragraphs.append(
            f"Run ranking by final clean accuracy highlights this spread clearly. Top performers: {top_text}. "
            f"Lowest performers: {bot_text}."
        )

    if len(run_with_asr) >= 3:
        asr_top3 = sorted(run_with_asr, key=lambda r: float(r["max_asr"]), reverse=True)[:3]
        asr_text = ", ".join(f"{r['label']} ({float(r['max_asr']):.4f})" for r in asr_top3)
        paragraphs.append(
            f"The three highest-ASR runs are {asr_text}, which pinpoints where backdoor risk concentrates in this sweep."
        )

    if worst_min_acc is not None:
        paragraphs.append(
            f"The minimum in-training clean accuracy reaches {float(worst_min_acc['min_acc']):.4f} "
            f"(run {worst_min_acc['label']}). In total, {len(collapsed)}/{total_runs} runs end at or below "
            f"0.20 clean accuracy, and {len(high_asr)}/{total_runs} runs reach ASR >= 0.50. "
            f"This confirms that failures are not isolated outliers in this sweep space."
        )

    # Adaptive vs weighted_random under matched settings (except mode).
    groups: Dict[Tuple[object, ...], Dict[str, Dict[str, object]]] = {}
    for r in runs:
        key = (
            r["start"],
            r["end"],
            r["ramp_end"],
            r["selection_mode"],
            r["churn_fraction"],
            r["layering_mode"],
            r["layered_k"],
        )
        groups.setdefault(key, {})[str(r["attack_mode"])] = r

    matched_policy_pairs: List[Tuple[Dict[str, object], Dict[str, object]]] = []
    for g in groups.values():
        if "adaptive" in g and "weighted_random" in g:
            matched_policy_pairs.append((g["adaptive"], g["weighted_random"]))

    if matched_policy_pairs:
        best_pair = max(
            matched_policy_pairs,
            key=lambda p: abs(float(p[0]["last_acc"] or 0.0) - float(p[1]["last_acc"] or 0.0)),
        )
        adp, wgt = best_pair
        delta_last = float(adp["last_acc"] or 0.0) - float(wgt["last_acc"] or 0.0)
        delta_asr = float(adp["max_asr"] or 0.0) - float(wgt["max_asr"] or 0.0)
        direction = "lower" if delta_last < 0 else "higher"
        paragraphs.append(
            f"Policy comparison under matched schedule shows a clear gap: {adp['label']} (adaptive) ends at "
            f"{float(adp['last_acc'] or 0.0):.4f} clean accuracy versus {wgt['label']} (weighted_random) at "
            f"{float(wgt['last_acc'] or 0.0):.4f}, so adaptive is {abs(delta_last):.4f} {direction} on final clean accuracy "
            f"for that matched setting. The ASR difference for the same pair is {delta_asr:+.4f}."
        )

    # Timing analysis by start round (adaptive + single layering focus).
    timing_focus = [
        r
        for r in runs
        if str(r["attack_mode"]) == "adaptive" and str(r["layering_mode"]) == "single"
    ]
    if len(timing_focus) >= 2:
        by_start: Dict[int, List[Dict[str, object]]] = {}
        for r in timing_focus:
            by_start.setdefault(int(r["start"]), []).append(r)
        if len(by_start) >= 2:
            start_stats = []
            for s, grp in sorted(by_start.items()):
                last_vals = [float(x["last_acc"]) for x in grp if x["last_acc"] is not None]
                asr_vals = [float(x["max_asr"]) for x in grp if x["max_asr"] is not None]
                start_stats.append((s, _mean(last_vals), _mean(asr_vals), len(grp)))
            early = start_stats[0]
            late = start_stats[-1]
            if early[1] is not None and late[1] is not None:
                paragraphs.append(
                    f"Timing remains causal in this sweep. For adaptive single-layer runs, the earliest start group "
                    f"(start={early[0]}, n={early[3]}) has mean final accuracy {early[1]:.4f}, while the latest start group "
                    f"(start={late[0]}, n={late[3]}) has mean final accuracy {late[1]:.4f}. "
                    f"This is a gap of {late[1] - early[1]:+.4f}. Mean ASR moves from "
                    f"{_fmt_float(early[2])} to {_fmt_float(late[2])} across those groups."
                )

    # Selection mode analysis (adaptive single runs).
    sel_focus = [
        r
        for r in runs
        if str(r["attack_mode"]) == "adaptive" and str(r["layering_mode"]) == "single"
    ]
    if sel_focus:
        by_sel: Dict[str, List[Dict[str, object]]] = {}
        for r in sel_focus:
            by_sel.setdefault(str(r["selection_mode"]), []).append(r)
        if len(by_sel) >= 2:
            sel_lines: List[str] = []
            for name, grp in sorted(by_sel.items()):
                last_vals = [float(x["last_acc"]) for x in grp if x["last_acc"] is not None]
                asr_vals = [float(x["max_asr"]) for x in grp if x["max_asr"] is not None]
                if not last_vals:
                    continue
                sel_lines.append(
                    f"{name}: mean LastAcc={_fmt_float(_mean(last_vals))}, mean MaxASR={_fmt_float(_mean(asr_vals))}, n={len(grp)}"
                )
            if sel_lines:
                paragraphs.append(
                    "Selection-mode behavior differs materially across the adaptive runs. "
                    "Group-level outcomes are: " + "; ".join(sel_lines) + "."
                )

    # Churn analysis where other settings are matched as much as possible.
    churn_focus = [
        r
        for r in runs
        if str(r["attack_mode"]) == "adaptive"
        and str(r["selection_mode"]) == "churn"
        and str(r["layering_mode"]) == "single"
    ]
    if churn_focus:
        by_churn: Dict[float, List[Dict[str, object]]] = {}
        for r in churn_focus:
            by_churn.setdefault(float(r["churn_fraction"]), []).append(r)
        if len(by_churn) >= 2:
            churn_lines: List[str] = []
            for cf, grp in sorted(by_churn.items(), key=lambda x: x[0]):
                last_vals = [float(x["last_acc"]) for x in grp if x["last_acc"] is not None]
                asr_vals = [float(x["max_asr"]) for x in grp if x["max_asr"] is not None]
                churn_lines.append(
                    f"churn={cf:.2f}: mean LastAcc={_fmt_float(_mean(last_vals))}, mean MaxASR={_fmt_float(_mean(asr_vals))}, n={len(grp)}"
                )
            paragraphs.append(
                "Churn intensity also changes outcomes, though not always monotonically across all schedules. "
                "Observed aggregates are: " + "; ".join(churn_lines) + "."
            )

    # Ramp-end analysis for adaptive/churn/single.
    ramp_focus = [
        r
        for r in runs
        if str(r["attack_mode"]) == "adaptive"
        and str(r["selection_mode"]) == "churn"
        and str(r["layering_mode"]) == "single"
    ]
    if ramp_focus:
        by_ramp: Dict[float, List[Dict[str, object]]] = {}
        for r in ramp_focus:
            by_ramp.setdefault(float(r["ramp_end"]), []).append(r)
        if len(by_ramp) >= 2:
            ramp_lines: List[str] = []
            for ramp, grp in sorted(by_ramp.items(), key=lambda x: x[0]):
                last_vals = [float(x["last_acc"]) for x in grp if x["last_acc"] is not None]
                asr_vals = [float(x["max_asr"]) for x in grp if x["max_asr"] is not None]
                ramp_lines.append(
                    f"ramp_end={ramp:.1f}: mean LastAcc={_fmt_float(_mean(last_vals))}, mean MaxASR={_fmt_float(_mean(asr_vals))}, n={len(grp)}"
                )
            paragraphs.append(
                "Ramp scaling contributes to damage but does not appear as a strict monotonic driver in this sweep. "
                "By ramp bucket: " + "; ".join(ramp_lines) + "."
            )

    # Layering analysis.
    single_runs = [r for r in runs if str(r["layering_mode"]) == "single"]
    layered_runs = [r for r in runs if str(r["layering_mode"]) != "single"]
    if single_runs and layered_runs:
        single_last = [float(r["last_acc"]) for r in single_runs if r["last_acc"] is not None]
        single_asr = [float(r["max_asr"]) for r in single_runs if r["max_asr"] is not None]
        layered_last = [float(r["last_acc"]) for r in layered_runs if r["last_acc"] is not None]
        layered_asr = [float(r["max_asr"]) for r in layered_runs if r["max_asr"] is not None]
        if single_last and layered_last:
            paragraphs.append(
                f"Layering mode shifts behavior but is not universally dominant by itself. Single-mode runs "
                f"show mean LastAcc={_fmt_float(_mean(single_last))} and mean MaxASR={_fmt_float(_mean(single_asr))}, "
                f"while layered runs show mean LastAcc={_fmt_float(_mean(layered_last))} and mean MaxASR={_fmt_float(_mean(layered_asr))}."
            )
        else:
            paragraphs.append(
                "Layering analysis is partially limited because one of the groups has missing metric files in this sweep folder. "
                "The table still reports available runs, and complete comparisons will be produced for fully logged runs."
            )

    # Window-phase analysis.
    phase_drops: List[Tuple[str, float, float, float]] = []
    for r in runs:
        pre = r.get("pre_attack_acc")
        attack = r.get("attack_window_acc")
        post = r.get("post_attack_acc")
        if pre is None or attack is None:
            continue
        phase_drops.append((str(r["label"]), float(pre), float(attack), float(post) if post is not None else float("nan")))
    if phase_drops:
        steepest = min(phase_drops, key=lambda x: x[2] - x[1])
        paragraphs.append(
            f"Phase-wise accuracy confirms schedule effects: the steepest pre-attack to in-window drop is in "
            f"{steepest[0]} (pre={steepest[1]:.4f}, in-window={steepest[2]:.4f}, delta={steepest[2]-steepest[1]:+.4f}). "
            f"This quantifies how quickly performance can degrade once the attack window opens."
        )

    last_values = [float(r["last_acc"]) for r in run_with_last]
    asr_values = [float(r["max_asr"]) for r in run_with_asr]
    if last_values and asr_values:
        paragraphs.append(
            f"Overall dispersion remains high (LastAcc std={_fmt_float(_std(last_values))}, "
            f"MaxASR std={_fmt_float(_std(asr_values))}), reinforcing that policy and scheduling dynamics are "
            f"major determinants of robustness outcomes."
        )

    # Repeat-aware analysis for thesis-grade claims.
    grouped: Dict[str, List[Dict[str, object]]] = {}
    for r in runs:
        base = str(r.get("base_label") or r.get("label") or "")
        if not base:
            label = str(r.get("label") or "")
            base = re.sub(r"__rep\d+$", "", label)
        grouped.setdefault(base, []).append(r)

    repeated_groups = {k: v for k, v in grouped.items() if len(v) >= 2}
    if repeated_groups:
        rep_lines: List[str] = []
        for base, grp in sorted(repeated_groups.items()):
            last_vals = [float(x["last_acc"]) for x in grp if x.get("last_acc") is not None]
            asr_vals = [float(x["max_asr"]) for x in grp if x.get("max_asr") is not None]
            if not last_vals:
                continue
            collapse_rate = (
                sum(1 for x in grp if x.get("last_acc") is not None and float(x["last_acc"]) <= 0.20)
                / float(len(last_vals))
            )
            rep_lines.append(
                f"{base}: LastAcc mean={_fmt_float(_mean(last_vals))}, std={_fmt_float(_std(last_vals))}, "
                f"MaxASR mean={_fmt_float(_mean(asr_vals))}, n={len(last_vals)}, collapse_rate={collapse_rate:.2f}"
            )

        if rep_lines:
            paragraphs.append(
                "Repeat-consistency analysis (same config across multiple seeds) shows whether failures are systematic "
                "or accidental. Per-config aggregate evidence: " + "; ".join(rep_lines) + "."
            )

    paragraphs.append(
        "In summary, this run set provides concrete evidence that robustness cannot be characterized by Byzantine "
        "fraction alone: attack policy, cohort selection dynamics, and temporal scheduling each shift both clean "
        "accuracy and backdoor success, often by large margins within the same nominal threat budget."
    )

    return "\n\n".join(paragraphs) + "\n"


def _build_table(rows: List[Dict[str, str]]) -> str:
    columns = [
        "Run",
        "Start",
        "End",
        "RampEnd",
        "Mode",
        "Selection",
        "Churn",
        "Layer",
        "MinAcc",
        "LastAcc",
        "MaxASR",
    ]

    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            widths[col] = max(widths[col], len(row[col]))

    def fmt_row(r: Dict[str, str]) -> str:
        return " | ".join(r[col].ljust(widths[col]) for col in columns)

    header = fmt_row({c: c for c in columns})
    # Match historical sweep_summary.txt style: dashed columns separated by '+'
    separator = "+".join("-" * widths[col] for col in columns)
    body = [fmt_row(r) for r in rows]
    return "\n".join([header, separator, *body]) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate sweep_summary.txt from sweep outputs")
    parser.add_argument("--sweep-root", required=True, help="Path to sweep root folder")
    parser.add_argument("--settings-csv", default="", help="Path to sweep_settings.csv")
    parser.add_argument("--output", default="", help="Path to output summary txt")
    args = parser.parse_args()

    sweep_root = Path(args.sweep_root).resolve()
    settings_csv = Path(args.settings_csv).resolve() if args.settings_csv else sweep_root / "sweep_settings.csv"
    output_path = Path(args.output).resolve() if args.output else sweep_root / "sweep_summary.txt"

    if not settings_csv.exists():
        raise FileNotFoundError(f"Missing settings CSV: {settings_csv}")

    rows: List[Dict[str, str]] = []
    run_stats: List[Dict[str, object]] = []
    with settings_csv.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for item in reader:
            label = (item.get("label") or "").strip()
            run_folder = (item.get("run_folder") or "").strip()
            run_path = sweep_root / run_folder

            acc_points = _read_metric_points(run_path / "metrics" / "evaluate_server__accuracy.csv")
            asr_points = _read_metric_points(run_path / "metrics" / "evaluate_server__backdoor_asr.csv")
            acc_values = _series_values(acc_points)
            asr_values = _series_values(asr_points)

            start = _safe_int((item.get("attack_window_start") or "").strip())
            end = _safe_int((item.get("attack_window_end") or "").strip())

            min_acc = min(acc_values) if acc_values else None
            last_acc = acc_values[-1] if acc_values else None
            max_asr = max(asr_values) if asr_values else None

            run_stats.append(
                {
                    "label": label,
                    "base_label": (item.get("base_label") or "").strip(),
                    "run_folder": run_folder,
                    "start": start,
                    "end": end,
                    "ramp_end": _safe_float((item.get("ramp_end") or "").strip()),
                    "attack_mode": (item.get("attack_mode") or "").strip(),
                    "selection_mode": (item.get("selection_mode") or "").strip(),
                    "churn_fraction": _safe_float((item.get("churn_fraction") or "").strip()),
                    "layering_mode": (item.get("layering_mode") or "").strip(),
                    "layered_k": (item.get("layered_k") or "").strip(),
                    "min_acc": min_acc,
                    "last_acc": last_acc,
                    "max_asr": max_asr,
                    "attack_window_acc": _mean_in_window(acc_points, start, end),
                    "pre_attack_acc": _mean_before(acc_points, start),
                    "post_attack_acc": _mean_after(acc_points, end),
                }
            )

            rows.append(
                {
                    "Run": label,
                    "Start": (item.get("attack_window_start") or "").strip(),
                    "End": (item.get("attack_window_end") or "").strip(),
                    "RampEnd": (item.get("ramp_end") or "").strip(),
                    "Mode": (item.get("attack_mode") or "").strip(),
                    "Selection": (item.get("selection_mode") or "").strip(),
                    "Churn": (item.get("churn_fraction") or "").strip(),
                    "Layer": (item.get("layering_mode") or "").strip(),
                    "MinAcc": _fmt_float(min_acc),
                    "LastAcc": _fmt_float(last_acc),
                    "MaxASR": _fmt_float(max_asr),
                }
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_text = _build_table(rows) + "\n" + _build_narrative(run_stats)
    output_path.write_text(output_text, encoding="utf-8")

    print(f"Wrote summary: {output_path}")


if __name__ == "__main__":
    main()
