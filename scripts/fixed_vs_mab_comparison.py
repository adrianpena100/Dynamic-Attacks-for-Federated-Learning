"""
Fixed-attack vs MAB comparison report generator.

Reads a sweep directory (produced by run_thesis_sweep.sh with docs/fixed_vs_mab_sweep.conf)
and writes a self-contained HTML report comparing fixed single-attack baselines against
the epsilon-greedy MAB adaptive strategy (sticky / churn / random scheduling),
across all tested defenses.

Usage:
    python scripts/fixed_vs_mab_comparison.py <sweep_dir_glob_or_path> [--out report.html]

Example:
    python scripts/fixed_vs_mab_comparison.py "logs/sweeps/*fixed_vs_mab_full*" \
        --out docs/reports/fixed_vs_mab_full.html
"""

import argparse
import csv
import glob
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATTACK_LABELS = {
    "BASELINE_clean":      "Clean Baseline",
    "FIXED_GAUSSIAN":      "Gaussian Noise (fixed)",
    "FIXED_SIGN_FLIP":     "Sign Flip (fixed)",
    "FIXED_LABEL_FLIP":    "Label Flip (fixed)",
    "FIXED_BACKDOOR":      "Backdoor (fixed)",
    "FIXED_ALIE":          "ALIE (fixed)",
    "FIXED_MEAN_SHIFT":    "Mean Shift (fixed)",
    "MAB_ADAPTIVE_STICKY": "MAB — Sticky",
    "MAB_ADAPTIVE_CHURN":  "MAB — Churn",
    "MAB_ADAPTIVE_RANDOM": "MAB — Random",
    # legacy single-variant label from the verify run
    "MAB_ADAPTIVE":        "MAB Adaptive",
}

FIXED_ORDER = [
    "BASELINE_clean",
    "FIXED_GAUSSIAN",
    "FIXED_SIGN_FLIP",
    "FIXED_LABEL_FLIP",
    "FIXED_BACKDOOR",
    "FIXED_ALIE",
    "FIXED_MEAN_SHIFT",
    "MAB_ADAPTIVE_STICKY",
    "MAB_ADAPTIVE_CHURN",
    "MAB_ADAPTIVE_RANDOM",
    "MAB_ADAPTIVE",
]

MAB_LABELS = {"MAB_ADAPTIVE_STICKY", "MAB_ADAPTIVE_CHURN", "MAB_ADAPTIVE_RANDOM", "MAB_ADAPTIVE"}


# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

def _read_csv_col(path: Path, col: str) -> list:
    if not path.exists():
        return []
    with path.open() as f:
        reader = csv.DictReader(f)
        return [row[col] for row in reader if col in row]


def _final_accuracy(run_dir: Path) -> float | None:
    p = run_dir / "metrics" / "evaluate_server__accuracy.csv"
    vals = _read_csv_col(p, "value")
    return float(vals[-1]) if vals else None


def _accuracy_curve(run_dir: Path) -> list[tuple[int, float]]:
    p = run_dir / "metrics" / "evaluate_server__accuracy.csv"
    if not p.exists():
        return []
    with p.open() as f:
        reader = csv.DictReader(f)
        return [(int(row["round"]), float(row["value"])) for row in reader]


def _final_backdoor_asr(run_dir: Path) -> float | None:
    p = run_dir / "metrics" / "evaluate_server__backdoor_asr.csv"
    vals = _read_csv_col(p, "value")
    # return None if all zeros (attack type doesn't inject a backdoor trigger)
    floats = [float(v) for v in vals]
    if not floats or max(floats) == 0.0:
        return None
    return floats[-1]


def _attack_timeline_stats(run_dir: Path) -> dict:
    """
    Parse summaries/attack_timeline.csv and return:
        dominant: most-frequent attack name
        mal_count_avg: average num_malicious across rounds
        mal_count_max: maximum num_malicious across any round
        total_clients: most common num_selected_clients
        attack_counts: {attack_name: round_count}
    """
    p = run_dir / "summaries" / "attack_timeline.csv"
    if not p.exists():
        return {"dominant": "—", "mal_count_avg": None, "mal_count_max": None,
                "total_clients": None, "attack_counts": {}}

    attack_counts: dict[str, int] = defaultdict(int)
    mal_counts: list[int] = []
    selected_counts: list[int] = []

    with p.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get("attack_name", "").strip()
            if name and name not in {"none", "off", ""}:
                attack_counts[name] += 1

            nm = row.get("num_malicious", "").strip()
            if nm.isdigit():
                mal_counts.append(int(nm))

            ns = row.get("num_selected_clients", "").strip()
            if ns.isdigit():
                selected_counts.append(int(ns))

    dominant = max(attack_counts, key=attack_counts.__getitem__) if attack_counts else "—"
    mal_avg = round(mean(mal_counts)) if mal_counts else None
    mal_max = max(mal_counts) if mal_counts else None
    # most common selected-client count
    total = max(set(selected_counts), key=selected_counts.count) if selected_counts else None

    return {
        "dominant": dominant,
        "mal_count_avg": mal_avg,
        "mal_count_max": mal_max,
        "total_clients": total,
        "attack_counts": dict(attack_counts),
    }


def _strategy_from_meta(run_dir: Path) -> str:
    p = run_dir / "meta.json"
    if not p.exists():
        return "unknown"
    with p.open() as f:
        d = json.load(f)
    return d.get("strategy", "unknown")


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def collect_sweep_data(sweep_dirs: list[Path]) -> dict:
    """
    Returns nested dict:
        data[strategy][base_label] = list of run dicts
    """
    data: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))

    for sweep_dir in sweep_dirs:
        settings_csv = sweep_dir / "sweep_settings.csv"
        if not settings_csv.exists():
            print(f"  [skip] no sweep_settings.csv in {sweep_dir}", file=sys.stderr)
            continue

        with settings_csv.open() as f:
            reader = csv.DictReader(f)
            for row in reader:
                base_label = row.get("base_label", row.get("label", "")).strip()
                run_folder = row.get("run_folder", "").strip()
                seed = row.get("seed", "?").strip()

                run_dir = sweep_dir / run_folder
                if not run_dir.exists():
                    continue

                strategy = _strategy_from_meta(run_dir)
                acc = _final_accuracy(run_dir)
                asr = _final_backdoor_asr(run_dir)
                curve = _accuracy_curve(run_dir)
                tl = _attack_timeline_stats(run_dir)

                data[strategy][base_label].append({
                    "acc": acc,
                    "asr": asr,
                    "seed": seed,
                    "run_dir": str(run_dir),
                    "curve": curve,
                    "dominant": tl["dominant"],
                    "mal_count_avg": tl["mal_count_avg"],
                    "mal_count_max": tl["mal_count_max"],
                    "total_clients": tl["total_clients"],
                    "attack_counts": tl["attack_counts"],
                })

    return data


def _agg(values: list) -> dict:
    vals = [v for v in values if v is not None]
    if not vals:
        return {"mean": None, "std": None, "n": 0}
    return {
        "mean": mean(vals),
        "std": stdev(vals) if len(vals) > 1 else 0.0,
        "n": len(vals),
    }


# ---------------------------------------------------------------------------
# HTML generation helpers
# ---------------------------------------------------------------------------

CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       max-width: 1500px; margin: 0 auto; padding: 20px; background: #f8f9fa; }
h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }
h2 { color: #16213e; margin-top: 40px; }
h3 { color: #0f3460; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(700px, 1fr)); gap: 20px; }
.card { background: white; border-radius: 8px; padding: 16px; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
.card h3 { margin-top: 0; font-size: 1em; }
table { width: 100%; border-collapse: collapse; font-size: 0.83em; margin-top: 8px; }
th { background: #1a1a2e; color: white; padding: 6px 8px; text-align: left; white-space: nowrap; }
td { padding: 5px 8px; border-bottom: 1px solid #eee; vertical-align: middle; }
tr.baseline { background: #e8f5e9; }
tr.mab-sticky { background: #e3f2fd; font-weight: 600; }
tr.mab-churn  { background: #e8eaf6; font-weight: 600; }
tr.mab-random { background: #fce4ec; font-weight: 600; }
.acc { font-variant-numeric: tabular-nums; }
.drop-pos { color: #c62828; font-weight: 600; }
.drop-neg { color: #2e7d32; font-weight: 600; }
.badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 0.72em; margin-left: 4px; }
.badge-mab    { background: #1565c0; color: white; }
.badge-fixed  { background: #e65100; color: white; }
.badge-sticky { background: #1565c0; color: white; }
.badge-churn  { background: #4527a0; color: white; }
.badge-random { background: #880e4f; color: white; }
.chart-container { width: 100%; overflow-x: auto; margin-top: 8px; }
.note { color: #666; font-size: 0.80em; }
.section-intro { color: #444; font-size: 0.9em; margin-bottom: 10px; }
.toc { margin: 12px 0 24px; }
.toc a { display: inline-block; margin: 3px 6px 3px 0; padding: 4px 10px;
          background: #1a1a2e; color: white; border-radius: 4px;
          text-decoration: none; font-size: 0.85em; }
.toc a:hover { background: #e94560; }
.winner { background: #ffe082; border-radius: 3px; padding: 1px 5px; font-weight: 600; }
.mal-count { font-variant-numeric: tabular-nums; color: #555; }
"""

JS = ""


def _pct(v) -> str:
    if v is None:
        return "—"
    return f"{float(v) * 100:.1f}%"


def _drop_html(baseline: float | None, attacked: float | None) -> str:
    if baseline is None or attacked is None:
        return "—"
    drop = (baseline - attacked) * 100
    cls = "drop-pos" if drop > 0.3 else "drop-neg"
    sign = "−" if drop > 0 else "+"
    return f'<span class="{cls}">{sign}{abs(drop):.1f} pp</span>'


def _mal_str(entries: list) -> str:
    """Summarise malicious-client count across seeds as 'avg / total'."""
    avgs = [e["mal_count_avg"] for e in entries if e.get("mal_count_avg") is not None]
    totals = [e["total_clients"] for e in entries if e.get("total_clients") is not None]
    if not avgs:
        return "—"
    avg = round(mean(avgs))
    total = round(mean(totals)) if totals else "?"
    pct = f"{avg/total*100:.0f}%" if isinstance(total, (int, float)) and total else ""
    return f'<span class="mal-count">{avg} / {total} ({pct})</span>'


def _sparkline_svg(curves: list, width=300, height=55) -> str:
    if not any(curves):
        return ""
    COLORS = ["#1565c0", "#e65100", "#2e7d32", "#6a1b9a", "#ad1457"]
    all_rounds = [r for c in curves for r, _ in c]
    all_vals   = [v for c in curves for _, v in c]
    if not all_rounds:
        return ""
    min_r, max_r = min(all_rounds), max(all_rounds)
    min_v, max_v = min(all_vals), max(all_vals)
    if max_r == min_r: max_r += 1
    if max_v == min_v: max_v = min_v + 0.01

    def px(r, v):
        x = (r - min_r) / (max_r - min_r) * (width - 4) + 2
        y = height - (v - min_v) / (max_v - min_v) * (height - 6) - 3
        return x, y

    paths = []
    for i, curve in enumerate(curves):
        if not curve:
            continue
        color = COLORS[i % len(COLORS)]
        pts = " ".join(f"{px(r,v)[0]:.1f},{px(r,v)[1]:.1f}" for r, v in curve)
        paths.append(
            f'<polyline points="{pts}" stroke="{color}" stroke-width="1.5" fill="none" opacity="0.75"/>'
        )
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'xmlns="http://www.w3.org/2000/svg">'
        f'<rect width="{width}" height="{height}" fill="#f0f0f0" rx="3"/>'
        + "".join(paths) + "</svg>"
    )


def _row_class(base_label: str) -> str:
    if base_label == "BASELINE_clean":
        return "baseline"
    if base_label == "MAB_ADAPTIVE_STICKY":
        return "mab-sticky"
    if base_label == "MAB_ADAPTIVE_CHURN":
        return "mab-churn"
    if base_label in ("MAB_ADAPTIVE_RANDOM", "MAB_ADAPTIVE"):
        return "mab-random"
    return ""


def _label_badge(base_label: str) -> str:
    if base_label == "BASELINE_clean":
        return ""
    if base_label == "MAB_ADAPTIVE_STICKY":
        return '<span class="badge badge-sticky">MAB sticky</span>'
    if base_label == "MAB_ADAPTIVE_CHURN":
        return '<span class="badge badge-churn">MAB churn</span>'
    if base_label in ("MAB_ADAPTIVE_RANDOM", "MAB_ADAPTIVE"):
        return '<span class="badge badge-random">MAB random</span>'
    return '<span class="badge badge-fixed">fixed</span>'


def _attack_breakdown(entries: list) -> str:
    """For MAB runs, show which attacks were selected and how often (averaged across seeds)."""
    combined: dict[str, list] = defaultdict(list)
    for e in entries:
        for atk, cnt in e.get("attack_counts", {}).items():
            combined[atk].append(cnt)
    if not combined:
        return ""
    parts = []
    for atk in sorted(combined, key=lambda a: -mean(combined[a])):
        avg = mean(combined[atk])
        parts.append(f"{atk}: {avg:.0f}r")
    return "<br><span class='note'>" + " · ".join(parts) + "</span>"


def build_strategy_table(strategy: str, scenario_data: dict, baseline_acc: float | None) -> str:
    rows = []
    for base_label in FIXED_ORDER:
        if base_label not in scenario_data:
            continue
        entries = scenario_data[base_label]
        label = ATTACK_LABELS.get(base_label, base_label)

        acc_agg = _agg([e["acc"] for e in entries])
        asr_agg = _agg([e for e in [e.get("asr") for e in entries] if e is not None])

        acc_str = _pct(acc_agg["mean"])
        if acc_agg["std"] and acc_agg["n"] > 1:
            acc_str += f'<span class="note"> ±{acc_agg["std"]*100:.1f}</span>'

        drop_str = "—" if base_label == "BASELINE_clean" else _drop_html(baseline_acc, acc_agg["mean"])
        asr_str  = _pct(asr_agg["mean"]) if asr_agg["mean"] is not None else "—"
        mal_str  = "—" if base_label == "BASELINE_clean" else _mal_str(entries)

        dom_attacks = list({e["dominant"] for e in entries if e["dominant"] != "—"})
        dom_str = ", ".join(dom_attacks) if dom_attacks else "—"

        # For MAB runs, append per-attack breakdown
        if base_label in MAB_LABELS:
            dom_str += _attack_breakdown(entries)

        rows.append(
            f'<tr class="{_row_class(base_label)}">'
            f"<td>{label}{_label_badge(base_label)}</td>"
            f'<td class="acc">{acc_str}</td>'
            f"<td>{drop_str}</td>"
            f"<td>{mal_str}</td>"
            f"<td>{asr_str}</td>"
            f"<td>{dom_str}</td>"
            f"<td>{acc_agg['n']}</td>"
            f"</tr>"
        )

    return (
        "<table><thead><tr>"
        "<th>Scenario</th>"
        "<th>Final Acc</th>"
        "<th>Drop vs Baseline</th>"
        "<th>Poisoned / Total clients</th>"
        "<th>Backdoor ASR</th>"
        "<th>Attack(s) Used</th>"
        "<th>Seeds</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def build_sparkline_section(scenario_data: dict) -> str:
    parts = ["<div class='chart-container'><table><tr>"]
    for base_label in FIXED_ORDER:
        if base_label not in scenario_data:
            continue
        label = ATTACK_LABELS.get(base_label, base_label)
        curves = [e["curve"] for e in scenario_data[base_label] if e.get("curve")]
        svg = _sparkline_svg(curves)
        parts.append(
            f"<td style='padding:4px;vertical-align:top;text-align:center'>"
            f"<div style='font-size:.72em;color:#555;margin-bottom:2px'>{label}</div>{svg}</td>"
        )
    parts.append("</tr></table></div>")
    return "".join(parts)


def build_global_summary(data: dict) -> str:
    rows = []
    for strategy in sorted(data.keys()):
        sd = data[strategy]
        bl_acc = _agg([e["acc"] for e in sd.get("BASELINE_clean", [])])["mean"]

        # Most damaging fixed attack
        best_fixed_label, best_fixed_acc = None, None
        for bl in FIXED_ORDER:
            if bl in ("BASELINE_clean",) or bl in MAB_LABELS:
                continue
            if bl not in sd:
                continue
            a = _agg([e["acc"] for e in sd[bl]])["mean"]
            if a is not None and (best_fixed_acc is None or a < best_fixed_acc):
                best_fixed_acc, best_fixed_label = a, bl

        # Best (most damaging) MAB variant
        best_mab_label, best_mab_acc = None, None
        for bl in ("MAB_ADAPTIVE_STICKY", "MAB_ADAPTIVE_CHURN", "MAB_ADAPTIVE_RANDOM", "MAB_ADAPTIVE"):
            if bl not in sd:
                continue
            a = _agg([e["acc"] for e in sd[bl]])["mean"]
            if a is not None and (best_mab_acc is None or a < best_mab_acc):
                best_mab_acc, best_mab_label = a, bl

        def drop(v):
            if bl_acc is None or v is None:
                return None
            return (bl_acc - v) * 100

        fixed_drop = drop(best_fixed_acc)
        mab_drop   = drop(best_mab_acc)

        if fixed_drop is not None and mab_drop is not None:
            if mab_drop > fixed_drop + 0.5:
                winner = '<span class="winner">MAB</span>'
            elif fixed_drop > mab_drop + 0.5:
                winner = f'<span class="winner">{ATTACK_LABELS.get(best_fixed_label, best_fixed_label)}</span>'
            else:
                winner = "Tie"
        else:
            winner = "—"

        # Malicious client count (from most damaging fixed attack as representative)
        mal_example = ""
        if best_fixed_label and best_fixed_label in sd:
            mal_example = _mal_str(sd[best_fixed_label])

        rows.append(
            f"<tr><td><b>{strategy}</b></td>"
            f"<td>{_pct(bl_acc)}</td>"
            f"<td>{ATTACK_LABELS.get(best_fixed_label, '—')} → {_pct(best_fixed_acc)}</td>"
            f"<td>{ATTACK_LABELS.get(best_mab_label, '—')} → {_pct(best_mab_acc)}</td>"
            f"<td>{mal_example}</td>"
            f"<td>{winner}</td></tr>"
        )

    return (
        "<table><thead><tr>"
        "<th>Defense</th>"
        "<th>Baseline Acc</th>"
        "<th>Most Damaging Fixed Attack</th>"
        "<th>Best MAB Variant</th>"
        "<th>Poisoned / Total clients</th>"
        "<th>More Effective</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def generate_html(data: dict, title: str = "Fixed-Attack vs MAB Comparison") -> str:
    strategies = sorted(data.keys())

    toc = '<div class="toc">' + "".join(
        f'<a href="#{s}">{s}</a>' for s in strategies
    ) + "</div>"

    sections = []
    for strategy in strategies:
        sd = data[strategy]
        bl_acc = _agg([e["acc"] for e in sd.get("BASELINE_clean", [])])["mean"]
        n_seeds = max((len(v) for v in sd.values()), default=0)

        table_html = build_strategy_table(strategy, sd, bl_acc)
        spark_html = build_sparkline_section(sd)

        sections.append(f"""
<div class="card" id="{strategy}">
  <h3>{strategy}
    <span style="font-weight:normal;color:#888;font-size:.85em">
      ({n_seeds} seed{'s' if n_seeds!=1 else ''} · baseline {_pct(bl_acc)})
    </span>
  </h3>
  {table_html}
  <details style="margin-top:8px">
    <summary style="cursor:pointer;color:#555;font-size:.82em">Accuracy curves (one line per seed)</summary>
    {spark_html}
  </details>
</div>""")

    global_table = build_global_summary(data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>{CSS}</style>
</head>
<body>
<h1>{title}</h1>
<p class="section-intro">
  Compares six fixed single-attack baselines (sticky malicious clients, one primitive per run)
  against three MAB adaptive variants (sticky / churn / random client scheduling) across each
  tested defense. All fixed attacks use the same malicious clients every round — the standard
  literature evaluation protocol. Baseline is a clean run with no attack.
  Values are final-round means ± std across seeds.
  <b>Poisoned / Total clients</b> shows the average number of malicious clients per round
  out of the total selected clients (e.g. 24 / 100 = 24%).
</p>

{toc}

<h2>Global Summary</h2>
<p class="section-intro">
  For each defense: the most damaging fixed attack (lowest final accuracy) and the most
  damaging MAB variant. "More Effective" shows which caused the larger accuracy drop.
  Tie = difference &lt; 0.5 pp.
</p>
{global_table}

<h2>Per-Defense Detail</h2>
<div class="summary-grid">{"".join(sections)}</div>

<hr style="margin-top:40px">
<p class="note">
  Generated by <code>scripts/fixed_vs_mab_comparison.py</code>
  from <code>docs/fixed_vs_mab_sweep.conf</code>.<br>
  Accuracy = final-round centralized evaluation (<code>evaluate_server__accuracy.csv</code>).
  Drop = percentage-point difference vs clean baseline (red = larger drop).
  Backdoor ASR shown only when non-zero.
  Poisoned count from <code>summaries/attack_timeline.csv</code> → <code>num_malicious</code> column.
  Attack breakdown (rounds) averaged across seeds.
  Conservative framing: observed candidate weaknesses, not confirmed novel vulnerabilities.
  To regenerate: <code>python scripts/fixed_vs_mab_comparison.py "logs/sweeps/*fixed_vs_mab_full*"
  --out docs/reports/fixed_vs_mab_full.html</code>
</p>
<script>{JS}</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Fixed-attack vs MAB HTML comparison report")
    parser.add_argument("sweep_path", help="Path or glob to sweep directory/directories")
    parser.add_argument("--out", default="fixed_vs_mab_comparison.html", help="Output HTML path")
    args = parser.parse_args()

    candidates = glob.glob(args.sweep_path)
    if not candidates:
        candidates = [args.sweep_path]

    sweep_dirs = [Path(c) for c in candidates if Path(c).is_dir()]
    if not sweep_dirs:
        print(f"ERROR: no directories found matching '{args.sweep_path}'", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(sweep_dirs)} sweep director{'y' if len(sweep_dirs)==1 else 'ies'}:")
    for d in sweep_dirs:
        print(f"  {d}")

    print("Collecting run data...")
    data = collect_sweep_data(sweep_dirs)

    if not data:
        print("ERROR: no run data found.", file=sys.stderr)
        sys.exit(1)

    print(f"Strategies: {', '.join(sorted(data.keys()))}")
    for s, sd in data.items():
        for lbl, entries in sd.items():
            print(f"  {s}/{lbl}: {len(entries)} seed(s)")

    html = generate_html(data)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    print(f"\nReport written to: {out_path.resolve()}")


if __name__ == "__main__":
    main()
