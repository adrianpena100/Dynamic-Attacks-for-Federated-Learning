#!/usr/bin/env python3
"""Run comprehensive LLM analysis over FL sweep artifacts.

Coverage for each run directory (S00_* ... S10_*):
- metrics/*.csv
- rounds/round_*.json
- summaries/*.csv and attack_log.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


try:
    from anthropic import Anthropic, AnthropicFoundry
except Exception:  # pragma: no cover
    Anthropic = None  # type: ignore[assignment]
    AnthropicFoundry = None  # type: ignore[assignment]


DEFAULT_MODEL = "claude-opus-4-6"


def _load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


def _safe_float(raw: Any) -> Optional[float]:
    if raw is None:
        return None
    try:
        s = str(raw).strip()
        if s == "":
            return None
        return float(s)
    except Exception:
        return None


def _read_metric_series(csv_path: Path) -> List[float]:
    out: List[float] = []
    if not csv_path.exists():
        return out
    try:
        with csv_path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                v = _safe_float(row.get("value"))
                if v is not None:
                    out.append(float(v))
    except Exception:
        return []
    return out


def _series_stats(vals: List[float]) -> Dict[str, float]:
    if not vals:
        return {}
    return {
        "first": float(vals[0]),
        "last": float(vals[-1]),
        "min": float(min(vals)),
        "max": float(max(vals)),
        "mean": float(sum(vals) / len(vals)),
        "median": float(statistics.median(vals)),
    }


def _inventory_csvs(run_dir: Path) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    for sub in ("metrics", "summaries"):
        p = run_dir / sub
        if not p.exists():
            continue
        for f in sorted(p.glob("*.csv")):
            row_count = 0
            columns: List[str] = []
            try:
                with f.open("r", newline="", encoding="utf-8") as h:
                    reader = csv.DictReader(h)
                    columns = list(reader.fieldnames or [])
                    for _ in reader:
                        row_count += 1
            except Exception:
                pass
            entries.append(
                {
                    "rel_path": str(f.relative_to(run_dir)),
                    "rows": int(row_count),
                    "columns": columns,
                }
            )
    return {
        "csv_count": int(len(entries)),
        "csv_inventory": entries,
    }


def _summarize_rounds_json(run_dir: Path) -> Dict[str, Any]:
    rounds_dir = run_dir / "rounds"
    if not rounds_dir.exists():
        return {"round_json_count": 0}

    acc_vals: List[float] = []
    asr_vals: List[float] = []
    attack_flags: List[float] = []
    round_files = sorted(rounds_dir.glob("round_*.json"))

    for rp in round_files:
        try:
            obj = json.loads(rp.read_text(encoding="utf-8"))
        except Exception:
            continue
        metrics = obj.get("metrics") or {}
        evs = metrics.get("evaluate_server") or {}
        trc = metrics.get("train_client") or {}

        v_acc = _safe_float(evs.get("accuracy"))
        v_asr = _safe_float(evs.get("backdoor_asr"))
        v_attack = _safe_float(trc.get("attack_is_malicious"))

        if v_acc is not None:
            acc_vals.append(float(v_acc))
        if v_asr is not None:
            asr_vals.append(float(v_asr))
        if v_attack is not None:
            attack_flags.append(float(v_attack))

    return {
        "round_json_count": int(len(round_files)),
        "round_json_accuracy": _series_stats(acc_vals),
        "round_json_backdoor_asr": _series_stats(asr_vals),
        "round_json_attack_is_malicious": _series_stats(attack_flags),
    }


def _summarize_attack_log(run_dir: Path) -> Dict[str, Any]:
    path = run_dir / "summaries" / "attack_log.jsonl"
    if not path.exists():
        return {"attack_events": 0, "attack_name_counts": {}}

    counts: Counter[str] = Counter()
    rounds_active: List[int] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            name = str(rec.get("attack_name") or "none")
            counts[name] += 1
            rnd = rec.get("round")
            if isinstance(rnd, int) and name != "none":
                rounds_active.append(rnd)

    out = {
        "attack_events": int(sum(counts.values())),
        "attack_name_counts": dict(counts.most_common(12)),
    }
    if rounds_active:
        out["attack_active_window"] = {
            "start": int(min(rounds_active)),
            "end": int(max(rounds_active)),
            "unique_rounds": int(len(set(rounds_active))),
        }
    return out


def _summarize_defense_selection(run_dir: Path) -> Dict[str, Any]:
    path = run_dir / "summaries" / "defense_selection_by_round.csv"
    if not path.exists():
        return {"defense_selection_rows": 0}

    frac_vals: List[float] = []
    mal_selected: List[float] = []
    rows = 0
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows += 1
            v_frac = _safe_float(row.get("malicious_selected_fraction"))
            v_nmal = _safe_float(row.get("num_malicious_selected_by_defense"))
            if v_frac is not None:
                frac_vals.append(float(v_frac))
            if v_nmal is not None:
                mal_selected.append(float(v_nmal))

    return {
        "defense_selection_rows": int(rows),
        "malicious_selected_fraction": _series_stats(frac_vals),
        "num_malicious_selected_by_defense": _series_stats(mal_selected),
    }


def _summarize_round_attack_stats(run_dir: Path) -> Dict[str, Any]:
    path = run_dir / "summaries" / "round_attack_stats.csv"
    if not path.exists():
        return {"round_attack_rows": 0}

    rows = 0
    attack_counts: Counter[str] = Counter()
    stealth_applied = 0
    stealthy_overlap_rounds = 0

    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows += 1
            name = str(row.get("attack_name") or "none")
            attack_counts[name] += 1

            st = _safe_float(row.get("stealth_applied"))
            if st is not None and st > 0:
                stealth_applied += 1

            mal_post = _safe_float(row.get("max_mal_norm_post"))
            honest_p90 = _safe_float(row.get("honest_norm_p90"))
            if mal_post is not None and honest_p90 is not None and mal_post <= honest_p90:
                stealthy_overlap_rounds += 1

    return {
        "round_attack_rows": int(rows),
        "round_attack_name_counts": dict(attack_counts.most_common(12)),
        "stealth_applied_rounds": int(stealth_applied),
        "stealthy_overlap_rounds": int(stealthy_overlap_rounds),
    }


def _parse_run_summary_json(run_dir: Path) -> Dict[str, Any]:
    path = run_dir / "summaries" / "run_config_and_summary.json"
    if not path.exists():
        return {}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    final_acc = _safe_float(obj.get("final_acc"))
    final_asr = _safe_float(obj.get("final_asr"))
    summary_obj = obj.get("summary") or {}
    if final_acc is None:
        final_acc = _safe_float(summary_obj.get("final_acc"))
    if final_asr is None:
        final_asr = _safe_float(summary_obj.get("final_asr"))

    out: Dict[str, Any] = {}
    if final_acc is not None:
        out["final_acc"] = float(final_acc)
    if final_asr is not None:
        out["final_asr"] = float(final_asr)
    return out


def _build_run_record(run_dir: Path) -> Dict[str, Any]:
    label = run_dir.name.split("__")[0]
    rec: Dict[str, Any] = {
        "run_dir": str(run_dir),
        "run_label": label,
    }

    rec.update(_inventory_csvs(run_dir))
    rec.update(_summarize_rounds_json(run_dir))
    rec.update(_summarize_attack_log(run_dir))
    rec.update(_summarize_defense_selection(run_dir))
    rec.update(_summarize_round_attack_stats(run_dir))
    rec.update(_parse_run_summary_json(run_dir))

    acc_vals = _read_metric_series(run_dir / "metrics" / "evaluate_server__accuracy.csv")
    asr_vals = _read_metric_series(run_dir / "metrics" / "evaluate_server__backdoor_asr.csv")
    loss_vals = _read_metric_series(run_dir / "metrics" / "evaluate_server__loss.csv")
    rec["metrics_accuracy"] = _series_stats(acc_vals)
    rec["metrics_backdoor_asr"] = _series_stats(asr_vals)
    rec["metrics_loss"] = _series_stats(loss_vals)

    if "final_acc" not in rec and acc_vals:
        rec["final_acc"] = float(acc_vals[-1])
    if "final_asr" not in rec and asr_vals:
        rec["final_asr"] = float(asr_vals[-1])

    return rec


def _aggregate_strategy(strategy_dir: Path) -> Dict[str, Any]:
    run_dirs = [
        p for p in sorted(strategy_dir.iterdir()) if p.is_dir() and p.name.startswith("S") and "__" in p.name
    ]

    run_records = [_build_run_record(r) for r in run_dirs]
    accs = [float(r["final_acc"]) for r in run_records if r.get("final_acc") is not None]
    asrs = [float(r["final_asr"]) for r in run_records if r.get("final_asr") is not None]

    collapse_20 = sum(1 for a in accs if a <= 0.20)
    collapse_10 = sum(1 for a in accs if a <= 0.10)
    high_asr = sum(1 for x in asrs if x >= 0.50)

    top_deadliest = sorted(
        [r for r in run_records if r.get("final_acc") is not None],
        key=lambda r: float(r.get("final_acc", 1.0)),
    )[:10]

    strategy_name = strategy_dir.name.split("_thesis_full__")[0].lower()
    supports_malicious_selection = strategy_name in {"multikrum", "krum"}
    def _deadliest_run_entry(r):
        entry = {
            "run_label": r.get("run_label"),
            "final_acc": r.get("final_acc"),
            "final_asr": r.get("final_asr"),
            "attack_name_counts": r.get("round_attack_name_counts", {}),
            "stealthy_overlap_rounds": r.get("stealthy_overlap_rounds", 0),
        }
        if supports_malicious_selection:
            msf = r.get("malicious_selected_fraction")
            if isinstance(msf, dict):
                entry["malicious_selected_fraction"] = msf.get("mean")
            else:
                entry["malicious_selected_fraction"] = None
        return entry

    return {
        "strategy_dir": str(strategy_dir),
        "strategy_name": strategy_name,
        "run_count": int(len(run_records)),
        "has_sweep_settings": (strategy_dir / "sweep_settings.csv").exists(),
        "has_sweep_summary": (strategy_dir / "sweep_summary.txt").exists(),
        "aggregate": {
            "final_acc": _series_stats(accs),
            "final_asr": _series_stats(asrs),
            "collapse_le_20": int(collapse_20),
            "collapse_le_10": int(collapse_10),
            "high_asr_ge_50": int(high_asr),
        },
        "top_deadliest_runs": [_deadliest_run_entry(r) for r in top_deadliest],
        "run_records": run_records,
    }


def _find_strategy_dirs(root: Path) -> List[Path]:
    if (root / "sweep_settings.csv").exists():
        return [root]
    found = {p.parent for p in root.rglob("sweep_settings.csv")}
    return sorted(found)


def _call_llm(client: Any, model: str, prompt: str, max_tokens: int = 7000) -> str:
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=0.1,
        messages=[{"role": "user", "content": prompt}],
    )
    chunks: List[str] = []
    for block in resp.content:
        t = getattr(block, "text", None)
        if t:
            chunks.append(t)
    return "\n".join(chunks).strip()


def _build_strategy_prompt(payload_json: str) -> str:
    return (
        "You are analyzing one federated learning strategy sweep for Byzantine vulnerability assessment.\n"
        "Input contains run-level aggregates derived from all CSV files in metrics/ and summaries/,\n"
        "plus per-round JSON telemetry from rounds/.\n"
        "Deliver an evidence-grounded report with:\n"
        "1) Data coverage audit and telemetry gaps.\n"
        "2) Vulnerability profile: collapse behavior, ASR behavior, stealth behavior, defense slip-through.\n"
        "3) Most dangerous run patterns (timing, mode, layering, selection) inferred from run labels + metrics.\n"
        "4) Defense failure mechanism hypotheses (explicitly separate observed vs inferred).\n"
        "5) Quantified findings with concrete numbers and thresholds.\n"
        "6) Prioritized follow-up experiments (at least 8).\n"
        "Use concise technical language. Avoid generic statements.\n\n"
        "Payload:\n"
        f"{payload_json}"
    )


def _build_global_prompt(strategy_reports: Dict[str, str], payloads: Dict[str, Dict[str, Any]]) -> str:
    blob = json.dumps({"reports": strategy_reports, "payload_summaries": payloads}, indent=2)
    return (
        "Synthesize vulnerabilities across all available strategies for this dataset sweep.\n"
        "Produce:\n"
        "1) Strategy robustness ranking with justification.\n"
        "2) Cross-strategy attacker tactic ranking by damage.\n"
        "3) What generalizes and what is strategy-specific.\n"
        "4) High-confidence conclusions vs tentative hypotheses.\n"
        "5) Thesis-ready executive summary and threat model implications.\n"
        "6) Next 10 runs/ablations to execute.\n\n"
        "Input:\n"
        f"{blob}"
    )


def _resolve_client(project_root: Path, model_arg: Optional[str]) -> tuple[Any, str]:
    _load_dotenv(project_root / ".env")
    if Anthropic is None:
        raise RuntimeError("Missing dependency 'anthropic'. Install with: pip install anthropic")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    model = (model_arg or os.environ.get("ANTHROPIC_MODEL") or DEFAULT_MODEL).strip()

    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set (env or .env)")
    if not base_url:
        raise RuntimeError("ANTHROPIC_BASE_URL is not set (env or .env)")
    if not model:
        raise RuntimeError("No model provided. Set --model or ANTHROPIC_MODEL")

    # Users sometimes paste the full messages endpoint (e.g. .../anthropic/v1/messages).
    # The SDK expects the service base endpoint (e.g. .../anthropic/).
    lower_url = base_url.lower()
    if lower_url.endswith("/v1/messages"):
        base_url = base_url[: -len("/v1/messages")]
    elif lower_url.endswith("/messages"):
        base_url = base_url[: -len("/messages")]
    if not base_url.endswith("/"):
        base_url = base_url + "/"

    force_foundry = os.environ.get("ANTHROPIC_USE_FOUNDRY", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    auto_foundry = (
        ".services.ai.azure.com" in base_url.lower() or "/anthropic" in base_url.lower()
    )

    if (force_foundry or auto_foundry) and AnthropicFoundry is not None:
        return AnthropicFoundry(api_key=api_key, base_url=base_url), model

    return Anthropic(api_key=api_key, base_url=base_url), model


def main() -> None:
    parser = argparse.ArgumentParser(description="Comprehensive LLM analysis over strategy sweep artifacts")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="dynamic_fl project root (contains .env)",
    )
    parser.add_argument(
        "--sweeps-root",
        type=Path,
        default=None,
        help="Can be dataset folder (e.g., logs/sweeps/FEMNIST_2026-04-02), strategy folder, or logs/sweeps.",
    )
    parser.add_argument("--model", default=None)
    parser.add_argument("--skip-global", action="store_true")
    parser.add_argument(
        "--call-api",
        action="store_true",
        help="Actually call the LLM endpoint. Default behavior only prepares payloads locally.",
    )
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    sweeps_root = (
        args.sweeps_root.resolve()
        if args.sweeps_root is not None
        else (project_root / "logs" / "sweeps")
    )

    if not sweeps_root.exists():
        raise SystemExit(f"sweeps-root does not exist: {sweeps_root}")

    client = None
    model = ""
    if args.call_api:
        client, model = _resolve_client(project_root, args.model)

    strategy_dirs = _find_strategy_dirs(sweeps_root)
    if not strategy_dirs:
        raise SystemExit(f"No strategy sweep folders found below: {sweeps_root}")

    strategy_reports: Dict[str, str] = {}
    strategy_payload_index: Dict[str, Dict[str, Any]] = {}

    for sdir in strategy_dirs:
        print(f"[llm-analysis] Parsing strategy folder: {sdir}", flush=True)
        payload = _aggregate_strategy(sdir)

        payload_path = sdir / "llm_comprehensive_payload.json"
        payload_json = json.dumps(payload, indent=2)
        payload_path.write_text(payload_json, encoding="utf-8")

        if args.call_api:
            prompt = _build_strategy_prompt(payload_json)
            try:
                report = _call_llm(client, model, prompt)
            except Exception as exc:
                report = (
                    "# LLM Analysis Failed\n\n"
                    f"Reason: {exc}\n\n"
                    "The comprehensive payload was still generated successfully in "
                    "`llm_comprehensive_payload.json`.\n"
                )
        else:
            report = (
                "# API Not Called (Setup Mode)\n\n"
                "No external LLM API call was made.\n\n"
                "This file is a placeholder. Use `--call-api` to generate model-written analysis "
                "from `llm_comprehensive_payload.json`.\n"
            )
        report_path = sdir / "llm_comprehensive_analysis.md"
        report_path.write_text(report + "\n", encoding="utf-8")

        strategy_name = payload.get("strategy_name", sdir.name)
        strategy_reports[str(strategy_name)] = report
        strategy_payload_index[str(strategy_name)] = {
            "strategy_dir": str(sdir),
            "run_count": payload.get("run_count", 0),
            "aggregate": payload.get("aggregate", {}),
        }

        print(f"[llm-analysis] Wrote {report_path}", flush=True)

    if (not args.call_api) or args.skip_global or len(strategy_reports) <= 1:
        return

    print("[llm-analysis] Building cross-strategy synthesis", flush=True)
    global_prompt = _build_global_prompt(strategy_reports, strategy_payload_index)
    try:
        global_report = _call_llm(client, model, global_prompt)
    except Exception as exc:
        global_report = (
            "# Global LLM Analysis Failed\n\n"
            f"Reason: {exc}\n\n"
            "Per-strategy payloads and reports were generated where possible.\n"
        )

    out_root = sweeps_root if sweeps_root.is_dir() else project_root
    out_path = out_root / "llm_global_analysis.md"
    out_path.write_text(global_report + "\n", encoding="utf-8")
    print(f"[llm-analysis] Wrote {out_path}", flush=True)


if __name__ == "__main__":
    main()
