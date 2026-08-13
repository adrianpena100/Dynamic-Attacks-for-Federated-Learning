"""
Post-run analysis: reads a completed FL run directory, detects vulnerability
patterns, generates defense-specific suggestions, prints a terminal summary,
and saves structured JSON for later database ingestion.

Usage:
    python scripts/post_run_analysis.py <run_dir>
    python scripts/post_run_analysis.py <run_dir> --json-only
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Allow importing from project root (db/ and scripts/ are siblings)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from db.atlas_mapping import (
        ATLAS_TECHNIQUES,
        FINDING_PATTERNS,
        build_finding_context,
        classify_finding,
        classify_novelty,
        get_attack_techniques,
        is_novel_dimension,
        lookup_known_vulnerability,
    )
    _HAS_ATLAS = True
except ImportError:
    _HAS_ATLAS = False


# ── Data loading ─────────────────────────────────────────────────────────────

def _read_csv_series(path: Path) -> List[Tuple[int, float]]:
    if not path.exists():
        return []
    rows = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                rows.append((int(row["round"]), float(row["value"])))
            except (ValueError, KeyError):
                continue
    return rows


def _read_csv_dicts(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def _read_json(path: Path) -> Optional[Dict]:
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def load_run_data(run_dir: Path) -> Dict[str, Any]:
    meta = _read_json(run_dir / "meta.json") or {}
    config = _read_json(run_dir / "summaries" / "run_config_and_summary.json") or {}
    metrics_dir = run_dir / "metrics"
    summaries_dir = run_dir / "summaries"

    run_config = config.get("run_config", {})
    if not run_config.get("strategy") and meta.get("strategy"):
        run_config["strategy"] = meta["strategy"]
    if not run_config.get("dataset") and meta.get("dataset"):
        run_config["dataset"] = meta["dataset"]
    if not run_config.get("partitioner") and meta.get("partitioner"):
        run_config["partitioner"] = meta["partitioner"]
    if not run_config.get("dirichlet-alpha") and meta.get("dirichlet-alpha"):
        run_config["dirichlet-alpha"] = meta["dirichlet-alpha"]
    if not run_config.get("num-server-rounds"):
        rcn = meta.get("resolved_config_for_naming", {})
        if rcn.get("num-server-rounds"):
            run_config["num-server-rounds"] = rcn["num-server-rounds"]

    return {
        "meta": meta,
        "config": config,
        "run_config": run_config,
        "attack_config": config.get("resolved_attack_config", {}),
        "attack_frequency": config.get("attack_frequency", {}),
        "defense_summary": config.get("defense_selection_summary", {}),
        "accuracy": _read_csv_series(metrics_dir / "evaluate_server__accuracy.csv"),
        "f1_macro": _read_csv_series(metrics_dir / "evaluate_server__f1_macro.csv"),
        "backdoor_asr": _read_csv_series(metrics_dir / "evaluate_server__backdoor_asr.csv"),
        "loss": _read_csv_series(metrics_dir / "evaluate_server__loss.csv"),
        "attack_timeline": _read_csv_dicts(summaries_dir / "attack_timeline.csv"),
        "round_attack_stats": _read_csv_dicts(summaries_dir / "round_attack_stats.csv"),
        "trust_by_round": _read_csv_dicts(summaries_dir / "trust_strategy_by_round.csv"),
        "defense_selection": _read_csv_dicts(summaries_dir / "defense_selection_by_round.csv"),
        "malicious_ids": set(str(x) for x in config.get("ever_malicious_client_ids", [])),
    }


# ── Analysis functions ───────────────────────────────────────────────────────

def compute_accuracy_stats(series: List[Tuple[int, float]]) -> Dict:
    if not series:
        return {"available": False}
    vals = [v for _, v in series]
    final = vals[-1]
    peak = max(vals)
    peak_round = series[vals.index(peak)][0]

    last5 = vals[-5:] if len(vals) >= 5 else vals
    std5 = (sum((v - sum(last5) / len(last5)) ** 2 for v in last5) / len(last5)) ** 0.5

    if final < 0.05:
        trajectory = "collapsed"
    elif len(vals) >= 5 and vals[-1] < vals[-5] - 0.05:
        trajectory = "declining"
    elif std5 < 0.02 and final > 0.3:
        trajectory = "plateau"
    else:
        trajectory = "rising"

    return {
        "available": True,
        "final": final,
        "peak": peak,
        "peak_round": peak_round,
        "first": vals[0],
        "drop_from_peak": peak - final,
        "converged": final > 0.3 and std5 < 0.02,
        "collapsed": final < 0.05,
        "trajectory": trajectory,
    }


def analyze_attack_behavior(data: Dict) -> Dict:
    rc = data["run_config"]
    ac = data["attack_config"]
    freq = data["attack_frequency"]
    timeline = data["attack_timeline"]
    round_stats = data["round_attack_stats"]

    ae_raw = rc.get("attack-enabled", "true")
    attack_enabled = str(ae_raw).strip().lower() not in ("false", "0", "no")
    has_attacks = bool(freq and sum(freq.values()) > 0)
    if (not attack_enabled and not has_attacks) or not freq:
        return {"active": False}

    total_rounds = len(timeline) if timeline else int(rc.get("num-server-rounds", 30))
    dominant_attack = max(freq, key=freq.get) if freq else "none"
    dominant_count = freq.get(dominant_attack, 0)
    total_attack_rounds = sum(freq.values())

    stealth_rounds = 0
    assumption_gaps = []
    for row in round_stats:
        try:
            if str(row.get("stealth_applied", "0")) == "1":
                mal_post = float(row.get("max_mal_norm_post", 0) or 0)
                honest_p90 = float(row.get("honest_norm_p90", 0) or 0)
                if mal_post > 0 and honest_p90 > 0 and mal_post <= honest_p90:
                    stealth_rounds += 1
            gap = row.get("assumption_gap")
            if gap and gap not in ("", "-"):
                assumption_gaps.append(float(gap))
        except (ValueError, TypeError):
            continue

    mode = ac.get("mode", rc.get("attack-mode", "adaptive"))
    selection = ac.get("selection_mode", rc.get("attack-selection-mode", "churn"))
    mal_frac = float(ac.get("malicious_fraction", rc.get("attack-malicious-fraction", 0.24)))
    reward_source = str(ac.get("adaptive_reward_source", "server")).strip().lower() or "server"

    return {
        "active": True,
        "mode": mode,
        "selection_mode": selection,
        "malicious_fraction": mal_frac,
        "adaptive_reward_source": reward_source,
        "total_rounds": total_rounds,
        "attack_rounds": total_attack_rounds,
        "dominant_attack": dominant_attack,
        "dominant_count": dominant_count,
        "dominant_fraction": dominant_count / max(total_attack_rounds, 1),
        "all_attack_counts": dict(sorted(freq.items(), key=lambda x: -x[1])),
        "stealth_evasion_rounds": stealth_rounds,
        "assumption_gap_present": any(g < 0 for g in assumption_gaps),
        "assumption_gaps": assumption_gaps,
    }


TRUST_STRATEGIES = {"fltrust", "foolsgold", "flram", "mab-rfl"}
FILTER_STRATEGIES = {"bulyan", "multikrum", "krum"}

def analyze_defense_behavior(data: Dict) -> Dict:
    strategy = data["run_config"].get("strategy", "unknown")
    is_trust = strategy in TRUST_STRATEGIES
    is_filter = strategy in FILTER_STRATEGIES
    trust_csv = data["trust_by_round"]
    defense_sel = data["defense_selection"]
    defense_summary = data["defense_summary"]
    malicious_ids = data["malicious_ids"]

    result = {
        "strategy": strategy,
        "is_trust_based": is_trust,
        "is_filter_based": is_filter,
    }

    if is_trust and trust_csv and malicious_ids:
        mal_trusts = []
        benign_trusts = []
        high_trust_mal = 0
        trust_failure_rounds = set()

        for row in trust_csv:
            cid = str(row.get("client_id", ""))
            try:
                trust = float(row.get("trust_score", 0) or 0)
            except (ValueError, TypeError):
                continue

            if cid in malicious_ids:
                mal_trusts.append(trust)
                if trust > 0.5:
                    high_trust_mal += 1
                    trust_failure_rounds.add(row.get("round", ""))
            else:
                benign_trusts.append(trust)

        avg_mal = sum(mal_trusts) / max(len(mal_trusts), 1)
        avg_benign = sum(benign_trusts) / max(len(benign_trusts), 1)

        result.update({
            "avg_mal_trust": avg_mal,
            "avg_benign_trust": avg_benign,
            "trust_separation": avg_benign - avg_mal,
            "high_trust_malicious_count": high_trust_mal,
            "trust_failure_rounds": len(trust_failure_rounds),
        })

    if is_filter and defense_summary:
        slipthrough = defense_summary.get("overall_malicious_selected_fraction", 0)
        result.update({
            "slipthrough_rate": slipthrough,
            "rounds_with_slipthrough": defense_summary.get(
                "rounds_with_any_malicious_selected", 0),
            "total_malicious_selected": defense_summary.get(
                "total_malicious_selected_by_defense", 0),
            "total_selected": defense_summary.get(
                "total_selected_by_defense", 0),
        })

    return result


# ── Finding detection ────────────────────────────────────────────────────────

def detect_findings(
    acc: Dict, attack: Dict, defense: Dict, asr_series: List[Tuple[int, float]],
    run_config: Optional[Dict] = None,
) -> List[Dict]:
    findings = []
    strategy = defense.get("strategy", "unknown")
    dominant = attack.get("dominant_attack", "none") if attack.get("active") else "none"

    if not attack.get("active"):
        return findings

    if acc.get("available") and acc.get("collapsed"):
        findings.append({
            "pattern": "defense_collapse",
            "severity": "critical",
            "description": f"Accuracy collapsed to {acc['final']:.3f} (< 0.05)",
            "evidence": {"final_accuracy": acc["final"], "peak": acc["peak"]},
        })

    if (acc.get("available") and not acc.get("collapsed")
            and acc["final"] < 0.7 * acc["peak"]
            and (acc["peak"] - acc["final"]) > 0.10):
        findings.append({
            "pattern": "accuracy_degradation",
            "severity": "medium",
            "description": (
                f"Accuracy dropped {acc['peak'] - acc['final']:.1%} from peak "
                f"({acc['peak']:.3f} -> {acc['final']:.3f})"
            ),
            "evidence": {
                "final": acc["final"], "peak": acc["peak"],
                "drop": acc["peak"] - acc["final"],
            },
        })

    if defense.get("is_filter_based") and defense.get("slipthrough_rate", 0) > 0.3:
        findings.append({
            "pattern": "high_slipthrough",
            "severity": "high",
            "description": (
                f"Malicious slipthrough rate: "
                f"{defense['slipthrough_rate']:.1%}"
            ),
            "evidence": {
                "slipthrough_rate": defense["slipthrough_rate"],
                "total_malicious_selected": defense.get("total_malicious_selected"),
                "total_selected": defense.get("total_selected"),
            },
        })

    if defense.get("is_trust_based"):
        if defense.get("high_trust_malicious_count", 0) > 0:
            findings.append({
                "pattern": "trust_failure",
                "severity": "high",
                "description": (
                    f"{defense['high_trust_malicious_count']} malicious client "
                    f"observations with trust > 0.5"
                ),
                "evidence": {
                    "high_trust_count": defense["high_trust_malicious_count"],
                    "trust_failure_rounds": defense.get("trust_failure_rounds", 0),
                    "avg_mal_trust": defense.get("avg_mal_trust"),
                },
            })

        sep = defense.get("trust_separation")
        if sep is not None and sep < 0.1:
            findings.append({
                "pattern": "poor_trust_separation",
                "severity": "medium",
                "description": (
                    f"Trust separation: {sep:.3f} (need > 0.1)"
                ),
                "evidence": {
                    "trust_separation": sep,
                    "avg_mal_trust": defense.get("avg_mal_trust"),
                    "avg_benign_trust": defense.get("avg_benign_trust"),
                },
            })

    if attack.get("stealth_evasion_rounds", 0) > attack.get("total_rounds", 30) * 0.3:
        findings.append({
            "pattern": "stealth_evasion",
            "severity": "medium",
            "description": (
                f"Stealth evasion in {attack['stealth_evasion_rounds']}/"
                f"{attack['total_rounds']} rounds"
            ),
            "evidence": {"stealth_rounds": attack["stealth_evasion_rounds"]},
        })

    if asr_series:
        final_asr = asr_series[-1][1]
        if final_asr > 0.1:
            findings.append({
                "pattern": "backdoor_success",
                "severity": "high",
                "description": f"Backdoor ASR: {final_asr:.3f} (> 0.1)",
                "evidence": {"final_asr": final_asr, "peak_asr": max(v for _, v in asr_series)},
            })

    if (attack.get("mode") == "adaptive"
            and attack.get("dominant_fraction", 0) > 0.3):
        reward_src = attack.get("adaptive_reward_source", "server")
        findings.append({
            "pattern": "adaptive_convergence",
            "severity": "medium",
            "description": (
                f"Adaptive MAB converged to {dominant} "
                f"({attack['dominant_fraction']:.0%} of rounds) "
                f"[reward source: {reward_src}]"
            ),
            "evidence": {
                "dominant_attack": dominant,
                "dominant_fraction": attack["dominant_fraction"],
                "all_counts": attack.get("all_attack_counts"),
                "adaptive_reward_source": reward_src,
            },
        })

    if _HAS_ATLAS:
        for f in findings:
            classification = classify_finding(
                f["pattern"], strategy, dominant,
                accuracy_drop=f.get("evidence", {}).get("drop"),
                slipthrough_rate=f.get("evidence", {}).get("slipthrough_rate"),
                trust_score=f.get("evidence", {}).get("avg_mal_trust"),
                collapse_detected=(f["pattern"] == "defense_collapse"),
            )
            f["atlas_technique_ids"] = classification["atlas_technique_ids"]
            f["atlas_techniques"] = classification["atlas_techniques"]
            f["novelty_status"] = classification["novelty_status"]
            f["literature_refs"] = classification["literature_refs"]
            f["kb_matches"] = classification.get("kb_matches", [])
            f["rationale"] = classification.get("rationale", "")

        # Build rich context from KB + XLSX survey
        for f in findings:
            try:
                ctx = build_finding_context(
                    attack=dominant,
                    defense=strategy,
                    pattern=f["pattern"],
                    accuracy_drop=f.get("evidence", {}).get("drop"),
                    slipthrough_rate=f.get("evidence", {}).get("slipthrough_rate"),
                    trust_score=f.get("evidence", {}).get("avg_mal_trust"),
                )
                f["context"] = ctx
            except Exception:
                f["context"] = None

        # Check novel dimensions at run level
        rc = run_config or {}
        novel_dims = is_novel_dimension(
            attack_mode=rc.get("attack-mode"),
            selection_mode=rc.get("malicious-selection-mode"),
            layering_mode=rc.get("layering-mode"),
            onset_round=rc.get("attack-onset-round", 0),
            intensity_ramp=rc.get("intensity-ramp", 1.0),
        )
        for f in findings:
            f["kb_novel_dimensions"] = [d["dimension"] for d in novel_dims]

    return findings


# ── Suggestion engine ────────────────────────────────────────────────────────

def generate_suggestions(
    data: Dict, findings: List[Dict], attack: Dict, defense: Dict, acc: Dict
) -> List[Dict]:
    strategy = defense.get("strategy", "unknown")
    rc = data["run_config"]
    dominant = attack.get("dominant_attack", "none")
    patterns = {f["pattern"] for f in findings}
    suggestions = []

    if not findings:
        return suggestions

    if strategy == "bulyan":
        if "high_slipthrough" in patterns:
            if dominant == "alie":
                suggestions.append({
                    "finding_pattern": "high_slipthrough",
                    "text": (
                        f"ALIE stayed within the coordinate distribution. "
                        f"Bulyan's coordinate-wise trimming cannot catch "
                        f"in-distribution poisoning. Consider adding "
                        f"cosine-similarity pre-filtering before Bulyan "
                        f"aggregation, or layering FLTrust as a first pass."
                    ),
                    "param_changes": [],
                })
            else:
                mal_nodes = int(rc.get("num-malicious-nodes", 0))
                actual_frac = attack.get("malicious_fraction", 0.24)
                total = int(rc.get("num-total-clients", 100))
                recommended = max(1, round(actual_frac * total * 1.2))
                suggestions.append({
                    "finding_pattern": "high_slipthrough",
                    "text": (
                        f"Bulyan selected "
                        f"{defense.get('slipthrough_rate', 0):.0%} of "
                        f"malicious clients. Increase num-malicious-nodes "
                        f"to tighten filtering."
                    ),
                    "param_changes": [
                        {"param": "num-malicious-nodes",
                         "current": mal_nodes, "suggested": recommended},
                    ],
                })

        if "defense_collapse" in patterns:
            suggestions.append({
                "finding_pattern": "defense_collapse",
                "text": (
                    f"Bulyan collapsed under {dominant}. With "
                    f"{attack.get('malicious_fraction', 0.24):.0%} malicious "
                    f"fraction, Bulyan's theta formula (n-2f) may leave too "
                    f"few updates. Consider reducing the malicious fraction "
                    f"assumption or switching to a trust-based defense like "
                    f"FLTrust for this attack profile."
                ),
                "param_changes": [],
            })

    elif strategy == "multikrum":
        if "high_slipthrough" in patterns:
            current_select = int(rc.get("num-nodes-to-select", 0))
            total = int(rc.get("num-total-clients", 100))
            mal_nodes = int(rc.get("num-malicious-nodes", 0))
            recommended = max(1, total // 2 - mal_nodes)
            suggestions.append({
                "finding_pattern": "high_slipthrough",
                "text": (
                    f"MultiKrum's distance metric failed to separate "
                    f"malicious updates. Dominant attack: {dominant}. "
                    f"Reduce num-nodes-to-select to tighten selection."
                ),
                "param_changes": [
                    {"param": "num-nodes-to-select",
                     "current": current_select, "suggested": recommended},
                ],
            })

        if "defense_collapse" in patterns:
            suggestions.append({
                "finding_pattern": "defense_collapse",
                "text": (
                    f"MultiKrum collapsed under {dominant}. The distance-"
                    f"based scoring was unable to distinguish malicious from "
                    f"honest updates. Consider combining MultiKrum with a "
                    f"trust-based pre-filter, or test with lower malicious "
                    f"fractions to find the defense's tolerance threshold."
                ),
                "param_changes": [],
            })

    elif strategy == "fedtrimmedavg":
        if "defense_collapse" in patterns or "accuracy_degradation" in patterns:
            current_beta = float(rc.get("trimmed-beta", 0.2))
            suggested_beta = min(0.4, current_beta + 0.1)
            suggestions.append({
                "finding_pattern": "accuracy_degradation",
                "text": (
                    f"Coordinate-wise trimming failed under {dominant}. "
                    f"Increase trimmed-beta to trim more aggressively — but "
                    f"verify clean accuracy doesn't degrade. If ALIE is "
                    f"dominant, trimming alone may be insufficient; consider "
                    f"a cosine-based defense."
                ),
                "param_changes": [
                    {"param": "trimmed-beta",
                     "current": current_beta, "suggested": suggested_beta},
                ],
            })

    elif strategy == "fedmedian":
        if "defense_collapse" in patterns:
            mal_frac = attack.get("malicious_fraction", 0.24)
            suggestions.append({
                "finding_pattern": "defense_collapse",
                "text": (
                    f"Coordinate-wise median was shifted by {dominant} with "
                    f"{mal_frac:.0%} malicious fraction. When enough clients "
                    f"collude, the median moves toward poisoned values. "
                    f"Consider combining with a trust-based pre-filter to "
                    f"reduce the effective malicious fraction before "
                    f"computing the median."
                ),
                "param_changes": [],
            })

    elif strategy == "fltrust":
        if "poor_trust_separation" in patterns:
            root_size = int(rc.get("fltrust-root-size", 1860))
            server_lr = float(rc.get("fltrust-server-lr", 0.1))
            suggestions.append({
                "finding_pattern": "poor_trust_separation",
                "text": (
                    f"FLTrust cosine trust scores do not separate "
                    f"malicious from benign clients (separation="
                    f"{defense.get('trust_separation', 0):.3f}). "
                    f"Non-IID variance may mask malicious behavior. "
                    f"Increase fltrust-root-size for stronger server "
                    f"gradient signal."
                ),
                "param_changes": [
                    {"param": "fltrust-root-size",
                     "current": root_size, "suggested": root_size * 2},
                    {"param": "fltrust-server-lr",
                     "current": server_lr,
                     "suggested": round(server_lr * 0.5, 3)},
                ],
            })

        if "trust_failure" in patterns:
            strength = float(rc.get("trust-aggregation-strength", 1.0))
            suggestions.append({
                "finding_pattern": "trust_failure",
                "text": (
                    f"Malicious clients received trust > 0.5 in "
                    f"{defense.get('trust_failure_rounds', 0)} rounds. "
                    f"The trust mechanism is being bypassed. Reduce "
                    f"trust-aggregation-strength to penalize uncertain "
                    f"clients more aggressively."
                ),
                "param_changes": [
                    {"param": "trust-aggregation-strength",
                     "current": strength,
                     "suggested": round(strength * 0.5, 2)},
                ],
            })

    elif strategy == "foolsgold":
        if "accuracy_degradation" in patterns or "defense_collapse" in patterns:
            suggestions.append({
                "finding_pattern": "accuracy_degradation",
                "text": (
                    f"FoolsGold similarity tracking was evaded. Adaptive "
                    f"mode produces diverse attack combos each round, so "
                    f"no malicious client looks like a Sybil. Consider "
                    f"combining FoolsGold with norm-based pre-filtering, "
                    f"or add a cooldown penalty for clients whose updates "
                    f"cause accuracy drops."
                ),
                "param_changes": [],
            })

        if "trust_failure" in patterns or "poor_trust_separation" in patterns:
            suggestions.append({
                "finding_pattern": "trust_failure",
                "text": (
                    f"FoolsGold assigned high trust to malicious clients. "
                    f"When attackers diversify their update patterns, "
                    f"similarity-based detection fails. A secondary signal "
                    f"(e.g., update norm or cosine to global direction) "
                    f"would strengthen detection."
                ),
                "param_changes": [],
            })

    elif strategy == "flram":
        if "trust_failure" in patterns or "poor_trust_separation" in patterns:
            min_score = float(rc.get("flram-min-score", 0.1))
            suggestions.append({
                "finding_pattern": "trust_failure",
                "text": (
                    f"FLRAM's multi-signal scoring (norm, direction, sign "
                    f"agreement) gave malicious clients high scores. "
                    f"Dominant attack {dominant} mimics honest signal "
                    f"patterns. Increase flram-min-score to raise the "
                    f"exclusion threshold, or add historical consistency "
                    f"tracking — clients that oscillate between high and "
                    f"low norm are suspicious."
                ),
                "param_changes": [
                    {"param": "flram-min-score",
                     "current": min_score,
                     "suggested": round(min(0.5, min_score + 0.15), 2)},
                ],
            })

        if "defense_collapse" in patterns:
            suggestions.append({
                "finding_pattern": "defense_collapse",
                "text": (
                    f"FLRAM collapsed under {dominant}. The reliability "
                    f"scoring was insufficient to filter poisoned updates. "
                    f"Test with stronger trust-aggregation-strength or "
                    f"combine FLRAM with a distance-based pre-filter like "
                    f"MultiKrum."
                ),
                "param_changes": [],
            })

    elif strategy == "mab-rfl":
        if "defense_collapse" in patterns or "accuracy_degradation" in patterns:
            decay = float(rc.get("mab-rfl-reputation-decay", 0.9))
            warmup = int(rc.get("trust-warmup-rounds", 3))
            suggestions.append({
                "finding_pattern": "defense_collapse",
                "text": (
                    f"MAB-RFL reputation scores decayed too slowly to "
                    f"catch malicious clients. Increase reputation-decay "
                    f"to penalize bad rounds faster, and reduce warmup "
                    f"rounds to start filtering earlier."
                ),
                "param_changes": [
                    {"param": "mab-rfl-reputation-decay",
                     "current": decay,
                     "suggested": round(min(0.98, decay + 0.05), 2)},
                    {"param": "trust-warmup-rounds",
                     "current": warmup,
                     "suggested": max(1, warmup - 2)},
                ],
            })

        if "trust_failure" in patterns:
            current_wt = float(rc.get("mab-rfl-current-weight", 0.3))
            suggestions.append({
                "finding_pattern": "trust_failure",
                "text": (
                    f"Malicious clients maintained high reputation in "
                    f"MAB-RFL. Increase mab-rfl-current-weight to give "
                    f"more weight to the current round's score versus "
                    f"historical reputation."
                ),
                "param_changes": [
                    {"param": "mab-rfl-current-weight",
                     "current": current_wt,
                     "suggested": round(min(0.7, current_wt + 0.15), 2)},
                ],
            })

    # Cross-cutting suggestions
    if "adaptive_convergence" in patterns:
        reward_src = attack.get("adaptive_reward_source", "server")
        reward_note = ""
        if reward_src == "client":
            reward_note = (
                f" Note: this used client-side reward (malicious clients' "
                f"local eval) — the server-side MAB may converge to a "
                f"different attack."
            )
        suggestions.append({
            "finding_pattern": "adaptive_convergence",
            "text": (
                f"Adaptive MAB converged to {dominant} in "
                f"{attack.get('dominant_fraction', 0):.0%} of rounds "
                f"(reward source: {reward_src}) — "
                f"this is the dominant vulnerability for {strategy}. "
                f"Run a targeted single-attack experiment with just "
                f"{dominant} to measure its standalone impact, then test "
                f"a defense parameter adjustment against that attack."
                f"{reward_note}"
            ),
            "param_changes": [],
        })

    if attack.get("assumption_gap_present"):
        suggestions.append({
            "finding_pattern": "assumption_gap",
            "text": (
                f"Defense underestimated the number of malicious nodes. "
                f"Rerun with num-malicious-nodes matching the actual "
                f"malicious fraction to get a fair evaluation."
            ),
            "param_changes": [],
        })

    for i, s in enumerate(suggestions):
        s["rank"] = i + 1

    return suggestions


# ── Terminal output ──────────────────────────────────────────────────────────

def _label(val, thresholds):
    for threshold, label in thresholds:
        if val >= threshold:
            return label
    return thresholds[-1][1] if thresholds else ""


def format_terminal_output(
    run_dir: Path, data: Dict, acc: Dict, attack: Dict,
    defense: Dict, findings: List[Dict], suggestions: List[Dict]
) -> str:
    rc = data["run_config"]
    strategy = rc.get("strategy", "unknown")
    dataset = rc.get("dataset", "unknown")
    partitioner = rc.get("partitioner", "dirichlet")
    alpha = rc.get("dirichlet-alpha", "?")
    rounds = rc.get("num-server-rounds", "?")
    timestamp = data["meta"].get("timestamp", "unknown")
    iid_label = "IID" if partitioner == "iid" else "non-IID"

    lines = []
    w = 60
    lines.append("=" * w)
    lines.append(f"  POST-RUN ANALYSIS: {strategy} | {dataset}")
    lines.append(f"  Run: {timestamp}")
    lines.append("=" * w)
    lines.append("")

    # Results
    lines.append("RESULTS")
    lines.append("-" * 40)
    lines.append(f"  Strategy       : {strategy}")
    lines.append(f"  Dataset        : {dataset} ({iid_label}, alpha={alpha})")
    lines.append(f"  Rounds         : {rounds}")

    if acc.get("available"):
        lines.append(
            f"  Final Accuracy : {acc['final']:.3f}  "
            f"(peak: {acc['peak']:.3f}, round {acc['peak_round']})"
        )
        lines.append(f"  Trajectory     : {acc['trajectory']}")
    else:
        lines.append("  Final Accuracy : [data unavailable]")

    f1_series = data.get("f1_macro", [])
    if f1_series:
        lines.append(f"  Final F1 Macro : {f1_series[-1][1]:.3f}")

    asr_series = data.get("backdoor_asr", [])
    if asr_series:
        final_asr = asr_series[-1][1]
        asr_label = _label(final_asr, [
            (0.5, "HIGH"), (0.1, "MODERATE"), (0.0, "LOW")])
        lines.append(f"  Backdoor ASR   : {final_asr:.3f}  [{asr_label}]")

    lines.append("")

    if attack.get("active"):
        lines.append("ATTACK CONFIG")
        lines.append("-" * 40)
        reward_src = attack.get("adaptive_reward_source", "server")
        mode_detail = (
            f"{attack['mode']} "
            f"({attack['selection_mode']}, "
            f"{attack['malicious_fraction']:.0%} malicious)"
        )
        if attack["mode"] == "adaptive":
            mode_detail += f"  [reward: {reward_src}]"
        lines.append(f"  Mode           : {mode_detail}")
        dom = attack["dominant_attack"]
        lines.append(
            f"  Dominant Attack: {dom} "
            f"({attack['dominant_count']}/{attack['attack_rounds']} "
            f"rounds, {attack['dominant_fraction']:.0%})"
        )
        counts_str = ", ".join(
            f"{k}:{v}" for k, v in attack["all_attack_counts"].items()
        )
        lines.append(f"  All Attacks    : {counts_str}")
        lines.append("")

    # Defense behavior
    lines.append("DEFENSE BEHAVIOR")
    lines.append("-" * 40)
    if defense.get("is_trust_based"):
        lines.append("  [trust-based]")
        if "avg_mal_trust" in defense:
            lines.append(
                f"  Avg trust (malicious) : "
                f"{defense['avg_mal_trust']:.3f}"
            )
            lines.append(
                f"  Avg trust (benign)    : "
                f"{defense['avg_benign_trust']:.3f}"
            )
            sep = defense["trust_separation"]
            sep_label = "GOOD" if sep >= 0.1 else "POOR"
            lines.append(
                f"  Trust separation      : {sep:.3f}  [{sep_label}]"
            )
            lines.append(
                f"  Malicious trust > 0.5 : "
                f"{defense.get('high_trust_malicious_count', 0)} "
                f"observations"
            )
        else:
            lines.append("  [no trust data available]")
    elif defense.get("is_filter_based"):
        lines.append("  [filter-based]")
        slip = defense.get("slipthrough_rate", 0)
        slip_label = "HIGH" if slip > 0.3 else "OK"
        lines.append(
            f"  Slipthrough rate : {slip:.1%}  [{slip_label}]"
        )
        lines.append(
            f"  Rounds with leak : "
            f"{defense.get('rounds_with_slipthrough', 0)}"
        )
    else:
        lines.append(f"  [{strategy} — coordinate-wise defense]")
    lines.append("")

    # Findings
    lines.append("FINDINGS")
    lines.append("-" * 40)
    if not findings:
        lines.append("  No vulnerability findings detected.")
    known_count = 0
    novel_count = 0
    for i, f in enumerate(findings, 1):
        severity = f.get("severity", "medium").upper()
        novelty = f.get("novelty_status", "")
        if novelty in ("known_weakness", "reproduced"):
            tag = "KNOWN"
            known_count += 1
        elif novelty == "known_robust":
            tag = "ROBUST"
            known_count += 1
        elif novelty == "candidate_new":
            tag = "NOVEL"
            novel_count += 1
        else:
            tag = novelty.upper() if novelty else "?"
        lines.append(
            f"  [{i}] [{tag}] {f['pattern'].upper().replace('_', ' ')}  "
            f"(severity: {severity})"
        )
        lines.append(f"      {f['description']}")
        if f.get("atlas_techniques"):
            atlas_str = ", ".join(
                f"{t['id']} ({t['name']})" for t in f["atlas_techniques"][:3]
            )
            lines.append(f"      ATLAS: {atlas_str}")

        # Rich context from KB + XLSX survey
        ctx = f.get("context")
        if ctx:
            # Sub-categories
            for sc in ctx["atlas_mapping"].get("sub_categories", [])[:2]:
                for st in sc.get("matched_sub_techniques", [])[:1]:
                    lines.append(
                        f"      Sub-category: {sc['atlas_id']} -> {st['name']}"
                    )

            # Defense assumptions exploited
            exploited = ctx.get("assumptions_exploited", [])
            if exploited:
                lines.append(f"      Assumption exploited: {exploited[0]}")

            # What was known
            known_text = ctx.get("what_was_known", "")
            if known_text:
                # Truncate for terminal display
                if len(known_text) > 120:
                    known_text = known_text[:117] + "..."
                lines.append(f"      Known: {known_text}")

            # What might be new
            new_text = ctx.get("what_might_be_new")
            if new_text:
                if len(new_text) > 120:
                    new_text = new_text[:117] + "..."
                lines.append(f"      Novelty: {new_text}")

            # MAB insight
            mab = ctx.get("mab_insight")
            if mab:
                if len(mab) > 120:
                    mab = mab[:117] + "..."
                lines.append(f"      MAB: {mab}")

            # Unified literature
            lit = ctx.get("literature", {})
            matching = lit.get("matching_papers", [])
            defense_breaking = lit.get("defense_breaking_papers", [])
            related = lit.get("related_papers", [])
            if matching:
                for p in matching[:3]:
                    first_author = (
                        p.get("authors", "").split(",")[0].strip()
                        or p.get("key", "?")
                    )
                    year = p.get("year", "?")
                    result = (
                        p.get("experimental_results")
                        or p.get("mechanism")
                        or ""
                    )
                    if len(result) > 80:
                        result = result[:77] + "..."
                    lines.append(
                        f"      Paper: {first_author} ({year}) — {result}"
                    )
            if defense_breaking:
                lines.append(
                    f"      Defense-breaking: {len(defense_breaking)} paper(s)"
                )
            if related:
                lines.append(
                    f"      Related: {len(related)} paper(s)"
                )
            if lit.get("total_papers_searched"):
                lines.append(
                    f"      Searched: {lit['total_papers_searched']} "
                    f"in-scope papers"
                )

            # Next steps (first one only for brevity)
            steps = ctx.get("what_to_test_next", [])
            if steps:
                lines.append(f"      Next: {steps[0]}")
        else:
            # Fallback to old-style KB display
            kb_matches = f.get("kb_matches", [])
            if kb_matches:
                refs = [m.get("first_demonstrated", "?") for m in kb_matches]
                lines.append(
                    f"      KB: {len(kb_matches)} match(es) — {', '.join(refs)}"
                )
            elif novelty == "candidate_new":
                lines.append("      KB: 0 matches in knowledge base")

        novel_dims = f.get("kb_novel_dimensions", [])
        if novel_dims:
            lines.append(
                f"      Novel dims: {', '.join(d.replace('_', ' ') for d in novel_dims)}"
            )
        lines.append("")
    if findings:
        lines.append(
            f"  Summary: {known_count} known, {novel_count} candidate novel, "
            f"{len(findings) - known_count - novel_count} other"
        )
    lines.append("")

    # Suggestions
    lines.append("SUGGESTIONS")
    lines.append("-" * 40)
    if not suggestions:
        lines.append("  No specific suggestions for this run.")
    for s in suggestions:
        lines.append(f"  [{s['rank']}] {s['text']}")
        if s.get("param_changes"):
            for pc in s["param_changes"]:
                lines.append(
                    f"      -> {pc['param']}: {pc['current']} -> "
                    f"{pc['suggested']}"
                )
        lines.append("")

    lines.append("=" * w)
    json_path = run_dir / "summaries" / "run_analysis.json"
    lines.append(f"  Saved: {json_path}")
    lines.append("=" * w)

    return "\n".join(lines)


# ── JSON output ──────────────────────────────────────────────────────────────

def _strip_context(findings: List[Dict]) -> List[Dict]:
    """Remove the heavy 'context' key for JSON serialization; keep a summary."""
    out = []
    for f in findings:
        stripped = {k: v for k, v in f.items() if k != "context"}
        ctx = f.get("context")
        if ctx:
            lit = ctx.get("literature", {})
            stripped["context_summary"] = {
                "novelty_status": lit.get("status"),
                "what_was_known": ctx.get("what_was_known", ""),
                "what_might_be_new": ctx.get("what_might_be_new"),
                "assumptions_exploited": ctx.get("assumptions_exploited", []),
                "what_to_test_next": ctx.get("what_to_test_next", []),
                "matching_papers": len(lit.get("matching_papers", [])),
                "related_papers": len(lit.get("related_papers", [])),
                "defense_breaking_papers": len(
                    lit.get("defense_breaking_papers", [])
                ),
            }
        out.append(stripped)
    return out


def build_json_output(
    run_dir: Path, data: Dict, acc: Dict, attack: Dict,
    defense: Dict, findings: List[Dict], suggestions: List[Dict]
) -> Dict:
    rc = data["run_config"]
    f1_series = data.get("f1_macro", [])
    asr_series = data.get("backdoor_asr", [])

    output = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_dir": str(run_dir),
        "meta": {
            "strategy": rc.get("strategy", "unknown"),
            "dataset": rc.get("dataset", "unknown"),
            "partitioner": rc.get("partitioner", "dirichlet"),
            "dirichlet_alpha": rc.get("dirichlet-alpha"),
            "num_rounds": rc.get("num-server-rounds"),
            "timestamp": data["meta"].get("timestamp", "unknown"),
        },
        "accuracy": acc if acc.get("available") else {"available": False},
        "f1_macro": {
            "final": f1_series[-1][1] if f1_series else None,
            "peak": max((v for _, v in f1_series), default=None),
        },
        "backdoor_asr": {
            "final": asr_series[-1][1] if asr_series else None,
            "peak": max((v for _, v in asr_series), default=None),
        },
        "attack": attack,
        "defense": defense,
        "findings": _strip_context(findings),
        "suggestions": suggestions,
    }

    return output


# ── Main ─────────────────────────────────────────────────────────────────────

def analyze_run(run_dir: Path, json_only: bool = False) -> Dict:
    data = load_run_data(run_dir)
    acc = compute_accuracy_stats(data["accuracy"])
    attack = analyze_attack_behavior(data)
    defense = analyze_defense_behavior(data)
    findings = detect_findings(acc, attack, defense, data["backdoor_asr"],
                               run_config=data.get("run_config"))
    suggestions = generate_suggestions(data, findings, attack, defense, acc)

    json_output = build_json_output(
        run_dir, data, acc, attack, defense, findings, suggestions
    )

    json_path = run_dir / "summaries" / "run_analysis.json"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(json_output, f, indent=2, default=str)

    if not json_only:
        terminal = format_terminal_output(
            run_dir, data, acc, attack, defense, findings, suggestions
        )
        print(terminal)

    return json_output


def main():
    parser = argparse.ArgumentParser(
        description="Post-run vulnerability analysis for FL experiments"
    )
    parser.add_argument("run_dir", type=Path, help="Path to completed run directory")
    parser.add_argument("--json-only", action="store_true",
                        help="Only write JSON, no terminal output")
    args = parser.parse_args()

    if not args.run_dir.is_dir():
        print(f"Error: {args.run_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    analyze_run(args.run_dir, json_only=args.json_only)


if __name__ == "__main__":
    main()
