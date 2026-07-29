"""
MITRE ATLAS vulnerability analysis pipeline for Dynamic FL.

Queries the database, classifies findings via ATLAS mapping, scores severity,
populates the agent_recommendations table, and generates a markdown report.

Usage:
    python db/analyze.py                  # analyze + generate report
    python db/analyze.py --report-only    # just regenerate the report from existing recommendations
"""

import json
import sqlite3
import sys
import uuid
from datetime import datetime
from pathlib import Path

DB_DIR = Path(__file__).parent
DB_PATH = DB_DIR / "dynamic_fl.sqlite"
REPORT_PATH = DB_DIR.parent / "docs" / "reports"

sys.path.insert(0, str(DB_DIR))
from atlas_mapping import (
    ATLAS_TECHNIQUES,
    LITERATURE,
    classify_finding,
    get_attack_techniques,
    get_novelty_summary,
)


def _uid():
    return uuid.uuid4().hex[:12]


def get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ---------------------------------------------------------------------------
# Analysis queries — extract findings from the database
# ---------------------------------------------------------------------------

def find_defense_collapses(conn):
    """Find defenses where accuracy collapsed below 5% under attack."""
    rows = conn.execute("""
        SELECT
            bc.strategy,
            r.attack_mode,
            r.layering_mode,
            r.selection_mode,
            bc.accuracy_drop,
            bc.attacked_final_accuracy,
            bc.clean_final_accuracy,
            bc.f1_macro_drop,
            bc.collapse_detected,
            ae.attack_name AS final_attack
        FROM baseline_comparisons bc
        JOIN runs r ON r.run_id = bc.attacked_run_id
        LEFT JOIN attack_events ae ON ae.run_id = bc.attacked_run_id
            AND ae.round = (SELECT MAX(round) FROM attack_events WHERE run_id = ae.run_id)
        WHERE bc.collapse_detected = 1
        ORDER BY bc.accuracy_drop DESC
    """).fetchall()
    return [dict(r) for r in rows]


def find_accuracy_degradations(conn):
    """Find significant accuracy drops (>10pp) without full collapse."""
    rows = conn.execute("""
        SELECT
            bc.strategy,
            r.attack_mode,
            r.layering_mode,
            r.selection_mode,
            bc.accuracy_drop,
            bc.attacked_final_accuracy,
            bc.clean_final_accuracy,
            bc.f1_macro_drop,
            bc.collapse_detected,
            ae.attack_name AS final_attack
        FROM baseline_comparisons bc
        JOIN runs r ON r.run_id = bc.attacked_run_id
        LEFT JOIN attack_events ae ON ae.run_id = bc.attacked_run_id
            AND ae.round = (SELECT MAX(round) FROM attack_events WHERE run_id = ae.run_id)
        WHERE bc.accuracy_drop > 0.1 AND bc.collapse_detected = 0
        ORDER BY bc.accuracy_drop DESC
    """).fetchall()
    return [dict(r) for r in rows]


def find_slipthrough_rates(conn):
    """Find strategies with high malicious client slipthrough."""
    rows = conn.execute("""
        SELECT
            r.strategy,
            SUM(CASE WHEN ds.is_malicious = 1 AND ds.selected_for_aggregation = 1 THEN 1 ELSE 0 END) AS mal_selected,
            SUM(CASE WHEN ds.is_malicious = 1 THEN 1 ELSE 0 END) AS mal_total,
            ROUND(
                SUM(CASE WHEN ds.is_malicious = 1 AND ds.selected_for_aggregation = 1 THEN 1 ELSE 0 END) * 1.0
                / MAX(SUM(CASE WHEN ds.is_malicious = 1 THEN 1 ELSE 0 END), 1),
            3) AS slip_rate
        FROM defense_selection ds
        JOIN runs r ON r.run_id = ds.run_id
        WHERE r.is_baseline = 0
        GROUP BY r.strategy
        HAVING slip_rate > 0.3
        ORDER BY slip_rate DESC
    """).fetchall()
    return [dict(r) for r in rows]


def find_trust_failures(conn):
    """Find malicious clients with trust scores > 0.5."""
    rows = conn.execute("""
        SELECT
            r.strategy,
            tm.round,
            tm.client_id,
            tm.trust_score,
            tm.effective_weight,
            tm.reputation,
            COUNT(*) AS occurrences
        FROM trust_metrics tm
        JOIN runs r ON r.run_id = tm.run_id
        JOIN client_attack_events cae
          ON cae.run_id = tm.run_id AND cae.round = tm.round
             AND CAST(cae.src_node_id AS TEXT) = CAST(tm.client_id AS TEXT)
        WHERE cae.is_malicious = 1
          AND r.is_baseline = 0
          AND tm.trust_score > 0.5
        GROUP BY r.strategy
        ORDER BY tm.trust_score DESC
    """).fetchall()
    return [dict(r) for r in rows]


def find_trust_separation(conn):
    """Find strategies with poor trust score separation between benign and malicious."""
    rows = conn.execute("""
        SELECT
            r.strategy,
            cae.is_malicious,
            AVG(tm.trust_score) AS avg_trust,
            MIN(tm.trust_score) AS min_trust,
            MAX(tm.trust_score) AS max_trust,
            COUNT(*) AS n
        FROM trust_metrics tm
        JOIN runs r ON r.run_id = tm.run_id
        JOIN client_attack_events cae
          ON cae.run_id = tm.run_id AND cae.round = tm.round
             AND CAST(cae.src_node_id AS TEXT) = CAST(tm.client_id AS TEXT)
        WHERE r.is_baseline = 0
        GROUP BY r.strategy, cae.is_malicious
        ORDER BY r.strategy, cae.is_malicious
    """).fetchall()

    findings = []
    by_strategy = {}
    for r in rows:
        d = dict(r)
        by_strategy.setdefault(d["strategy"], {})[d["is_malicious"]] = d

    for strategy, groups in by_strategy.items():
        if 0 in groups and 1 in groups:
            benign_avg = groups[0]["avg_trust"]
            mal_avg = groups[1]["avg_trust"]
            separation = benign_avg - mal_avg
            if separation < 0.1:
                findings.append({
                    "strategy": strategy,
                    "benign_avg_trust": benign_avg,
                    "malicious_avg_trust": mal_avg,
                    "separation": separation,
                })
    return findings


def find_stealth_evasion(conn):
    """Find rounds where stealth-capped malicious norms evade detection."""
    rows = conn.execute("""
        SELECT
            r.strategy,
            ae.attack_name,
            COUNT(*) AS evasion_rounds,
            r.num_rounds
        FROM attack_events ae
        JOIN runs r ON r.run_id = ae.run_id
        WHERE ae.stealth_applied = 1
          AND ae.max_mal_norm_post <= ae.honest_norm_p90
        GROUP BY r.strategy, ae.attack_name
        ORDER BY evasion_rounds DESC
    """).fetchall()
    return [dict(r) for r in rows]


def find_adaptive_convergence(conn):
    """Find dominant attacks per defense (MAB convergence patterns)."""
    rows = conn.execute("""
        SELECT
            r.strategy,
            ae.attack_name,
            COUNT(*) AS rounds_selected
        FROM attack_events ae
        JOIN runs r ON r.run_id = ae.run_id
        WHERE r.is_baseline = 0
        GROUP BY r.strategy, ae.attack_name
        ORDER BY r.strategy, rounds_selected DESC
    """).fetchall()

    # Get total attacked rounds per strategy
    totals = conn.execute("""
        SELECT r.strategy, COUNT(*) AS total_rounds
        FROM attack_events ae
        JOIN runs r ON r.run_id = ae.run_id
        WHERE r.is_baseline = 0
        GROUP BY r.strategy
    """).fetchall()
    total_by_strategy = {t["strategy"]: t["total_rounds"] for t in totals}

    findings = []
    by_strategy = {}
    for r in rows:
        d = dict(r)
        by_strategy.setdefault(d["strategy"], []).append(d)

    for strategy, attacks in by_strategy.items():
        if not attacks:
            continue
        total = total_by_strategy.get(strategy, 30)
        for a in attacks:
            a["fraction"] = round(a["rounds_selected"] / max(total, 1), 3)
        attacks.sort(key=lambda x: x["fraction"], reverse=True)
        if attacks[0]["fraction"] > 0.3:
            findings.append({
                "strategy": strategy,
                "dominant_attack": attacks[0]["attack_name"],
                "fraction": attacks[0]["fraction"],
                "all_attacks": attacks,
            })
    return findings


def find_resilient_defenses(conn):
    """Find defenses that showed minimal accuracy degradation."""
    rows = conn.execute("""
        SELECT
            bc.strategy,
            bc.accuracy_drop,
            bc.attacked_final_accuracy,
            bc.clean_final_accuracy,
            bc.collapse_detected
        FROM baseline_comparisons bc
        WHERE bc.accuracy_drop < 0.05 AND bc.accuracy_drop > -0.05
        ORDER BY ABS(bc.accuracy_drop) ASC
    """).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_finding(finding_type, data):
    """Score a finding for defense_weakness, attack_effectiveness, evidence_strength."""

    if finding_type == "defense_collapse":
        weakness = min(1.0, 0.7 + (data.get("accuracy_drop", 0) or 0))
        effectiveness = 0.9 if data.get("collapse_detected") else 0.7
        evidence = 0.6  # single seed
    elif finding_type == "accuracy_degradation":
        drop = data.get("accuracy_drop", 0) or 0
        weakness = min(1.0, 0.3 + drop * 2)
        effectiveness = min(1.0, 0.3 + drop * 2)
        evidence = 0.5
    elif finding_type == "high_slipthrough":
        rate = data.get("slip_rate", 0) or 0
        weakness = min(1.0, rate)
        effectiveness = min(1.0, rate * 0.8)
        evidence = 0.6
    elif finding_type == "trust_failure":
        weakness = 0.8
        effectiveness = 0.7
        evidence = 0.5
    elif finding_type == "poor_trust_separation":
        weakness = 0.6
        effectiveness = 0.5
        evidence = 0.5
    elif finding_type == "stealth_evasion":
        weakness = 0.5
        effectiveness = 0.6
        evidence = 0.5
    elif finding_type == "adaptive_convergence":
        weakness = 0.5
        effectiveness = 0.5
        evidence = 0.7
    elif finding_type == "resilient_defense":
        weakness = 0.1
        effectiveness = 0.1
        evidence = 0.6
    else:
        weakness = 0.3
        effectiveness = 0.3
        evidence = 0.3

    priority = 0.4 * weakness + 0.3 * effectiveness + 0.3 * evidence
    return {
        "defense_weakness_score": round(weakness, 2),
        "attack_effectiveness_score": round(effectiveness, 2),
        "evidence_strength": round(evidence, 2),
        "priority_score": round(priority, 2),
    }


# ---------------------------------------------------------------------------
# Write recommendations to database
# ---------------------------------------------------------------------------

def write_recommendations(conn, findings):
    """Write classified findings to the agent_recommendations table."""
    conn.execute("DELETE FROM agent_recommendations")

    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    for f in findings:
        atlas_ids = ",".join(f["classification"]["atlas_technique_ids"])
        novelty = f["classification"]["novelty_status"]
        scores = f["scores"]

        config = json.dumps({
            "strategy": f.get("strategy", ""),
            "attack": f.get("attack", ""),
            "pattern": f.get("pattern", ""),
        })

        conn.execute(
            """INSERT INTO agent_recommendations VALUES
               (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f"rec_{_uid()}",
                now,
                None,  # run_id (could be linked but not critical)
                f.get("strategy", ""),
                f.get("attack", ""),
                "flwrlabs/femnist",
                f.get("attack_mode", ""),
                f.get("selection_mode", ""),
                f.get("layering_mode", ""),
                scores["defense_weakness_score"],
                scores["attack_effectiveness_score"],
                scores["evidence_strength"],
                scores["priority_score"],
                config,
                f["classification"]["rationale"],
                atlas_ids,
                novelty,
            ),
        )
    conn.commit()


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(conn, findings):
    """Generate a markdown vulnerability report with ATLAS mappings."""

    lines = []
    lines.append("# Dynamic FL Vulnerability Analysis Report — MITRE ATLAS Mapped")
    lines.append("")
    lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")

    # --- Database summary ---
    total_runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    strategies = conn.execute(
        "SELECT DISTINCT strategy FROM runs ORDER BY strategy"
    ).fetchall()
    strategy_list = [s[0] for s in strategies]
    total_comparisons = conn.execute("SELECT COUNT(*) FROM baseline_comparisons").fetchone()[0]

    lines.append("## Database Summary")
    lines.append("")
    lines.append(f"- **Runs ingested:** {total_runs}")
    lines.append(f"- **Strategies tested:** {', '.join(strategy_list)}")
    lines.append(f"- **Baseline comparisons:** {total_comparisons}")
    lines.append(f"- **Dataset:** FEMNIST (non-IID, Dirichlet)")
    lines.append(f"- **Seeds per config:** 1 (pilot — needs replication)")
    lines.append("")

    # --- Executive summary ---
    lines.append("## Executive Summary")
    lines.append("")

    collapses = [f for f in findings if f["pattern"] == "defense_collapse"]
    resilient = [f for f in findings if f["pattern"] == "resilient_defense"]
    degraded = [f for f in findings if f["pattern"] == "accuracy_degradation"]

    if collapses:
        collapsed_defenses = sorted(set(f["strategy"] for f in collapses))
        lines.append(f"**Collapsed under attack:** {', '.join(collapsed_defenses)}")
        for f in collapses:
            lines.append(
                f"  - {f['strategy']}: {f.get('clean_final_accuracy', 0):.1%} → "
                f"{f.get('attacked_final_accuracy', 0):.1%} "
                f"(drop: {f.get('accuracy_drop', 0):.1%}) "
                f"under {f.get('attack', 'unknown')}"
            )
        lines.append("")

    if resilient:
        resilient_defenses = sorted(set(f["strategy"] for f in resilient))
        lines.append(f"**Resilient (minimal degradation):** {', '.join(resilient_defenses)}")
        for f in resilient:
            lines.append(
                f"  - {f['strategy']}: {f.get('clean_final_accuracy', 0):.1%} → "
                f"{f.get('attacked_final_accuracy', 0):.1%} "
                f"(drop: {f.get('accuracy_drop', 0):.1%})"
            )
        lines.append("")

    if degraded:
        degraded_defenses = sorted(set(f["strategy"] for f in degraded))
        lines.append(f"**Significant degradation (no collapse):** {', '.join(degraded_defenses)}")
        lines.append("")

    # --- Per-finding analysis ---
    lines.append("## Findings with MITRE ATLAS Mapping")
    lines.append("")

    for i, f in enumerate(findings, 1):
        c = f["classification"]
        s = f["scores"]
        atlas_str = ", ".join(
            f'{t["id"]} ({t["name"]})'
            for t in c["atlas_techniques"]
        )

        lines.append(f"### Finding {i}: {f['pattern'].replace('_', ' ').title()} — {f['strategy']}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Defense | {f['strategy']} |")
        lines.append(f"| Attack | {f.get('attack', 'N/A')} |")
        lines.append(f"| Pattern | {f['pattern']} |")
        lines.append(f"| ATLAS Techniques | {atlas_str} |")
        lines.append(f"| Novelty Status | **{c['novelty_status']}** |")
        lines.append(f"| Severity | {c['severity']} |")
        lines.append(f"| Weakness Score | {s['defense_weakness_score']:.2f} |")
        lines.append(f"| Effectiveness Score | {s['attack_effectiveness_score']:.2f} |")
        lines.append(f"| Evidence Strength | {s['evidence_strength']:.2f} |")
        lines.append(f"| Priority | {s['priority_score']:.2f} |")
        lines.append("")
        lines.append(f"**Rationale:** {c['rationale']}")
        lines.append("")
        if c["literature_refs"]:
            lines.append(f"**Literature:** {', '.join(c['literature_refs'])}")
            lines.append("")

    # --- Cross-defense comparison ---
    lines.append("## Cross-Defense Comparison")
    lines.append("")
    lines.append("| Defense | Clean Acc | Attacked Acc | Drop | Collapsed | ATLAS Category |")
    lines.append("|---------|-----------|-------------|------|-----------|----------------|")

    bc_rows = conn.execute("""
        SELECT strategy, clean_final_accuracy, attacked_final_accuracy,
               accuracy_drop, collapse_detected
        FROM baseline_comparisons
        WHERE accuracy_drop IS NOT NULL
        ORDER BY accuracy_drop DESC
    """).fetchall()

    for row in bc_rows:
        r = dict(row)
        collapse = "YES" if r["collapse_detected"] else "no"
        category = "AML.T0031" if r["collapse_detected"] else "AML.T0018.000"
        lines.append(
            f"| {r['strategy']} | {r['clean_final_accuracy']:.3f} | "
            f"{r['attacked_final_accuracy']:.3f} | "
            f"{r['accuracy_drop']:+.3f} | {collapse} | {category} |"
        )
    lines.append("")

    # --- Adaptive convergence patterns ---
    convergence = [f for f in findings if f["pattern"] == "adaptive_convergence"]
    if convergence:
        lines.append("## Adaptive Attack Convergence (Defense Fingerprinting)")
        lines.append("")
        lines.append("The adaptive MAB engine converges to different dominant attacks per defense,")
        lines.append("effectively fingerprinting the defense mechanism (ATLAS: AML.T0007).")
        lines.append("")
        lines.append("| Defense | Dominant Attack | Selection Rate | Implication |")
        lines.append("|---------|----------------|----------------|-------------|")
        for f in convergence:
            attack = f.get("dominant_attack", "unknown")
            fraction = f.get("fraction", 0)
            impl = _get_convergence_implication(f["strategy"], attack)
            lines.append(
                f"| {f['strategy']} | {attack} | {fraction:.0%} | {impl} |"
            )
        lines.append("")

    # --- Novelty assessment ---
    lines.append("## Novelty Assessment")
    lines.append("")

    novelty_summary = get_novelty_summary()

    lines.append("### Candidate Novel Contributions")
    lines.append("")
    for item in novelty_summary["candidate_novel"]:
        lines.append(f"**{item['claim']}**")
        lines.append(f"- {item['detail']}")
        if item["prior_art"]:
            refs = ", ".join(item["prior_art"])
            lines.append(f"- Prior art: {refs}")
        lines.append(f"- Distinction: {item['distinction']}")
        lines.append("")

    lines.append("### Well-Established (Not Novel)")
    lines.append("")
    for item in novelty_summary["well_established"]:
        lines.append(f"- {item}")
    lines.append("")

    # --- Caveats ---
    lines.append("## Caveats and Limitations")
    lines.append("")
    lines.append("- All findings are from **single-seed pilot runs** — statistical "
                 "significance requires 3+ seeds per configuration.")
    lines.append("- Only FEMNIST dataset tested so far — cross-dataset validation needed.")
    lines.append("- Baseline accuracy for some defenses (fedmedian, foolsgold) was already "
                 "low, which may confound drop measurements.")
    lines.append("- ATLAS technique mappings are approximate — FL-specific attack patterns "
                 "don't have exact 1:1 ATLAS equivalents.")
    lines.append("- Novelty claims are **candidate** status until validated against "
                 "comprehensive literature review.")
    lines.append("")

    # --- Recommended next experiments ---
    lines.append("## Recommended Next Experiments")
    lines.append("")
    lines.append("| Priority | Defense | Action | Reason |")
    lines.append("|----------|---------|--------|--------|")

    high_priority = sorted(findings, key=lambda f: f["scores"]["priority_score"], reverse=True)
    for f in high_priority[:8]:
        action = _get_recommended_action(f)
        lines.append(
            f"| {f['scores']['priority_score']:.2f} | {f['strategy']} | "
            f"{action} | {f['pattern']} |"
        )
    lines.append("")

    return "\n".join(lines)


def _get_convergence_implication(defense, attack):
    """Plain-English implication of attack convergence."""
    implications = {
        ("bulyan", "alie"): "ALIE evades Bulyan's coordinate-wise trimming by matching honest distribution",
        ("multikrum", "alie"): "ALIE stays within krum distance threshold via distribution-aware crafting",
        ("fedtrimmedavg", "alie"): "ALIE designed specifically to evade trimmed mean (Baruch et al. 2019)",
        ("fedmedian", "alie"): "ALIE targets coordinate-wise median's assumption of bounded deviation",
        ("fltrust", "sign_flip"): "Sign flip may partially align with trusted server update direction",
        ("foolsgold", "gaussian_noise"): "Random noise avoids triggering similarity-based Sybil detection",
    }
    key = (defense, attack.split("+")[0] if "+" in attack else attack)
    return implications.get(key, f"MAB identified {attack} as most effective against {defense}")


def _get_recommended_action(finding):
    """Suggest next action for a finding."""
    pattern = finding["pattern"]
    if pattern == "defense_collapse":
        return "Replicate with 3 seeds, test with alpha=0.1"
    elif pattern == "accuracy_degradation":
        return "Test with stronger attacks and more seeds"
    elif pattern == "high_slipthrough":
        return "Investigate filtering threshold tuning"
    elif pattern == "adaptive_convergence":
        return "Run longer (60+ rounds) to confirm convergence"
    elif pattern == "trust_failure":
        return "Test with varying malicious fractions"
    elif pattern == "poor_trust_separation":
        return "Test with IID data to separate non-IID effect"
    elif pattern == "stealth_evasion":
        return "Test without stealth to measure defense baseline"
    elif pattern == "resilient_defense":
        return "Stress test with stronger attacks and higher mal. fraction"
    return "Needs further investigation"


# ---------------------------------------------------------------------------
# Main analysis pipeline
# ---------------------------------------------------------------------------

def run_analysis():
    """Run the full analysis pipeline."""
    conn = get_conn()
    all_findings = []

    print("Analyzing database...")

    # 1. Defense collapses
    collapses = find_defense_collapses(conn)
    print(f"  Found {len(collapses)} defense collapses")
    for c in collapses:
        attack = c.get("final_attack", "unknown") or "unknown"
        classification = classify_finding(
            "defense_collapse", c["strategy"], attack,
            accuracy_drop=c.get("accuracy_drop"),
            collapse_detected=True,
        )
        scores = score_finding("defense_collapse", c)
        all_findings.append({
            "pattern": "defense_collapse",
            "strategy": c["strategy"],
            "attack": attack,
            "attack_mode": c.get("attack_mode"),
            "selection_mode": c.get("selection_mode"),
            "layering_mode": c.get("layering_mode"),
            "accuracy_drop": c.get("accuracy_drop"),
            "clean_final_accuracy": c.get("clean_final_accuracy"),
            "attacked_final_accuracy": c.get("attacked_final_accuracy"),
            "classification": classification,
            "scores": scores,
        })

    # 2. Accuracy degradations (no collapse)
    degradations = find_accuracy_degradations(conn)
    print(f"  Found {len(degradations)} significant accuracy degradations")
    for d in degradations:
        attack = d.get("final_attack", "unknown") or "unknown"
        classification = classify_finding(
            "accuracy_degradation", d["strategy"], attack,
            accuracy_drop=d.get("accuracy_drop"),
        )
        scores = score_finding("accuracy_degradation", d)
        all_findings.append({
            "pattern": "accuracy_degradation",
            "strategy": d["strategy"],
            "attack": attack,
            "attack_mode": d.get("attack_mode"),
            "accuracy_drop": d.get("accuracy_drop"),
            "clean_final_accuracy": d.get("clean_final_accuracy"),
            "attacked_final_accuracy": d.get("attacked_final_accuracy"),
            "classification": classification,
            "scores": scores,
        })

    # 3. Slipthrough rates
    slipthroughs = find_slipthrough_rates(conn)
    print(f"  Found {len(slipthroughs)} strategies with high slipthrough")
    for s in slipthroughs:
        classification = classify_finding(
            "high_slipthrough", s["strategy"], "composite",
            slipthrough_rate=s.get("slip_rate"),
        )
        scores = score_finding("high_slipthrough", s)
        all_findings.append({
            "pattern": "high_slipthrough",
            "strategy": s["strategy"],
            "attack": "composite",
            "slipthrough_rate": s.get("slip_rate"),
            "classification": classification,
            "scores": scores,
        })

    # 4. Trust failures
    trust_failures = find_trust_failures(conn)
    print(f"  Found {len(trust_failures)} trust failures")
    for t in trust_failures:
        classification = classify_finding(
            "trust_failure", t["strategy"], "unknown",
            trust_score=t.get("trust_score"),
        )
        scores = score_finding("trust_failure", t)
        all_findings.append({
            "pattern": "trust_failure",
            "strategy": t["strategy"],
            "attack": "unknown",
            "classification": classification,
            "scores": scores,
        })

    # 5. Poor trust separation
    poor_sep = find_trust_separation(conn)
    print(f"  Found {len(poor_sep)} strategies with poor trust separation")
    for p in poor_sep:
        classification = classify_finding(
            "poor_trust_separation", p["strategy"], "composite",
        )
        scores = score_finding("poor_trust_separation", p)
        all_findings.append({
            "pattern": "poor_trust_separation",
            "strategy": p["strategy"],
            "attack": "composite",
            "benign_avg_trust": p.get("benign_avg_trust"),
            "malicious_avg_trust": p.get("malicious_avg_trust"),
            "separation": p.get("separation"),
            "classification": classification,
            "scores": scores,
        })

    # 6. Stealth evasion
    evasions = find_stealth_evasion(conn)
    print(f"  Found {len(evasions)} stealth evasion patterns")
    for e in evasions:
        classification = classify_finding(
            "stealth_evasion", e["strategy"], e["attack_name"],
        )
        scores = score_finding("stealth_evasion", e)
        all_findings.append({
            "pattern": "stealth_evasion",
            "strategy": e["strategy"],
            "attack": e["attack_name"],
            "evasion_rounds": e.get("evasion_rounds"),
            "total_rounds": e.get("num_rounds"),
            "classification": classification,
            "scores": scores,
        })

    # 7. Adaptive convergence
    convergences = find_adaptive_convergence(conn)
    print(f"  Found {len(convergences)} adaptive convergence patterns")
    for c in convergences:
        classification = classify_finding(
            "adaptive_convergence", c["strategy"], c["dominant_attack"],
        )
        scores = score_finding("adaptive_convergence", c)
        all_findings.append({
            "pattern": "adaptive_convergence",
            "strategy": c["strategy"],
            "attack": c["dominant_attack"],
            "dominant_attack": c["dominant_attack"],
            "fraction": c["fraction"],
            "classification": classification,
            "scores": scores,
        })

    # 8. Resilient defenses
    resilient = find_resilient_defenses(conn)
    print(f"  Found {len(resilient)} resilient defense observations")
    for r in resilient:
        classification = classify_finding(
            "resilient_defense", r["strategy"], "all_tested",
        )
        scores = score_finding("resilient_defense", r)
        all_findings.append({
            "pattern": "resilient_defense",
            "strategy": r["strategy"],
            "attack": "all_tested",
            "accuracy_drop": r.get("accuracy_drop"),
            "clean_final_accuracy": r.get("clean_final_accuracy"),
            "attacked_final_accuracy": r.get("attacked_final_accuracy"),
            "classification": classification,
            "scores": scores,
        })

    # Sort by priority
    all_findings.sort(key=lambda f: f["scores"]["priority_score"], reverse=True)

    print(f"\n  Total findings: {len(all_findings)}")

    # Write to database
    print("  Writing recommendations to database...")
    write_recommendations(conn, all_findings)

    rec_count = conn.execute("SELECT COUNT(*) FROM agent_recommendations").fetchone()[0]
    print(f"  Wrote {rec_count} recommendations")

    # Generate report
    print("  Generating report...")
    report = generate_report(conn, all_findings)

    REPORT_PATH.mkdir(parents=True, exist_ok=True)
    report_file = REPORT_PATH / "vulnerability_report_atlas.md"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"  Report written to: {report_file}")

    conn.close()
    return all_findings, report


if __name__ == "__main__":
    findings, report = run_analysis()

    # Print summary
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)

    by_novelty = {}
    for f in findings:
        n = f["classification"]["novelty_status"]
        by_novelty.setdefault(n, []).append(f)

    for status in ["candidate_new", "known_weakness", "reproduced", "needs_testing"]:
        items = by_novelty.get(status, [])
        if items:
            print(f"\n  {status} ({len(items)}):")
            for f in items:
                print(f"    - {f['strategy']}: {f['pattern']} "
                      f"({', '.join(f['classification']['atlas_technique_ids'][:3])})")
