"""
Vulnerability discovery queries for the Dynamic FL database.

Each function runs a query and prints human-readable results.
These queries are designed for an AI agent to identify:
  - defense weaknesses
  - effective attacks
  - trust/reputation failures
  - adaptive attack patterns
  - configurations worth testing next
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "dynamic_fl.sqlite"


def get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# 1. Which defense performs worst under each attack?
# ---------------------------------------------------------------------------
def query_worst_defense_per_attack():
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            ae.attack_name,
            r.strategy,
            bc.accuracy_drop,
            bc.attacked_final_accuracy,
            bc.clean_final_accuracy,
            bc.f1_macro_drop,
            bc.collapse_detected
        FROM baseline_comparisons bc
        JOIN runs r ON r.run_id = bc.attacked_run_id
        JOIN attack_events ae ON ae.run_id = bc.attacked_run_id
        WHERE ae.round = (SELECT MAX(round) FROM attack_events WHERE run_id = ae.run_id)
        ORDER BY bc.accuracy_drop DESC
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 1: Which defense performs worst under each attack?")
    print("=" * 80)
    for row in rows:
        collapse = " [COLLAPSE]" if row["collapse_detected"] else ""
        print(f"  Attack: {row['attack_name']:30s}  Defense: {row['strategy']:12s}  "
              f"Acc drop: {row['accuracy_drop']:+.4f}  "
              f"({row['clean_final_accuracy']:.3f} → {row['attacked_final_accuracy']:.3f})"
              f"{collapse}")
    print()


# ---------------------------------------------------------------------------
# 2. Which attacks cause the biggest accuracy and F1 drop?
# ---------------------------------------------------------------------------
def query_biggest_drops():
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            r.strategy,
            r.attack_mode,
            r.layering_mode,
            bc.accuracy_drop,
            bc.f1_macro_drop,
            bc.f1_weighted_drop,
            bc.backdoor_asr_increase,
            bc.loss_increase,
            bc.collapse_detected
        FROM baseline_comparisons bc
        JOIN runs r ON r.run_id = bc.attacked_run_id
        ORDER BY bc.accuracy_drop DESC
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 2: Biggest accuracy and F1 drops across all attack configurations")
    print("=" * 80)
    for row in rows:
        mode = row['attack_mode'] or 'none'
        layers = row['layering_mode'] or 'none'
        f1d = row['f1_macro_drop'] or 0
        asr = row['backdoor_asr_increase'] or 0
        print(f"  {row['strategy']:12s}  mode={mode:<16s}  "
              f"layers={layers:<10s}  "
              f"acc_drop={row['accuracy_drop']:+.4f}  "
              f"f1m_drop={f1d:+.4f}  "
              f"ASR_inc={asr:+.4f}  "
              f"collapse={'YES' if row['collapse_detected'] else 'no'}")
    print()


# ---------------------------------------------------------------------------
# 3. Which malicious clients were selected for aggregation?
# ---------------------------------------------------------------------------
def query_malicious_selected():
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            r.strategy,
            ds.round,
            ds.client_id,
            ds.selected_for_aggregation,
            ds.is_malicious,
            ds.rejection_reason
        FROM defense_selection ds
        JOIN runs r ON r.run_id = ds.run_id
        WHERE ds.is_malicious = 1
          AND r.is_baseline = 0
          AND ds.selected_for_aggregation = 1
        ORDER BY r.strategy, ds.round, ds.client_id
    """).fetchall()
    conn.close()

    # Aggregate per strategy
    by_strategy = {}
    for row in rows:
        s = row["strategy"]
        by_strategy.setdefault(s, {"total_malicious_rounds": 0, "selected": 0})
        by_strategy[s]["selected"] += 1

    # Count total malicious client-rounds
    conn2 = get_conn()
    for s in by_strategy:
        total = conn2.execute("""
            SELECT COUNT(*) FROM defense_selection ds
            JOIN runs r ON r.run_id = ds.run_id
            WHERE ds.is_malicious = 1 AND r.is_baseline = 0 AND r.strategy = ?
        """, (s,)).fetchone()[0]
        by_strategy[s]["total_malicious_rounds"] = total
    conn2.close()

    print("=" * 80)
    print("QUERY 3: Malicious clients selected for aggregation (slipthrough rate)")
    print("=" * 80)
    for s, data in sorted(by_strategy.items()):
        rate = data["selected"] / max(data["total_malicious_rounds"], 1)
        print(f"  {s:12s}  malicious selected: {data['selected']:4d} / "
              f"{data['total_malicious_rounds']} total  "
              f"(slipthrough rate: {rate:.1%})")
    print()


# ---------------------------------------------------------------------------
# 4. Malicious clients NOT downweighted by trust
# ---------------------------------------------------------------------------
def query_malicious_not_downweighted():
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            r.strategy,
            tm.round,
            tm.client_id,
            tm.trust_score,
            tm.effective_weight,
            tm.reputation,
            tm.selected_for_aggregation,
            cae.is_malicious
        FROM trust_metrics tm
        JOIN runs r ON r.run_id = tm.run_id
        JOIN client_attack_events cae
          ON cae.run_id = tm.run_id AND cae.round = tm.round AND cae.client_id = tm.client_id
        WHERE cae.is_malicious = 1
          AND r.is_baseline = 0
          AND tm.trust_score > 0.5
        ORDER BY tm.trust_score DESC
        LIMIT 20
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 4: Malicious clients with HIGH trust scores (trust failure)")
    print("=" * 80)
    if not rows:
        print("  No malicious clients found with trust > 0.5 (trust is working)")
    for row in rows:
        rep = f"  rep={row['reputation']:.3f}" if row["reputation"] is not None else ""
        print(f"  {row['strategy']:12s}  round={row['round']:2d}  client={row['client_id']}  "
              f"trust={row['trust_score']:.3f}  weight={row['effective_weight']:.3f}"
              f"{rep}  selected={row['selected_for_aggregation']}")
    print()


# ---------------------------------------------------------------------------
# 5. Trust score separation: benign vs malicious
# ---------------------------------------------------------------------------
def query_trust_separation():
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            r.strategy AS defense,
            cae.is_malicious,
            AVG(tm.trust_score) AS avg_trust,
            MIN(tm.trust_score) AS min_trust,
            MAX(tm.trust_score) AS max_trust,
            AVG(tm.effective_weight) AS avg_weight,
            COUNT(*) AS n
        FROM trust_metrics tm
        JOIN runs r ON r.run_id = tm.run_id
        JOIN client_attack_events cae
          ON cae.run_id = tm.run_id AND cae.round = tm.round AND cae.client_id = tm.client_id
        WHERE r.is_baseline = 0
        GROUP BY r.strategy, cae.is_malicious
        ORDER BY r.strategy, cae.is_malicious
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 5: Trust score separation — benign vs malicious clients")
    print("=" * 80)
    for row in rows:
        label = "MALICIOUS" if row["is_malicious"] else "benign  "
        print(f"  {row['defense']:12s}  {label}  "
              f"avg_trust={row['avg_trust']:.3f}  "
              f"[{row['min_trust']:.3f}, {row['max_trust']:.3f}]  "
              f"avg_weight={row['avg_weight']:.3f}  "
              f"n={row['n']}")
    print()


# ---------------------------------------------------------------------------
# 6. Which attack/defense combos caused collapse?
# ---------------------------------------------------------------------------
def query_collapse_detection():
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            r.strategy,
            r.attack_mode,
            r.layering_mode,
            r.selection_mode,
            bc.attacked_final_accuracy,
            bc.clean_final_accuracy,
            bc.accuracy_drop,
            bc.collapse_detected
        FROM baseline_comparisons bc
        JOIN runs r ON r.run_id = bc.attacked_run_id
        WHERE bc.collapse_detected = 1
        ORDER BY bc.attacked_final_accuracy ASC
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 6: Attack/defense combinations that caused collapse (<5% accuracy)")
    print("=" * 80)
    if not rows:
        print("  No collapses detected in current data")
    for row in rows:
        print(f"  {row['strategy']:12s}  mode={row['attack_mode'] or 'n/a'}  "
              f"layers={row['layering_mode'] or 'n/a'}  sched={row['selection_mode'] or 'n/a'}  "
              f"final_acc={row['attacked_final_accuracy']:.4f}  "
              f"(clean={row['clean_final_accuracy']:.4f})")
    print()


# ---------------------------------------------------------------------------
# 7. Rounds showing adaptive attack switching
# ---------------------------------------------------------------------------
def query_adaptive_switching():
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            r.strategy,
            ae.round,
            ae.previous_attack,
            ae.attack_name AS new_attack,
            rm.metric_value AS accuracy_at_switch
        FROM attack_events ae
        JOIN runs r ON r.run_id = ae.run_id
        LEFT JOIN round_metrics rm
          ON rm.run_id = ae.run_id AND rm.round = ae.round AND rm.metric_name = 'accuracy'
        WHERE ae.adaptive_switched = 1
        ORDER BY r.strategy, ae.round
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 7: Rounds where adaptive attack switched")
    print("=" * 80)
    if not rows:
        print("  No adaptive switches detected")
    for row in rows:
        acc = f"{row['accuracy_at_switch']:.4f}" if row["accuracy_at_switch"] else "N/A"
        print(f"  {row['strategy']:12s}  round={row['round']:2d}  "
              f"{row['previous_attack']} → {row['new_attack']}  "
              f"acc={acc}")
    print()


# ---------------------------------------------------------------------------
# 8. Dominant attack per defense (which attack was selected most often?)
# ---------------------------------------------------------------------------
def query_dominant_attacks():
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            r.strategy,
            ae.attack_name,
            COUNT(*) AS rounds_selected,
            r.num_rounds,
            ROUND(COUNT(*) * 1.0 / r.num_rounds, 2) AS fraction
        FROM attack_events ae
        JOIN runs r ON r.run_id = ae.run_id
        WHERE r.is_baseline = 0
        GROUP BY r.strategy, ae.attack_name
        ORDER BY r.strategy, rounds_selected DESC
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 8: Dominant attack per defense (most frequently selected)")
    print("=" * 80)
    for row in rows:
        bar = "#" * int(row["fraction"] * 30)
        print(f"  {row['strategy']:12s}  {row['attack_name']:30s}  "
              f"{row['rounds_selected']:2d}/{row['num_rounds']} rounds  "
              f"({row['fraction']:.0%})  {bar}")
    print()


# ---------------------------------------------------------------------------
# 9. Stealth evasion: malicious norms vs honest norms
# ---------------------------------------------------------------------------
def query_stealth_evasion():
    conn = get_conn()
    rows = conn.execute("""
        SELECT
            r.strategy,
            ae.round,
            ae.attack_name,
            ae.stealth_applied,
            ae.max_mal_norm_pre,
            ae.max_mal_norm_post,
            ae.honest_norm_p50,
            ae.honest_norm_p90,
            CASE WHEN ae.max_mal_norm_post <= ae.honest_norm_p90
                 THEN 'EVADED' ELSE 'DETECTABLE' END AS evasion_status
        FROM attack_events ae
        JOIN runs r ON r.run_id = ae.run_id
        WHERE ae.stealth_applied = 1
        ORDER BY r.strategy, ae.round
        LIMIT 15
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 9: Stealth norm evasion (malicious norms vs honest distribution)")
    print("=" * 80)
    for row in rows:
        print(f"  {row['strategy']:12s}  r={row['round']:2d}  {row['attack_name']:15s}  "
              f"mal_pre={row['max_mal_norm_pre']:8.2f}  "
              f"mal_post={row['max_mal_norm_post']:8.2f}  "
              f"honest_p90={row['honest_norm_p90']:8.3f}  "
              f"[{row['evasion_status']}]")
    print()


# ---------------------------------------------------------------------------
# 10. Recommended next experiments (from agent_recommendations)
# ---------------------------------------------------------------------------
def query_agent_recommendations():
    conn = get_conn()
    rows = conn.execute("""
        SELECT *
        FROM agent_recommendations
        ORDER BY priority_score DESC
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 10: Agent-recommended next experiments (by priority)")
    print("=" * 80)
    for row in rows:
        print(f"  Priority: {row['priority_score']:.2f}  "
              f"Defense: {row['strategy']:12s}  Attack: {row['attack_name']}")
        print(f"    weakness={row['defense_weakness_score']:.2f}  "
              f"effectiveness={row['attack_effectiveness_score']:.2f}  "
              f"evidence={row['evidence_strength']:.2f}")
        print(f"    Rationale: {row['rationale'][:100]}...")
        print()


# ---------------------------------------------------------------------------
# 11. Cross-query: configurations the agent should recommend testing next
# ---------------------------------------------------------------------------
def query_suggested_followups():
    conn = get_conn()

    # Find defenses with high slipthrough AND high accuracy drop
    rows = conn.execute("""
        WITH slipthrough AS (
            SELECT
                r.strategy,
                SUM(CASE WHEN ds.is_malicious = 1 AND ds.selected_for_aggregation = 1 THEN 1 ELSE 0 END) * 1.0
                / MAX(SUM(CASE WHEN ds.is_malicious = 1 THEN 1 ELSE 0 END), 1) AS slip_rate
            FROM defense_selection ds
            JOIN runs r ON r.run_id = ds.run_id
            WHERE r.is_baseline = 0
            GROUP BY r.strategy
        ),
        drops AS (
            SELECT
                bc.strategy,
                bc.accuracy_drop,
                bc.f1_macro_drop,
                bc.collapse_detected,
                r.attack_mode,
                r.layering_mode,
                r.selection_mode
            FROM baseline_comparisons bc
            JOIN runs r ON r.run_id = bc.attacked_run_id
        )
        SELECT
            s.strategy,
            s.slip_rate,
            d.accuracy_drop,
            d.f1_macro_drop,
            d.collapse_detected,
            d.attack_mode,
            d.layering_mode,
            d.selection_mode
        FROM slipthrough s
        JOIN drops d ON d.strategy = s.strategy
        WHERE s.slip_rate > 0.3 OR d.accuracy_drop > 0.1
        ORDER BY d.accuracy_drop DESC
    """).fetchall()
    conn.close()

    print("=" * 80)
    print("QUERY 11: Suggested follow-up experiments (high risk configs)")
    print("=" * 80)
    for row in rows:
        f1d = row['f1_macro_drop'] or 0
        print(f"  {row['strategy']:12s}  slip_rate={row['slip_rate']:.1%}  "
              f"acc_drop={row['accuracy_drop']:+.4f}  "
              f"f1_drop={f1d:+.4f}  "
              f"collapse={'YES' if row['collapse_detected'] else 'no'}")
        print(f"    Config: mode={row['attack_mode'] or 'n/a'}  "
              f"layers={row['layering_mode'] or 'n/a'}  "
              f"sched={row['selection_mode'] or 'n/a'}")
        print(f"    → Recommend: replicate with 3 seeds, test with alpha=0.1 stress")
        print()


# ---------------------------------------------------------------------------
# Run all queries
# ---------------------------------------------------------------------------

def run_all_queries():
    query_worst_defense_per_attack()
    query_biggest_drops()
    query_malicious_selected()
    query_malicious_not_downweighted()
    query_trust_separation()
    query_collapse_detection()
    query_adaptive_switching()
    query_dominant_attacks()
    query_stealth_evasion()
    query_agent_recommendations()
    query_suggested_followups()


if __name__ == "__main__":
    run_all_queries()
