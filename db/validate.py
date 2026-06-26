"""
End-to-end validation: create the database, insert dummy data, run all queries,
and verify row counts and FK integrity.
"""

import sqlite3
import sys

from create_db import DB_PATH, build_dummy_database
from queries import run_all_queries


def validate_database():
    print("=" * 80)
    print("STEP 1: Create database with dummy data")
    print("=" * 80)
    build_dummy_database()
    print()

    print("=" * 80)
    print("STEP 2: Run all vulnerability discovery queries")
    print("=" * 80)
    print()
    run_all_queries()

    print("=" * 80)
    print("STEP 3: Integrity checks")
    print("=" * 80)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA foreign_keys = ON")

    errors = []

    # Check FK integrity
    fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk_issues:
        errors.append(f"Foreign key violations: {fk_issues}")
    else:
        print("  [PASS] No foreign key violations")

    # Check integrity
    result = conn.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        errors.append(f"Integrity check failed: {result}")
    else:
        print("  [PASS] Database integrity check passed")

    # Verify expected table counts
    expected = {
        "sweeps": 1,
        "runs": 6,
        "baseline_comparisons": 3,
        "agent_recommendations": 3,
    }
    for table, expected_count in expected.items():
        actual = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        if actual != expected_count:
            errors.append(f"{table}: expected {expected_count} rows, got {actual}")
        else:
            print(f"  [PASS] {table}: {actual} rows (expected {expected_count})")

    # Verify attacked runs have attack events
    attacked_runs = conn.execute(
        "SELECT run_id, strategy FROM runs WHERE is_baseline = 0"
    ).fetchall()
    for run_id, strategy in attacked_runs:
        ae_count = conn.execute(
            "SELECT COUNT(*) FROM attack_events WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        if ae_count == 0:
            errors.append(f"Attacked run {run_id} ({strategy}) has 0 attack events")
        else:
            print(f"  [PASS] {strategy} attacked run has {ae_count} attack event rounds")

    # Verify baseline runs have NO attack events
    baseline_runs = conn.execute(
        "SELECT run_id, strategy FROM runs WHERE is_baseline = 1"
    ).fetchall()
    for run_id, strategy in baseline_runs:
        ae_count = conn.execute(
            "SELECT COUNT(*) FROM attack_events WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        if ae_count != 0:
            errors.append(f"Baseline run {run_id} ({strategy}) has {ae_count} attack events (should be 0)")
        else:
            print(f"  [PASS] {strategy} baseline run has 0 attack events (correct)")

    # Verify trust metrics exist only for trust strategies
    trust_strategies = conn.execute(
        "SELECT DISTINCT strategy FROM trust_metrics"
    ).fetchall()
    trust_set = {s for (s,) in trust_strategies}
    expected_trust = {"fltrust", "mab-rfl"}
    if trust_set != expected_trust:
        errors.append(f"Trust metrics strategies: {trust_set}, expected {expected_trust}")
    else:
        print(f"  [PASS] Trust metrics only for: {trust_set}")

    # Verify every baseline comparison has valid run references
    bad_comps = conn.execute("""
        SELECT bc.comparison_id
        FROM baseline_comparisons bc
        LEFT JOIN runs r1 ON r1.run_id = bc.attacked_run_id
        LEFT JOIN runs r2 ON r2.run_id = bc.baseline_run_id
        WHERE r1.run_id IS NULL OR r2.run_id IS NULL
    """).fetchall()
    if bad_comps:
        errors.append(f"Baseline comparisons with invalid run refs: {bad_comps}")
    else:
        print("  [PASS] All baseline comparisons reference valid runs")

    # Verify layered attack data exists for mab-rfl (sample_k)
    layer_count = conn.execute("""
        SELECT COUNT(DISTINCT ael.layer_name)
        FROM attack_event_layers ael
        JOIN runs r ON r.run_id = ael.run_id
        WHERE r.strategy = 'mab-rfl'
    """).fetchone()[0]
    if layer_count < 2:
        errors.append(f"MAB-RFL should have multiple attack layers, got {layer_count} distinct")
    else:
        print(f"  [PASS] MAB-RFL has {layer_count} distinct attack layers (sample_k working)")

    conn.close()

    print()
    if errors:
        print("VALIDATION FAILED:")
        for e in errors:
            print(f"  [FAIL] {e}")
        return False
    else:
        print("ALL VALIDATION CHECKS PASSED")
        return True


if __name__ == "__main__":
    ok = validate_database()
    sys.exit(0 if ok else 1)
