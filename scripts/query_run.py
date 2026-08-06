"""
Query the SQLite database for a specific run's results.

Usage:
    python scripts/query_run.py <run_dir>
    python scripts/query_run.py <run_dir> --format json
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = _PROJECT_ROOT / "db" / "dynamic_fl.sqlite"


def _find_run(conn: sqlite3.Connection, run_basename: str) -> dict | None:
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM runs WHERE run_folder LIKE ?",
                (f"%{run_basename}%",))
    row = cur.fetchone()
    return dict(row) if row else None


def _get_final_metrics(conn: sqlite3.Connection, run_id: str) -> dict:
    cur = conn.cursor()
    cur.execute("""
        SELECT metric_name, metric_value FROM round_metrics
        WHERE run_id = ? AND round = (
            SELECT MAX(round) FROM round_metrics WHERE run_id = ?
        )
    """, (run_id, run_id))
    return {row[0]: row[1] for row in cur.fetchall()}


def _get_baseline_comparison(conn: sqlite3.Connection, run_id: int) -> dict | None:
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM baseline_comparisons WHERE attacked_run_id = ?
    """, (run_id,))
    row = cur.fetchone()
    return dict(row) if row else None


def _get_attack_summary(conn: sqlite3.Connection, run_id: int) -> list:
    cur = conn.cursor()
    cur.execute("""
        SELECT attack_name, COUNT(*) as rounds
        FROM attack_events WHERE run_id = ?
        GROUP BY attack_name ORDER BY rounds DESC
    """, (run_id,))
    return [{"attack": row[0], "rounds": row[1]} for row in cur.fetchall()]


def _get_trust_summary(conn: sqlite3.Connection, run_id: int) -> dict | None:
    cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(DISTINCT client_id) as n_clients,
               AVG(trust_score) as avg_trust,
               MIN(trust_score) as min_trust,
               MAX(trust_score) as max_trust
        FROM trust_metrics WHERE run_id = ?
    """, (run_id,))
    row = cur.fetchone()
    if row and row[0] > 0:
        return {
            "n_clients": row[0],
            "avg_trust": row[1],
            "min_trust": row[2],
            "max_trust": row[3],
        }
    return None


def query_run(run_dir: Path) -> dict:
    run_basename = run_dir.name

    if not DB_PATH.exists():
        return {"error": f"Database not found at {DB_PATH}"}

    conn = sqlite3.connect(str(DB_PATH))
    try:
        run_info = _find_run(conn, run_basename)
        if not run_info:
            return {
                "error": "Run not found in database",
                "hint": f"Ingest first: python db/ingest.py <sweep_dir>",
            }

        run_id = run_info["run_id"]
        result = {
            "run": {
                "run_id": run_id,
                "strategy": run_info.get("strategy"),
                "dataset": run_info.get("dataset"),
                "attack_mode": run_info.get("attack_mode"),
                "selection_mode": run_info.get("selection_mode"),
                "malicious_fraction": run_info.get("malicious_fraction"),
                "num_rounds": run_info.get("num_rounds"),
            },
            "final_metrics": _get_final_metrics(conn, run_id),
            "baseline_comparison": _get_baseline_comparison(conn, run_id),
            "attack_summary": _get_attack_summary(conn, run_id),
            "trust_summary": _get_trust_summary(conn, run_id),
        }
        return result
    finally:
        conn.close()


def _print_table(result: dict) -> None:
    if "error" in result:
        print(f"Error: {result['error']}")
        if "hint" in result:
            print(f"  {result['hint']}")
        return

    run = result["run"]
    print("=" * 60)
    print(f"  DATABASE LOOKUP: {run['strategy']} | {run['dataset']}")
    print("=" * 60)

    print("\nRUN INFO")
    for key in ["run_id", "strategy", "dataset", "attack_mode",
                "selection_mode", "malicious_fraction", "num_rounds"]:
        val = run.get(key)
        if val is not None:
            print(f"  {key:25s}: {val}")

    fm = result.get("final_metrics", {})
    if fm:
        print("\nFINAL METRICS")
        for key in sorted(fm):
            if key.startswith("class_"):
                continue
            print(f"  {key:25s}: {fm[key]:.4f}")

    bc = result.get("baseline_comparison")
    if bc:
        print("\nBASELINE COMPARISON")
        print(f"  {'Baseline accuracy':25s}: {bc.get('clean_final_accuracy', 'N/A')}")
        print(f"  {'Attacked accuracy':25s}: {bc.get('attacked_final_accuracy', 'N/A')}")
        drop = bc.get("accuracy_drop")
        if drop is not None:
            print(f"  {'Accuracy drop':25s}: {drop:.4f}")
        f1_drop = bc.get("f1_macro_drop")
        if f1_drop is not None:
            print(f"  {'F1 macro drop':25s}: {f1_drop:.4f}")

    attacks = result.get("attack_summary", [])
    if attacks:
        print("\nATTACK SUMMARY")
        for a in attacks:
            print(f"  {a['attack']:25s}: {a['rounds']} rounds")

    trust = result.get("trust_summary")
    if trust:
        print("\nTRUST SUMMARY")
        print(f"  {'Clients tracked':25s}: {trust['n_clients']}")
        print(f"  {'Avg trust':25s}: {trust['avg_trust']:.4f}")
        print(f"  {'Min trust':25s}: {trust['min_trust']:.4f}")
        print(f"  {'Max trust':25s}: {trust['max_trust']:.4f}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Query the database for a specific run's results."
    )
    parser.add_argument("run_dir", type=Path, help="Path to the run output directory")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                        help="Output format (default: table)")
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    if not run_dir.is_dir():
        print(f"Error: {run_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    result = query_run(run_dir)

    if args.format == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_table(result)


if __name__ == "__main__":
    main()
