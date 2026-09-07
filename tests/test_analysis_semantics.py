import csv
import json
from pathlib import Path

import tomli

from scripts.llm_sweep_analysis import (
    _aggregate_strategy,
    _summarize_defense_filter,
    _summarize_defense_selection,
)
from scripts.post_run_analysis import analyze_defense_behavior, assess_research_validity


ROOT = Path(__file__).resolve().parent.parent


def _write_csv(path: Path, fieldnames, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_placeholder_selection_is_unavailable(tmp_path):
    path = tmp_path / "summaries" / "defense_selection_by_round.csv"
    _write_csv(
        path,
        [
            "round", "defense_strategy", "num_selected_by_defense",
            "num_malicious_selected_by_defense", "malicious_selected_fraction",
        ],
        [{
            "round": 1,
            "defense_strategy": "-",
            "num_selected_by_defense": 0,
            "num_malicious_selected_by_defense": 0,
            "malicious_selected_fraction": 0,
        }],
    )

    summary = _summarize_defense_selection(tmp_path)
    assert summary["defense_selection_rows"] == 1
    assert summary["defense_selection_valid_rows"] == 0
    assert summary["defense_selection_telemetry"]["available"] is False
    assert summary["malicious_selected_fraction"] == {}


def test_real_selection_is_available(tmp_path):
    path = tmp_path / "summaries" / "defense_selection_by_round.csv"
    _write_csv(
        path,
        [
            "round", "defense_strategy", "num_selected_by_defense",
            "num_malicious_selected_by_defense", "malicious_selected_fraction",
        ],
        [{
            "round": 1,
            "defense_strategy": "multikrum",
            "num_selected_by_defense": 73,
            "num_malicious_selected_by_defense": 20,
            "malicious_selected_fraction": 20 / 73,
        }],
    )

    summary = _summarize_defense_selection(tmp_path)
    assert summary["defense_selection_valid_rows"] == 1
    assert summary["defense_selection_telemetry"]["available"] is True
    assert summary["malicious_selected_fraction"]["mean"] == 20 / 73


def test_none_filter_is_reported_as_inactive(tmp_path):
    path = tmp_path / "summaries" / "defense_filter_by_round.csv"
    _write_csv(
        path,
        ["round", "mode", "num_before", "num_after", "num_rejected"],
        [{"round": 1, "mode": "none", "num_before": 100, "num_after": 100, "num_rejected": 0}],
    )

    summary = _summarize_defense_filter(tmp_path)["defense_filter_telemetry"]
    assert summary["available"] is True
    assert summary["active"] is False
    assert summary["total_rejected"] == 0
    assert summary["total_kept_observations"] == 100


def test_coordinate_defense_does_not_infer_rejection_from_placeholders():
    data = {
        "run_config": {"strategy": "fedmedian"},
        "trust_by_round": [],
        "defense_selection": [{
            "defense_strategy": "-",
            "num_selected_by_defense": "0",
            "num_malicious_selected_by_defense": "0",
        }],
        "defense_filter": [{
            "mode": "none", "num_after": "100", "num_rejected": "0",
        }],
        "defense_summary": {"overall_malicious_selected_fraction": 0},
        "malicious_ids": {"1"},
    }

    defense = analyze_defense_behavior(data)
    assert defense["telemetry_availability"]["defense_selection"] == {
        "applicable": False,
        "available": False,
        "reason": "not_applicable",
    }
    assert defense["defense_filter"]["active"] is False
    assert defense["defense_filter"]["total_rejected"] == 0
    assert "slipthrough_rate" not in defense


def test_single_run_validity_is_exploratory():
    validity = assess_research_validity({}, {"mode": "adaptive"})
    assert validity["status"] == "exploratory_observation"
    assert validity["causal_attack_effect_validated"] is False
    assert validity["adaptive_advantage_validated"] is False
    assert any("fixed primitive" in item for item in validity["limitations"])


def test_sweep_validity_requires_matched_baseline_fixed_and_adaptive_triplets(tmp_path):
    common = {
        "strategy": "fedmedian",
        "dataset": "flwrlabs/femnist",
        "partitioner": "dirichlet",
        "dirichlet-alpha": 0.5,
        "model": "simple-cnn",
        "num-total-clients": 100,
        "num-server-rounds": 60,
        "fraction-train": 1.0,
        "local-epochs": 1,
        "learning-rate": 0.1,
        "batch-size": 32,
    }
    for seed in (7, 42, 1337):
        for label, enabled, mode in (
            ("S_BASELINE", False, "phase"),
            ("S_FIXED_ALIE", True, "phase"),
            ("S_ADAPTIVE", True, "adaptive"),
        ):
            run_dir = tmp_path / f"{label}__seed_{seed}"
            summary_path = run_dir / "summaries" / "run_config_and_summary.json"
            summary_path.parent.mkdir(parents=True)
            summary_path.write_text(json.dumps({
                "resolved_attack_config": {
                    "enabled": enabled,
                    "seed": seed,
                    "mode": mode,
                },
                "run_config": {**common, "attack-seed": seed},
            }), encoding="utf-8")

    validity = _aggregate_strategy(tmp_path)["research_validity"]
    assert validity["central_claim_ready"] is True
    assert validity["matched_comparison_triplets"] == 3
    assert validity["unique_matched_seeds"] == ["1337", "42", "7"]


def test_default_seed_is_reproducible_and_shared():
    with (ROOT / "pyproject.toml").open("rb") as handle:
        data = tomli.load(handle)
    app_seed = data["tool"]["flwr"]["app"]["config"]["attack-seed"]
    attack_seed = data["tool"]["flwr"]["attack"]["seed"]
    assert app_seed == attack_seed == 1337


def test_run_script_honors_llm_opt_out_and_server_uses_run_checkpoint():
    run_script = (ROOT / "run.sh").read_text(encoding="utf-8")
    server_source = (ROOT / "pytorchexample" / "server_app.py").read_text(encoding="utf-8")
    assert 'CALL_LLM_ANALYSIS:-1' in run_script
    assert 'checkpoint_dir = Path(str(artifact_dir_raw)).resolve() / "checkpoints"' in server_source
