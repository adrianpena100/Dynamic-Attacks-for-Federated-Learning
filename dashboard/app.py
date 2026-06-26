from __future__ import annotations

import csv
import json
import mimetypes
import re
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from scripts.run_simulation_and_log import ParseState

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = PROJECT_ROOT / "dashboard" / "static"
PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"
LOGS_ROOT = PROJECT_ROOT / "logs"
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

ATTACK_OVERRIDE_MAP = {
    "enabled": "attack-enabled",
    "preset": "attack-preset",
    "seed": "attack-seed",
    "malicious_fraction": "attack-malicious-fraction",
    "malicious_fraction_mode": "attack-malicious-fraction-mode",
    "malicious_fraction_ramp_mode": "attack-malicious-fraction-ramp-mode",
    "malicious_fraction_ramp_start_round": "attack-malicious-fraction-ramp-start-round",
    "malicious_fraction_ramp_end_round": "attack-malicious-fraction-ramp-end-round",
    "malicious_fraction_ramp_value_start": "attack-malicious-fraction-ramp-value-start",
    "malicious_fraction_ramp_value_end": "attack-malicious-fraction-ramp-value-end",
    "malicious_fraction_cap": "attack-malicious-fraction-cap",
    "selection_mode": "attack-selection-mode",
    "deterministic_per_round": "attack-deterministic-per-round",
    "sticky_rounds": "attack-sticky-rounds",
    "churn_fraction": "attack-churn-fraction",
    "churn_min_replace": "attack-churn-min-replace",
    "cooldown_rounds": "attack-cooldown-rounds",
    "mode": "attack-mode",
    "window_start_round": "attack-window-start-round",
    "window_end_round": "attack-window-end-round",
    "layering_mode": "attack-layering-mode",
    "layered_k": "attack-layered-k",
    "layered_attacks": "attack-layered-attacks",
    "random_intensity_mode": "attack-random-intensity-mode",
    "random_intensity_value": "attack-random-intensity-value",
    "random_intensity_min": "attack-random-intensity-min",
    "random_intensity_max": "attack-random-intensity-max",
    "random_relative_to_update_norm_probability": "attack-random-relative-to-update-norm-prob",
    "intensity_cap": "attack-intensity-cap",
    "intensity_ramp_mode": "attack-intensity-ramp-mode",
    "intensity_ramp_start_round": "attack-intensity-ramp-start-round",
    "intensity_ramp_end_round": "attack-intensity-ramp-end-round",
    "intensity_ramp_multiplier_start": "attack-intensity-ramp-multiplier-start",
    "intensity_ramp_multiplier_end": "attack-intensity-ramp-multiplier-end",
    "intensity_fail_escalation": "attack-intensity-fail-escalation",
    "intensity_fail_multiplier_step": "attack-intensity-fail-multiplier-step",
    "intensity_fail_multiplier_max": "attack-intensity-fail-multiplier-max",
    "layer_intensity_gaussian_noise": "attack-layer-intensity-gaussian-noise",
    "layer_intensity_sign_flip": "attack-layer-intensity-sign-flip",
    "layer_intensity_alie": "attack-layer-intensity-alie",
    "layer_intensity_mean_shift": "attack-layer-intensity-mean-shift",
    "layer_intensity_label_flip": "attack-layer-intensity-label-flip",
    "layer_intensity_backdoor": "attack-layer-intensity-backdoor",
}

DATASET_OPTIONS = [
    {"value": "ylecun/mnist", "label": "MNIST"},
    {"value": "uoft-cs/cifar10", "label": "CIFAR-10"},
    {"value": "uoft-cs/cifar100", "label": "CIFAR-100"},
    {"value": "zalando-datasets/fashion_mnist", "label": "Fashion-MNIST"},
    {"value": "flwrlabs/femnist", "label": "FEMNIST"},
    {"value": "flwrlabs/usps", "label": "USPS"},
    {"value": "flwrlabs/cinic10", "label": "CINIC-10"},
    {"value": "flwrlabs/pacs", "label": "PACS"},
]

FIELD_GROUPS = [
    {
        "title": "Experiment",
        "fields": [
            {"scope": "app", "key": "dataset", "type": "select", "options": DATASET_OPTIONS},
            {"scope": "app", "key": "strategy", "type": "select", "options": ["fedavg", "fedavgm", "fedprox", "qfedavg", "fedadagrad", "fedadam", "fedyogi", "fedmedian", "fedtrimmedavg", "krum", "multikrum", "bulyan", "fltrust", "foolsgold", "flram", "mab-rfl"]},
            {"scope": "app", "key": "partitioner", "type": "select", "options": ["iid", "dirichlet"]},
            {"scope": "app", "key": "dirichlet-alpha", "type": "number", "step": 0.01, "min": 0},
            {"scope": "app", "key": "num-server-rounds", "type": "number", "step": 1, "min": 1},
            {"scope": "app", "key": "local-epochs", "type": "number", "step": 1, "min": 1},
            {"scope": "app", "key": "learning-rate", "type": "number", "step": 0.001, "min": 0},
            {"scope": "app", "key": "batch-size", "type": "number", "step": 1, "min": 1},
            {"scope": "app", "key": "fraction-train", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "app", "key": "fraction-evaluate", "type": "number", "step": 0.01, "min": 0, "max": 1},
        ],
    },
    {
        "title": "Defense",
        "fields": [
            {"scope": "app", "key": "num-malicious-nodes", "type": "number", "step": 1, "min": 0},
            {"scope": "app", "key": "num-nodes-to-select", "type": "number", "step": 1, "min": 1},
            {"scope": "app", "key": "trimmed-beta", "type": "number", "step": 0.01, "min": 0},
            {"scope": "app", "key": "fltrust-root-size", "type": "number", "step": 1, "min": 0},
            {"scope": "app", "key": "fltrust-server-epochs", "type": "number", "step": 1, "min": 0},
            {"scope": "app", "key": "fltrust-root-batch-size", "type": "number", "step": 1, "min": 1},
            {"scope": "app", "key": "fltrust-server-lr", "type": "number", "step": 0.001, "min": 0},
            {"scope": "app", "key": "trust-aggregation-strength", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "app", "key": "trust-min-weight", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "app", "key": "trust-warmup-rounds", "type": "number", "step": 1, "min": 0},
            {"scope": "app", "key": "flram-min-score", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "app", "key": "mab-rfl-reputation-decay", "type": "number", "step": 0.01, "min": 0, "max": 0.999},
            {"scope": "app", "key": "mab-rfl-current-weight", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "app", "key": "mab-rfl-min-score", "type": "number", "step": 0.01, "min": 0, "max": 1},
        ],
    },
    {
        "title": "Attack Control",
        "fields": [
            {"scope": "attack", "key": "enabled", "type": "boolean"},
            {"scope": "attack", "key": "preset", "type": "select", "options": ["custom", "all", "update_only", "data_only", "noise_only", "sign_flip_only", "label_only", "backdoor_only", "off"]},
            {"scope": "attack", "key": "mode", "type": "select", "options": ["phase", "weighted_random", "adaptive"]},
            {"scope": "attack", "key": "selection_mode", "type": "select", "options": ["per_round_random", "sticky", "sticky_k", "churn"]},
            {"scope": "attack", "key": "malicious_fraction", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "attack", "key": "malicious_fraction_mode", "type": "select", "options": ["fixed", "uniform", "choice"]},
            {"scope": "attack", "key": "malicious_fraction_ramp_mode", "type": "select", "options": ["none", "linear", "exp"]},
            {"scope": "attack", "key": "malicious_fraction_ramp_start_round", "type": "number", "step": 1, "min": 1},
            {"scope": "attack", "key": "malicious_fraction_ramp_end_round", "type": "number", "step": 1, "min": 0},
            {"scope": "attack", "key": "malicious_fraction_ramp_value_start", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "attack", "key": "malicious_fraction_ramp_value_end", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "attack", "key": "malicious_fraction_cap", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "attack", "key": "sticky_rounds", "type": "number", "step": 1, "min": 1},
            {"scope": "attack", "key": "churn_fraction", "type": "number", "step": 0.01, "min": 0, "max": 1},
            {"scope": "attack", "key": "cooldown_rounds", "type": "number", "step": 1, "min": 0},
            {"scope": "attack", "key": "window_start_round", "label": "Attack Start Round", "help": "Use 1 to begin attacking immediately.", "type": "number", "step": 1, "min": 1},
            {"scope": "attack", "key": "window_end_round", "label": "Attack End Round", "type": "number", "step": 1, "min": 0},
        ],
    },
    {
        "title": "Layering",
        "fields": [
            {"scope": "attack", "key": "layering_mode", "type": "select", "options": ["single", "fixed", "sample_k"]},
            {"scope": "attack", "key": "layered_k", "type": "number", "step": 1, "min": 1},
            {"scope": "attack", "key": "layered_attacks", "type": "text", "placeholder": "backdoor;sign_flip"},
            {"scope": "attack", "key": "layer_intensity_gaussian_noise", "type": "number", "step": 0.01, "min": 0},
            {"scope": "attack", "key": "layer_intensity_sign_flip", "type": "number", "step": 0.01, "min": 0},
            {"scope": "attack", "key": "layer_intensity_alie", "type": "number", "step": 0.01, "min": 0},
            {"scope": "attack", "key": "layer_intensity_mean_shift", "type": "number", "step": 0.01, "min": 0},
            {"scope": "attack", "key": "layer_intensity_label_flip", "type": "number", "step": 0.01, "min": 0},
            {"scope": "attack", "key": "layer_intensity_backdoor", "type": "number", "step": 0.01, "min": 0},
        ],
    },
]


# Dashboard-only starting defaults. These do not rewrite pyproject.toml; they
# only determine the initial form state presented in the UI.
DASHBOARD_DEFAULT_OVERRIDES = {
    "app": {
        "dataset": "ylecun/mnist",
        "strategy": "multikrum",
        "partitioner": "dirichlet",
        "dirichlet-alpha": 0.1,
        "num-server-rounds": 30,
        "local-epochs": 1,
        "learning-rate": 0.1,
        "batch-size": 32,
        "fraction-train": 1.0,
        "fraction-evaluate": 1.0,
        "num-malicious-nodes": 25,
        "num-nodes-to-select": 73,
    },
    "attack": {
        # Match the older harsher MNIST MultiKrum failures more closely.
        "enabled": True,
        "preset": "all",
        "mode": "weighted_random",
        "selection_mode": "sticky",
        "malicious_fraction": 0.25,
        "malicious_fraction_mode": "fixed",
        "sticky_rounds": 5,
        "churn_fraction": 0.0,
        "cooldown_rounds": 2,
        "window_start_round": 1,
        "window_end_round": 30,
        "layering_mode": "single",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_pyproject() -> Dict[str, Any]:
    if not PYPROJECT_PATH.exists():
        return {}
    with PYPROJECT_PATH.open("rb") as handle:
        return tomllib.load(handle)


def load_defaults() -> Dict[str, Dict[str, Any]]:
    data = read_pyproject()
    tool = data.get("tool") or {}
    flwr = tool.get("flwr") or {}
    app_config = dict(((flwr.get("app") or {}).get("config") or {}))
    raw_attack_config = dict(flwr.get("attack") or {})
    attack_config = dict(raw_attack_config)

    # Surface the first configured global attack window in the dashboard so the
    # UI reflects the real default timing instead of leaving these blank.
    windows = raw_attack_config.get("windows") or []
    if windows and isinstance(windows, list):
        first_window = windows[0] or {}
        if isinstance(first_window, dict):
            attack_config["window_start_round"] = first_window.get("start_round")
            attack_config["window_end_round"] = first_window.get("end_round")

    # Expose layer intensity defaults through the same flat keys used by the UI.
    layer_multipliers = raw_attack_config.get("layer_intensity_multipliers") or {}
    if isinstance(layer_multipliers, dict):
        for attack_name, multiplier in layer_multipliers.items():
            attack_config[f"layer_intensity_{attack_name}"] = multiplier

    return {"app": app_config, "attack": attack_config}


def load_dashboard_defaults() -> Dict[str, Dict[str, Any]]:
    defaults = load_defaults()
    merged = {"app": dict(defaults["app"]), "attack": dict(defaults["attack"])}
    for scope in ("app", "attack"):
        merged[scope].update(DASHBOARD_DEFAULT_OVERRIDES.get(scope, {}))
    return merged


EDITABLE_FIELDS = {(field["scope"], field["key"]) for group in FIELD_GROUPS for field in group["fields"]}


def quote_toml(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(quote_toml(v) for v in value) + "]"
    if isinstance(value, dict):
        inner = ", ".join(f"{k} = {quote_toml(v)}" for k, v in value.items())
        return "{ " + inner + " }"
    return json.dumps("" if value is None else str(value))


def render_toml(app_config: Dict[str, Any], attack_config: Dict[str, Any]) -> str:
    lines = ["[tool.flwr.app.config]"]
    for key in sorted(app_config.keys()):
        lines.append(f"{key} = {quote_toml(app_config[key])}")
    lines.append("")
    lines.append("[tool.flwr.attack]")
    for key in sorted(attack_config.keys()):
        lines.append(f"{key} = {quote_toml(attack_config[key])}")
    return "\n".join(lines) + "\n"


def coerce_like(value: Any, template: Any) -> Any:
    if isinstance(template, bool):
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}
    if isinstance(template, int) and not isinstance(template, bool):
        return int(float(value))
    if isinstance(template, float):
        return float(value)
    return value


def merge_payload(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    defaults = load_defaults()
    merged = {"app": dict(defaults["app"]), "attack": dict(defaults["attack"])}
    for scope in ("app", "attack"):
        for key, value in (payload.get(scope) or {}).items():
            if (scope, key) not in EDITABLE_FIELDS:
                continue
            if key in merged[scope]:
                try:
                    merged[scope][key] = coerce_like(value, merged[scope][key])
                except Exception:
                    merged[scope][key] = value
            else:
                merged[scope][key] = value
    return merged


def build_run_config_overrides(merged: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    defaults = load_defaults()
    overrides: Dict[str, Any] = {}
    for key, value in merged["app"].items():
        if key == "artifact-dir":
            continue
        if key in defaults["app"] and defaults["app"].get(key) != value:
            overrides[key] = value
    for key, value in merged["attack"].items():
        mapped = ATTACK_OVERRIDE_MAP.get(key)
        normalized_value = value
        if key == "window_start_round":
            try:
                normalized_value = max(1, int(value))
            except Exception:
                normalized_value = value
        if (
            mapped
            and mapped in defaults["app"]
            and defaults["attack"].get(key) != normalized_value
        ):
            overrides[mapped] = normalized_value
    return overrides


def run_config_string(overrides: Dict[str, Any]) -> str:
    parts = []
    for key in sorted(overrides.keys()):
        value = overrides[key]
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            rendered = str(value)
        else:
            rendered = json.dumps(str(value))
        parts.append(f"{key}={rendered}")
    return " ".join(parts)


def normalize_series(series: Dict[str, Dict[str, List[Any]]]) -> Dict[str, Dict[str, List[Dict[str, float]]]]:
    out: Dict[str, Dict[str, List[Dict[str, float]]]] = {}
    for phase, metrics in series.items():
        out[phase] = {}
        for metric_name, points in metrics.items():
            last_by_round: Dict[int, float] = {}
            for round_id, value in points:
                last_by_round[int(round_id)] = float(value)
            out[phase][metric_name] = [{"round": rnd, "value": val} for rnd, val in sorted(last_by_round.items())]
    return out


def read_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return fallback


def read_markdown(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return list(csv.DictReader(handle))
    except Exception:
        return []


def read_client_number_map(run_dir: Path) -> Dict[str, str]:
    for candidate in [
        run_dir / "summaries" / "client_number_map.csv",
        run_dir / "client_number_map.csv",
    ]:
        rows = read_csv_rows(candidate)
        if rows:
            mapping: Dict[str, str] = {}
            for row in rows:
                src_node_id = (row.get("src_node_id") or "").strip()
                client_number = (row.get("client_number") or "").strip()
                if src_node_id and client_number:
                    mapping[src_node_id] = client_number
            if mapping:
                return mapping
    return {}


def safe_rel(path: Path) -> str:
    return str(path.resolve().relative_to(PROJECT_ROOT))


def clean_log_line(line: str) -> str:
    return ANSI_ESCAPE_RE.sub("", line).rstrip("\n")


def should_show_log_line(line: str) -> bool:
    normalized = clean_log_line(line)
    if not normalized:
        return False
    if "ClientAppActor pid=" in normalized:
        return False
    return True


def sorted_run_dirs() -> List[Path]:
    dirs = [meta.parent for meta in LOGS_ROOT.glob("**/meta.json")]
    return sorted(set(dirs), key=lambda path: path.stat().st_mtime, reverse=True)


def summarize_run_dir(run_dir: Path) -> Dict[str, Any]:
    meta = read_json(run_dir / "meta.json", {})
    metrics = read_json(run_dir / "metrics" / "metrics.json", {})
    rounds = read_json(run_dir / "metrics" / "rounds.json", {})
    accuracy_points = (((metrics or {}).get("evaluate_server") or {}).get("accuracy")) or []
    last_accuracy = accuracy_points[-1].get("value") if accuracy_points else None
    return {
        "path": safe_rel(run_dir),
        "name": run_dir.name,
        "dataset": meta.get("dataset"),
        "strategy": meta.get("strategy"),
        "timestamp": meta.get("timestamp"),
        "roundCount": len((rounds.get("by_round") or {})) if isinstance(rounds, dict) else 0,
        "lastAccuracy": last_accuracy,
        "loggedAttackEvents": len(read_csv_rows(run_dir / "summaries" / "round_attack_stats.csv")),
        "meta": meta,
    }


def artifact_manifest(run_dir: Path) -> List[Dict[str, Any]]:
    files = []
    for artifact in sorted(run_dir.rglob("*")):
        if not artifact.is_file():
            continue
        kind = "binary"
        suffix = artifact.suffix.lower()
        if suffix in {".png", ".jpg", ".jpeg", ".gif", ".svg"}:
            kind = "image"
        elif suffix == ".md":
            kind = "markdown"
        elif suffix in {".json", ".jsonl", ".csv", ".txt", ".log"}:
            kind = "text"
        files.append({"path": str(artifact.relative_to(run_dir)), "kind": kind, "size": artifact.stat().st_size})
    return files


def resolve_run_path(path_value: str) -> Path:
    path = (PROJECT_ROOT / path_value).resolve()
    if not path.exists() or PROJECT_ROOT not in path.parents:
        raise HTTPException(status_code=404, detail="Run path not found.")
    return path


@dataclass
class SessionState:
    session_id: str
    effective_config: Dict[str, Dict[str, Any]]
    run_config_overrides: Dict[str, Any]
    total_rounds: int
    created_at: str = field(default_factory=utc_now)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    status: str = "queued"
    process: Optional[subprocess.Popen[str]] = None
    run_dir: Optional[Path] = None
    error: Optional[str] = None
    return_code: Optional[int] = None
    parse_state: ParseState = field(default_factory=ParseState)
    logs: deque[str] = field(default_factory=lambda: deque(maxlen=1400))
    recent_attack_events: List[Dict[str, Any]] = field(default_factory=list)
    recent_defense_events: List[Dict[str, Any]] = field(default_factory=list)
    event_history: List[Dict[str, Any]] = field(default_factory=list)
    round: int = 0
    llm_status: str = "pending"
    lock: threading.Lock = field(default_factory=threading.Lock)

    def publish(self, event_type: str, payload: Dict[str, Any]) -> None:
        with self.lock:
            self.event_history.append(
                {
                    "seq": len(self.event_history) + 1,
                    "type": event_type,
                    "timestamp": utc_now(),
                    "payload": payload,
                }
            )
            if len(self.event_history) > 4000:
                self.event_history = self.event_history[-2000:]

    def append_log(self, line: str) -> None:
        text = clean_log_line(line)
        if not should_show_log_line(text):
            return
        with self.lock:
            self.logs.append(text)
        self.publish("log", {"line": text})

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "id": self.session_id,
                "status": self.status,
                "createdAt": self.created_at,
                "startedAt": self.started_at,
                "finishedAt": self.finished_at,
                "runDir": safe_rel(self.run_dir) if self.run_dir else None,
                "error": self.error,
                "returnCode": self.return_code,
                "round": self.round,
                "totalRounds": self.total_rounds,
                "logs": list(self.logs)[-400:],
                "metrics": normalize_series(self.parse_state.series),
                "metricsByRound": {str(k): v for k, v in sorted(self.parse_state.by_round.items())},
                "sampling": self.parse_state.sampling,
                "recentAttackEvents": self.recent_attack_events[-20:],
                "recentDefenseEvents": self.recent_defense_events[-20:],
                "llmStatus": self.llm_status,
                "effectiveConfig": self.effective_config,
                "runConfigOverrides": self.run_config_overrides,
            }


class RunManager:
    def __init__(self) -> None:
        self.sessions: Dict[str, SessionState] = {}
        self.lock = threading.Lock()

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self.lock:
            sessions = list(self.sessions.values())
        return [session.snapshot() for session in sorted(sessions, key=lambda item: item.created_at, reverse=True)]

    def get(self, session_id: str) -> SessionState:
        with self.lock:
            session = self.sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Run session not found.")
        return session

    def start(self, payload: Dict[str, Any]) -> SessionState:
        effective = merge_payload(payload)
        overrides = build_run_config_overrides(effective)
        session = SessionState(
            session_id=str(uuid.uuid4()),
            effective_config=effective,
            run_config_overrides=overrides,
            total_rounds=int(effective["app"].get("num-server-rounds", 0) or 0),
        )
        with self.lock:
            if any(existing.status in {"queued", "running"} for existing in self.sessions.values()):
                raise HTTPException(status_code=409, detail="A dashboard-managed run is already active.")
            self.sessions[session.session_id] = session
        threading.Thread(target=self._execute, args=(session,), daemon=True).start()
        return session

    def _discover_run_dir(self, known: set[str]) -> Optional[Path]:
        for run_dir in sorted_run_dirs():
            if safe_rel(run_dir) not in known:
                return run_dir
        return None

    def _watch_artifacts(self, session: SessionState) -> None:
        seen_attack: set[tuple[Any, ...]] = set()
        seen_defense: set[tuple[Any, ...]] = set()
        while session.status in {"queued", "running"} or session.llm_status in {"pending", "running"}:
            time.sleep(1.0)
            if session.run_dir is None:
                continue
            for row in read_csv_rows(session.run_dir / "summaries" / "round_attack_stats.csv")[-8:]:
                key = (row.get("round"), row.get("attack_name"), row.get("intensity"))
                if key in seen_attack:
                    continue
                seen_attack.add(key)
                with session.lock:
                    session.recent_attack_events.append(row)
                session.publish("attack", row)
            for row in read_csv_rows(session.run_dir / "summaries" / "defense_selection_by_round.csv")[-8:]:
                key = (row.get("round"), row.get("defense_strategy"), row.get("malicious_selected_fraction"))
                if key in seen_defense:
                    continue
                seen_defense.add(key)
                with session.lock:
                    session.recent_defense_events.append(row)
                session.publish("defense", row)

            llm_candidates = [
                session.run_dir / "llm_analysis" / "llm_comprehensive_analysis.md",
                session.run_dir / "llm_analysis" / "llm_global_analysis.md",
            ]
            if session.llm_status in {"pending", "running"} and any(path.exists() for path in llm_candidates):
                session.llm_status = "ready"
                session.publish("llm", {"status": "ready"})

            if session.status in {"completed", "failed"} and session.llm_status not in {"pending", "running"}:
                break

    def _execute(self, session: SessionState) -> None:
        known_runs = {safe_rel(path) for path in sorted_run_dirs()}
        command = ["bash", "./run.sh"]
        cfg = run_config_string(session.run_config_overrides)
        if cfg:
            command.extend(["--run-config", cfg])

        with session.lock:
            session.status = "running"
            session.started_at = utc_now()

        threading.Thread(target=self._watch_artifacts, args=(session,), daemon=True).start()

        try:
            proc = subprocess.Popen(
                command,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            session.process = proc
            assert proc.stdout is not None
            round_pat = re.compile(r"\[ROUND\s+(\d+)\s*/\s*(\d+)\]")

            for line in proc.stdout:
                session.parse_state.feed_line(line)
                normalized_line = clean_log_line(line)
                if session.llm_status == "pending" and (
                    "[llm-analysis]" in normalized_line
                    or "llm_sweep_analysis.py" in normalized_line
                ):
                    session.llm_status = "running"
                    session.publish("llm", {"status": "running"})
                session.append_log(line)
                match = round_pat.search(line)
                if match:
                    session.round = int(match.group(1))
                    session.total_rounds = int(match.group(2))
                    session.publish("round", {"round": session.round, "total": session.total_rounds})
                if session.run_dir is None:
                    discovered = self._discover_run_dir(known_runs)
                    if discovered is not None:
                        session.run_dir = discovered
                        session.publish("run_dir", {"path": safe_rel(discovered)})

            session.return_code = proc.wait()
            llm_ready = False
            if session.run_dir is not None:
                llm_ready = any(
                    candidate.exists()
                    for candidate in [
                        session.run_dir / "llm_analysis" / "llm_comprehensive_analysis.md",
                        session.run_dir / "llm_analysis" / "llm_global_analysis.md",
                    ]
                )
            with session.lock:
                session.status = "completed" if session.return_code == 0 else "failed"
                session.finished_at = utc_now()
                if session.return_code != 0:
                    session.error = f"run.sh exited with code {session.return_code}"
                if llm_ready:
                    session.llm_status = "ready"
                elif session.llm_status == "pending":
                    session.llm_status = "unavailable"
        except Exception as exc:
            with session.lock:
                session.status = "failed"
                session.error = str(exc)
                session.finished_at = utc_now()
                session.llm_status = "unavailable"
            session.publish("error", {"message": str(exc)})


run_manager = RunManager()

app = FastAPI(title="Dynamic FL Dashboard", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))


@app.get("/api/config")
def get_config() -> Dict[str, Any]:
    defaults = load_dashboard_defaults()
    return {
        "defaults": defaults,
        "groups": FIELD_GROUPS,
        "advancedFields": [],
        "tomlPreview": render_toml(defaults["app"], defaults["attack"]),
        "notes": [
            "Dashboard defaults start from pyproject.toml and then apply a harsher website preset.",
            "The website now starts with an MNIST + MultiKrum stress profile that attacks from round 1, which is the first active training round.",
            "Derived and backend-owned values such as dataset keys, splits, and num-classes stay fixed from the current codebase.",
            "The UI focuses on dataset choice, experiment setup, and attack behavior.",
            "The dashboard launches ./run.sh and passes only CLI-compatible overrides.",
        ],
    }


@app.post("/api/runs")
def start_run(payload: Dict[str, Any]) -> Dict[str, Any]:
    return run_manager.start(payload).snapshot()


@app.get("/api/runs")
def list_runs() -> Dict[str, Any]:
    return {"sessions": run_manager.list_sessions()}


@app.get("/api/runs/{session_id}")
def run_snapshot(session_id: str) -> Dict[str, Any]:
    return run_manager.get(session_id).snapshot()


@app.get("/api/runs/{session_id}/events")
def run_events(session_id: str):
    session = run_manager.get(session_id)

    def stream():
        seq = 0
        while True:
            history = list(session.event_history)
            if seq < len(history):
                for event in history[seq:]:
                    yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                seq = len(history)
            elif session.status in {"completed", "failed"} and session.llm_status != "running":
                yield f"event: done\ndata: {json.dumps({'status': session.status})}\n\n"
                break
            else:
                yield "event: ping\ndata: {}\n\n"
            time.sleep(1.0)

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/history")
def history() -> Dict[str, Any]:
    return {"runs": [summarize_run_dir(run_dir) for run_dir in sorted_run_dirs()[:30]]}


@app.get("/api/history/run")
def history_run(path: str = Query(...)) -> Dict[str, Any]:
    run_dir = resolve_run_path(path)
    llm_path = None
    for candidate in [
        run_dir / "llm_analysis" / "llm_comprehensive_analysis.md",
        run_dir / "llm_analysis" / "llm_global_analysis.md",
        run_dir / "llm_comprehensive_analysis.md",
        run_dir / "llm_global_analysis.md",
    ]:
        if candidate.exists():
            llm_path = candidate
            break
    return {
        "summary": summarize_run_dir(run_dir),
        "metrics": read_json(run_dir / "metrics" / "metrics.json", {}),
        "rounds": read_json(run_dir / "metrics" / "rounds.json", {}),
        "artifacts": artifact_manifest(run_dir),
        "attackSummary": read_markdown(run_dir / "summaries" / "attack_summary.md"),
        "llmSummary": read_markdown(llm_path) if llm_path else None,
        "clientNumberMap": read_client_number_map(run_dir),
    }


@app.get("/api/history/file")
def history_file(path: str = Query(...), file: str = Query(...)):
    run_dir = resolve_run_path(path)
    artifact = (run_dir / file).resolve()
    if not artifact.exists() or run_dir not in artifact.parents:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    mime, _ = mimetypes.guess_type(str(artifact))
    return FileResponse(artifact, media_type=mime or "application/octet-stream")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def main() -> None:
    import uvicorn

    uvicorn.run("dashboard.app:app", host="127.0.0.1", port=8000, reload=False)
