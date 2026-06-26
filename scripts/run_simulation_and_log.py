#!/usr/bin/env python3
"""Run Flower simulation and persist metrics + graphs.

This script wraps `flwr run .` and produces a per-run folder:

logs/<strategy>__<dataset>__<iid|noniid>__<YYYY-MM-DD_HH-MM-SS>/
  - stdout.log, stderr.log
  - metrics/metrics.json
  - metrics/*.csv
  - graphs/*.png

It parses metrics from the Flower console output ("Aggregated MetricRecord" lines
and optional "Global evaluation" MetricRecord lines).

Usage examples:
  python scripts/run_simulation_and_log.py
  python scripts/run_simulation_and_log.py --federation local-simulation-gpu
  python scripts/run_simulation_and_log.py --run-config "num-server-rounds=5 local-epochs=2"
  python scripts/run_simulation_and_log.py --strategy-name CustomFedAdagrad
"""

from __future__ import annotations

import argparse
import ast
import collections
from collections import Counter, defaultdict
import csv
import io
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ParsedMetrics:
    # phase -> metric -> list[(round, value)]
    series: Dict[str, Dict[str, List[Tuple[int, float]]]]

    # round -> phase -> metric -> value
    by_round: Dict[int, Dict[str, Dict[str, float]]]

    # round -> {train/evaluate}->{count:int, out_of:int|None, ids:list[str]|None}
    sampling: Dict[int, Dict[str, Dict[str, Any]]]

    # Optional per-client metrics parsed from explicit client log lines.
    # phase (train_client/evaluate_client) -> client_id -> metric -> list[(round, value)]
    per_client: Dict[str, Dict[str, Dict[str, List[Tuple[int, float]]]]]

    def to_jsonable(self) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        out: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for phase, metrics in self.series.items():
            out[phase] = {}
            for metric_name, points in metrics.items():
                out[phase][metric_name] = [
                    {"round": float(r), "value": _json_number(v)} for (r, v) in points
                ]
        return out

    def to_round_jsonable(self) -> Dict[str, Any]:
        return {
            "by_round": {
                str(rnd): _jsonify_nested(phases)
                for rnd, phases in sorted(self.by_round.items())
            },
            "sampling": {
                str(rnd): phases for rnd, phases in sorted(self.sampling.items())
            },
        }


def _json_number(value: float) -> Optional[float]:
    """Return a JSON-safe float (non-finite becomes null)."""
    try:
        v = float(value)
    except Exception:
        return None

    return v if math.isfinite(v) else None


def _module_available(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except Exception:
        return False


def _jsonify_nested(value: Any) -> Any:
    """Recursively convert floats to JSON-safe values."""
    if isinstance(value, float):
        return _json_number(value)
    if isinstance(value, dict):
        return {k: _jsonify_nested(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonify_nested(v) for v in value]
    return value


@dataclass
class ParseState:
    current_round: Optional[int] = None
    current_stage: Optional[str] = None  # train/evaluate
    last_line_was_global_eval: bool = False

    series: Dict[str, Dict[str, List[Tuple[int, float]]]] = None  # type: ignore[assignment]
    by_round: Dict[int, Dict[str, Dict[str, float]]] = None  # type: ignore[assignment]
    sampling: Dict[int, Dict[str, Dict[str, Any]]] = None  # type: ignore[assignment]

    round_pat: re.Pattern = None  # type: ignore[assignment]
    sampled_pat: re.Pattern = None  # type: ignore[assignment]
    client_metric_pat: re.Pattern = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.series is None:
            self.series = {
                "train_client": {},
                "evaluate_client": {},
                "evaluate_server": {},
            }
        if self.by_round is None:
            self.by_round = {}
        if self.sampling is None:
            self.sampling = {}
        if self.round_pat is None:
            self.round_pat = re.compile(r"\[ROUND\s+(\d+)\s*/\s*(\d+)\]")
        if self.sampled_pat is None:
            self.sampled_pat = re.compile(
                r"configure_(train|evaluate):\s*Sampled\s+(\d+)\s+nodes\s*\(out\s+of\s+(\d+)\)"
            )
        if self.client_metric_pat is None:
            # Examples (Ray may prefix lines with '(ClientAppActor pid=...)'):
            #   CM s=train pid=0 gid=<group_id> tl=2.30
            #   CM s=evaluate pid=0 gid=<group_id> el=2.29 ea=0.11
            # Legacy:
            #   CLIENT_METRICS stage=train partition_id=0 train_loss=2.30
            self.client_metric_pat = re.compile(
                r"(?:^|\s)(CM\s+.*|CLIENT_METRICS\s+.*)$"
            )

        # Optional per-client series (created lazily)
        self._per_client: Dict[str, Dict[str, Dict[str, List[Tuple[int, float]]]]] = {}
        # Per-client counters to infer rounds when logs are buffered/flushed at end.
        # key: (phase, client_id) -> count
        self._per_client_counter: Dict[Tuple[str, str], int] = {}

    def feed_line(self, raw_line: str) -> None:
        # Strip ANSI escape codes (Flower logs often include colored INFO prefixes)
        line = re.sub(r"\x1b\[[0-9;]*m", "", raw_line).strip()

        m = self.round_pat.search(line)
        if m:
            self.current_round = int(m.group(1))
            self.current_stage = None
            self.last_line_was_global_eval = False
            return

        # Optional per-client metric lines emitted by ClientApp.
        m = self.client_metric_pat.search(line)
        if m:
            payload = m.group(1).strip()
            if payload.startswith("CM "):
                # CM format uses short keys.
                tokens = payload.split()
                kv: Dict[str, str] = {}
                # tokens: ["CM", "s=train", "pid=0", "gid=...", "tl=..."]
                for tok in tokens[1:]:
                    if "=" not in tok:
                        continue
                    k, v = tok.split("=", 1)
                    kv[k.strip()] = v.strip()
                stage = kv.get("s")
                client_id = kv.get("pid")
                if stage not in {"train", "evaluate"} or not client_id:
                    return
                phase = "train_client" if stage == "train" else "evaluate_client"
                # Try explicit round first; otherwise infer by per-client event index.
                round_val = kv.get("r") or kv.get("round")
                round_num = None
                if round_val is not None:
                    try:
                        round_num = int(round_val)
                    except Exception:
                        round_num = None
                # Prefer the known server round if available.
                if round_num is None and self.current_round is not None:
                    round_num = int(self.current_round)
                if round_num is None:
                    key = (phase, client_id)
                    self._per_client_counter[key] = self._per_client_counter.get(key, 0) + 1
                    round_num = self._per_client_counter[key]

                # Map short metric keys to stable names
                metric_map = {
                    "tl": "train_loss",
                    "el": "eval_loss",
                    "ea": "eval_acc",
                }
                for short_k, metric_name in metric_map.items():
                    if short_k not in kv:
                        continue
                    value_f = _coerce_metric_value(kv[short_k])
                    if value_f is None:
                        continue
                    self._per_client.setdefault(phase, {}).setdefault(client_id, {}).setdefault(
                        metric_name, []
                    ).append((int(round_num), value_f))
                return

            if payload.startswith("CLIENT_METRICS"):
                # Legacy: CLIENT_METRICS stage=train partition_id=0 k=v...
                # Parse key=value tokens (best-effort; Ray may wrap long lines).
                stage_m = re.search(r"stage=(train|evaluate)", payload)
                pid_m = re.search(r"partition_id=(\d+)", payload)
                if not stage_m or not pid_m:
                    return
                stage = stage_m.group(1)
                client_id = pid_m.group(1)
                phase = "train_client" if stage == "train" else "evaluate_client"
                if self.current_round is None:
                    return
                for tok in payload.split():
                    if "=" not in tok:
                        continue
                    k, v = tok.split("=", 1)
                    if k in {"stage", "partition_id"}:
                        continue
                    value_f = _coerce_metric_value(v)
                    if value_f is None:
                        continue
                    self._per_client.setdefault(phase, {}).setdefault(client_id, {}).setdefault(
                        k, []
                    ).append((int(self.current_round), value_f))
                return

        # Sampling info
        m = self.sampled_pat.search(line)
        if m and self.current_round is not None:
            stage = m.group(1)  # train/evaluate
            count = int(m.group(2))
            out_of = int(m.group(3))

            ids: Optional[List[str]] = None
            if ":" in line:
                tail = line.split(":", 1)[1].strip()
                try:
                    parsed = ast.literal_eval(tail)
                    if isinstance(parsed, (list, tuple)):
                        ids = [str(x) for x in parsed]
                except Exception:
                    ids = None

            self.sampling.setdefault(self.current_round, {})[stage] = {
                "count": count,
                "out_of": out_of,
                "ids": ids,
            }
            return

        # Stage hints
        if "aggregate_train" in line:
            self.current_stage = "train"
            self.last_line_was_global_eval = False
            return
        if "aggregate_evaluate" in line:
            self.current_stage = "evaluate"
            self.last_line_was_global_eval = False
            return

        if "Global evaluation" in line:
            self.last_line_was_global_eval = True
            return

        # Aggregated MetricRecord (client-side)
        if "Aggregated MetricRecord:" in line:
            if self.current_round is None:
                return
            frag = line.split("Aggregated MetricRecord:", 1)[1].strip()
            d = _safe_literal_dict(frag)
            if d is None:
                return

            # Prefer inferring phase from metric names (more robust than relying on
            # current_stage because logs can interleave).
            keys = {str(k) for k in d.keys()}
            if any(k.startswith("eval") or k.startswith("evaluate") for k in keys):
                phase = "evaluate_client"
            elif any(k.startswith("train") for k in keys):
                phase = "train_client"
            elif self.current_stage == "train":
                phase = "train_client"
            else:
                phase = "evaluate_client"

            for k, v in d.items():
                value_f = _coerce_metric_value(v)
                if value_f is None:
                    continue
                self.series[phase].setdefault(str(k), []).append(
                    (self.current_round, value_f)
                )
                self.by_round.setdefault(self.current_round, {}).setdefault(phase, {})[
                    str(k)
                ] = value_f
            return

        # Server-side MetricRecord (centralized evaluation)
        if "MetricRecord:" in line and self.last_line_was_global_eval:
            if self.current_round is None:
                return
            frag = line.split("MetricRecord:", 1)[1].strip()
            d = _safe_literal_dict(frag)
            if d is None:
                return
            for k, v in d.items():
                value_f = _coerce_metric_value(v)
                if value_f is None:
                    continue
                self.series["evaluate_server"].setdefault(str(k), []).append(
                    (self.current_round, value_f)
                )
                self.by_round.setdefault(self.current_round, {}).setdefault(
                    "evaluate_server", {}
                )[str(k)] = value_f
            return

    def finalize(self) -> ParsedMetrics:
        # Sort and de-dup by round (keep last occurrence per round)
        for phase, metric_map in list(self.series.items()):
            cleaned: Dict[str, List[Tuple[int, float]]] = {}
            for metric_name, points in metric_map.items():
                last_by_round: Dict[int, float] = {}
                for r, v in points:
                    last_by_round[int(r)] = float(v)
                cleaned[metric_name] = sorted(last_by_round.items(), key=lambda x: x[0])
            self.series[phase] = cleaned

        # Sort/de-dup per-client series
        for phase, clients in list(getattr(self, "_per_client", {}).items()):
            for client_id, metrics in list(clients.items()):
                cleaned: Dict[str, List[Tuple[int, float]]] = {}
                for metric_name, points in metrics.items():
                    last_by_round: Dict[int, float] = {}
                    for r, v in points:
                        last_by_round[int(r)] = float(v)
                    cleaned[metric_name] = sorted(last_by_round.items(), key=lambda x: x[0])
                clients[client_id] = cleaned

        return ParsedMetrics(
            series=self.series,
            by_round=self.by_round,
            sampling=self.sampling,
            per_client=getattr(self, "_per_client", {}),
        )


def _write_sampling_table(run_dir: Path, parsed: ParsedMetrics) -> None:
    """Write sampling summary as CSV and (if matplotlib available) PNG table."""

    if not parsed.sampling:
        return

    metrics_dir = run_dir / "metrics"
    graphs_dir = run_dir / "graphs"

    rounds = sorted(parsed.sampling.keys())
    rows: List[List[str]] = []
    for rnd in rounds:
        tr = parsed.sampling.get(rnd, {}).get("train", {})
        ev = parsed.sampling.get(rnd, {}).get("evaluate", {})
        rows.append(
            [
                str(rnd),
                str(tr.get("count", "")),
                str(tr.get("out_of", "")),
                str(ev.get("count", "")),
                str(ev.get("out_of", "")),
            ]
        )

    header = ["round", "train_count", "train_out_of", "eval_count", "eval_out_of"]
    csv_lines = [",".join(header)] + [",".join(r) for r in rows]
    (metrics_dir / "sampling.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")

    # PNG rendering is optional and only happens if graphs/ exists.
    if not graphs_dir.exists():
        return

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return

    fig_h = max(2.5, 0.35 * (len(rows) + 2))
    fig = plt.figure(figsize=(10, fig_h))
    ax = fig.add_subplot(1, 1, 1)
    ax.axis("off")
    table = ax.table(cellText=rows, colLabels=header, loc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.0, 1.2)
    ax.set_title("Sampling per round", pad=12)
    fig.tight_layout()
    fig.savefig(graphs_dir / "sampling__table.png", dpi=160)
    plt.close(fig)


def _write_config_summary_table(run_dir: Path) -> None:
    """Render a PNG table of the run configuration (meta.json)."""

    meta_path = run_dir / "meta.json"
    if not meta_path.exists():
        return

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return

    # Prefer the resolved config used for naming (defaults + overrides).
    resolved = meta.get("resolved_config_for_naming") or {}
    if not isinstance(resolved, dict):
        resolved = {}

    # Include a few top-level meta fields.
    extra_fields = {
        "strategy": meta.get("strategy"),
        "dataset": meta.get("dataset"),
        "partitioner": meta.get("partitioner"),
        "dirichlet-alpha": meta.get("dirichlet-alpha"),
        "federation": meta.get("federation"),
        "timestamp": meta.get("timestamp"),
    }

    # Build key/value rows, filter out noisy/empty values.
    def _is_empty(v: Any) -> bool:
        return v is None or v == "" or v == [] or v == {}

    kv: Dict[str, Any] = {**resolved, **{k: v for k, v in extra_fields.items() if not _is_empty(v)}}

    # Keep ordering stable and put the most important knobs first.
    preferred_order = [
        "strategy",
        "dataset",
        "partitioner",
        "dirichlet-alpha",
        "num-server-rounds",
        "fraction-train",
        "fraction-evaluate",
        "min-train-nodes",
        "min-evaluate-nodes",
        "min-available-nodes",
        "local-epochs",
        "learning-rate",
        "batch-size",
        "max-train-examples",
        "max-val-examples",
        "max-central-eval-examples",
        "dataset-modality",
        "dataset-train-split",
        "dataset-eval-split",
        "dataset-subset",
        "hf-trust-remote-code",
        "federation",
        "timestamp",
    ]
    rows: List[List[str]] = []
    seen = set()
    for k in preferred_order:
        if k in kv and not _is_empty(kv[k]):
            rows.append([k, str(kv[k])])
            seen.add(k)
    for k in sorted(k for k in kv.keys() if k not in seen):
        if not _is_empty(kv[k]):
            rows.append([k, str(kv[k])])

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return

    fig_h = max(3.0, 0.32 * (len(rows) + 2))
    fig = plt.figure(figsize=(10, fig_h))
    ax = fig.add_subplot(1, 1, 1)
    ax.axis("off")
    table = ax.table(cellText=rows, colLabels=["key", "value"], loc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.0, 1.15)
    ax.set_title("Run configuration summary", pad=12)
    fig.tight_layout()
    fig.savefig(run_dir / "graphs" / "config__summary.png", dpi=160)
    plt.close(fig)


def _rgba_to_hex(rgba: Tuple[float, float, float, float]) -> str:
    r, g, b, _a = rgba
    return "#{:02x}{:02x}{:02x}".format(int(r * 255), int(g * 255), int(b * 255))


def _assign_client_colors(client_ids: List[str]) -> Dict[str, Tuple[float, float, float, float]]:
    """Assign stable colors to client ids."""

    # Keep deterministic ordering.
    ids = sorted(client_ids, key=lambda x: int(x))
    if not ids:
        return {}

    try:
        import matplotlib

        matplotlib.use("Agg")
        # Matplotlib >=3.7 prefers matplotlib.colormaps
        try:
            cmap = matplotlib.colormaps.get_cmap("turbo")  # type: ignore[attr-defined]
        except Exception:
            import matplotlib.cm as cm

            cmap = cm.get_cmap("turbo")
    except Exception:
        return {}
    n = len(ids)
    colors: Dict[str, Tuple[float, float, float, float]] = {}
    for i, cid in enumerate(ids):
        t = 0.5 if n == 1 else i / (n - 1)
        colors[cid] = cmap(t)
    return colors


def _write_client_color_key(
    metrics_dir: Path,
    graphs_dir: Path,
    client_ids: List[str],
    colors: Dict[str, Tuple[float, float, float, float]],
) -> None:
    """Persist client index/partition_id -> color mapping (CSV/JSON + PNG)."""

    ids = sorted(client_ids, key=lambda x: int(x))
    if not ids:
        return

    # CSV/JSON in metrics/
    csv_lines = ["client_index,partition_id,color_hex"]
    out_json: Dict[str, Any] = {}
    for idx, cid in enumerate(ids, start=1):
        hex_color = _rgba_to_hex(colors[cid]) if cid in colors else ""
        csv_lines.append(f"{idx},{cid},{hex_color}")
        out_json[str(idx)] = {"partition_id": int(cid), "color": hex_color}
    (metrics_dir / "per_client_color_key.csv").write_text(
        "\n".join(csv_lines) + "\n", encoding="utf-8"
    )
    (metrics_dir / "per_client_color_key.json").write_text(
        json.dumps(out_json, indent=2, sort_keys=True), encoding="utf-8"
    )

    # PNG table in graphs/
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return

    rows: List[List[str]] = []
    for idx, cid in enumerate(ids, start=1):
        rows.append([f"client {idx}", f"partition_id={cid}", _rgba_to_hex(colors[cid])])

    fig_h = max(3.0, 0.32 * (len(rows) + 2))
    fig = plt.figure(figsize=(10, fig_h))
    ax = fig.add_subplot(1, 1, 1)
    ax.axis("off")

    table = ax.table(cellText=rows, colLabels=["client", "id", "color"], loc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.0, 1.12)

    # Color the "color" column cells with the actual colors
    # Row 0 is header; data rows start at 1.
    for i, cid in enumerate(ids, start=1):
        if cid not in colors:
            continue
        cell = table[(i, 2)]
        cell.set_facecolor(colors[cid])
        # Pick readable text color
        r, g, b, _a = colors[cid]
        luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b
        cell.get_text().set_color("black" if luminance > 0.6 else "white")

    ax.set_title("Per-client color key", pad=12)
    fig.tight_layout()
    fig.savefig(graphs_dir / "per_client__color_key.png", dpi=160)
    plt.close(fig)


def _infer_total_clients_from_sampling(parsed: ParsedMetrics) -> Optional[int]:
    """Infer total number of clients/supernodes from sampling logs."""
    if not parsed.sampling:
        return None
    first_round = min(parsed.sampling.keys())
    entry = parsed.sampling.get(first_round, {})
    for stage in ("train", "evaluate"):
        s = entry.get(stage) or {}
        out_of = s.get("out_of")
        if isinstance(out_of, int) and out_of > 0:
            return out_of
        count = s.get("count")
        if isinstance(count, int) and count > 0:
            # Fallback if out_of is missing
            return count
    return None


def _write_label_distribution_artifacts(run_dir: Path, parsed: ParsedMetrics) -> None:
    """Write per-partition label distribution (CSV + heatmaps) for the training split.

    This is a data-diagnostics artifact (not a training metric). It helps interpret
    heterogeneity and later poisoning/label-flip effects.
    """

    total_clients = _infer_total_clients_from_sampling(parsed)
    if total_clients is None or total_clients <= 1:
        return

    meta_path = run_dir / "meta.json"
    if not meta_path.exists():
        return

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return

    resolved = meta.get("resolved_config_for_naming") or {}
    if not isinstance(resolved, dict):
        resolved = {}

    dataset = resolved.get("dataset") or meta.get("dataset")
    if not dataset:
        return
    dataset = str(dataset)

    partitioner_name = str(resolved.get("partitioner") or meta.get("partitioner") or "iid")
    dirichlet_alpha = resolved.get("dirichlet-alpha") or meta.get("dirichlet-alpha")
    dataset_subset = str(resolved.get("dataset-subset") or "")
    label_name = str(resolved.get("label-key") or "") or "label"
    max_examples_per_partition = int(resolved.get("label-dist-max-examples-per-partition") or 0)

    metrics_dir = run_dir / "metrics"
    graphs_dir = run_dir / "graphs" / "diagnostics"
    if not metrics_dir.exists():
        return

    try:
        from flwr_datasets import FederatedDataset
        from flwr_datasets.partitioner import DirichletPartitioner, IidPartitioner
    except Exception:
        # flwr-datasets not installed in this env
        return

    # Reconstruct the partitioner used for the train split.
    if partitioner_name.lower() in {"iid"}:
        part = IidPartitioner(num_partitions=total_clients)
    elif partitioner_name.lower() in {"dirichlet", "dir"}:
        try:
            alpha = float(dirichlet_alpha) if dirichlet_alpha is not None else 0.5
        except Exception:
            alpha = 0.5
        part = DirichletPartitioner(
            num_partitions=total_clients,
            alpha=alpha,
            partition_by=label_name,
            seed=42,
            min_partition_size=0,
        )
    else:
        # Only generate this artifact for partitioners we can reconstruct today.
        return

    try:
        fds = FederatedDataset(
            dataset=dataset,
            subset=dataset_subset if dataset_subset else None,
            partitioners={"train": part},
        )
    except Exception:
        return

    # Determine label names if available.
    label_names: Optional[List[str]] = None
    num_labels: Optional[int] = None
    try:
        ds0 = fds.load_partition(partition_id=0)
        feat = getattr(ds0, "features", {}).get(label_name)
        names = getattr(feat, "names", None)
        if isinstance(names, list) and names:
            label_names = [str(x) for x in names]
            num_labels = len(label_names)
    except Exception:
        pass

    # Count labels per partition.
    counts: List[collections.Counter[int]] = []
    max_label_seen = -1
    for pid in range(total_clients):
        try:
            ds = fds.load_partition(partition_id=pid)
            labels = ds[label_name]
            if max_examples_per_partition and hasattr(labels, "__len__"):
                labels = labels[:max_examples_per_partition]
            c = collections.Counter(int(x) for x in labels)
            if c:
                max_label_seen = max(max_label_seen, max(c.keys()))
            counts.append(c)
        except Exception:
            counts.append(collections.Counter())

    if num_labels is None:
        num_labels = max_label_seen + 1 if max_label_seen >= 0 else 0
    if num_labels <= 0:
        return

    if label_names is None:
        label_names = [str(i) for i in range(num_labels)]
    else:
        # Ensure length matches
        if len(label_names) < num_labels:
            label_names = label_names + [str(i) for i in range(len(label_names), num_labels)]

    matrix_abs: List[List[int]] = []
    for pid in range(total_clients):
        row = [int(counts[pid].get(i, 0)) for i in range(num_labels)]
        matrix_abs.append(row)

    # Write CSVs
    header = ["partition_id"] + [f"label_{name}" for name in label_names]
    lines = [",".join(header)]
    for pid, row in enumerate(matrix_abs):
        lines.append(",".join([str(pid)] + [str(v) for v in row]))
    (metrics_dir / "label_distribution__train__absolute.csv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    # Percent-normalized by partition
    lines = [",".join(header)]
    for pid, row in enumerate(matrix_abs):
        s = float(sum(row))
        if s <= 0:
            pct = [0.0 for _ in row]
        else:
            pct = [v / s for v in row]
        lines.append(",".join([str(pid)] + [f"{v:.6f}" for v in pct]))
    (metrics_dir / "label_distribution__train__percent.csv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    # Heatmap PNGs (optional)
    if not graphs_dir.exists():
        return
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return

    def _plot_heatmap(data: List[List[float]], title: str, out_name: str, vmin: float) -> None:
        fig = plt.figure(figsize=(max(8, 0.6 * num_labels + 4), max(6, 0.22 * total_clients + 3)))
        ax = fig.add_subplot(1, 1, 1)
        im = ax.imshow(data, aspect="auto", cmap="Greens", vmin=vmin)
        ax.set_title(title)
        ax.set_xlabel("Label")
        ax.set_ylabel("Partition ID")
        ax.set_xticks(list(range(num_labels)))
        ax.set_xticklabels(label_names, rotation=45, ha="right")
        ax.set_yticks(list(range(total_clients)))
        ax.set_yticklabels([str(i) for i in range(total_clients)])
        cbar = fig.colorbar(im, ax=ax)
        cbar.ax.set_ylabel("count" if vmin == 0 else "fraction")
        fig.tight_layout()
        fig.savefig(graphs_dir / out_name, dpi=160)
        plt.close(fig)

    _plot_heatmap(
        [[float(v) for v in row] for row in matrix_abs],
        title=f"Label distribution (train split) — absolute\n{dataset} | {partitioner_name} | clients={total_clients}",
        out_name="data__label_distribution__train__absolute.png",
        vmin=0.0,
    )
    matrix_pct = []
    for row in matrix_abs:
        s = float(sum(row))
        matrix_pct.append([0.0 if s <= 0 else (v / s) for v in row])
    _plot_heatmap(
        matrix_pct,
        title=f"Label distribution (train split) — percent\n{dataset} | {partitioner_name} | clients={total_clients}",
        out_name="data__label_distribution__train__percent.png",
        vmin=0.0,
    )


def _mirror_attack_plots_into_graph_folders(run_dir: Path) -> None:
    """Copy server-written attack plots into the runner's graph folders.

    The ServerApp writes into `run_dir/summaries/`. The runner's visual artifacts
    live under `run_dir/graphs/*`. This helper keeps everything discoverable.
    """

    summaries = run_dir / "summaries"
    if not summaries.exists():
        return

    graphs_summaries = run_dir / "graphs" / "summaries"
    graphs_agg_server = run_dir / "graphs" / "aggregated_server"
    graphs_summaries.mkdir(parents=True, exist_ok=True)
    graphs_agg_server.mkdir(parents=True, exist_ok=True)

    names = [
        "malicious_clients_over_time.png",
        "attack_type_timeline.png",
        "intensity_over_time.png",
        "client_outlier_score_over_time.png",
        "defense_malicious_selected_vs_sampled.png",
    ]
    for name in names:
        src = summaries / name
        if not src.exists():
            continue
        for dst_dir in (graphs_summaries, graphs_agg_server):
            try:
                shutil.copy2(src, dst_dir / name)
            except Exception:
                pass


def _maybe_write_research_plots(run_dir: Path) -> None:
    """Generate research-ready plots into `run_dir/summaries/plots/`.

    This is intentionally post-run and decoupled from training.

    Inputs (best-effort; any missing input will skip the corresponding plot):
    - summaries/poisoning_by_client_round.csv
    - summaries/malicious_clients_by_round.csv
    - summaries/attack_log.jsonl
    - metrics/metrics.json

    Outputs:
    - summaries/plots/poison_heatmap.png
    - summaries/plots/update_norm_distribution.png
    - summaries/plots/global_accuracy_with_attack_overlay.png
    - summaries/plots/attack_type_distribution.png
    - summaries/plots/defense_slipthrough_over_time.png
    - summaries/plots/defense_selection_breakdown.png
    - summaries/plots/defense_malicious_fraction_vs_accuracy.png
    - summaries/plots/per_client_eval_loss_distribution.png
    """

    summaries_dir = run_dir / "summaries"
    plots_dir = summaries_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    # Matplotlib is optional.
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.colors as mcolors
        import matplotlib.patheffects as pe
    except Exception:
        return

    # NumPy is strongly preferred for compact plotting; skip gracefully if missing.
    try:
        import numpy as np
    except Exception:
        return

    def _safe_float(v: Any, default: float = 0.0) -> float:
        try:
            x = float(v)
        except Exception:
            return default
        return x if math.isfinite(x) else default

    def _read_csv(path: Path) -> List[Dict[str, str]]:
        if not path.exists():
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            # Fall back to platform default decoding.
            try:
                text = path.read_text(errors="replace")
            except Exception:
                return []
        if "\x00" in text:
            # Some environments can accidentally write NULs; csv module rejects them.
            text = text.replace("\x00", "")
        try:
            return list(csv.DictReader(io.StringIO(text)))
        except Exception:
            return []

    def _parse_int(value: Any, default: int = 0) -> int:
        try:
            return int(float(value))
        except Exception:
            return default

    # Paper-friendly style (local, to avoid affecting earlier plots)
    plt.rcParams.update(
        {
            "figure.dpi": 140,
            "savefig.dpi": 220,
            "font.size": 11,
            "axes.titlesize": 12,
            "axes.labelsize": 11,
            "legend.fontsize": 10,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "axes.grid": True,
            "grid.alpha": 0.25,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "lines.linewidth": 2.2,
            "axes.edgecolor": "#111111",
            "axes.linewidth": 1.1,
        }
    )

    def _outline_line(line: Any, stroke: float = 3.6) -> None:
        """Add a black outline to a line for print-friendly readability."""
        try:
            lw = float(getattr(line, "get_linewidth", lambda: 2.0)())
            line.set_path_effects([pe.Stroke(linewidth=max(stroke, lw + 2.0), foreground="black"), pe.Normal()])
        except Exception:
            return

    # ----------------------------
    # Load artifacts once
    # ----------------------------
    mal_rounds_path = summaries_dir / "malicious_clients_by_round.csv"
    poison_by_cr_path = summaries_dir / "poisoning_by_client_round.csv"
    attack_log_path = summaries_dir / "attack_log.jsonl"
    defense_sel_path = summaries_dir / "defense_selection_by_round.csv"
    round_stats_path = summaries_dir / "round_attack_stats.csv"
    attack_summary_path = summaries_dir / "attack_summary.md"
    metrics_path = run_dir / "metrics" / "metrics.json"
    per_client_metrics_path = run_dir / "metrics" / "per_client_metrics.json"

    rounds: List[int] = []
    attack_name_by_round: Dict[int, str] = {}
    intensity_by_round: Dict[int, float] = {}
    malicious_client_numbers_by_round: Dict[int, set[int]] = {}

    assumption_label = ""
    configured_mf: Optional[float] = None
    if attack_summary_path.exists():
        try:
            text = attack_summary_path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"malicious_fraction\s*:\s*`?([0-9.]+)`?", text)
            if m:
                configured_mf = float(m.group(1))
        except Exception:
            configured_mf = None
    stats_rows = _read_csv(round_stats_path)
    if stats_rows:
        sel_vals: List[int] = []
        mal_vals: List[int] = []
        mf_vals: List[float] = []
        assumed_vals: List[int] = []
        for r in stats_rows:
            sel = _parse_int(r.get("num_selected_clients"), 0)
            mal = _parse_int(r.get("num_malicious"), 0)
            assumed = _parse_int(r.get("defense_assumed_num_malicious_nodes"), 0)
            mf = _safe_float(r.get("malicious_fraction_used"), default=float("nan"))
            if sel > 0:
                sel_vals.append(sel)
                mal_vals.append(mal)
                assumed_vals.append(assumed)
                if math.isfinite(mf):
                    mf_vals.append(float(mf))
                else:
                    mf_vals.append(float(mal) / float(sel))

        def _mode_int(values: List[int]) -> int:
            if not values:
                return 0
            return Counter(values).most_common(1)[0][0]

        def _mode_float(values: List[float]) -> float:
            if not values:
                return float("nan")
            rounded = [round(float(v), 4) for v in values if math.isfinite(float(v))]
            if not rounded:
                return float("nan")
            return Counter(rounded).most_common(1)[0][0]

        sel_mode = _mode_int(sel_vals)
        mal_mode = _mode_int(mal_vals)
        assumed_mode = _mode_int(assumed_vals)
        mf_mode = _mode_float(mf_vals)
        if sel_mode > 0 and math.isfinite(float(mf_mode)):
            assumed_frac = float(assumed_mode) / float(sel_mode) if sel_mode > 0 else 0.0
            label_parts: List[str] = []
            if configured_mf is not None and math.isfinite(float(configured_mf)):
                label_parts.append(f"malicious configured={configured_mf * 100:.1f}%")
            label_parts.append(f"malicious used={mf_mode * 100:.1f}% ({mal_mode}/{sel_mode})")
            label_parts.append(f"defense assumed={assumed_frac * 100:.1f}% ({assumed_mode}/{sel_mode})")
            assumption_label = " | ".join(label_parts)

    mal_rows = _read_csv(mal_rounds_path)
    for r in mal_rows:
        rnd = _parse_int(r.get("round"), 0)
        if rnd <= 0:
            continue
        rounds.append(rnd)
        attack_name_by_round[rnd] = str(r.get("attack_name") or "none")
        intensity_by_round[rnd] = _safe_float(r.get("intensity"), 0.0)
        nums_s = str(r.get("malicious_client_numbers") or "").strip()
        nums: set[int] = set()
        if nums_s:
            for part in nums_s.split(";"):
                part = part.strip()
                if not part:
                    continue
                try:
                    nums.add(int(part))
                except Exception:
                    continue
        malicious_client_numbers_by_round[rnd] = nums

    rounds = sorted(set(rounds))

    selected_clients_by_round: Dict[int, set[int]] = defaultdict(set)
    malicious_clients_by_round_from_poison: Dict[int, set[int]] = defaultdict(set)
    malicious_attack_counts_by_round: Dict[int, Counter] = defaultdict(Counter)

    poison_rows = _read_csv(poison_by_cr_path)
    for r in poison_rows:
        rnd = _parse_int(r.get("round"), 0)
        client_num = _parse_int(r.get("client_number"), 0)
        if rnd <= 0 or client_num <= 0:
            continue
        selected_clients_by_round[rnd].add(client_num)
        is_mal = str(r.get("is_malicious") or "0").strip() in {"1", "true", "True"}
        if is_mal:
            malicious_clients_by_round_from_poison[rnd].add(client_num)

            raw_name = str(r.get("attack_name") or "none")
            raw_name = raw_name.strip()

            # In multi-layer mode, attack_name may be a composite like "label_flip+backdoor".
            # Count each layer so per-round bars become multi-colored.
            parts = raw_name.replace(";", "+").split("+") if raw_name else ["none"]
            layers: List[str] = []
            for p in parts:
                key = str(p).strip().lower().replace("-", "_")
                if not key or key in {"none", "off", "disabled"}:
                    continue
                layers.append(key)
            if not layers and raw_name:
                key = raw_name.strip().lower().replace("-", "_")
                if key and key not in {"none", "off", "disabled"}:
                    layers = [key]

            if layers:
                # De-dup within a client/round while preserving order
                seen = set()
                for a in layers:
                    if a in seen:
                        continue
                    seen.add(a)
                    malicious_attack_counts_by_round[rnd][a] += 1
            else:
                malicious_attack_counts_by_round[rnd]["none"] += 1

    # Update norms per client per round
    norms_by_round: Dict[int, Dict[str, float]] = {}
    malicious_ids_by_round: Dict[int, set[str]] = {}
    if attack_log_path.exists():
        for line in attack_log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            rnd = _parse_int(rec.get("round"), 0)
            if rnd <= 0:
                continue

            per = rec.get("per_client_update_norm") or {}
            if isinstance(per, dict):
                d: Dict[str, float] = {}
                for k, v in per.items():
                    vv = _safe_float(v, default=float("nan"))
                    if math.isfinite(vv):
                        d[str(k)] = float(vv)
                if d:
                    norms_by_round[rnd] = d

            mids = rec.get("malicious_client_ids") or []
            if isinstance(mids, list):
                malicious_ids_by_round[rnd] = {str(x) for x in mids}

    # Accuracy series
    acc_series: List[Tuple[int, float]] = []
    server_acc_by_round: Dict[int, float] = {}
    if metrics_path.exists():
        try:
            data = json.loads(metrics_path.read_text(encoding="utf-8"))
            points = (((data or {}).get("evaluate_client") or {}).get("eval_acc"))
            if isinstance(points, list):
                for p in points:
                    if not isinstance(p, dict):
                        continue
                    rnd = _parse_int(p.get("round"), 0)
                    val = _safe_float(p.get("value"), default=float("nan"))
                    if rnd > 0 and math.isfinite(val):
                        acc_series.append((rnd, float(val)))

            server_pts = (((data or {}).get("evaluate_server") or {}).get("accuracy"))
            if isinstance(server_pts, list):
                for p in server_pts:
                    if not isinstance(p, dict):
                        continue
                    rnd = _parse_int(p.get("round"), 0)
                    val = _safe_float(p.get("value"), default=float("nan"))
                    if rnd > 0 and math.isfinite(val):
                        server_acc_by_round[int(rnd)] = float(val)
        except Exception:
            acc_series = []
    acc_series.sort(key=lambda x: x[0])

    # If rounds list is empty, infer rounds from any available artifact.
    if not rounds:
        rounds = sorted(
            set(selected_clients_by_round.keys())
            | set(norms_by_round.keys())
            | {r for r, _ in acc_series}
        )

    # Resolve malicious client numbers by round (prefer explicit list; fall back to poisoning rows).
    malicious_clients_by_round: Dict[int, set[int]] = {}
    for r in rounds:
        if r in malicious_client_numbers_by_round:
            malicious_clients_by_round[r] = set(malicious_client_numbers_by_round[r])
        else:
            malicious_clients_by_round[r] = set(malicious_clients_by_round_from_poison.get(r, set()))

    attacked_rounds = {r for r in rounds if len(malicious_clients_by_round.get(r, set())) > 0}

    # ----------------------------
    # A) Poison heatmap
    # ----------------------------
    try:
        # Determine client universe (only selected clients; if missing, use malicious).
        client_universe: set[int] = set()
        for s in selected_clients_by_round.values():
            client_universe |= set(s)
        if not client_universe:
            for s in malicious_clients_by_round.values():
                client_universe |= set(s)
        clients = sorted(client_universe)

        if rounds and clients:
            # Base selection mask (selected clients show as light gray).
            selected_mask = np.zeros((len(clients), len(rounds)), dtype=float)
            selected_mask[:] = np.nan

            # Malicious intensity overlay (NaN for non-malicious).
            mal_int = np.full((len(clients), len(rounds)), np.nan, dtype=float)
            client_to_i = {c: i for i, c in enumerate(clients)}

            for j, rnd in enumerate(rounds):
                sel = selected_clients_by_round.get(rnd, set())
                mal = malicious_clients_by_round.get(rnd, set())
                inten = float(intensity_by_round.get(rnd, 0.0) or 0.0)
                for c in sel:
                    i = client_to_i.get(c)
                    if i is not None:
                        selected_mask[i, j] = 1.0
                for c in mal:
                    i = client_to_i.get(c)
                    if i is not None:
                        mal_int[i, j] = max(0.0, inten)

            fig = plt.figure(figsize=(12.5, 0.20 * min(len(clients), 80) + 3.2))
            gs = fig.add_gridspec(nrows=2, ncols=1, height_ratios=[0.18, 1.0], hspace=0.05)
            ax_top = fig.add_subplot(gs[0, 0])
            ax = fig.add_subplot(gs[1, 0])

            # Clean attack-type timeline (single row)
            try:
                import matplotlib.patches as patches

                # Fixed, thesis-friendly palette.
                # Use only Red/Orange/Yellow/Blue/Green (with slight shade variants when needed).
                RED = (0.839, 0.153, 0.157, 1.0)      # ~#d62728
                ORANGE = (1.0, 0.498, 0.055, 1.0)     # ~#ff7f0e
                YELLOW = (1.0, 0.824, 0.2, 1.0)       # warm yellow (readable)
                BLUE = (0.122, 0.467, 0.706, 1.0)     # ~#1f77b4
                GREEN = (0.173, 0.627, 0.173, 1.0)    # ~#2ca02c

                def _normalize_attack_key(name: str) -> str:
                    return str(name).strip().lower().replace("-", "_").replace(" ", "_")

                def _pretty_attack_name(name: str) -> str:
                    key = _normalize_attack_key(name)
                    if key in {"", "none"}:
                        return "None"
                    if key == "alie":
                        return "ALIE"
                    words = key.split("_")
                    return " ".join([w.capitalize() for w in words if w])

                def _attack_color(name: str) -> Tuple[float, float, float, float]:
                    key = _normalize_attack_key(name)
                    # Update poisoning
                    if key == "mean_shift":
                        return RED
                    if key == "sign_flip":
                        return ORANGE
                    if key == "gaussian_noise":
                        return YELLOW
                    if key == "alie":
                        return BLUE
                    # Data poisoning (use green family)
                    if key == "backdoor":
                        return GREEN
                    if key == "label_flip":
                        # lighter green so it stays within the palette but remains distinguishable
                        return (0.42, 0.78, 0.42, 1.0)
                    # Fallback: neutral gray
                    return (0.65, 0.65, 0.65, 1.0)

                attack_names = [str(attack_name_by_round.get(r, "none") or "none") for r in rounds]
                uniq_attacks = [a for a in sorted(set(attack_names)) if _normalize_attack_key(a) not in {"", "none"}]
                color_by_attack: Dict[str, Tuple[float, float, float, float]] = {a: _attack_color(a) for a in uniq_attacks}
                none_color = (0.93, 0.93, 0.93, 1.0)

                # Compress consecutive rounds into segments
                segments: List[Tuple[int, int, str]] = []  # (start_idx, length, attack_name)
                if attack_names:
                    s = 0
                    cur = attack_names[0]
                    for i in range(1, len(attack_names)):
                        if attack_names[i] != cur:
                            segments.append((s, i - s, cur))
                            s = i
                            cur = attack_names[i]
                    segments.append((s, len(attack_names) - s, cur))

                ax_top.set_xlim(-0.5, len(rounds) - 0.5)
                ax_top.set_ylim(0.0, 1.0)
                ax_top.set_yticks([])
                ax_top.set_xticks([])
                for (start, length, name) in segments:
                    color = color_by_attack.get(name, none_color) if _normalize_attack_key(name) not in {"", "none"} else none_color
                    rect = patches.Rectangle(
                        (start - 0.5, 0.0),
                        float(length),
                        1.0,
                        facecolor=color,
                        edgecolor="#111111",
                        linewidth=0.35,
                    )
                    ax_top.add_patch(rect)

                    # Inline label only for longer segments
                    if _normalize_attack_key(name) not in {"", "none"} and length >= 2:
                        r, g, b, _a = color
                        lum = 0.2126 * r + 0.7152 * g + 0.0722 * b
                        text_color = "#111111" if lum > 0.62 else "#ffffff"
                        ax_top.text(
                            start - 0.5 + float(length) / 2.0,
                            0.5,
                            _pretty_attack_name(name),
                            ha="center",
                            va="center",
                            fontsize=8,
                            color=text_color,
                            alpha=0.92,
                        )

                # Subtle border to separate the band
                for spine in ax_top.spines.values():
                    spine.set_visible(True)
                    spine.set_linewidth(0.8)
                    spine.set_color("#111111")
            except Exception:
                ax_top.axis("off")

            # Background: selected vs not selected
            base_cmap = mcolors.ListedColormap(["#ffffff", "#e6e6e6"])
            ax.imshow(
                np.where(np.isfinite(selected_mask), 1.0, 0.0),
                aspect="auto",
                interpolation="nearest",
                cmap=base_cmap,
                vmin=0.0,
                vmax=1.0,
            )

            # Overlay: malicious intensity
            cmap = plt.cm.magma.copy()
            cmap.set_bad(alpha=0.0)
            vmax = float(np.nanmax(mal_int)) if np.any(np.isfinite(mal_int)) else 1.0
            im = ax.imshow(
                mal_int,
                aspect="auto",
                interpolation="nearest",
                cmap=cmap,
                vmin=0.0,
                vmax=max(1e-9, vmax),
            )

            ax.set_title("Client–Round Poisoning Heatmap (Attack Intensity)")
            ax.set_xlabel("Round")
            ax.set_ylabel("Client #")

            # Tick density control
            if len(rounds) <= 30:
                xticks = list(range(len(rounds)))
            else:
                step = max(1, len(rounds) // 15)
                xticks = list(range(0, len(rounds), step))
            ax.set_xticks(xticks)
            ax.set_xticklabels([str(rounds[i]) for i in xticks], rotation=0)

            if len(clients) <= 40:
                yticks = list(range(len(clients)))
            else:
                step = max(1, len(clients) // 20)
                yticks = list(range(0, len(clients), step))
            ax.set_yticks(yticks)
            ax.set_yticklabels([str(clients[i]) for i in yticks])

            cbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
            cbar.set_label("Attack Intensity")

            fig.tight_layout()
            fig.savefig(plots_dir / "poison_heatmap.png", bbox_inches="tight")
            plt.close(fig)
    except Exception:
        pass

    # ----------------------------
    # B) Update norm distribution
    # ----------------------------
    try:
        data_by_round: List[Any] = []
        all_points: List[Tuple[float, float]] = []
        mal_points: List[Tuple[float, float]] = []

        for idx, rnd in enumerate(rounds, start=1):
            norms = norms_by_round.get(rnd, {})
            vals = np.array(list(norms.values()), dtype=float)
            vals = vals[np.isfinite(vals)]
            data_by_round.append(vals)

            if vals.size:
                xs = idx + np.random.uniform(-0.12, 0.12, size=vals.size)
                for x, y in zip(xs, vals):
                    all_points.append((float(x), float(y)))

            mids = malicious_ids_by_round.get(rnd, set())
            for cid, v in norms.items():
                if cid in mids and math.isfinite(float(v)):
                    x = idx + float(np.random.uniform(-0.10, 0.10))
                    mal_points.append((x, float(v)))

        if any(getattr(a, "size", 0) for a in data_by_round):
            fig = plt.figure(figsize=(13.0, 4.8))
            ax = fig.add_subplot(1, 1, 1)

            # Shade attacked rounds for context.
            for idx, rnd in enumerate(rounds, start=1):
                if rnd in attacked_rounds:
                    inten = float(intensity_by_round.get(rnd, 0.0) or 0.0)
                    ax.axvspan(idx - 0.5, idx + 0.5, color="#ff7f0e", alpha=min(0.22, 0.06 + 0.08 * inten), linewidth=0)

            parts = ax.violinplot(
                data_by_round,
                positions=np.arange(1, len(rounds) + 1),
                widths=0.85,
                showmeans=False,
                showextrema=False,
                showmedians=False,
            )
            for pc in parts.get("bodies", []):
                pc.set_facecolor("#bdbdbd")
                pc.set_edgecolor("#666666")
                pc.set_alpha(0.25)

            if all_points:
                xs, ys = zip(*all_points)
                ax.scatter(xs, ys, s=10, color="#555555", alpha=0.18, linewidths=0)
            if mal_points:
                xs, ys = zip(*mal_points)
                ax.scatter(
                    xs,
                    ys,
                    s=16,
                    color="#d62728",
                    alpha=0.85,
                    linewidths=0,
                    label="Poisoned Clients",
                )

            # Add per-round median markers
            med_x = []
            med_y = []
            for idx, vals in enumerate(data_by_round, start=1):
                if getattr(vals, "size", 0):
                    med_x.append(idx)
                    med_y.append(float(np.median(vals)))
            if med_x:
                med_line = ax.plot(med_x, med_y, color="#1f77b4", marker="o", markersize=3.5, linewidth=2.0, alpha=0.9, label="Median")
                _outline_line(med_line[0], stroke=3.2)

            ax.set_title("Per-Round Update-Norm Distribution")
            ax.set_xlabel("Round")
            ax.set_ylabel("Client update L2 norm")

            if len(rounds) <= 30:
                xt = np.arange(1, len(rounds) + 1)
            else:
                step = max(1, len(rounds) // 15)
                xt = np.arange(1, len(rounds) + 1, step)
            ax.set_xticks(xt)
            ax.set_xticklabels([str(rounds[i - 1]) for i in xt])

            # Use log scale when norms explode.
            all_vals = np.concatenate([a for a in data_by_round if getattr(a, "size", 0)])
            if all_vals.size:
                p95 = float(np.percentile(all_vals, 95))
                mx = float(np.max(all_vals))
                if mx > 0 and p95 > 0 and (mx / max(p95, 1e-9)) > 30:
                    ax.set_yscale("log")
                    ax.set_ylabel("Client update L2 norm (log scale)")
                else:
                    p999 = float(np.percentile(all_vals, 99.9))
                    ax.set_ylim(bottom=0.0, top=max(1e-9, p999 * 1.15))

            if mal_points:
                ax.legend(loc="upper right", frameon=False)

            fig.tight_layout()
            fig.savefig(plots_dir / "update_norm_distribution.png", bbox_inches="tight")
            plt.close(fig)
    except Exception:
        pass

    # ----------------------------
    # C) Accuracy with attack overlay
    # ----------------------------
    try:
        if acc_series:
            fig = plt.figure(figsize=(12.5, 4.5))
            ax = fig.add_subplot(1, 1, 1)
            xs = [r for r, _ in acc_series]
            ys = [v for _, v in acc_series]

            intens = [float(intensity_by_round.get(r, 0.0) or 0.0) for r in rounds]
            max_int = max(intens) if intens else 0.0
            for r in rounds:
                if r not in attacked_rounds:
                    continue
                inten = float(intensity_by_round.get(r, 0.0) or 0.0)
                alpha = 0.06 + (0.28 * min(1.0, max(0.0, inten / max_int))) if max_int > 0 else 0.12
                ax.axvspan(r - 0.5, r + 0.5, color="#ff7f0e", alpha=alpha, linewidth=0)

            (acc_line,) = ax.plot(
                xs,
                ys,
                color="#1f77b4",
                linewidth=2.4,
                marker="o",
                markersize=3.5,
                label="Global accuracy",
            )
            _outline_line(acc_line, stroke=3.8)

            ax.set_title("Global Accuracy (Attacks Overlaid)")
            if assumption_label:
                ax.text(
                    0.01,
                    0.98,
                    assumption_label,
                    transform=ax.transAxes,
                    ha="left",
                    va="top",
                    fontsize=9,
                    color="#111111",
                    alpha=0.85,
                )
            ax.set_xlabel("Round")
            ax.set_ylabel("Accuracy")
            ax.set_ylim(0.0, 1.0)

            ax2 = ax.twinx()
            if rounds:
                r_sorted = list(sorted(set(rounds)))
                step_x = r_sorted + [r_sorted[-1] + 1]
                step_y = [float(intensity_by_round.get(r, 0.0) or 0.0) for r in r_sorted] + [
                    float(intensity_by_round.get(r_sorted[-1], 0.0) or 0.0)
                ]
                ax2.step(
                    step_x,
                    step_y,
                    where="post",
                    color="#ff7f0e",
                    linewidth=2.0,
                    alpha=0.75,
                    label="Attack intensity",
                )
                ax2.set_ylabel("Attack intensity")
                ax2.grid(False)

            h1, l1 = ax.get_legend_handles_labels()
            h2, l2 = ax2.get_legend_handles_labels()
            ax.legend(h1 + h2, l1 + l2, loc="lower right", frameon=False)

            fig.tight_layout()
            fig.savefig(plots_dir / "global_accuracy_with_attack_overlay.png", bbox_inches="tight")
            plt.close(fig)
    except Exception:
        pass

    # ----------------------------
    # D) Attack type distribution (composition)
    # ----------------------------
    try:
        if rounds and selected_clients_by_round:
            # Fallback helpers (in case earlier plot blocks failed before defining them).
            if "_attack_color" not in globals() or "_pretty_attack_name" not in globals():
                def _normalize_attack_key(name: str) -> str:
                    return str(name).strip().lower().replace("-", "_").replace(" ", "_")

                def _pretty_attack_name(name: str) -> str:
                    key = _normalize_attack_key(name)
                    if key in {"", "none"}:
                        return "None"
                    if key == "alie":
                        return "ALIE"
                    words = key.split("_")
                    return " ".join([w.capitalize() for w in words if w])

                def _attack_color(name: str) -> Tuple[float, float, float, float]:
                    # Palette matches the one used elsewhere in this script.
                    key = _normalize_attack_key(name)
                    RED = (0.839, 0.153, 0.157, 1.0)
                    ORANGE = (1.0, 0.498, 0.055, 1.0)
                    YELLOW = (1.0, 0.824, 0.2, 1.0)
                    BLUE = (0.122, 0.467, 0.706, 1.0)
                    GREEN = (0.173, 0.627, 0.173, 1.0)
                    if key == "mean_shift":
                        return RED
                    if key == "sign_flip":
                        return ORANGE
                    if key == "gaussian_noise":
                        return YELLOW
                    if key == "alie":
                        return BLUE
                    if key == "backdoor":
                        return GREEN
                    if key == "label_flip":
                        return (0.42, 0.78, 0.42, 1.0)
                    return (0.65, 0.65, 0.65, 1.0)

            # Plot ONLY poisoned clients (no "clean" bar), normalized to fraction of selected.
            all_attacks: set[str] = set()
            totals_by_attack: Counter = Counter()
            for c in malicious_attack_counts_by_round.values():
                for k, v in c.items():
                    if k and k != "none":
                        totals_by_attack[k] += int(v)
                        all_attacks.add(k)
            attack_names = [a for a, _ in totals_by_attack.most_common()]

            if attack_names:
                stacks_frac: Dict[str, List[float]] = {a: [] for a in attack_names}
                for r in rounds:
                    total_selected = max(1, len(selected_clients_by_round.get(r, set())))
                    mal_counter = malicious_attack_counts_by_round.get(r, Counter())
                    for a in attack_names:
                        stacks_frac[a].append(float(mal_counter.get(a, 0)) / float(total_selected))

                if any(sum(vs) for vs in stacks_frac.values()):
                    fig = plt.figure(figsize=(13.0, 4.8))
                    ax = fig.add_subplot(1, 1, 1)

                    x = np.arange(len(rounds))
                    bottom = np.zeros(len(rounds), dtype=float)
                    colors = plt.cm.tab20(np.linspace(0, 1, max(1, len(attack_names))))
                    for i, a in enumerate(attack_names):
                        vals = np.array(stacks_frac[a], dtype=float)
                        if float(np.sum(vals)) <= 0:
                            continue
                        color = _attack_color(a)
                        ax.bar(
                            x,
                            vals,
                            bottom=bottom,
                            width=0.92,
                            color=color,
                            edgecolor="#111111",
                            linewidth=0.4,
                            label=_pretty_attack_name(a),
                        )
                        bottom += vals

                    ax.set_title("Attack-Type Composition per Round (Fraction of Selected)")
                    if assumption_label:
                        ax.text(
                            0.01,
                            0.98,
                            assumption_label,
                            transform=ax.transAxes,
                            ha="left",
                            va="top",
                            fontsize=9,
                            color="#111111",
                            alpha=0.85,
                        )
                    ax.set_xlabel("Round")
                    ax.set_ylabel("Fraction of Selected Clients (per layer)")
                    # With stacked layers, totals can exceed 1.0.
                    max_sum = 0.0
                    for i in range(len(rounds)):
                        s = 0.0
                        for a in attack_names:
                            s += float(stacks_frac.get(a, [0.0] * len(rounds))[i])
                        if s > max_sum:
                            max_sum = float(s)
                    ax.set_ylim(0.0, max(1.0, max_sum * 1.15))

                    if len(rounds) <= 30:
                        xt = x
                    else:
                        step = max(1, len(rounds) // 15)
                        xt = x[::step]
                    ax.set_xticks(xt)
                    ax.set_xticklabels([str(rounds[i]) for i in xt], rotation=0)

                    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False)
                    fig.tight_layout()
                    fig.savefig(plots_dir / "attack_type_distribution.png", bbox_inches="tight")
                    plt.close(fig)
    except Exception:
        pass

    # ----------------------------
    # E) Defense slip-through over time
    # ----------------------------
    try:
        # Per-round: defense-selected malicious fraction vs sampled malicious fraction.
        if stats_rows:
            sampled_frac_by_round: Dict[int, float] = {}
            for r in stats_rows:
                rnd = _parse_int(r.get("round"), 0)
                if rnd <= 0:
                    continue
                sel = _parse_int(r.get("num_selected_clients"), 0)
                mal = _parse_int(r.get("num_malicious"), 0)
                frac = _safe_float(r.get("malicious_fraction_used"), default=float("nan"))
                if not math.isfinite(frac):
                    frac = float(mal) / float(max(1, sel))
                sampled_frac_by_round[rnd] = float(max(0.0, min(1.0, frac)))

            defense_rows = _read_csv(defense_sel_path)
            if sampled_frac_by_round and defense_rows:
                xs: List[int] = []
                ys_sampled: List[float] = []
                ys_defense: List[float] = []
                for r in defense_rows:
                    rnd = _parse_int(r.get("round"), 0)
                    if rnd <= 0 or rnd not in sampled_frac_by_round:
                        continue
                    frac = _safe_float(r.get("malicious_selected_fraction"), default=float("nan"))
                    if not math.isfinite(frac):
                        n_sel = _parse_int(r.get("num_selected_by_defense"), 0)
                        n_mal = _parse_int(r.get("num_malicious_selected_by_defense"), 0)
                        frac = float(n_mal) / float(max(1, n_sel))
                    xs.append(rnd)
                    ys_sampled.append(float(sampled_frac_by_round[rnd]))
                    ys_defense.append(float(max(0.0, min(1.0, frac))))

                if xs:
                    order = np.argsort(np.array(xs, dtype=int))
                    xs = [xs[i] for i in order]
                    ys_sampled = [ys_sampled[i] for i in order]
                    ys_defense = [ys_defense[i] for i in order]

                    fig = plt.figure(figsize=(12.5, 4.2))
                    ax = fig.add_subplot(1, 1, 1)

                    (line1,) = ax.plot(
                        xs,
                        ys_sampled,
                        color="#1f77b4",
                        linewidth=2.4,
                        marker="o",
                        markersize=3.0,
                        label="Sampled malicious fraction",
                    )
                    (line2,) = ax.plot(
                        xs,
                        ys_defense,
                        color="#d62728",
                        linewidth=2.4,
                        marker="o",
                        markersize=3.0,
                        label="Defense-selected malicious fraction",
                    )
                    _outline_line(line1, stroke=3.6)
                    _outline_line(line2, stroke=3.6)

                    ax.set_title("Malicious Fraction: Sampled vs Defense-Selected")
                    if assumption_label:
                        ax.text(
                            0.01,
                            0.98,
                            assumption_label,
                            transform=ax.transAxes,
                            ha="left",
                            va="top",
                            fontsize=9,
                            color="#111111",
                            alpha=0.85,
                        )
                    ax.set_xlabel("Round")
                    ax.set_ylabel("Fraction")
                    ax.set_ylim(0.0, 1.0)
                    ax.legend(loc="upper right", frameon=False)
                    fig.tight_layout()
                    fig.savefig(
                        summaries_dir / "defense_malicious_selected_vs_sampled.png",
                        bbox_inches="tight",
                    )
                    plt.close(fig)

        rows = _read_csv(defense_sel_path)
        if rows:
            xs: List[int] = []
            ys_frac: List[float] = []
            ys_num_mal: List[int] = []
            ys_num_sel: List[int] = []
            sel_client_numbers_by_round: Dict[int, List[int]] = {}
            defense_name: str = ""
            for r in rows:
                rnd = _parse_int(r.get("round"), 0)
                if rnd <= 0:
                    continue
                frac = _safe_float(r.get("malicious_selected_fraction"), default=float("nan"))
                if not math.isfinite(frac):
                    # Backwards/partial rows: recompute from counts.
                    n_sel = _parse_int(r.get("num_selected_by_defense"), 0)
                    n_mal = _parse_int(r.get("num_malicious_selected_by_defense"), 0)
                    frac = float(n_mal) / float(max(1, n_sel))
                n_sel = _parse_int(r.get("num_selected_by_defense"), 0)
                n_mal = _parse_int(r.get("num_malicious_selected_by_defense"), 0)

                nums_raw = str(r.get("selected_client_numbers") or "").strip()
                nums: List[int] = []
                if nums_raw:
                    for part in nums_raw.split(";"):
                        part = part.strip()
                        if not part:
                            continue
                        try:
                            nums.append(int(part))
                        except Exception:
                            continue
                if nums:
                    sel_client_numbers_by_round[rnd] = nums

                xs.append(rnd)
                ys_frac.append(float(max(0.0, min(1.0, frac))))
                ys_num_mal.append(int(max(0, n_mal)))
                ys_num_sel.append(int(max(0, n_sel)))
                if not defense_name:
                    defense_name = str(r.get("defense_strategy") or "")

            if xs:
                # Sort by round
                order = np.argsort(np.array(xs, dtype=int))
                xs = [xs[i] for i in order]
                ys_frac = [ys_frac[i] for i in order]
                ys_num_mal = [ys_num_mal[i] for i in order]
                ys_num_sel = [ys_num_sel[i] for i in order]

                fig = plt.figure(figsize=(12.5, 4.5))
                ax = fig.add_subplot(1, 1, 1)

                # Small markers; heavy, outlined line for print.
                label = "Malicious selected fraction"
                if defense_name:
                    label = f"Malicious selected fraction ({defense_name})"
                (line,) = ax.plot(
                    xs,
                    ys_frac,
                    color="#2ca02c",
                    linewidth=2.4,
                    marker="o",
                    markersize=3.2,
                    label=label,
                )
                _outline_line(line, stroke=3.8)

                ax.set_title("Defense Slip-Through Over Time")
                if assumption_label:
                    ax.text(
                        0.01,
                        0.98,
                        assumption_label,
                        transform=ax.transAxes,
                        ha="left",
                        va="top",
                        fontsize=9,
                        color="#111111",
                        alpha=0.85,
                    )
                ax.set_xlabel("Round")
                ax.set_ylabel("Fraction of selected updates that are malicious")
                ax.set_ylim(0.0, 1.0)

                # Optional context: show counts in a compact legend entry.
                any_counts = any(n > 0 for n in ys_num_sel)
                if any_counts:
                    total_sel = int(sum(ys_num_sel))
                    total_mal = int(sum(ys_num_mal))
                    ax.text(
                        0.01,
                        0.02,
                        f"Total selected: {total_sel} | Total malicious selected: {total_mal}",
                        transform=ax.transAxes,
                        fontsize=9,
                        color="#111111",
                        alpha=0.85,
                    )

                ax.legend(loc="upper right", frameon=False)
                fig.tight_layout()
                fig.savefig(plots_dir / "defense_slipthrough_over_time.png", bbox_inches="tight")
                plt.close(fig)

                # ----------------------------------
                # E) Malicious fraction vs accuracy (scatter)
                # ----------------------------------
                if server_acc_by_round:
                    xs_scatter: List[float] = []
                    ys_scatter: List[float] = []
                    colors: List[int] = []
                    for r_idx, rnd in enumerate(xs):
                        acc = server_acc_by_round.get(int(rnd))
                        if acc is None:
                            continue
                        xs_scatter.append(float(ys_frac[r_idx]))
                        ys_scatter.append(float(acc))
                        colors.append(int(rnd))

                    if xs_scatter and ys_scatter:
                        fig = plt.figure(figsize=(6.2, 5.0))
                        ax = fig.add_subplot(1, 1, 1)
                        sc = ax.scatter(
                            xs_scatter,
                            ys_scatter,
                            c=colors,
                            cmap="viridis",
                            s=46,
                            edgecolor="black",
                            linewidth=0.5,
                            alpha=0.85,
                        )
                        ax.set_title("Defense slip-through vs server accuracy")
                        ax.set_xlabel("Malicious selected fraction")
                        ax.set_ylabel("Server accuracy")
                        ax.set_xlim(0.0, 1.0)
                        ax.set_ylim(0.0, 1.0)
                        cbar = fig.colorbar(sc, ax=ax, fraction=0.046, pad=0.04)
                        cbar.set_label("Round")
                        fig.tight_layout()
                        fig.savefig(
                            plots_dir / "defense_malicious_fraction_vs_accuracy.png",
                            bbox_inches="tight",
                        )
                        plt.close(fig)

                # ----------------------------------
                # F) Defense selection breakdown
                # ----------------------------------
                # Per-round stacked bars: benign vs malicious selected.
                # (No heatmap, no fraction line.)
                fig = plt.figure(figsize=(13.0, 4.8))
                ax_counts = fig.add_subplot(1, 1, 1)

                x = np.arange(len(xs), dtype=int)
                n_sel_arr = np.array(ys_num_sel, dtype=float)
                n_mal_arr = np.array(ys_num_mal, dtype=float)
                n_ben_arr = np.maximum(0.0, n_sel_arr - n_mal_arr)

                # Stacked bars: benign vs malicious selected.
                benign_color = "#4c78a8"  # muted blue
                malicious_color = "#e45756"  # muted red
                ax_counts.bar(
                    x,
                    n_ben_arr,
                    width=0.88,
                    color=benign_color,
                    edgecolor="black",
                    linewidth=0.55,
                    label="Benign selected",
                )
                ax_counts.bar(
                    x,
                    n_mal_arr,
                    bottom=n_ben_arr,
                    width=0.88,
                    color=malicious_color,
                    edgecolor="black",
                    linewidth=0.55,
                    label="Malicious selected",
                )

                title = "Defense selection breakdown"
                if defense_name:
                    title = f"Defense selection breakdown ({defense_name})"
                ax_counts.set_title(title)
                if assumption_label:
                    ax_counts.text(
                        0.01,
                        0.98,
                        assumption_label,
                        transform=ax_counts.transAxes,
                        ha="left",
                        va="top",
                        fontsize=9,
                        color="#111111",
                        alpha=0.85,
                    )
                ax_counts.set_ylabel("# clients selected")
                y_top = float(np.nanmax(n_sel_arr)) if n_sel_arr.size else 1.0
                ax_counts.set_ylim(0.0, max(1.0, y_top) * 1.12)

                # Reference line for the typical/maximum selection count (often 30).
                ref_total = int(round(float(np.nanmax(n_sel_arr)))) if n_sel_arr.size else 0
                if ref_total > 0:
                    ax_counts.axhline(
                        ref_total,
                        color="#111111",
                        linestyle=(0, (4, 3)),
                        linewidth=1.1,
                        alpha=0.55,
                        zorder=0,
                    )
                    ax_counts.text(
                        0.01,
                        min(0.98, (ref_total / max(1.0, y_top * 1.12)) + 0.01),
                        f"reference={ref_total}",
                        transform=ax_counts.transAxes,
                        fontsize=9,
                        color="#111111",
                        alpha=0.70,
                        va="bottom",
                    )

                # Nice x ticks: label by round number.
                if len(xs) <= 30:
                    xt = x
                else:
                    step = max(1, len(xs) // 15)
                    xt = x[::step]
                ax_counts.set_xticks(xt)
                ax_counts.set_xticklabels([str(xs[i]) for i in xt], rotation=0)
                ax_counts.set_xlabel("Round")

                ax_counts.legend(loc="upper right", frameon=False)

                fig.tight_layout()
                fig.savefig(plots_dir / "defense_selection_breakdown.png", bbox_inches="tight")
                plt.close(fig)
    except Exception:
        pass

    # ----------------------------------
    # G) Per-client eval loss distribution by round
    # ----------------------------------
    try:
        if per_client_metrics_path.exists():
            data = json.loads(per_client_metrics_path.read_text(encoding="utf-8"))
            eval_client = (data or {}).get("evaluate_client") or {}
            per_round_losses: Dict[int, List[float]] = defaultdict(list)
            if isinstance(eval_client, dict):
                for _cid, metrics in eval_client.items():
                    if not isinstance(metrics, dict):
                        continue
                    points = metrics.get("eval_loss") or []
                    if not isinstance(points, list):
                        continue
                    for item in points:
                        if not isinstance(item, (list, tuple)) or len(item) < 2:
                            continue
                        rnd = _parse_int(item[0], 0)
                        val = _safe_float(item[1], default=float("nan"))
                        if rnd > 0 and math.isfinite(val):
                            per_round_losses[int(rnd)].append(float(val))

            if per_round_losses:
                rounds_sorted = sorted(per_round_losses.keys())
                data_series = [per_round_losses[r] for r in rounds_sorted]

                fig = plt.figure(figsize=(12.8, 4.8))
                ax = fig.add_subplot(1, 1, 1)
                bp = ax.boxplot(
                    data_series,
                    positions=list(range(len(rounds_sorted))),
                    widths=0.65,
                    showfliers=False,
                    patch_artist=True,
                )
                for box in bp.get("boxes", []):
                    box.set(facecolor="#4c78a8", alpha=0.55, edgecolor="black", linewidth=0.6)
                for med in bp.get("medians", []):
                    med.set(color="#111111", linewidth=1.6)

                ax.set_title("Per-client eval loss distribution by round")
                ax.set_xlabel("Round")
                ax.set_ylabel("Eval loss")

                if len(rounds_sorted) <= 30:
                    xt = list(range(len(rounds_sorted)))
                else:
                    step = max(1, len(rounds_sorted) // 15)
                    xt = list(range(0, len(rounds_sorted), step))
                ax.set_xticks(xt)
                ax.set_xticklabels([str(rounds_sorted[i]) for i in xt], rotation=0)

                fig.tight_layout()
                fig.savefig(
                    plots_dir / "per_client_eval_loss_distribution.png",
                    bbox_inches="tight",
                )
                plt.close(fig)
    except Exception:
        pass

    # ----------------------------------
    # H) Trust strategy diagnostics
    # ----------------------------------
    try:
        trust_rows = _read_csv(summaries_dir / "trust_strategy_by_round.csv")
        if trust_rows:
            trust_by_round: Dict[int, List[float]] = defaultdict(list)
            selected_by_round: Dict[int, int] = defaultdict(int)
            total_by_round: Dict[int, int] = defaultdict(int)
            trust_by_client_round: Dict[int, Dict[int, float]] = defaultdict(dict)
            strategy_name = ""
            for row in trust_rows:
                rnd = _parse_int(row.get("round"), 0)
                cid = _parse_int(row.get("client_id"), -1)
                if rnd <= 0 or cid < 0:
                    continue
                score = _safe_float(row.get("trust_score"), default=float("nan"))
                if not math.isfinite(score):
                    continue
                selected = str(row.get("selected_for_aggregation") or "0").strip() in {"1", "true", "True"}
                trust_by_round[rnd].append(float(score))
                trust_by_client_round[rnd][cid] = float(score)
                total_by_round[rnd] += 1
                if selected:
                    selected_by_round[rnd] += 1
                if not strategy_name:
                    strategy_name = str(row.get("strategy") or "trust")

            rounds_trust = sorted(trust_by_round.keys())
            if rounds_trust:
                xs = rounds_trust
                avg_trust = [float(np.mean(trust_by_round[r])) for r in xs]
                min_trust = [float(np.min(trust_by_round[r])) for r in xs]
                max_trust = [float(np.max(trust_by_round[r])) for r in xs]

                fig = plt.figure(figsize=(12.5, 4.6))
                ax = fig.add_subplot(1, 1, 1)
                ax.fill_between(xs, min_trust, max_trust, color="#9ecae1", alpha=0.35, label="min-max trust")
                (line,) = ax.plot(xs, avg_trust, color="#08519c", marker="o", markersize=3.2, label="average trust")
                _outline_line(line, stroke=3.4)
                ax.set_title(f"Trust scores over time ({strategy_name})")
                ax.set_xlabel("Round")
                ax.set_ylabel("Trust score")
                ax.set_ylim(0.0, 1.02)
                ax.legend(loc="best", frameon=False)
                fig.tight_layout()
                fig.savefig(plots_dir / "trust_scores_over_time.png", bbox_inches="tight")
                plt.close(fig)

                fig = plt.figure(figsize=(12.5, 4.4))
                ax = fig.add_subplot(1, 1, 1)
                selected_vals = [int(selected_by_round.get(r, 0)) for r in xs]
                total_vals = [int(total_by_round.get(r, 0)) for r in xs]
                ax.bar(xs, total_vals, color="#c7c7c7", edgecolor="black", linewidth=0.4, label="scored clients")
                ax.bar(xs, selected_vals, color="#31a354", edgecolor="black", linewidth=0.4, label="trusted/used clients")
                ax.set_title(f"Trust strategy aggregation coverage ({strategy_name})")
                ax.set_xlabel("Round")
                ax.set_ylabel("# clients")
                ax.legend(loc="best", frameon=False)
                fig.tight_layout()
                fig.savefig(plots_dir / "trust_selected_count_over_time.png", bbox_inches="tight")
                plt.close(fig)

                client_ids = sorted({cid for per in trust_by_client_round.values() for cid in per.keys()})
                if client_ids and len(client_ids) <= 200:
                    matrix = np.full((len(client_ids), len(xs)), np.nan, dtype=float)
                    cid_to_i = {cid: i for i, cid in enumerate(client_ids)}
                    for j, rnd in enumerate(xs):
                        for cid, score in trust_by_client_round.get(rnd, {}).items():
                            i = cid_to_i.get(cid)
                            if i is not None:
                                matrix[i, j] = float(score)

                    fig = plt.figure(figsize=(max(9.5, 0.38 * len(xs) + 4), max(5.0, 0.18 * len(client_ids) + 3)))
                    ax = fig.add_subplot(1, 1, 1)
                    im = ax.imshow(matrix, aspect="auto", vmin=0.0, vmax=1.0, cmap="viridis")
                    ax.set_title(f"Per-client trust heatmap ({strategy_name})")
                    ax.set_xlabel("Round")
                    ax.set_ylabel("Client ID")
                    if len(xs) <= 30:
                        xt = list(range(len(xs)))
                    else:
                        step = max(1, len(xs) // 15)
                        xt = list(range(0, len(xs), step))
                    ax.set_xticks(xt)
                    ax.set_xticklabels([str(xs[i]) for i in xt])
                    if len(client_ids) <= 50:
                        yt = list(range(len(client_ids)))
                    else:
                        step = max(1, len(client_ids) // 25)
                        yt = list(range(0, len(client_ids), step))
                    ax.set_yticks(yt)
                    ax.set_yticklabels([str(client_ids[i]) for i in yt])
                    cbar = fig.colorbar(im, ax=ax)
                    cbar.set_label("Trust score")
                    fig.tight_layout()
                    fig.savefig(plots_dir / "trust_per_client_heatmap.png", bbox_inches="tight")
                    plt.close(fig)
    except Exception:
        pass

    # Copy plots into graphs/summaries for convenience.
    try:
        graphs_summaries_dir = run_dir / "graphs" / "summaries"
        graphs_summaries_dir.mkdir(parents=True, exist_ok=True)
        for name in (
            "poison_heatmap.png",
            "update_norm_distribution.png",
            "global_accuracy_with_attack_overlay.png",
            "attack_type_distribution.png",
            "defense_slipthrough_over_time.png",
            "defense_selection_breakdown.png",
            "defense_malicious_fraction_vs_accuracy.png",
            "per_client_eval_loss_distribution.png",
            "trust_scores_over_time.png",
            "trust_selected_count_over_time.png",
            "trust_per_client_heatmap.png",
        ):
            src = plots_dir / name
            if src.exists():
                shutil.copy2(src, graphs_summaries_dir / name)
    except Exception:
        pass

    # ----------------------------
    # Console summary
    # ----------------------------
    try:
        if mal_rows:
            unique_mal: set[int] = set()
            for r in rounds:
                unique_mal |= set(malicious_clients_by_round.get(r, set()))
            attacked = sorted(attacked_rounds)
            used_attacks = sorted({attack_name_by_round.get(r, "none") for r in attacked} - {"none", ""})
            intens = [float(intensity_by_round.get(r, 0.0) or 0.0) for r in attacked]
            avg_int = float(np.mean(intens)) if intens else 0.0
            max_int = float(np.max(intens)) if intens else 0.0
            print(f"Attack summary: attacked_rounds={len(attacked)} unique_malicious_clients={len(unique_mal)}")
            if used_attacks:
                print(f"Attack types used: {', '.join(used_attacks)}")
            if attacked:
                print(f"Intensity (attacked rounds): avg={avg_int:.3g} max={max_int:.3g}")
            print(f"Research plots: {plots_dir}")
    except Exception:
        pass


def _maybe_write_attack_summary_md(run_dir: Path) -> None:
    """Create a readable markdown summary from `attack_log.jsonl` if missing."""

    summaries = run_dir / "summaries"
    jsonl = summaries / "attack_log.jsonl"
    md = summaries / "attack_summary.md"
    if not jsonl.exists() or md.exists():
        return

    records: List[Dict[str, Any]] = []
    try:
        for line in jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    except Exception:
        return
    if not records:
        return

    # Best-effort: write a concise per-round table.
    lines: List[str] = []
    lines.append("# Attack Summary\n\n")
    lines.append(
        "| round | attack | intensity | #selected | #malicious | malicious_ids | median_norm | max_norm | max_mal_norm |\n"
    )
    lines.append("|---:|---|---:|---:|---:|---|---:|---:|---:|\n")
    for r in records:
        rnd = int(r.get("round", 0))
        name = str(r.get("attack_name", "none"))
        intensity = float(r.get("intensity", 0.0))
        nsel = int(r.get("num_selected_clients", 0))
        nmal = int(r.get("num_malicious", 0))
        mids = r.get("malicious_client_ids") or []
        mids_s = ";".join(str(x) for x in mids) if mids else "-"
        med = float(r.get("update_norm_median", 0.0))
        mx = float(r.get("update_norm_max", 0.0))
        mxm = float(r.get("update_norm_max_malicious", 0.0))
        lines.append(
            f"| {rnd} | `{name}` | {intensity:.6g} | {nsel} | {nmal} | {mids_s} | {med:.3g} | {mx:.3g} | {mxm:.3g} |\n"
        )
    md.write_text("".join(lines), encoding="utf-8")


def _infer_strategy_name(project_root: Path) -> str:
    """Best-effort inference based on pytorchexample/server_app.py."""
    server_app = project_root / "pytorchexample" / "server_app.py"
    if not server_app.exists():
        return "unknown-strategy"

    text = server_app.read_text(encoding="utf-8", errors="replace")

    # Try to find `strategy = Something(`
    m = re.search(r"^\s*strategy\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", text, re.M)
    if m:
        return m.group(1)

    # Fallback: import line
    m = re.search(
        r"^\s*from\s+flwr\.serverapp\.strategy\s+import\s+([A-Za-z_][A-Za-z0-9_]*)\s*$",
        text,
        re.M,
    )
    if m:
        return m.group(1)

    return "unknown-strategy"


def _slugify(value: Optional[str]) -> str:
    if value is None:
        return "unknown"
    s = str(value).strip().lower()
    s = s.replace("/", "_")
    s = re.sub(r"[^a-z0-9._-]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "unknown"


def _iid_flag_from_partitioner_name(partitioner_name: Optional[str]) -> str:
    """Return 'iid' or 'noniid' based on the configured partitioner name.

    The goal is a stable, human-readable folder name. Full details (e.g.
    Dirichlet alpha) stay in meta.json and run_config.
    """

    name = (partitioner_name or "").strip().lower()
    if not name:
        return "iid"
    if "iid" in name:
        return "iid"
    return "noniid"


def _read_flwr_app_config(project_root: Path) -> Dict[str, Any]:
    """Read [tool.flwr.app.config] from pyproject.toml (best-effort).

    We intentionally avoid adding TOML dependencies here; this parser extracts
    simple `key = value` pairs from that one section.
    """
    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists():
        return {}

    out: Dict[str, Any] = {}
    in_section = False
    try:
        for raw_line in pyproject.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if re.match(r"^\[\s*tool\.flwr\.app\.config\s*\]$", line):
                in_section = True
                continue
            if in_section and line.startswith("["):
                break
            if not in_section:
                continue

            # Remove inline comments (best-effort)
            if "#" in line:
                line = line.split("#", 1)[0].rstrip()
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            key = k.strip()
            value = v.strip()
            if not key:
                continue
            try:
                out[key] = ast.literal_eval(value)
            except Exception:
                # TOML booleans are lowercase true/false (Python wants True/False)
                lower = value.strip().lower()
                if lower == "true":
                    out[key] = True
                elif lower == "false":
                    out[key] = False
                else:
                    out[key] = value.strip('"').strip("'")
    except Exception:
        return {}

    return out


def _parse_run_config_overrides(run_config: Optional[str]) -> Dict[str, str]:
    """Parse Flower --run-config 'k=v k2=v2' into a dict of strings."""
    if not run_config:
        return {}
    overrides: Dict[str, str] = {}
    for token in shlex.split(run_config):
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k:
            overrides[k] = v
    return overrides


def _write_activated_config_artifacts(
    *,
    run_dir: Path,
    project_root: Path,
    final_run_config: str,
) -> None:
    """Persist the exact config inputs used for this run.

    Flower receives defaults from pyproject.toml plus the final --run-config
    string. The attack engine also writes its resolved semantic config into
    summaries/run_config_and_summary.json after the run starts; these files make
    the runner-side inputs easy to audit before reading parsed metrics.
    """

    config_dir = run_dir / "configs"
    config_dir.mkdir(parents=True, exist_ok=True)

    (config_dir / "activated_run_config.txt").write_text(
        str(final_run_config or "").strip() + "\n",
        encoding="utf-8",
    )

    parsed = _parse_run_config_overrides(final_run_config)
    lines = [
        "# Final Flower --run-config overrides for this run.",
        "# Values are written as strings because Flower performs its own TOML/run-config parsing.",
    ]
    for key in sorted(parsed.keys()):
        val = str(parsed[key]).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{key} = "{val}"')
    (config_dir / "activated_overrides.toml").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        try:
            shutil.copy2(pyproject, config_dir / "pyproject.snapshot.toml")
        except Exception:
            pass


def _safe_literal_dict(value: str) -> Optional[Dict[str, Any]]:
    """Parse a Python-literal dict from a log line fragment."""
    value = value.strip()

    # Quick sanity: must look like a dict
    if not (value.startswith("{") and value.endswith("}")):
        return None

    try:
        parsed = ast.literal_eval(value)
    except Exception:
        # Flower may print non-literal tokens like `nan`/`inf` (e.g. {'loss': nan}).
        # Fall back to a tiny parser that extracts key/value tokens.
        parsed = {}
        for m in re.finditer(r"'([^']+)'\s*:\s*([^,}]+)", value):
            k = m.group(1)
            token = m.group(2).strip()

            # Normalize common non-finite tokens
            lower = token.lower()
            if lower in {"nan", "+nan", "-nan"}:
                parsed[k] = float("nan")
                continue
            if lower in {"inf", "+inf", "infinity", "+infinity"}:
                parsed[k] = float("inf")
                continue
            if lower in {"-inf", "-infinity"}:
                parsed[k] = float("-inf")
                continue

            # Try literal_eval for quoted numbers/strings, else float
            try:
                parsed_val = ast.literal_eval(token)
            except Exception:
                parsed_val = token
            parsed[k] = parsed_val

    if not isinstance(parsed, dict):
        return None

    return parsed


def _coerce_metric_value(value: Any) -> Optional[float]:
    """Coerce metric values to float when possible."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        # Handles '2.2581e+00'
        lower = value.strip().lower()
        if lower in {"nan", "+nan", "-nan"}:
            return float("nan")
        if lower in {"inf", "+inf", "infinity", "+infinity"}:
            return float("inf")
        if lower in {"-inf", "-infinity"}:
            return float("-inf")
        try:
            return float(value)
        except Exception:
            return None
    return None


def parse_flwr_output(stdout_text: str) -> ParsedMetrics:
    """Extract per-round metrics from Flower output."""
    state = ParseState()
    for raw_line in stdout_text.splitlines():
        state.feed_line(raw_line)
    return state.finalize()


def write_metrics(run_dir: Path, parsed: ParsedMetrics) -> Path:
    metrics_dir = run_dir / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=False)

    metrics_json = metrics_dir / "metrics.json"
    metrics_json.write_text(
        json.dumps(parsed.to_jsonable(), indent=2, sort_keys=True), encoding="utf-8"
    )

    # Always write sampling.csv (PNG is handled later if graphs/ is created).
    _write_sampling_table(run_dir, parsed)

    if parsed.per_client:
        (metrics_dir / "per_client_metrics.json").write_text(
            json.dumps(_jsonify_nested(parsed.per_client), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    # Round-wise snapshots (easier to browse/paginate)
    rounds_dir = run_dir / "rounds"
    rounds_dir.mkdir(parents=True, exist_ok=False)
    for rnd in sorted(set(parsed.by_round.keys()) | set(parsed.sampling.keys())):
        round_path = rounds_dir / f"round_{rnd:03d}.json"
        round_payload = {
            "round": rnd,
            "metrics": _jsonify_nested(parsed.by_round.get(rnd, {})),
            "sampling": parsed.sampling.get(rnd, {}),
        }
        round_path.write_text(
            json.dumps(round_payload, indent=2, sort_keys=True), encoding="utf-8"
        )

    # Also write a combined round-wise view
    (metrics_dir / "rounds.json").write_text(
        json.dumps(parsed.to_round_jsonable(), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    # Also write CSVs per metric
    for phase, metrics in parsed.series.items():
        for metric_name, points in metrics.items():
            csv_path = metrics_dir / f"{phase}__{metric_name}.csv"
            lines = ["round,value"]
            for r, v in points:
                if math.isfinite(float(v)):
                    lines.append(f"{r},{v}")
                else:
                    lines.append(f"{r},nan")
            csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return metrics_json


def maybe_write_graphs(run_dir: Path, parsed: ParsedMetrics) -> Optional[Path]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return None

    graphs_dir = run_dir / "graphs"
    graphs_dir.mkdir(parents=True, exist_ok=True)

    def _pretty_metric_name(name: str) -> str:
        n = str(name)
        key = n.lower().strip()
        mapping = {
            "eval_acc": "Accuracy",
            "accuracy": "Accuracy",
            "eval_loss": "Loss",
            "loss": "Loss",
            "train_loss": "Training Loss",
            "backdoor_asr": "Backdoor ASR",
            "backdoor_loss": "Backdoor Loss",
        }
        if key in mapping:
            return mapping[key]
        # Fall back to title-cased words.
        return " ".join([w.capitalize() for w in n.replace("__", " ").replace("_", " ").split()])

    def _outline_line(line: Any) -> None:
        try:
            import matplotlib.patheffects as pe

            lw = float(getattr(line, "get_linewidth", lambda: 2.0)())
            line.set_path_effects([pe.Stroke(linewidth=lw + 2.5, foreground="black"), pe.Normal()])
        except Exception:
            return

    # Organize graphs into subfolders.
    aggregated_client_dir = graphs_dir / "aggregated_client"
    aggregated_server_dir = graphs_dir / "aggregated_server"
    per_client_dir = graphs_dir / "per_client"
    summaries_dir = graphs_dir / "summaries"
    diagnostics_dir = graphs_dir / "diagnostics"
    aggregated_client_dir.mkdir(parents=True, exist_ok=True)
    aggregated_server_dir.mkdir(parents=True, exist_ok=True)
    per_client_dir.mkdir(parents=True, exist_ok=True)
    summaries_dir.mkdir(parents=True, exist_ok=True)
    diagnostics_dir.mkdir(parents=True, exist_ok=True)

    for phase, metrics in parsed.series.items():
        for metric_name, points in metrics.items():
            if not points:
                continue
            rounds = [r for (r, _) in points]
            values = [v for (_, v) in points]

            fig = plt.figure(figsize=(7, 4))
            ax = fig.add_subplot(1, 1, 1)
            ax.plot(rounds, values, linewidth=2.4, color="#1f77b4")
            phase_title = {
                "train_client": "Client-Side Train",
                "evaluate_client": "Client-Side Evaluate",
                "evaluate_server": "Server-Side Evaluate",
            }.get(phase, phase)
            ax.set_title(f"{phase_title}: {_pretty_metric_name(metric_name)}")
            ax.set_xlabel("Round")
            ax.set_ylabel(_pretty_metric_name(metric_name))

            # If a loss spikes by many orders of magnitude, the linear scale can
            # make earlier rounds look like a flat line near zero.
            metric_lower = str(metric_name).lower()
            if "loss" in metric_lower:
                finite_pos = [float(v) for v in values if math.isfinite(float(v)) and float(v) > 0]
                if len(finite_pos) >= 2:
                    vmin = min(finite_pos)
                    vmax = max(finite_pos)
                    if vmin > 0 and vmax / vmin >= 1e4:
                        ax.set_yscale("log")

            ax.grid(True, alpha=0.3)
            fig.tight_layout()

            if phase == "evaluate_server":
                out_root = aggregated_server_dir
            else:
                out_root = aggregated_client_dir
            out_path = out_root / f"{phase}__{metric_name}.png"
            fig.savefig(out_path, dpi=160)
            plt.close(fig)

    # Per-client learning curves (only if clients emit CLIENT_METRICS lines)
    if parsed.per_client:
        # Build global client set across phases to keep the color mapping stable.
        all_client_ids = sorted(
            {cid for clients in parsed.per_client.values() for cid in clients.keys()},
            key=lambda x: int(x),
        )
        colors = _assign_client_colors(all_client_ids)

        # Persist the mapping as CSV/JSON + a PNG table.
        metrics_dir = run_dir / "metrics"
        if metrics_dir.exists():
            _write_client_color_key(metrics_dir, diagnostics_dir, all_client_ids, colors)

        skip_metrics = {"num_examples", "num-examples"}
        for phase, clients in parsed.per_client.items():
            metric_names = sorted(
                {
                    metric_name
                    for client_metrics in clients.values()
                    for metric_name in client_metrics.keys()
                    if metric_name not in skip_metrics
                }
            )

            # client_index is 1..N based on sorted partition_ids
            client_index_by_id = {cid: i + 1 for i, cid in enumerate(all_client_ids)}

            for metric_name in metric_names:
                fig = plt.figure(figsize=(9.5, 5.2))
                ax = fig.add_subplot(1, 1, 1)

                plotted = 0
                for client_id, client_metrics in sorted(
                    clients.items(), key=lambda x: int(x[0])
                ):
                    points = client_metrics.get(metric_name)
                    if not points:
                        continue
                    rounds = [r for r, _ in points]
                    values = [v for _, v in points]
                    idx = client_index_by_id.get(client_id, int(client_id) + 1)
                    label = f"client {idx} (partition {client_id})"
                    ax.plot(
                        rounds,
                        values,
                        linewidth=1.6,
                        alpha=0.75,
                        color=colors.get(client_id),
                        label=label,
                    )
                    plotted += 1

                if plotted == 0:
                    plt.close(fig)
                    continue

                ax.set_title(f"per-client: {phase} {metric_name} ({plotted} clients)")
                phase_title = {
                    "train_client": "Train",
                    "evaluate_client": "Evaluate",
                }.get(phase, str(phase).replace("_", " ").title())
                ax.set_title(f"Per-Client: {phase_title} — {_pretty_metric_name(metric_name)} ({plotted} clients)")
                ax.set_xlabel("Round")
                ax.set_ylabel(_pretty_metric_name(metric_name))
                ax.grid(True, alpha=0.25)

                # Legends get unusable at N=30. Show only for small N.
                if plotted <= 10:
                    ax.legend(
                        loc="upper left",
                        bbox_to_anchor=(1.02, 1.0),
                        borderaxespad=0.0,
                        fontsize=8,
                    )
                    fig.tight_layout(rect=[0, 0, 0.78, 1])
                else:
                    fig.tight_layout()

                fig.savefig(
                    per_client_dir / f"per_client__{phase}__{metric_name}.png", dpi=160
                )
                plt.close(fig)

    # Write sampling + config summaries into graphs/diagnostics.
    _write_sampling_table(run_dir, parsed)
    _write_config_summary_table(run_dir)

    for name in ("sampling__table.png", "config__summary.png"):
        p = graphs_dir / name
        if p.exists():
            try:
                p.replace(diagnostics_dir / name)
            except Exception:
                pass

    # Convenience summary: compare clean accuracy vs backdoor ASR.
    # This makes it obvious when "clean accuracy looks fine" but the model is
    # still vulnerable to the trigger (high ASR).
    try:
        server_metrics = parsed.series.get("evaluate_server") or {}
        acc_pts = server_metrics.get("accuracy") or []
        asr_pts = server_metrics.get("backdoor_asr") or []
        if acc_pts and asr_pts:
            acc_by_round = {int(r): float(v) for (r, v) in acc_pts}
            asr_by_round = {int(r): float(v) for (r, v) in asr_pts}
            rounds = sorted(set(acc_by_round.keys()) & set(asr_by_round.keys()))
            if rounds:
                acc_vals = [acc_by_round[r] for r in rounds]
                asr_vals = [asr_by_round[r] for r in rounds]

                fig = plt.figure(figsize=(7.8, 4.4))
                ax = fig.add_subplot(1, 1, 1)
                ax.plot(rounds, acc_vals, marker="o", linewidth=2.0, label="clean accuracy")
                ax.plot(rounds, asr_vals, marker="s", linewidth=2.0, label="backdoor ASR")
                ax.set_title("Server eval: accuracy vs backdoor ASR")
                ax.set_xlabel("Round")
                ax.set_ylabel("Rate")
                ax.set_ylim(0.0, 1.0)
                ax.grid(True, alpha=0.25)
                ax.legend(loc="best")
                fig.tight_layout()

                name = "evaluate_server__accuracy_vs_backdoor_asr.png"
                fig.savefig(summaries_dir / name, dpi=160)
                fig.savefig(aggregated_server_dir / name, dpi=160)
                plt.close(fig)
    except Exception:
        pass

    return graphs_dir


def run_flwr(project_root: Path, federation: Optional[str], run_config: Optional[str]) -> subprocess.CompletedProcess:
    flwr_exe = shutil.which("flwr")
    if flwr_exe is None:
        # In venvs, sys.executable is often a symlink; using .resolve() can
        # incorrectly jump to the base framework Python, so avoid resolving.
        candidates = [
            Path(sys.executable).parent / "flwr",
            Path(sys.prefix) / "bin" / "flwr",
        ]
        for candidate in candidates:
            if candidate.exists():
                flwr_exe = str(candidate)
                break

    if flwr_exe is None:
        raise FileNotFoundError(
            "Could not find `flwr` executable. Install it into the active environment "
            "(e.g. `pip install -U \"flwr[simulation]\"`) and ensure it is on PATH."
        )

    cmd: List[str] = [flwr_exe, "run", "."]
    if federation:
        cmd.append(federation)
    if run_config:
        cmd.extend(["--run-config", run_config])

    env = os.environ.copy()

    # Keep full per-client logs (Ray deduplicates by default, which breaks per-client time series).
    env.setdefault("RAY_DEDUP_LOGS", "0")

    # Ensure the Flower engine helpers (e.g. `flower-simulation`) are on PATH.
    # This is needed because VS Code tool execution may not inherit an activated venv PATH.
    extra_bins: List[str] = []
    extra_bins.append(str(Path(sys.executable).parent))
    extra_bins.append(str(Path(sys.prefix) / "bin"))
    extra_bins.append(str(Path(flwr_exe).parent))

    # Prepend (dedup, keep order)
    existing = env.get("PATH", "")
    parts: List[str] = []
    for p in extra_bins + existing.split(":"):
        if not p:
            continue
        if p not in parts:
            parts.append(p)
    env["PATH"] = ":".join(parts)

    return subprocess.run(
        cmd,
        cwd=str(project_root),
        text=True,
        capture_output=True,
        env=env,
    )


def run_flwr_streaming(
    project_root: Path,
    federation: Optional[str],
    run_config: Optional[str],
    stdout_log_path: Path,
    *,
    live_output_stream = None,
) -> Tuple[int, ParseState]:
    """Run Flower and stream logs to the terminal while parsing metrics."""

    flwr_exe = shutil.which("flwr")
    if flwr_exe is None:
        candidates = [
            Path(sys.executable).parent / "flwr",
            Path(sys.prefix) / "bin" / "flwr",
        ]
        for candidate in candidates:
            if candidate.exists():
                flwr_exe = str(candidate)
                break

    if flwr_exe is None:
        raise FileNotFoundError(
            "Could not find `flwr` executable. Install it into the active environment "
            "(e.g. `pip install -U \"flwr[simulation]\"`) and ensure it is on PATH."
        )

    cmd: List[str] = [flwr_exe, "run", "."]
    if federation:
        cmd.append(federation)
    if run_config:
        cmd.extend(["--run-config", run_config])

    env = os.environ.copy()

    # Reduce noisy, non-actionable warnings in typical local runs.
    # Ray prints a FutureWarning unless this env var is set.
    env.setdefault("RAY_ACCEL_ENV_VAR_OVERRIDE_ON_ZERO", "0")
    # Keep full per-client logs (Ray deduplicates by default, which breaks per-client time series).
    env.setdefault("RAY_DEDUP_LOGS", "0")
    extra_bins: List[str] = []
    extra_bins.append(str(Path(sys.executable).parent))
    extra_bins.append(str(Path(sys.prefix) / "bin"))
    extra_bins.append(str(Path(flwr_exe).parent))
    existing = env.get("PATH", "")
    parts: List[str] = []
    for p in extra_bins + existing.split(":"):
        if not p:
            continue
        if p not in parts:
            parts.append(p)
    env["PATH"] = ":".join(parts)

    out_stream = live_output_stream or sys.stdout
    state = ParseState()
    with stdout_log_path.open("w", encoding="utf-8") as log_f:
        proc = subprocess.Popen(
            cmd,
            cwd=str(project_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            bufsize=1,
        )
        assert proc.stdout is not None

        # Some libraries print one-off informational warnings that can clutter the
        # terminal. Keep them in stdout.log but don't echo them live.
        suppress_live_substrings = (
            "You are sending unauthenticated requests to the HF Hub.",
        )

        for line in proc.stdout:
            # Tee into log file (always)
            log_f.write(line)

            # Print like a normal run, but suppress known-noisy lines.
            if not any(s in line for s in suppress_live_substrings):
                out_stream.write(line)
                out_stream.flush()

            # Tee into log file
            # Parse metrics
            state.feed_line(line)
        return_code = proc.wait()

    return return_code, state


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run `flwr run .` and save logs/metrics/graphs per run."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Path to dynamic_fl project root (default: cwd).",
    )
    parser.add_argument(
        "--federation",
        type=str,
        default=None,
        help="Optional federation name (e.g. local-simulation-gpu).",
    )
    parser.add_argument(
        "--run-config",
        type=str,
        default=None,
        help='Optional run config string (e.g. "num-server-rounds=5 local-epochs=2").',
    )
    parser.add_argument(
        "--strategy-name",
        type=str,
        default=None,
        help="Used in the run folder name. If omitted, inferred from server_app.py.",
    )
    parser.add_argument(
        "--reparse-run",
        type=Path,
        default=None,
        help="Path to an existing logs/<run>/ folder to regenerate metrics/graphs from stdout.log.",
    )
    parser.add_argument(
        "--print-log-dir",
        action="store_true",
        help="Print only the resolved run log directory to stdout while sending live logs to stderr.",
    )

    args = parser.parse_args()

    # Parse-only mode (useful if parsing logic changes or the run produced NaNs)
    if args.reparse_run is not None:
        run_dir = args.reparse_run.resolve()
        stdout_log = run_dir / "stdout.log"
        if not stdout_log.exists():
            raise FileNotFoundError(f"Missing stdout.log in {run_dir}")

        text = stdout_log.read_text(encoding="utf-8", errors="replace")
        parsed = parse_flwr_output(text)

        can_plot = _module_available("matplotlib")

        # Regenerate outputs (delete existing folders first)
        for sub in ("metrics", "rounds"):
            p = run_dir / sub
            if p.exists():
                shutil.rmtree(p)
        # Only wipe/rebuild graphs if plotting is possible in this interpreter.
        if can_plot:
            p = run_dir / "graphs"
            if p.exists():
                shutil.rmtree(p)
        write_metrics(run_dir, parsed)
        if can_plot:
            maybe_write_graphs(run_dir, parsed)
            _write_label_distribution_artifacts(run_dir, parsed)
        _maybe_write_attack_summary_md(run_dir)
        if can_plot:
            _maybe_write_research_plots(run_dir)
        print(f"Re-parsed run folder: {run_dir}")
        return 0

    project_root: Path = args.project_root.resolve()
    logs_root = project_root / "logs"
    logs_root.mkdir(parents=True, exist_ok=True)

    defaults = _read_flwr_app_config(project_root)
    overrides = _parse_run_config_overrides(args.run_config)
    resolved_for_naming: Dict[str, Any] = {**defaults, **overrides}

    strategy_name = args.strategy_name or str(
        resolved_for_naming.get("strategy") or _infer_strategy_name(project_root)
    )
    dataset_name = resolved_for_naming.get("dataset")
    partitioner_name = resolved_for_naming.get("partitioner")
    dirichlet_alpha = resolved_for_naming.get("dirichlet-alpha")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    # Folder names are intentionally minimal. For a fixed strategy/dataset/iid
    # combination, lexicographic sort matches execution time.
    strategy_slug = _slugify(strategy_name)
    dataset_slug = _slugify(dataset_name) if dataset_name else ""
    iid_flag = _iid_flag_from_partitioner_name(partitioner_name)
    if dataset_slug:
        run_dir = logs_root / f"{strategy_slug}__{dataset_slug}__{iid_flag}__{timestamp}"
    else:
        run_dir = logs_root / f"{strategy_slug}__{iid_flag}__{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=False)

    # Capture runtime package versions for reproducibility
    _versions: dict = {}
    for _pkg_name, _import_name in [
        ("torch", "torch"), ("flwr", "flwr"),
        ("flwr_datasets", "flwr_datasets"), ("numpy", "numpy"),
    ]:
        try:
            _mod = __import__(_import_name)
            _versions[_pkg_name] = getattr(_mod, "__version__", "unknown")
        except Exception:
            pass

    # Save run metadata
    (run_dir / "meta.json").write_text(
        json.dumps(
            {
                "strategy": strategy_name,
                "dataset": dataset_name,
                "partitioner": partitioner_name,
                "dirichlet-alpha": dirichlet_alpha,
                "timestamp": timestamp,
                "federation": args.federation,
                "run_config": args.run_config,
                "resolved_config_for_naming": resolved_for_naming,
                "versions": _versions,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    # Execute Flower (streaming like `flwr run .`)
    stdout_log_path = run_dir / "stdout.log"
    stderr_log_path = run_dir / "stderr.log"

    # Provide the per-run artifact directory to the Flower app so server-side
    # components can write additional artifacts (e.g., attack provenance).
    run_config = args.run_config
    artifact_kv = f"artifact-dir=\"{str(run_dir)}\""
    if run_config:
        if "artifact-dir=" not in run_config:
            run_config = (run_config.strip() + " " + artifact_kv).strip()
    else:
        run_config = artifact_kv

    _write_activated_config_artifacts(
        run_dir=run_dir,
        project_root=project_root,
        final_run_config=str(run_config or ""),
    )

    live_output_stream = sys.stderr if args.print_log_dir else sys.stdout
    return_code, state = run_flwr_streaming(
        project_root,
        args.federation,
        run_config,
        stdout_log_path,
        live_output_stream=live_output_stream,
    )
    # Stderr is merged into stdout for faithful live output.
    stderr_log_path.write_text("", encoding="utf-8")

    parsed = state.finalize()
    write_metrics(run_dir, parsed)
    graphs_dir = maybe_write_graphs(run_dir, parsed)
    _write_label_distribution_artifacts(run_dir, parsed)
    _maybe_write_attack_summary_md(run_dir)
    _maybe_write_research_plots(run_dir)

    # Print a short summary for humans.
    # In --print-log-dir mode, keep stdout machine-readable for the caller.
    summary_stream = sys.stderr if args.print_log_dir else sys.stdout
    print(f"Run folder: {run_dir}", file=summary_stream)
    print(f"Exit code: {return_code}", file=summary_stream)
    for phase, metrics in parsed.series.items():
        if not metrics:
            continue
        metric_list = ", ".join(sorted(metrics.keys()))
        label = {
            "train_client": "client-side train",
            "evaluate_client": "client-side evaluate",
            "evaluate_server": "server-side evaluate",
        }.get(phase, phase)
        print(f"Parsed {label} metrics: {metric_list}", file=summary_stream)
    if parsed.sampling:
        print("Parsed per-round sampling counts (and IDs if present in logs).", file=summary_stream)
    if not parsed.per_client:
        print(
            "Per-client curves not generated (no per-client metrics found). "
            "Enable with: --run-config \"emit-client-metrics=true\"",
            file=summary_stream,
        )
    if graphs_dir is None:
        print(
            "Graphs not generated (matplotlib missing). Install with: pip install matplotlib",
            file=summary_stream,
        )
    if args.print_log_dir:
        print(str(run_dir))

    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
