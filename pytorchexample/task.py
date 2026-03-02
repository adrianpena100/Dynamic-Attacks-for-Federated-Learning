"""pytorchexample: A Flower / PyTorch app.

Goal: make dataset + partitioning *toggable* via Flower run config/TOML.

This module provides a small "task pipeline" abstraction so you can set:

- dataset (HF dataset id)
- dataset-modality (auto|vision|text|tabular|audio)
- partitioner (iid|dirichlet)

and the code picks a compatible model + preprocessing.

Notes:
- Vision is fully supported (CIFAR10/100, MNIST/FashionMNIST).
- Text/tabular are supported with simple hashed-feature baselines.
- Audio is scaffolded and requires extra deps (torchaudio).
"""

from __future__ import annotations

import json
import math
import os
import random
import re
import shutil
import importlib
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from datasets import load_dataset
from flwr_datasets import FederatedDataset
from flwr_datasets.partitioner import DirichletPartitioner, IidPartitioner
from torch.utils.data import DataLoader
from torchvision.transforms import Compose, Normalize, ToTensor


@dataclass(frozen=True)
class AttackWindow:
    start_round: int
    end_round: int


@dataclass(frozen=True)
class AttackPhase:
    start_round: int
    end_round: int
    attack_name: str

    intensity_schedule: str = "constant"  # constant|linear_ramp|step|periodic
    intensity_value: float = 1.0
    intensity_start: float = 0.0
    intensity_end: float = 1.0
    step_points: Optional[List[int]] = None
    step_values: Optional[List[float]] = None
    periodic_base: float = 0.0
    periodic_amp: float = 1.0
    periodic_period: int = 10
    relative_to_update_norm: bool = False


@dataclass(frozen=True)
class LayerMultiplierSchedule:
    """Deterministic per-layer multiplier schedule.

    This is applied on top of `layer_intensity_multipliers`.
    """

    layer: str
    start_round: int
    end_round: int
    mode: str = "linear"  # constant|linear|exp|step
    multiplier_value: float = 1.0
    multiplier_start: float = 1.0
    multiplier_end: float = 1.0
    step_points: Optional[List[int]] = None
    step_values: Optional[List[float]] = None


@dataclass(frozen=True)
class DefenseConfig:
    """Server-side defense knobs (optional).

    Implemented as a pre-aggregation filter on client updates.
    """

    enabled: bool = False
    mode: str = "none"  # none|norm_mad
    drop_non_finite: bool = True
    mad_z: float = 3.5
    max_reject_fraction: float = 0.2
    min_clients_after_filter: int = 2


@dataclass(frozen=True)
class GaussianNoiseAttackConfig:
    enabled: bool = True
    sigma: float = 0.5
    relative: bool = True


@dataclass(frozen=True)
class SignFlipAttackConfig:
    enabled: bool = True
    alpha: float = 1.0


@dataclass(frozen=True)
class LabelFlipAttackConfig:
    enabled: bool = False
    flip_rate: float = 0.2
    targeted: bool = False
    source_class: int = 0
    target_class: int = 1


@dataclass(frozen=True)
class BackdoorAttackConfig:
    enabled: bool = False
    poison_rate: float = 0.1
    target_label: int = 0
    trigger_type: str = "patch"
    patch_size: int = 4
    blend_alpha: float = 0.2


@dataclass(frozen=True)
class AlieAttackConfig:
    enabled: bool = False
    # Standardized shift factor. Typical ALIE uses negative z to shift away.
    # Effective z = z * intensity.
    z: float = -2.0


@dataclass(frozen=True)
class MeanShiftAttackConfig:
    enabled: bool = False
    # Mean-shift strength (effective beta = beta * intensity).
    # Crafted delta = -beta_eff * mean(honest_deltas).
    beta: float = 1.0


@dataclass(frozen=True)
class AttackConfig:
    enabled: bool = False
    seed: int = 1337
    log_level: str = "INFO"

    malicious_fraction: float = 0.0
    # How to determine the malicious fraction each round.
    # - fixed: use malicious_fraction
    # - uniform: sample U[malicious_fraction_min, malicious_fraction_max]
    # - choice: sample from malicious_fraction_choices
    malicious_fraction_mode: str = "fixed"  # fixed|uniform|choice
    malicious_fraction_min: float = 0.0
    malicious_fraction_max: float = 0.0
    malicious_fraction_choices: Optional[List[float]] = None

    # Optional per-round malicious fraction schedule.
    # If enabled, this overrides malicious_fraction_mode.
    # - none: disabled (use malicious_fraction_mode)
    # - linear: linear interpolation from start->end value
    # - exp: exponential interpolation from start->end value (requires >0 endpoints)
    malicious_fraction_ramp_mode: str = "none"  # none|linear|exp
    malicious_fraction_ramp_start_round: int = 1
    malicious_fraction_ramp_end_round: int = 0  # 0 => num_rounds
    malicious_fraction_ramp_value_start: float = 0.0
    malicious_fraction_ramp_value_end: float = 0.0
    malicious_fraction_cap: float = 0.0  # 0 disables cap

    # Which clients are malicious each round.
    # - per_round_random: sample a fresh malicious set each round
    # - sticky: choose once and reuse for entire run (size adjusts if k changes)
    # - sticky_k: keep a malicious set for `sticky_rounds`, then resample
    # - churn: keep most of last round's malicious set, replace a fraction each round
    selection_mode: str = "per_round_random"  # per_round_random|sticky|sticky_k|churn
    deterministic_per_round: bool = True

    # Sticky-window length (only used for selection_mode=sticky_k).
    sticky_rounds: int = 5

    # Churn settings (only used for selection_mode=churn).
    # churn_fraction is the fraction of the malicious set replaced each round.
    churn_fraction: float = 0.3
    churn_min_replace: int = 1

    # Optional: prevent recently-malicious clients from being re-selected.
    # If >0, any client that was malicious in the last `cooldown_rounds` rounds
    # is excluded from the candidate pool where possible.
    cooldown_rounds: int = 0

    mode: str = "phase"  # phase|weighted_random
    weights: Dict[str, float] = None  # type: ignore[assignment]
    phases: List[AttackPhase] = None  # type: ignore[assignment]
    windows: List[AttackWindow] = None  # type: ignore[assignment]

    # Weighted-random intensity policy (applies when mode=weighted_random).
    # Intensity is a multiplier applied to the underlying attack parameter.
    # - fixed: always random_intensity_value
    # - uniform: sample U[random_intensity_min, random_intensity_max]
    # - choice: sample from random_intensity_choices
    random_intensity_mode: str = "fixed"  # fixed|uniform|choice
    random_intensity_value: float = 1.0
    random_intensity_min: float = 0.0
    random_intensity_max: float = 1.0
    random_intensity_choices: Optional[List[float]] = None

    # Chance to treat gaussian_noise as "relative_to_update_norm" for a given round
    # when mode=weighted_random.
    random_relative_to_update_norm_probability: float = 0.0

    # Optional intensity escalation schedule (applies for mode=weighted_random and
    # mode=adaptive; phase mode already has per-phase schedules).
    # Effective intensity = base_intensity * ramp_multiplier * fail_multiplier.
    intensity_cap: float = 0.0  # 0 disables cap
    intensity_ramp_mode: str = "none"  # none|linear|exp
    intensity_ramp_start_round: int = 1
    intensity_ramp_end_round: int = 0  # 0 => num_rounds
    intensity_ramp_multiplier_start: float = 1.0
    intensity_ramp_multiplier_end: float = 1.0

    # Optional adaptive-only escalation when the chosen attack isn't improving the
    # metric (as tracked by adaptive_consecutive_fails).
    intensity_fail_escalation: bool = False
    intensity_fail_multiplier_step: float = 0.25
    intensity_fail_multiplier_max: float = 2.0

    # Adaptive mode: choose attacks based on observed server evaluation metrics.
    # When mode="adaptive", the engine will try different attack types and
    # bias toward those that reduce the chosen metric.
    adaptive_metric: str = "accuracy"  # e.g., accuracy|loss|backdoor_asr
    adaptive_goal: str = "minimize"  # minimize|below
    adaptive_target: float = 0.2
    adaptive_epsilon: float = 0.2
    adaptive_min_delta: float = 0.0
    adaptive_patience: int = 2
    adaptive_window: int = 5
    adaptive_burn_in_rounds: int = 1

    # Stealth mode for update poisoning: cap crafted malicious update norm to
    # a quantile of the honest norm distribution, optionally scaled.
    stealth_mode: bool = False
    stealth_norm_quantile: float = 0.9
    stealth_norm_multiplier: float = 1.0

    gaussian_noise: GaussianNoiseAttackConfig = GaussianNoiseAttackConfig()
    sign_flip: SignFlipAttackConfig = SignFlipAttackConfig()
    label_flip: LabelFlipAttackConfig = LabelFlipAttackConfig()
    backdoor: BackdoorAttackConfig = BackdoorAttackConfig()
    alie: AlieAttackConfig = AlieAttackConfig()
    mean_shift: MeanShiftAttackConfig = MeanShiftAttackConfig()

    # ----------------------------
    # Multi-layer attacks
    # ----------------------------
    # By default, the engine chooses exactly one attack per round (existing behavior).
    # When layering_mode != "single", the engine can apply multiple attacks in the same round.
    #
    # - single: choose exactly one attack per round via `mode` (phase/weighted_random/adaptive)
    # - fixed: always use `layered_attacks` (filtered to enabled)
    # - sample_k: sample `layered_k` unique attacks per round from the enabled candidates
    layering_mode: str = "single"  # single|fixed|sample_k
    layered_attacks: Optional[List[str]] = None
    layered_k: int = 2

    # Optional: per-layer intensity multipliers.
    # Effective intensity for a layer = round_intensity * layer_intensity_multipliers[layer]
    # Layers not present default to 1.0.
    layer_intensity_multipliers: Optional[Dict[str, float]] = None

    # Optional: deterministic per-layer multiplier schedules.
    # These are applied after `layer_intensity_multipliers`.
    # Effective layer intensity = round_intensity * base_multiplier[layer] * schedule_multiplier(layer, round)
    layer_multiplier_schedules: Optional[List[LayerMultiplierSchedule]] = None


def _read_toml(path: Path) -> Dict[str, Any]:
    """Read TOML using tomllib (3.11+) or tomli (3.10)."""

    try:
        toml = importlib.import_module("tomllib")
    except ModuleNotFoundError:
        toml = importlib.import_module("tomli")

    with path.open("rb") as f:
        return toml.load(f)


def _find_project_root() -> Path:
    # pytorchexample/task.py -> pytorchexample -> project root
    here = Path(__file__).resolve()
    return here.parents[1]


def load_attack_config(*, run_config: Dict[str, Any]) -> AttackConfig:
    """Load attack config from pyproject.toml and apply safe defaults.

    This keeps attack control entirely TOML-driven. `run_config` is used only for
    non-semantic runtime fields (e.g., artifact-dir) and to support future
    override keys if needed.
    """

    root = _find_project_root()
    pyproject = root / "pyproject.toml"
    attack: Dict[str, Any] = {}
    if pyproject.exists():
        data = _read_toml(pyproject)
        attack = ((data.get("tool") or {}).get("flwr") or {}).get("attack") or {}

    def get_bool(key: str, default: bool) -> bool:
        v = attack.get(key, default)
        return bool(v)

    def get_int(key: str, default: int) -> int:
        v = attack.get(key, default)
        try:
            return int(v)
        except Exception:
            return int(default)

    def get_float(key: str, default: float) -> float:
        v = attack.get(key, default)
        try:
            return float(v)
        except Exception:
            return float(default)

    enabled = get_bool("enabled", False)
    seed = get_int("seed", 1337)
    log_level = str(attack.get("log_level", "INFO")).strip().upper()

    # Convenience: presets to quickly toggle attack sets.
    # preset can be set in pyproject.toml or overridden via run_config key `attack-preset`.
    preset = str(attack.get("preset", "custom") or "custom").strip().lower()

    # Allow a "different every run" mode while still logging the resolved seed.
    # If seed < 0, derive a fresh seed from OS entropy for this run.
    if seed < 0:
        try:
            seed = int.from_bytes(os.urandom(8), "little") & 0x7FFFFFFF
        except Exception:
            seed = 1337

    malicious_fraction = get_float("malicious_fraction", 0.0)
    malicious_fraction_mode = str(attack.get("malicious_fraction_mode", "fixed")).strip().lower()
    malicious_fraction_min = get_float("malicious_fraction_min", malicious_fraction)
    malicious_fraction_max = get_float("malicious_fraction_max", malicious_fraction)
    mfc_raw = attack.get("malicious_fraction_choices")
    malicious_fraction_choices: Optional[List[float]] = None
    if isinstance(mfc_raw, list):
        vals: List[float] = []
        for x in mfc_raw:
            try:
                vals.append(float(x))
            except Exception:
                continue
        malicious_fraction_choices = vals or None

    malicious_fraction_ramp_mode = str(attack.get("malicious_fraction_ramp_mode", "none") or "none").strip().lower()
    malicious_fraction_ramp_start_round = get_int("malicious_fraction_ramp_start_round", 1)
    malicious_fraction_ramp_end_round = get_int("malicious_fraction_ramp_end_round", 0)
    malicious_fraction_ramp_value_start = get_float("malicious_fraction_ramp_value_start", malicious_fraction)
    malicious_fraction_ramp_value_end = get_float("malicious_fraction_ramp_value_end", malicious_fraction)
    malicious_fraction_cap = get_float("malicious_fraction_cap", 0.0)

    selection_mode = str(attack.get("selection_mode", "per_round_random")).strip().lower()
    deterministic_per_round = bool(attack.get("deterministic_per_round", True))

    sticky_rounds = get_int("sticky_rounds", 5)
    churn_fraction = get_float("churn_fraction", 0.3)
    churn_min_replace = get_int("churn_min_replace", 1)
    cooldown_rounds = get_int("cooldown_rounds", 0)

    mode = str(attack.get("mode", "phase")).strip().lower()
    if mode == "random":
        mode = "weighted_random"
    if mode in {"adaptive", "auto"}:
        mode = "adaptive"

    random_intensity_mode = str(attack.get("random_intensity_mode", "fixed")).strip().lower()
    random_intensity_value = get_float("random_intensity_value", 1.0)
    random_intensity_min = get_float("random_intensity_min", 0.0)
    random_intensity_max = get_float("random_intensity_max", 1.0)
    ric_raw = attack.get("random_intensity_choices")
    random_intensity_choices: Optional[List[float]] = None
    if isinstance(ric_raw, list):
        vals2: List[float] = []
        for x in ric_raw:
            try:
                vals2.append(float(x))
            except Exception:
                continue
        random_intensity_choices = vals2 or None

    rrtnp = get_float("random_relative_to_update_norm_probability", 0.0)

    intensity_cap = get_float("intensity_cap", 0.0)
    intensity_ramp_mode = str(attack.get("intensity_ramp_mode", "none")).strip().lower()
    intensity_ramp_start_round = get_int("intensity_ramp_start_round", 1)
    intensity_ramp_end_round = get_int("intensity_ramp_end_round", 0)
    intensity_ramp_multiplier_start = get_float("intensity_ramp_multiplier_start", 1.0)
    intensity_ramp_multiplier_end = get_float("intensity_ramp_multiplier_end", 1.0)
    intensity_fail_escalation = get_bool("intensity_fail_escalation", False)
    intensity_fail_multiplier_step = get_float("intensity_fail_multiplier_step", 0.25)
    intensity_fail_multiplier_max = get_float("intensity_fail_multiplier_max", 2.0)

    adaptive_metric = str(attack.get("adaptive_metric", "accuracy") or "accuracy").strip()
    adaptive_goal = str(attack.get("adaptive_goal", "minimize") or "minimize").strip().lower()
    adaptive_target = get_float("adaptive_target", 0.2)
    adaptive_epsilon = get_float("adaptive_epsilon", 0.2)
    adaptive_min_delta = get_float("adaptive_min_delta", 0.0)
    adaptive_patience = get_int("adaptive_patience", 2)
    adaptive_window = get_int("adaptive_window", 5)
    adaptive_burn_in_rounds = get_int("adaptive_burn_in_rounds", 1)

    stealth_mode = bool(attack.get("stealth_mode", False))
    stealth_norm_quantile = get_float("stealth_norm_quantile", 0.9)
    stealth_norm_multiplier = get_float("stealth_norm_multiplier", 1.0)

    # Multi-layer attack controls
    layering_mode = str(attack.get("layering_mode", "single") or "single").strip().lower()
    if layering_mode in {"", "none", "off", "disabled"}:
        layering_mode = "single"

    layered_k = get_int("layered_k", 2)
    layered_k = int(max(1, layered_k))

    layered_attacks_raw = attack.get("layered_attacks")
    if layered_attacks_raw is None:
        layered_attacks_raw = attack.get("attack_layers")

    layered_attacks: Optional[List[str]] = None
    if isinstance(layered_attacks_raw, list):
        xs: List[str] = []
        for x in layered_attacks_raw:
            try:
                s = str(x).strip().lower().replace("-", "_")
            except Exception:
                continue
            if not s:
                continue
            xs.append(s)
        layered_attacks = xs or None

    # Optional per-layer intensity multipliers
    lim_raw = attack.get("layer_intensity_multipliers")
    if lim_raw is None:
        lim_raw = attack.get("attack_layer_intensity_multipliers")
    if lim_raw is None:
        lim_raw = attack.get("attack_layer_intensity_multiplier")
    layer_intensity_multipliers: Optional[Dict[str, float]] = None
    if isinstance(lim_raw, dict):
        d: Dict[str, float] = {}
        for k, v in lim_raw.items():
            try:
                kk = str(k).strip().lower().replace("-", "_")
                if not kk or kk in {"none", "off", "disabled"}:
                    continue
                d[kk] = float(max(0.0, float(v)))
            except Exception:
                continue
        layer_intensity_multipliers = d or None
    elif isinstance(lim_raw, str) and lim_raw.strip():
        # Accept "a=1.0;b=0.5" as a convenience.
        d2: Dict[str, float] = {}
        parts = lim_raw.replace(",", ";").split(";")
        for p in parts:
            if "=" not in p:
                continue
            k, v = p.split("=", 1)
            kk = str(k).strip().lower().replace("-", "_")
            if not kk or kk in {"none", "off", "disabled"}:
                continue
            try:
                d2[kk] = float(max(0.0, float(v)))
            except Exception:
                continue
        layer_intensity_multipliers = d2 or None

    # Optional deterministic per-layer schedules
    lms_raw = attack.get("layer_multiplier_schedules")
    if lms_raw is None:
        lms_raw = attack.get("layer_intensity_multiplier_schedules")
    if lms_raw is None:
        lms_raw = attack.get("layer_schedules")

    layer_multiplier_schedules: Optional[List[LayerMultiplierSchedule]] = None
    if isinstance(lms_raw, list):
        schedules: List[LayerMultiplierSchedule] = []
        for ent in lms_raw:
            if not isinstance(ent, dict):
                continue
            try:
                layer = str(ent.get("layer", ent.get("attack", "")) or "").strip().lower().replace("-", "_")
            except Exception:
                layer = ""
            if not layer or layer in {"none", "off", "disabled"}:
                continue

            try:
                start_r = int(ent.get("start_round", 1) or 1)
            except Exception:
                start_r = 1
            try:
                end_r = int(ent.get("end_round", start_r) or start_r)
            except Exception:
                end_r = start_r
            start_r = int(max(1, start_r))
            end_r = int(max(start_r, end_r))

            mode2 = str(ent.get("mode", ent.get("schedule", "linear")) or "linear").strip().lower()
            mv = ent.get("multiplier_value", ent.get("value", 1.0))
            ms0 = ent.get("multiplier_start", ent.get("start", mv if mv is not None else 1.0))
            ms1 = ent.get("multiplier_end", ent.get("end", ms0 if ms0 is not None else 1.0))
            try:
                mv_f = float(mv if mv is not None else 1.0)
            except Exception:
                mv_f = 1.0
            try:
                ms0_f = float(ms0 if ms0 is not None else mv_f)
            except Exception:
                ms0_f = mv_f
            try:
                ms1_f = float(ms1 if ms1 is not None else ms0_f)
            except Exception:
                ms1_f = ms0_f

            pts_raw = ent.get("step_points")
            vals_raw = ent.get("step_values")
            pts: Optional[List[int]] = None
            vals: Optional[List[float]] = None
            if isinstance(pts_raw, list) and isinstance(vals_raw, list) and len(pts_raw) == len(vals_raw) and pts_raw:
                try:
                    pts = [int(x) for x in pts_raw]
                    vals = [float(x) for x in vals_raw]
                except Exception:
                    pts = None
                    vals = None

            schedules.append(
                LayerMultiplierSchedule(
                    layer=layer,
                    start_round=start_r,
                    end_round=end_r,
                    mode=mode2,
                    multiplier_value=float(max(0.0, mv_f)),
                    multiplier_start=float(max(0.0, ms0_f)),
                    multiplier_end=float(max(0.0, ms1_f)),
                    step_points=pts,
                    step_values=vals,
                )
            )

        layer_multiplier_schedules = schedules or None

    # Optional overrides from Flower run_config (useful for quick experiments)
    # NOTE: The fused run_config may include keys with empty/sentinel defaults.
    # Only apply overrides when the provided value is meaningful.
    if "attack-enabled" in run_config:
        v = run_config.get("attack-enabled")
        if isinstance(v, bool):
            enabled = bool(v)
    if "attack-preset" in run_config:
        preset = str(run_config.get("attack-preset") or preset).strip().lower()
    if "attack-seed" in run_config:
        v = run_config.get("attack-seed")
        try:
            sv = int(v)
            if sv >= 0:
                seed = sv
        except Exception:
            pass
    if "attack-malicious-fraction" in run_config:
        v = run_config.get("attack-malicious-fraction")
        try:
            fv = float(v)
            if fv >= 0.0:
                malicious_fraction = fv
        except Exception:
            pass
    if "attack-malicious-fraction-mode" in run_config:
        v = str(run_config.get("attack-malicious-fraction-mode") or "").strip().lower()
        if v:
            malicious_fraction_mode = v

    # Optional malicious-fraction schedule overrides via run_config
    if "attack-malicious-fraction-ramp-mode" in run_config:
        v = str(run_config.get("attack-malicious-fraction-ramp-mode") or "").strip().lower()
        if v:
            malicious_fraction_ramp_mode = v
    if "attack-malicious-fraction-ramp-start-round" in run_config:
        v = run_config.get("attack-malicious-fraction-ramp-start-round")
        try:
            iv = int(v)
            if iv > 0:
                malicious_fraction_ramp_start_round = iv
        except Exception:
            pass
    if "attack-malicious-fraction-ramp-end-round" in run_config:
        v = run_config.get("attack-malicious-fraction-ramp-end-round")
        try:
            iv = int(v)
            if iv >= 0:
                malicious_fraction_ramp_end_round = iv
        except Exception:
            pass
    if "attack-malicious-fraction-ramp-value-start" in run_config:
        v = run_config.get("attack-malicious-fraction-ramp-value-start")
        try:
            fv = float(v)
            if fv >= 0.0:
                malicious_fraction_ramp_value_start = fv
        except Exception:
            pass
    if "attack-malicious-fraction-ramp-value-end" in run_config:
        v = run_config.get("attack-malicious-fraction-ramp-value-end")
        try:
            fv = float(v)
            if fv >= 0.0:
                malicious_fraction_ramp_value_end = fv
        except Exception:
            pass
    if "attack-malicious-fraction-cap" in run_config:
        v = run_config.get("attack-malicious-fraction-cap")
        try:
            fv = float(v)
            if fv >= 0.0:
                malicious_fraction_cap = fv
        except Exception:
            pass
    if "attack-selection-mode" in run_config:
        v = str(run_config.get("attack-selection-mode") or "").strip().lower()
        if v:
            selection_mode = v
    if "attack-deterministic-per-round" in run_config:
        v = run_config.get("attack-deterministic-per-round")
        if isinstance(v, bool):
            deterministic_per_round = bool(v)

    # Optional selection policy overrides via run_config
    if "attack-sticky-rounds" in run_config:
        v = run_config.get("attack-sticky-rounds")
        try:
            iv = int(v)
            if iv > 0:
                sticky_rounds = iv
        except Exception:
            pass
    if "attack-churn-fraction" in run_config:
        v = run_config.get("attack-churn-fraction")
        try:
            fv = float(v)
            if fv >= 0.0:
                churn_fraction = fv
        except Exception:
            pass
    if "attack-churn-min-replace" in run_config:
        v = run_config.get("attack-churn-min-replace")
        try:
            iv = int(v)
            if iv >= 0:
                churn_min_replace = iv
        except Exception:
            pass
    if "attack-cooldown-rounds" in run_config:
        v = run_config.get("attack-cooldown-rounds")
        try:
            iv = int(v)
            if iv >= 0:
                cooldown_rounds = iv
        except Exception:
            pass
    if "attack-mode" in run_config:
        v = str(run_config.get("attack-mode") or "").strip().lower()
        if v:
            mode = v
            if mode == "random":
                mode = "weighted_random"

    if "attack-layering-mode" in run_config:
        v = str(run_config.get("attack-layering-mode") or "").strip().lower()
        if v:
            layering_mode = v
            if layering_mode in {"none", "off", "disabled"}:
                layering_mode = "single"
    if "attack-layered-k" in run_config:
        v = run_config.get("attack-layered-k")
        try:
            iv = int(v)
            if iv > 0:
                layered_k = int(max(1, iv))
        except Exception:
            pass
    if "attack-layered-attacks" in run_config:
        v = str(run_config.get("attack-layered-attacks") or "").strip()
        if v:
            # Accept comma/space separated list.
            parts = [p.strip().lower() for p in re.split(r"[\s,]+", v) if p.strip()]
            if parts:
                layered_attacks = parts

    # Optional per-layer intensity overrides via run_config.
    for layer_name in ("gaussian_noise", "sign_flip", "alie", "mean_shift", "label_flip", "backdoor"):
        key = f"attack-layer-intensity-{layer_name}"
        alt_key = f"attack-layer-intensity-{layer_name.replace('_', '-')}"
        for lookup_key in (key, alt_key):
            if lookup_key in run_config:
                try:
                    fv = float(run_config.get(lookup_key))
                    if fv >= 0.0:
                        if layer_intensity_multipliers is None:
                            layer_intensity_multipliers = {}
                        layer_intensity_multipliers[layer_name] = fv
                except Exception:
                    pass

    if "attack-random-intensity-mode" in run_config:
        v = str(run_config.get("attack-random-intensity-mode") or "").strip().lower()
        if v:
            random_intensity_mode = v
    if "attack-random-intensity-value" in run_config:
        try:
            random_intensity_value = float(run_config.get("attack-random-intensity-value"))
        except Exception:
            pass
    if "attack-random-intensity-min" in run_config:
        try:
            random_intensity_min = float(run_config.get("attack-random-intensity-min"))
        except Exception:
            pass
    if "attack-random-intensity-max" in run_config:
        try:
            random_intensity_max = float(run_config.get("attack-random-intensity-max"))
        except Exception:
            pass
    if "attack-random-relative-to-update-norm-prob" in run_config:
        try:
            rrtnp = float(run_config.get("attack-random-relative-to-update-norm-prob"))
        except Exception:
            pass

    if "attack-intensity-cap" in run_config:
        v = run_config.get("attack-intensity-cap")
        try:
            fv = float(v)
            if fv >= 0.0:
                intensity_cap = fv
        except Exception:
            pass
    if "attack-intensity-ramp-mode" in run_config:
        v = str(run_config.get("attack-intensity-ramp-mode") or "").strip().lower()
        if v:
            intensity_ramp_mode = v
    if "attack-intensity-ramp-start-round" in run_config:
        v = run_config.get("attack-intensity-ramp-start-round")
        try:
            iv = int(v)
            if iv > 0:
                intensity_ramp_start_round = iv
        except Exception:
            pass
    if "attack-intensity-ramp-end-round" in run_config:
        v = run_config.get("attack-intensity-ramp-end-round")
        try:
            iv = int(v)
            if iv >= 0:
                intensity_ramp_end_round = iv
        except Exception:
            pass
    if "attack-intensity-ramp-multiplier-start" in run_config:
        v = run_config.get("attack-intensity-ramp-multiplier-start")
        try:
            fv = float(v)
            if fv > 0.0:
                intensity_ramp_multiplier_start = fv
        except Exception:
            pass
    if "attack-intensity-ramp-multiplier-end" in run_config:
        v = run_config.get("attack-intensity-ramp-multiplier-end")
        try:
            fv = float(v)
            if fv > 0.0:
                intensity_ramp_multiplier_end = fv
        except Exception:
            pass
    if "attack-intensity-fail-escalation" in run_config:
        v = run_config.get("attack-intensity-fail-escalation")
        if isinstance(v, bool):
            intensity_fail_escalation = bool(v)
    if "attack-intensity-fail-multiplier-step" in run_config:
        v = run_config.get("attack-intensity-fail-multiplier-step")
        try:
            fv = float(v)
            if fv >= 0.0:
                intensity_fail_multiplier_step = fv
        except Exception:
            pass
    if "attack-intensity-fail-multiplier-max" in run_config:
        v = run_config.get("attack-intensity-fail-multiplier-max")
        try:
            fv = float(v)
            if fv >= 1.0:
                intensity_fail_multiplier_max = fv
        except Exception:
            pass

    weights_raw = (attack.get("weights") or {}) if isinstance(attack.get("weights"), dict) else {}
    weights: Dict[str, float] = {}
    for k, v in weights_raw.items():
        try:
            weights[str(k).strip().lower()] = float(v)
        except Exception:
            continue

    # Phases
    phases: List[AttackPhase] = []
    phases_raw = attack.get("phases") or []
    if isinstance(phases_raw, list):
        for p in phases_raw:
            if not isinstance(p, dict):
                continue
            start_round = int(p.get("start_round", 1))
            end_round = int(p.get("end_round", start_round))
            attack_name = str(p.get("attack_name", "none")).strip().lower()
            intensity_schedule = str(p.get("intensity_schedule", "constant")).strip().lower()
            phases.append(
                AttackPhase(
                    start_round=start_round,
                    end_round=end_round,
                    attack_name=attack_name,
                    intensity_schedule=intensity_schedule,
                    intensity_value=float(p.get("intensity_value", p.get("intensity", 1.0)) or 1.0),
                    intensity_start=float(p.get("intensity_start", 0.0) or 0.0),
                    intensity_end=float(p.get("intensity_end", 1.0) or 1.0),
                    step_points=[int(x) for x in (p.get("step_points") or [])]
                    if isinstance(p.get("step_points"), list)
                    else None,
                    step_values=[float(x) for x in (p.get("step_values") or [])]
                    if isinstance(p.get("step_values"), list)
                    else None,
                    periodic_base=float(p.get("periodic_base", 0.0) or 0.0),
                    periodic_amp=float(p.get("periodic_amp", 1.0) or 1.0),
                    periodic_period=int(p.get("periodic_period", p.get("period", 10)) or 10),
                    relative_to_update_norm=bool(p.get("relative_to_update_norm", False)),
                )
            )

    # Optional windows
    windows: List[AttackWindow] = []
    windows_raw = attack.get("windows") or []
    if isinstance(windows_raw, list):
        for w in windows_raw:
            if not isinstance(w, dict):
                continue
            windows.append(
                AttackWindow(
                    start_round=int(w.get("start_round", 1)),
                    end_round=int(w.get("end_round", 10**9)),
                )
            )

    # Optional per-run overrides for a single global attack window.
    # This lets sweep scripts vary the window without editing TOML.
    window_start_override = run_config.get("attack-window-start-round")
    window_end_override = run_config.get("attack-window-end-round")
    if window_start_override is not None or window_end_override is not None:
        try:
            start_override = int(window_start_override) if window_start_override is not None else None
        except Exception:
            start_override = None
        try:
            end_override = int(window_end_override) if window_end_override is not None else None
        except Exception:
            end_override = None

        if start_override is not None and start_override > 0:
            end_final = end_override if end_override is not None and end_override >= start_override else 10**9
            windows = [AttackWindow(start_round=start_override, end_round=end_final)]
        elif end_override is not None and end_override > 0:
            windows = [AttackWindow(start_round=1, end_round=end_override)]

    attacks = attack.get("attacks") or {}
    if not isinstance(attacks, dict):
        attacks = {}

    gn = attacks.get("gaussian_noise") or {}
    sf = attacks.get("sign_flip") or {}
    lf = attacks.get("label_flip") or {}
    bd = attacks.get("backdoor") or {}
    al = attacks.get("alie") or {}
    ms = attacks.get("mean_shift") or {}

    gaussian_noise = GaussianNoiseAttackConfig(
        enabled=bool((gn.get("enabled", True))),
        sigma=float(gn.get("sigma", 0.5) or 0.5),
        relative=bool(gn.get("relative", True)),
    )
    sign_flip = SignFlipAttackConfig(
        enabled=bool(sf.get("enabled", True)),
        alpha=float(sf.get("alpha", 1.0) or 1.0),
    )
    label_flip = LabelFlipAttackConfig(
        enabled=bool(lf.get("enabled", False)),
        flip_rate=float(lf.get("flip_rate", 0.2) or 0.2),
        targeted=bool(lf.get("targeted", False)),
        source_class=int(lf.get("source_class", 0) or 0),
        target_class=int(lf.get("target_class", 1) or 1),
    )
    backdoor = BackdoorAttackConfig(
        enabled=bool(bd.get("enabled", False)),
        poison_rate=float(bd.get("poison_rate", 0.1) or 0.1),
        target_label=int(bd.get("target_label", 0) or 0),
        trigger_type=str(bd.get("trigger_type", "patch") or "patch"),
        patch_size=int(bd.get("patch_size", 4) or 4),
        blend_alpha=float(bd.get("blend_alpha", 0.2) or 0.2),
    )

    alie = AlieAttackConfig(
        enabled=bool(al.get("enabled", False)),
        z=float(al.get("z", -2.0) or -2.0),
    )
    mean_shift = MeanShiftAttackConfig(
        enabled=bool(ms.get("enabled", False)),
        beta=float(ms.get("beta", 1.0) or 1.0),
    )

    # Apply preset last so it's a true override.
    # This can toggle enable flags + weights and (for stress presets) bump strengths.
    def apply_preset(p: str) -> None:
        nonlocal enabled, weights, gaussian_noise, sign_flip, label_flip, backdoor, alie, mean_shift
        nonlocal malicious_fraction_mode, malicious_fraction_min, malicious_fraction_max
        nonlocal random_intensity_mode, random_intensity_min, random_intensity_max, stealth_mode, stealth_norm_quantile, stealth_norm_multiplier
        p = str(p or "custom").strip().lower()
        if p in {"custom", ""}:
            return
        if p in {"off", "none", "disable", "disabled"}:
            enabled = False
            weights = {
                "gaussian_noise": 0.0,
                "sign_flip": 0.0,
                "label_flip": 0.0,
                "backdoor": 0.0,
                "alie": 0.0,
                "mean_shift": 0.0,
            }
            return

        enabled = True

        def set_enabled(gn2: bool, sf2: bool, lf2: bool, bd2: bool, al2: bool, ms2: bool) -> None:
            nonlocal gaussian_noise, sign_flip, label_flip, backdoor, alie, mean_shift
            gaussian_noise = GaussianNoiseAttackConfig(
                enabled=bool(gn2),
                sigma=float(gaussian_noise.sigma),
                relative=bool(gaussian_noise.relative),
            )
            sign_flip = SignFlipAttackConfig(
                enabled=bool(sf2),
                alpha=float(sign_flip.alpha),
            )
            label_flip = LabelFlipAttackConfig(
                enabled=bool(lf2),
                flip_rate=float(label_flip.flip_rate),
                targeted=bool(label_flip.targeted),
                source_class=int(label_flip.source_class),
                target_class=int(label_flip.target_class),
            )
            backdoor = BackdoorAttackConfig(
                enabled=bool(bd2),
                poison_rate=float(backdoor.poison_rate),
                target_label=int(backdoor.target_label),
                trigger_type=str(backdoor.trigger_type),
                patch_size=int(backdoor.patch_size),
                blend_alpha=float(backdoor.blend_alpha),
            )
            alie = AlieAttackConfig(
                enabled=bool(al2),
                z=float(alie.z),
            )
            mean_shift = MeanShiftAttackConfig(
                enabled=bool(ms2),
                beta=float(mean_shift.beta),
            )

        if p in {"all", "chaos", "full"}:
            set_enabled(True, True, True, True, True, True)
            weights = {
                "gaussian_noise": 1.0,
                "sign_flip": 1.0,
                "label_flip": 1.0,
                "backdoor": 1.0,
                "alie": 1.0,
                "mean_shift": 1.0,
            }
            return
        if p in {"update_only", "update-poison-only", "update_poison_only"}:
            set_enabled(True, True, False, False, True, True)
            weights = {
                "gaussian_noise": 1.0,
                "sign_flip": 1.0,
                "label_flip": 0.0,
                "backdoor": 0.0,
                "alie": 1.0,
                "mean_shift": 1.0,
            }
            return
        if p in {"data_only", "data-poison-only", "data_poison_only"}:
            set_enabled(False, False, True, True, False, False)
            weights = {
                "gaussian_noise": 0.0,
                "sign_flip": 0.0,
                "label_flip": 1.0,
                "backdoor": 1.0,
                "alie": 0.0,
                "mean_shift": 0.0,
            }
            return
        if p in {"stress", "stress_adaptive", "stress_stealth"}:
            # Aggressive defaults intended to *break* defenses.
            set_enabled(True, True, True, True, True, True)
            weights = {
                "gaussian_noise": 1.0,
                "sign_flip": 1.0,
                "label_flip": 1.0,
                "backdoor": 1.0,
                "alie": 1.0,
                "mean_shift": 1.0,
            }
            malicious_fraction_mode = "uniform"
            malicious_fraction_min = float(max(0.0, malicious_fraction_min, 0.25))
            malicious_fraction_max = float(max(malicious_fraction_max, 0.6))
            random_intensity_mode = "uniform"
            random_intensity_min = float(max(random_intensity_min, 1.0))
            random_intensity_max = float(max(random_intensity_max, 3.0))
            stealth_mode = True
            stealth_norm_quantile = float(stealth_norm_quantile if 0.0 < stealth_norm_quantile <= 1.0 else 0.9)
            stealth_norm_multiplier = float(max(0.5, stealth_norm_multiplier))
            gaussian_noise = GaussianNoiseAttackConfig(enabled=True, sigma=2.0, relative=True)
            sign_flip = SignFlipAttackConfig(enabled=True, alpha=2.0)
            label_flip = LabelFlipAttackConfig(
                enabled=True,
                flip_rate=max(float(label_flip.flip_rate), 0.6),
                targeted=bool(label_flip.targeted),
                source_class=int(label_flip.source_class),
                target_class=int(label_flip.target_class),
            )
            backdoor = BackdoorAttackConfig(
                enabled=True,
                poison_rate=max(float(backdoor.poison_rate), 0.5),
                target_label=int(backdoor.target_label),
                trigger_type=str(backdoor.trigger_type),
                patch_size=int(backdoor.patch_size),
                blend_alpha=max(float(backdoor.blend_alpha), 0.8),
            )
            alie = AlieAttackConfig(enabled=True, z=float(alie.z if alie.z != 0 else -2.0))
            mean_shift = MeanShiftAttackConfig(enabled=True, beta=max(float(mean_shift.beta), 2.0))
            return
        if p in {"noise_only", "gaussian_only", "gaussian_noise_only"}:
            set_enabled(True, False, False, False, False, False)
            weights = {
                "gaussian_noise": 1.0,
                "sign_flip": 0.0,
                "label_flip": 0.0,
                "backdoor": 0.0,
                "alie": 0.0,
                "mean_shift": 0.0,
            }
            return
        if p in {"sign_flip_only", "signflip_only"}:
            set_enabled(False, True, False, False, False, False)
            weights = {
                "gaussian_noise": 0.0,
                "sign_flip": 1.0,
                "label_flip": 0.0,
                "backdoor": 0.0,
                "alie": 0.0,
                "mean_shift": 0.0,
            }
            return
        if p in {"label_only", "label_flip_only", "labelflip_only"}:
            set_enabled(False, False, True, False, False, False)
            weights = {
                "gaussian_noise": 0.0,
                "sign_flip": 0.0,
                "label_flip": 1.0,
                "backdoor": 0.0,
                "alie": 0.0,
                "mean_shift": 0.0,
            }
            return
        if p in {"backdoor_only"}:
            set_enabled(False, False, False, True, False, False)
            weights = {
                "gaussian_noise": 0.0,
                "sign_flip": 0.0,
                "label_flip": 0.0,
                "backdoor": 1.0,
                "alie": 0.0,
                "mean_shift": 0.0,
            }
            return

    apply_preset(preset)

    # Defaults if empty
    if not weights:
        weights = {
            "gaussian_noise": 0.5,
            "sign_flip": 0.5,
            "label_flip": 0.0,
            "backdoor": 0.0,
            "alie": 0.0,
            "mean_shift": 0.0,
        }
    if not phases:
        phases = [AttackPhase(start_round=1, end_round=10**9, attack_name="none")]

    return AttackConfig(
        enabled=enabled,
        seed=seed,
        log_level=log_level,
        malicious_fraction=float(malicious_fraction),
        malicious_fraction_mode=str(malicious_fraction_mode),
        malicious_fraction_min=float(malicious_fraction_min),
        malicious_fraction_max=float(malicious_fraction_max),
        malicious_fraction_choices=malicious_fraction_choices,
        malicious_fraction_ramp_mode=str(malicious_fraction_ramp_mode or "none"),
        malicious_fraction_ramp_start_round=int(max(1, malicious_fraction_ramp_start_round))
        if int(malicious_fraction_ramp_start_round) > 0
        else 1,
        malicious_fraction_ramp_end_round=int(max(0, malicious_fraction_ramp_end_round)),
        malicious_fraction_ramp_value_start=float(max(0.0, malicious_fraction_ramp_value_start)),
        malicious_fraction_ramp_value_end=float(max(0.0, malicious_fraction_ramp_value_end)),
        malicious_fraction_cap=float(max(0.0, malicious_fraction_cap)),
        selection_mode=selection_mode,
        deterministic_per_round=bool(deterministic_per_round),
        sticky_rounds=int(max(1, sticky_rounds)) if int(sticky_rounds) > 0 else 1,
        churn_fraction=float(max(0.0, min(1.0, churn_fraction))),
        churn_min_replace=int(max(0, churn_min_replace)),
        cooldown_rounds=int(max(0, cooldown_rounds)),
        mode=mode,
        weights=weights,
        phases=phases,
        windows=windows,
        random_intensity_mode=str(random_intensity_mode),
        random_intensity_value=float(random_intensity_value),
        random_intensity_min=float(random_intensity_min),
        random_intensity_max=float(random_intensity_max),
        random_intensity_choices=random_intensity_choices,
        random_relative_to_update_norm_probability=float(rrtnp),
        intensity_cap=float(max(0.0, intensity_cap)),
        intensity_ramp_mode=str(intensity_ramp_mode or "none"),
        intensity_ramp_start_round=int(max(1, intensity_ramp_start_round))
        if int(intensity_ramp_start_round) > 0
        else 1,
        intensity_ramp_end_round=int(max(0, intensity_ramp_end_round)),
        intensity_ramp_multiplier_start=float(max(0.0, intensity_ramp_multiplier_start)),
        intensity_ramp_multiplier_end=float(max(0.0, intensity_ramp_multiplier_end)),
        intensity_fail_escalation=bool(intensity_fail_escalation),
        intensity_fail_multiplier_step=float(max(0.0, intensity_fail_multiplier_step)),
        intensity_fail_multiplier_max=float(max(1.0, intensity_fail_multiplier_max)),
        adaptive_metric=str(adaptive_metric),
        adaptive_goal=str(adaptive_goal),
        adaptive_target=float(adaptive_target),
        adaptive_epsilon=float(adaptive_epsilon),
        adaptive_min_delta=float(adaptive_min_delta),
        adaptive_patience=int(max(0, adaptive_patience)),
        adaptive_window=int(max(0, adaptive_window)),
        adaptive_burn_in_rounds=int(max(0, adaptive_burn_in_rounds)),
        stealth_mode=bool(stealth_mode),
        stealth_norm_quantile=float(stealth_norm_quantile),
        stealth_norm_multiplier=float(stealth_norm_multiplier),
        gaussian_noise=gaussian_noise,
        sign_flip=sign_flip,
        label_flip=label_flip,
        backdoor=backdoor,
        alie=alie,
        mean_shift=mean_shift,

        layering_mode=str(layering_mode),
        layered_attacks=layered_attacks,
        layered_k=int(layered_k),

        layer_intensity_multipliers=layer_intensity_multipliers,

        layer_multiplier_schedules=layer_multiplier_schedules,
    )


def load_defense_config(*, run_config: Dict[str, Any]) -> DefenseConfig:
    """Load server-side defense config from pyproject.toml.

    `run_config` is accepted for future CLI overrides; currently only `defense-enabled`
    is supported as a convenience.
    """

    root = _find_project_root()
    pyproject = root / "pyproject.toml"
    defense: Dict[str, Any] = {}
    if pyproject.exists():
        data = _read_toml(pyproject)
        defense = ((data.get("tool") or {}).get("flwr") or {}).get("defense") or {}

    def get_bool(key: str, default: bool) -> bool:
        try:
            return bool(defense.get(key, default))
        except Exception:
            return bool(default)

    def get_int(key: str, default: int) -> int:
        try:
            return int(defense.get(key, default))
        except Exception:
            return int(default)

    def get_float(key: str, default: float) -> float:
        try:
            return float(defense.get(key, default))
        except Exception:
            return float(default)

    enabled = get_bool("enabled", False)
    mode = str(defense.get("mode", "none") or "none").strip().lower()
    drop_non_finite = get_bool("drop_non_finite", True)
    mad_z = get_float("mad_z", 3.5)
    max_reject_fraction = get_float("max_reject_fraction", 0.2)
    min_clients_after_filter = get_int("min_clients_after_filter", 2)

    # Optional override from Flower run_config
    if "defense-enabled" in run_config and isinstance(run_config.get("defense-enabled"), bool):
        enabled = bool(run_config.get("defense-enabled"))

    return DefenseConfig(
        enabled=bool(enabled),
        mode=str(mode or "none"),
        drop_non_finite=bool(drop_non_finite),
        mad_z=float(max(0.0, mad_z)),
        max_reject_fraction=float(max(0.0, min(1.0, max_reject_fraction))),
        min_clients_after_filter=int(max(0, min_clients_after_filter)),
    )


def _round_in_windows(server_round: int, windows: List[AttackWindow]) -> bool:
    if not windows:
        return True
    for w in windows:
        if w.start_round <= server_round <= w.end_round:
            return True
    return False


def _find_phase(server_round: int, phases: List[AttackPhase]) -> AttackPhase:
    for p in phases:
        if p.start_round <= server_round <= p.end_round:
            return p
    # Fallback
    return phases[-1]


def _compute_intensity(server_round: int, phase: AttackPhase) -> float:
    sched = (phase.intensity_schedule or "constant").strip().lower()
    if sched in {"constant", "const"}:
        return float(phase.intensity_value)
    if sched in {"linear", "linear_ramp", "ramp"}:
        span = max(1, phase.end_round - phase.start_round)
        t = (server_round - phase.start_round) / float(span)
        return float(phase.intensity_start + t * (phase.intensity_end - phase.intensity_start))
    if sched in {"step", "stairs"}:
        pts = phase.step_points or []
        vals = phase.step_values or []
        if not pts or not vals or len(pts) != len(vals):
            return float(phase.intensity_value)
        chosen = vals[0]
        for r, v in zip(pts, vals):
            if server_round >= int(r):
                chosen = float(v)
        return float(chosen)
    if sched in {"periodic", "sin", "sine"}:
        period = max(1, int(phase.periodic_period))
        x = (server_round - phase.start_round) / float(period)
        return float(phase.periodic_base + phase.periodic_amp * math.sin(2.0 * math.pi * x))
    return float(phase.intensity_value)


def _stable_int_seed(seed: int, server_round: int, node_id: int, salt: int) -> int:
    # Deterministic across runs and processes
    return int((seed * 1000003 + server_round * 9176 + node_id * 1315423911 + salt) & 0xFFFFFFFF)


class AttackRecorder:
    def __init__(self, *, artifact_dir: Path, resolved_config: Dict[str, Any], attack_config: AttackConfig):
        self.artifact_dir = artifact_dir
        self.summaries_dir = artifact_dir / "summaries"
        self.summaries_dir.mkdir(parents=True, exist_ok=True)
        # Also mirror into the runner's graph folders for convenience
        self.graphs_summaries_dir = artifact_dir / "graphs" / "summaries"
        self.graphs_agg_server_dir = artifact_dir / "graphs" / "aggregated_server"
        self.graphs_summaries_dir.mkdir(parents=True, exist_ok=True)
        self.graphs_agg_server_dir.mkdir(parents=True, exist_ok=True)

        self.jsonl_path = self.summaries_dir / "attack_log.jsonl"
        self.csv_path = self.summaries_dir / "attack_timeline.csv"
        self.defense_csv_path = self.summaries_dir / "defense_selection_by_round.csv"
        self.attack_by_client_csv_path = self.summaries_dir / "attack_by_client_round.csv"
        self.summary_path = self.summaries_dir / "run_config_and_summary.json"
        self.md_path = self.summaries_dir / "attack_summary.md"
        self.attack_config = attack_config
        self.resolved_config = resolved_config

        self.records: List[Dict[str, Any]] = []
        if not self.csv_path.exists():
            self.csv_path.write_text(
                "round,attack_name,intensity,malicious_fraction_used,attack_active,mechanism,param_effective,malicious_client_ids,malicious_client_numbers,num_selected_clients,num_malicious,max_norm,max_norm_client_id,max_norm_client_number,max_norm_client_is_malicious,max_mal_norm_pre,max_mal_norm_post\n",
                encoding="utf-8",
            )

        if not self.defense_csv_path.exists():
            self.defense_csv_path.write_text(
                "round,defense_strategy,num_selected_by_defense,num_malicious_selected_by_defense,malicious_selected_fraction,selected_client_ids,selected_client_numbers\n",
                encoding="utf-8",
            )

        if not self.attack_by_client_csv_path.exists():
            self.attack_by_client_csv_path.write_text(
                "round,attack_name,client_number,src_node_id,is_malicious,attack_active,attack_layers,intensity,relative_to_update_norm,"
                "label_flip_flip_rate,label_flip_flip_rate_effective,label_flip_targeted,label_flip_source_class,label_flip_target_class,"
                "backdoor_poison_rate,backdoor_poison_rate_effective,backdoor_blend_alpha,backdoor_blend_alpha_effective,"
                "backdoor_target_label,backdoor_trigger_type,backdoor_patch_size,attack_layer_intensities\n",
                encoding="utf-8",
            )

    def _client_number_map(self) -> Dict[int, int]:
        """Stable, human-friendly client numbering (1..N) for this run.

        We derive it from the sorted union of server-visible client IDs seen so far.
        In typical simulations, all clients appear in round 1 so this is stable.
        """

        ids: set[int] = set()
        for r in self.records:
            for x in (r.get("selected_client_ids") or []):
                try:
                    ids.add(int(x))
                except Exception:
                    pass
        return {cid: i + 1 for i, cid in enumerate(sorted(ids))}

    def _write_client_number_map_csv(self) -> None:
        m = self._client_number_map()
        p = self.summaries_dir / "client_number_map.csv"
        lines = ["client_number,src_node_id\n"]
        for cid, num in sorted(((cid, num) for cid, num in m.items()), key=lambda x: x[1]):
            lines.append(f"{int(num)},{int(cid)}\n")
        p.write_text("".join(lines), encoding="utf-8")

    def _write_malicious_by_round_csv(self) -> None:
        m = self._client_number_map()
        p = self.summaries_dir / "malicious_clients_by_round.csv"
        lines = [
            "round,attack_name,intensity,malicious_fraction_used,malicious_k_target,num_malicious,malicious_client_numbers,malicious_client_ids\n"
        ]
        for r in self.records:
            rnd = int(r.get("round", 0))
            name = str(r.get("attack_name", "none"))
            intensity = float(r.get("intensity", 0.0))
            mf = float(r.get("malicious_fraction_used", 0.0) or 0.0)
            mk = int(r.get("malicious_k_target", 0) or 0)
            mids = [int(x) for x in (r.get("malicious_client_ids") or [])]
            nums = [m.get(cid) for cid in mids if cid in m]
            nums_s = ";".join(str(int(x)) for x in nums) if nums else ""
            mids_s = ";".join(str(int(x)) for x in mids) if mids else ""
            lines.append(
                f"{rnd},{name},{intensity:.10g},{mf:.10g},{mk},{int(r.get('num_malicious', 0))},{nums_s},{mids_s}\n"
            )
        p.write_text("".join(lines), encoding="utf-8")

    def _write_round_stats_csv(self) -> None:
        p = self.summaries_dir / "round_attack_stats.csv"
        lines = [
            "round,attack_name,mechanism,intensity,stealth_applied,stealth_cap,stealth_scale,"
            "num_selected_clients,num_malicious,malicious_fraction_used,malicious_k_target,"
            "defense_assumed_num_malicious_nodes,assumption_gap,"
            "honest_norm_p50,honest_norm_p90,honest_norm_max,"
            "max_mal_norm_pre,max_mal_norm_post\n"
        ]
        for r in self.records:
            rnd = int(r.get("round", 0) or 0)
            name = str(r.get("attack_name", "none"))
            details = r.get("attack_details") or {}
            mech = str(details.get("mechanism", "-")) if isinstance(details, dict) else "-"
            intensity = float(r.get("intensity", 0.0) or 0.0)
            stealth_applied = int(1 if bool(r.get("stealth_applied", False)) else 0)
            stealth_cap = float(r.get("stealth_cap", 0.0) or 0.0)
            stealth_scale = float(r.get("stealth_scale", 1.0) or 1.0)
            nsel = int(r.get("num_selected_clients", 0) or 0)
            nmal = int(r.get("num_malicious", 0) or 0)
            mf = float(r.get("malicious_fraction_used", 0.0) or 0.0)
            mk = int(r.get("malicious_k_target", 0) or 0)
            assumed = int(r.get("defense_assumed_num_malicious_nodes", 0) or 0)
            gap = int(r.get("defense_assumption_gap", 0) or 0)
            hp50 = float(r.get("honest_update_norm_p50", 0.0) or 0.0)
            hp90 = float(r.get("honest_update_norm_p90", 0.0) or 0.0)
            hmx = float(r.get("honest_update_norm_max", 0.0) or 0.0)
            mxm_pre = float(r.get("update_norm_max_malicious", 0.0) or 0.0)
            mxm_post_raw = r.get("update_norm_max_malicious_post", None)
            try:
                mxm_post = float(mxm_post_raw) if mxm_post_raw is not None else float("nan")
            except Exception:
                mxm_post = float("nan")
            lines.append(
                f"{rnd},{name},{mech},{intensity:.10g},{stealth_applied},{stealth_cap:.10g},{stealth_scale:.10g},"
                f"{nsel},{nmal},{mf:.10g},{mk},{assumed},{gap},"
                f"{hp50:.10g},{hp90:.10g},{hmx:.10g},{mxm_pre:.10g},{mxm_post:.10g}\n"
            )
        p.write_text("".join(lines), encoding="utf-8")

    def _write_poisoning_round_csv(self) -> None:
        """Per-round dataset-poisoning totals derived from client-side metrics."""
        p = self.summaries_dir / "round_poison_stats.csv"
        lines = [
            "round,attack_name,num_selected_clients,num_malicious,"
            "malicious_examples_seen,malicious_poisoned_examples,malicious_poisoned_fraction,"
            "malicious_poisoned_label_flip,malicious_poisoned_backdoor,"
            "all_examples_seen,all_poisoned_examples,all_poisoned_fraction\n"
        ]
        for r in self.records:
            rnd = int(r.get("round", 0) or 0)
            name = str(r.get("attack_name", "none"))
            nsel = int(r.get("num_selected_clients", 0) or 0)
            nmal = int(r.get("num_malicious", 0) or 0)

            m_seen = int(r.get("poison_malicious_examples_seen", 0) or 0)
            m_poison = int(r.get("poison_malicious_poisoned_examples", 0) or 0)
            m_plf = int(r.get("poison_malicious_poisoned_label_flip", 0) or 0)
            m_pbd = int(r.get("poison_malicious_poisoned_backdoor", 0) or 0)
            a_seen = int(r.get("poison_all_examples_seen", 0) or 0)
            a_poison = int(r.get("poison_all_poisoned_examples", 0) or 0)

            m_frac = float(m_poison) / float(m_seen) if m_seen > 0 else 0.0
            a_frac = float(a_poison) / float(a_seen) if a_seen > 0 else 0.0

            lines.append(
                f"{rnd},{name},{nsel},{nmal},"
                f"{m_seen},{m_poison},{m_frac:.10g},{m_plf},{m_pbd},"
                f"{a_seen},{a_poison},{a_frac:.10g}\n"
            )
        p.write_text("".join(lines), encoding="utf-8")

    def _write_poisoning_by_client_csv(self) -> None:
        """Per-round per-client poisoning counts (can be large but very useful)."""
        p = self.summaries_dir / "poisoning_by_client_round.csv"
        cmap = self._client_number_map()
        lines = [
            "round,attack_name,client_number,src_node_id,is_malicious,examples_seen,poisoned_examples,poisoned_label_flip,poisoned_backdoor\n"
        ]
        for r in self.records:
            rnd = int(r.get("round", 0) or 0)
            name = str(r.get("attack_name", "none"))
            per = r.get("poison_by_client") or {}
            if not isinstance(per, dict):
                continue
            for cid_s, d in per.items():
                try:
                    cid = int(cid_s)
                except Exception:
                    continue
                if not isinstance(d, dict):
                    continue
                num = int(cmap.get(cid, -1) or -1)
                is_mal = int(1 if bool(d.get("is_malicious", False)) else 0)
                seen = int(d.get("examples_seen", 0) or 0)
                pe = int(d.get("poisoned_examples", 0) or 0)
                plf = int(d.get("poisoned_label_flip_examples", 0) or 0)
                pbd = int(d.get("poisoned_backdoor_examples", 0) or 0)
                lines.append(f"{rnd},{name},{num},{cid},{is_mal},{seen},{pe},{plf},{pbd}\n")
        p.write_text("".join(lines), encoding="utf-8")

    def _write_attack_by_client_round_csv(self) -> None:
        """Per-round per-client attack assignments (what/when/how per client)."""
        p = self.summaries_dir / "attack_by_client_round.csv"
        cmap = self._client_number_map()
        lines = [
            "round,attack_name,client_number,src_node_id,is_malicious,attack_active,attack_layers,intensity,relative_to_update_norm,"
            "label_flip_flip_rate,label_flip_flip_rate_effective,label_flip_targeted,label_flip_source_class,label_flip_target_class,"
            "backdoor_poison_rate,backdoor_poison_rate_effective,backdoor_blend_alpha,backdoor_blend_alpha_effective,"
            "backdoor_target_label,backdoor_trigger_type,backdoor_patch_size,attack_layer_intensities\n"
        ]
        for r in self.records:
            rnd = int(r.get("round", 0) or 0)
            per = r.get("attack_by_client") or {}
            if not isinstance(per, dict):
                continue
            for cid_s, d in per.items():
                try:
                    cid = int(cid_s)
                except Exception:
                    continue
                if not isinstance(d, dict):
                    continue
                num = int(cmap.get(cid, -1) or -1)
                name = str(d.get("attack_name", r.get("attack_name", "none")) or "none")
                is_mal = int(1 if bool(d.get("is_malicious", False)) else 0)
                active = int(1 if bool(d.get("attack_active", False)) else 0)
                layers = d.get("attack_layers") or []
                if not isinstance(layers, list):
                    layers = []
                layers_s = ";".join(str(x) for x in layers if str(x).strip())
                intensity = float(d.get("intensity", 0.0) or 0.0)
                rel = int(1 if bool(d.get("relative_to_update_norm", False)) else 0)

                lf_rate = float(d.get("label_flip_flip_rate", 0.0) or 0.0)
                lf_eff = float(d.get("label_flip_flip_rate_effective", 0.0) or 0.0)
                lf_tgt = int(1 if bool(d.get("label_flip_targeted", False)) else 0)
                lf_src = int(d.get("label_flip_source_class", 0) or 0)
                lf_dst = int(d.get("label_flip_target_class", 0) or 0)

                bd_rate = float(d.get("backdoor_poison_rate", 0.0) or 0.0)
                bd_eff = float(d.get("backdoor_poison_rate_effective", 0.0) or 0.0)
                bd_alpha = float(d.get("backdoor_blend_alpha", 0.0) or 0.0)
                bd_alpha_eff = float(d.get("backdoor_blend_alpha_effective", 0.0) or 0.0)
                bd_label = int(d.get("backdoor_target_label", 0) or 0)
                bd_trigger = str(d.get("backdoor_trigger_type", "patch") or "patch")
                bd_patch = int(d.get("backdoor_patch_size", 0) or 0)

                ints = d.get("attack_layer_intensities") or {}
                if isinstance(ints, dict):
                    ints_s = ";".join(
                        f"{str(k).strip()}={float(v):.10g}"
                        for k, v in ints.items()
                        if str(k).strip()
                    )
                else:
                    ints_s = ""

                lines.append(
                    f"{rnd},{name},{num},{cid},{is_mal},{active},{layers_s},{intensity:.10g},{rel},"
                    f"{lf_rate:.10g},{lf_eff:.10g},{lf_tgt},{lf_src},{lf_dst},"
                    f"{bd_rate:.10g},{bd_eff:.10g},{bd_alpha:.10g},{bd_alpha_eff:.10g},"
                    f"{bd_label},{bd_trigger},{bd_patch},{ints_s}\n"
                )
        p.write_text("".join(lines), encoding="utf-8")

    def log_round(self, rec: Dict[str, Any]) -> None:
        self.records.append(rec)
        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

        # Keep auxiliary tables up to date for easy inspection
        self._write_client_number_map_csv()
        self._write_malicious_by_round_csv()
        self._write_round_stats_csv()
        self._write_poisoning_round_csv()
        self._write_poisoning_by_client_csv()
        self._write_attack_by_client_round_csv()

        # Append defense-selection trace (best-effort)
        try:
            defense = rec.get("defense_selection") or {}
            if isinstance(defense, dict):
                d_round = int(rec.get("round", 0) or 0)
                d_name = str(defense.get("defense_strategy", "-") or "-")
                d_sel = [int(x) for x in (defense.get("selected_client_ids") or [])]
                d_n = int(defense.get("num_selected", len(d_sel)) or len(d_sel))
                d_mal = int(defense.get("num_malicious_selected", 0) or 0)
                d_frac = float(defense.get("malicious_selected_fraction", 0.0) or 0.0)

                cmap = self._client_number_map()
                d_nums = [cmap.get(int(cid)) for cid in d_sel if int(cid) in cmap]
                d_nums_s = ";".join(str(int(x)) for x in d_nums) if d_nums else ""
                d_sel_s = ";".join(str(int(x)) for x in d_sel) if d_sel else ""

                with self.defense_csv_path.open("a", encoding="utf-8") as f:
                    f.write(f"{d_round},{d_name},{d_n},{d_mal},{d_frac:.10g},{d_sel_s},{d_nums_s}\n")
        except Exception:
            pass

        details = rec.get("attack_details") or {}
        if not isinstance(details, dict):
            details = {}
        attack_active = bool(details.get("attack_active", False))
        mechanism = str(details.get("mechanism", "-"))
        param_eff = "-"
        if mechanism == "gaussian_noise" and "sigma_effective" in details:
            try:
                param_eff = f"sigma_eff={float(details['sigma_effective']):.6g}"
            except Exception:
                param_eff = "sigma_eff=?"
        elif mechanism == "sign_flip" and "alpha_effective" in details:
            try:
                param_eff = f"alpha_eff={float(details['alpha_effective']):.6g}"
            except Exception:
                param_eff = "alpha_eff=?"
        elif mechanism == "alie" and "z_effective" in details:
            try:
                param_eff = f"z_eff={float(details['z_effective']):.6g}"
            except Exception:
                param_eff = "z_eff=?"
        elif mechanism == "mean_shift" and "beta_effective" in details:
            try:
                param_eff = f"beta_eff={float(details['beta_effective']):.6g}"
            except Exception:
                param_eff = "beta_eff=?"
        elif mechanism == "label_flip" and "flip_rate_effective" in details:
            try:
                param_eff = f"flip_rate_eff={float(details['flip_rate_effective']):.6g}"
            except Exception:
                param_eff = "flip_rate_eff=?"
        elif mechanism == "backdoor" and "poison_rate_effective" in details:
            try:
                pr = float(details["poison_rate_effective"])
                tl = int(details.get("target_label", -1))
                param_eff = f"poison_rate_eff={pr:.6g} target={tl}"
            except Exception:
                param_eff = "poison_rate_eff=?"

        malicious_ids = rec.get("malicious_client_ids") or []
        malicious_str = ";".join(str(x) for x in malicious_ids)

        cmap = self._client_number_map()
        mal_nums = [cmap.get(int(x)) for x in malicious_ids if int(x) in cmap]
        mal_nums_str = ";".join(str(int(x)) for x in mal_nums) if mal_nums else ""

        max_norm = float(rec.get("update_norm_max", 0.0))
        max_norm_client_id = int(rec.get("update_norm_max_client_id", -1) or -1)
        max_norm_client_number = int(cmap.get(max_norm_client_id, -1) or -1)
        max_norm_is_mal = int(1 if bool(rec.get("update_norm_max_client_is_malicious", False)) else 0)
        max_mal_pre = float(rec.get("update_norm_max_malicious", 0.0))
        max_mal_post_raw = rec.get("update_norm_max_malicious_post", None)
        try:
            max_mal_post = float(max_mal_post_raw) if max_mal_post_raw is not None else float("nan")
        except Exception:
            max_mal_post = float("nan")
        line = (
            f"{int(rec['round'])},{rec.get('attack_name','none')},{float(rec.get('intensity',0.0)):.10g},{float(rec.get('malicious_fraction_used',0.0)):.10g},"
            f"{int(1 if attack_active else 0)},{mechanism},{param_eff},{malicious_str},"
            f"{mal_nums_str},{int(rec.get('num_selected_clients',0))},{int(rec.get('num_malicious',0))},"
            f"{max_norm:.10g},{max_norm_client_id},{max_norm_client_number},{max_norm_is_mal},{max_mal_pre:.10g},{max_mal_post:.10g}\n"
        )
        with self.csv_path.open("a", encoding="utf-8") as f:
            f.write(line)

        self._write_summary_json()
        self._write_summary_md()

    def _write_summary_json(self) -> None:
        attack_counts: Dict[str, int] = {}
        ever_malicious: set[int] = set()
        mal_counts: List[int] = []

        defense_rounds_with_any_mal = 0
        defense_total_selected = 0
        defense_total_mal_selected = 0
        for r in self.records:
            name = str(r.get("attack_name", "none"))
            attack_counts[name] = attack_counts.get(name, 0) + 1
            mids = r.get("malicious_client_ids") or []
            for x in mids:
                try:
                    ever_malicious.add(int(x))
                except Exception:
                    pass
            mal_counts.append(int(r.get("num_malicious", 0)))

            dsel = r.get("defense_selection") or {}
            if isinstance(dsel, dict):
                n = int(dsel.get("num_selected", 0) or 0)
                m = int(dsel.get("num_malicious_selected", 0) or 0)
                if n > 0:
                    defense_total_selected += int(n)
                    defense_total_mal_selected += int(m)
                    if m > 0:
                        defense_rounds_with_any_mal += 1

        payload = {
            "resolved_attack_config": {
                "enabled": self.attack_config.enabled,
                "seed": self.attack_config.seed,
                "log_level": self.attack_config.log_level,
                "malicious_fraction": self.attack_config.malicious_fraction,
                "malicious_fraction_mode": self.attack_config.malicious_fraction_mode,
                "malicious_fraction_min": self.attack_config.malicious_fraction_min,
                "malicious_fraction_max": self.attack_config.malicious_fraction_max,
                "malicious_fraction_choices": self.attack_config.malicious_fraction_choices,
                "malicious_fraction_ramp_mode": getattr(self.attack_config, "malicious_fraction_ramp_mode", "none"),
                "malicious_fraction_ramp_start_round": getattr(
                    self.attack_config, "malicious_fraction_ramp_start_round", 1
                ),
                "malicious_fraction_ramp_end_round": getattr(self.attack_config, "malicious_fraction_ramp_end_round", 0),
                "malicious_fraction_ramp_value_start": getattr(
                    self.attack_config, "malicious_fraction_ramp_value_start", self.attack_config.malicious_fraction
                ),
                "malicious_fraction_ramp_value_end": getattr(
                    self.attack_config, "malicious_fraction_ramp_value_end", self.attack_config.malicious_fraction
                ),
                "malicious_fraction_cap": getattr(self.attack_config, "malicious_fraction_cap", 0.0),
                "selection_mode": self.attack_config.selection_mode,
                "sticky_rounds": getattr(self.attack_config, "sticky_rounds", 0),
                "churn_fraction": getattr(self.attack_config, "churn_fraction", 0.0),
                "churn_min_replace": getattr(self.attack_config, "churn_min_replace", 0),
                "cooldown_rounds": getattr(self.attack_config, "cooldown_rounds", 0),
                "deterministic_per_round": self.attack_config.deterministic_per_round,
                "mode": self.attack_config.mode,
                "weights": self.attack_config.weights,
                "phases": [p.__dict__ for p in self.attack_config.phases],
                "windows": [w.__dict__ for w in self.attack_config.windows],
                "random_intensity_mode": self.attack_config.random_intensity_mode,
                "random_intensity_value": self.attack_config.random_intensity_value,
                "random_intensity_min": self.attack_config.random_intensity_min,
                "random_intensity_max": self.attack_config.random_intensity_max,
                "random_intensity_choices": self.attack_config.random_intensity_choices,
                "random_relative_to_update_norm_probability": self.attack_config.random_relative_to_update_norm_probability,
                "stealth_mode": self.attack_config.stealth_mode,
                "stealth_norm_quantile": self.attack_config.stealth_norm_quantile,
                "stealth_norm_multiplier": self.attack_config.stealth_norm_multiplier,
                "attacks": {
                    "gaussian_noise": self.attack_config.gaussian_noise.__dict__,
                    "sign_flip": self.attack_config.sign_flip.__dict__,
                    "label_flip": self.attack_config.label_flip.__dict__,
                    "backdoor": self.attack_config.backdoor.__dict__,
                    "alie": self.attack_config.alie.__dict__,
                    "mean_shift": self.attack_config.mean_shift.__dict__,
                },
            },
            "run_config": self.resolved_config,
            "attack_frequency": attack_counts,
            "per_round_malicious_counts": mal_counts,
            "ever_malicious_client_ids": sorted(ever_malicious),
            "defense_selection_summary": {
                "rounds_with_any_malicious_selected": int(defense_rounds_with_any_mal),
                "total_selected_by_defense": int(defense_total_selected),
                "total_malicious_selected_by_defense": int(defense_total_mal_selected),
                "overall_malicious_selected_fraction": (
                    float(defense_total_mal_selected) / float(defense_total_selected)
                    if int(defense_total_selected) > 0
                    else 0.0
                ),
            },
        }
        self.summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _write_summary_md(self) -> None:
        # Human-readable report for quick visual/text confirmation.
        if not self.records:
            return

        enabled = bool(self.attack_config.enabled)
        seed = int(self.attack_config.seed)
        mode = str(self.attack_config.mode)
        sel = str(self.attack_config.selection_mode)
        sticky_rounds = int(getattr(self.attack_config, "sticky_rounds", 0) or 0)
        churn_fraction = float(getattr(self.attack_config, "churn_fraction", 0.0) or 0.0)
        cooldown_rounds = int(getattr(self.attack_config, "cooldown_rounds", 0) or 0)
        frac = float(self.attack_config.malicious_fraction)
        frac_mode = str(getattr(self.attack_config, "malicious_fraction_mode", "fixed"))
        frac_min = float(getattr(self.attack_config, "malicious_fraction_min", frac))
        frac_max = float(getattr(self.attack_config, "malicious_fraction_max", frac))
        frac_ramp_mode = str(getattr(self.attack_config, "malicious_fraction_ramp_mode", "none") or "none")
        frac_ramp_start = int(getattr(self.attack_config, "malicious_fraction_ramp_start_round", 1) or 1)
        frac_ramp_end = int(getattr(self.attack_config, "malicious_fraction_ramp_end_round", 0) or 0)
        frac_ramp_v0 = float(getattr(self.attack_config, "malicious_fraction_ramp_value_start", frac) or frac)
        frac_ramp_v1 = float(getattr(self.attack_config, "malicious_fraction_ramp_value_end", frac) or frac)
        frac_cap = float(getattr(self.attack_config, "malicious_fraction_cap", 0.0) or 0.0)
        rim = str(getattr(self.attack_config, "random_intensity_mode", "fixed"))
        rim_min = float(getattr(self.attack_config, "random_intensity_min", 0.0))
        rim_max = float(getattr(self.attack_config, "random_intensity_max", 1.0))

        lines: List[str] = []
        lines.append("# Attack Summary\n")
        lines.append(f"- enabled: `{enabled}`\n")
        lines.append(f"- seed: `{seed}`\n")
        lines.append(f"- mode: `{mode}`\n")
        lines.append(f"- selection_mode: `{sel}`\n")
        if sel in {"sticky_k", "sticky-window", "sticky_window"}:
            lines.append(f"- sticky_rounds: `{sticky_rounds}`\n")
        if sel in {"churn", "rotate", "rotating"}:
            lines.append(f"- churn_fraction: `{churn_fraction}`\n")
        if cooldown_rounds > 0:
            lines.append(f"- cooldown_rounds: `{cooldown_rounds}`\n")
        lines.append(f"- malicious_fraction: `{frac}`\n")
        lines.append(f"- malicious_fraction_mode: `{frac_mode}`\n")
        if frac_mode == "uniform":
            lines.append(f"- malicious_fraction_range: `[{frac_min}, {frac_max}]`\n")
        if str(frac_ramp_mode).strip().lower() not in {"", "none", "off", "disabled"}:
            lines.append(f"- malicious_fraction_ramp_mode: `{frac_ramp_mode}`\n")
            lines.append(f"- malicious_fraction_ramp_rounds: `[{frac_ramp_start}, {frac_ramp_end}]`\n")
            lines.append(f"- malicious_fraction_ramp_values: `[{frac_ramp_v0}, {frac_ramp_v1}]`\n")
            if frac_cap > 0.0:
                lines.append(f"- malicious_fraction_cap: `{frac_cap}`\n")
        if mode == "weighted_random":
            lines.append(f"- random_intensity_mode: `{rim}`\n")
            if rim == "uniform":
                lines.append(f"- random_intensity_range: `[{rim_min}, {rim_max}]`\n")
        lines.append("\n")

        # Quick aggregate counts
        attack_counts: Dict[str, int] = {}
        total_mal = 0
        all_selected: set[int] = set()
        ever_mal: set[int] = set()

        defense_rounds_with_selection = 0
        defense_rounds_with_any_mal = 0
        defense_total_selected = 0
        defense_total_mal_selected = 0
        for r in self.records:
            name = str(r.get("attack_name", "none"))
            attack_counts[name] = attack_counts.get(name, 0) + 1
            total_mal += int(r.get("num_malicious", 0))
            for x in (r.get("selected_client_ids") or []):
                try:
                    all_selected.add(int(x))
                except Exception:
                    pass
            for x in (r.get("malicious_client_ids") or []):
                try:
                    ever_mal.add(int(x))
                except Exception:
                    pass

            dsel = r.get("defense_selection") or {}
            if isinstance(dsel, dict):
                try:
                    n = int(dsel.get("num_selected", 0) or 0)
                    m = int(dsel.get("num_malicious_selected", 0) or 0)
                    if n > 0:
                        defense_rounds_with_selection += 1
                        defense_total_selected += int(n)
                        defense_total_mal_selected += int(m)
                        if m > 0:
                            defense_rounds_with_any_mal += 1
                except Exception:
                    pass
        lines.append("## Totals\n")
        lines.append(f"- rounds_logged: `{len(self.records)}`\n")
        lines.append(f"- total_malicious_selections: `{total_mal}`\n")
        lines.append("- attack_frequency:\n")
        for k in sorted(attack_counts.keys()):
            lines.append(f"  - `{k}`: `{attack_counts[k]}`\n")

        if defense_rounds_with_selection > 0 and defense_total_selected > 0:
            overall_frac = float(defense_total_mal_selected) / float(defense_total_selected)
            lines.append("- defense_selection:\n")
            lines.append(f"  - rounds_with_selection: `{defense_rounds_with_selection}`\n")
            lines.append(f"  - rounds_with_any_malicious_selected: `{defense_rounds_with_any_mal}`\n")
            lines.append(f"  - overall_malicious_selected_fraction: `{overall_frac:.6g}`\n")
        lines.append("\n")

        # Which clients are ever affected
        lines.append("## Affected Clients\n")
        lines.append(
            "- A client is considered *poisoned/affected* in a given round if it appears in `malicious_client_ids` for that round. Depending on the attack, this means either (a) it was instructed to poison its local training data (label_flip/backdoor) or (b) its update was modified server-side before aggregation (gaussian_noise/sign_flip).\n"
        )
        lines.append(
            "- Note: Flower's per-round `train_client` metrics (including `attack_is_malicious` and the `poisoned_*` counters) are aggregated by the *server strategy*. For robust aggregators (Krum/MultiKrum/Bulyan), this aggregation can effectively reflect only the subset of client updates chosen/used by the defense. As a result, these metrics can be `0` even when malicious clients were sampled and attacked in that round. For the ground-truth attack schedule, use `attack_timeline.csv`, `malicious_clients_by_round.csv`, and `poisoning_by_client_round.csv`.\n"
        )
        lines.append(f"- unique_selected_clients_seen: `{len(all_selected)}`\n")
        lines.append(f"- unique_malicious_clients_ever_selected: `{len(ever_mal)}`\n")
        lines.append(
            f"- ever_malicious_client_ids: `{';'.join(str(x) for x in sorted(ever_mal)) if ever_mal else '-'}`\n"
        )
        lines.append("\n")

        lines.append("## Client Numbering\n")
        lines.append(
            "- Logs use Flower's server-visible `src_node_id` (big integers). For readability, we also assign a stable `client_number` 1..N for this run.\n"
        )
        lines.append(
            "- See `client_number_map.csv` in this folder for the mapping.\n"
        )
        lines.append("\n")

        # Collapsed schedule table (much easier than reading plots)
        lines.append("## Schedule (Collapsed)\n")
        lines.append(
            "| start_round | end_round | attack | mechanism | intensity_min | intensity_max | total_mal_selections | unique_mal_clients |\n"
        )
        lines.append(
            "|---:|---:|---|---|---:|---:|---:|---:|\n"
        )

        recs_sorted = sorted(self.records, key=lambda r: int(r.get("round", 0)))
        seg_start = None
        seg_end = None
        seg_attack = None
        seg_mech = None
        seg_i_min = None
        seg_i_max = None
        seg_total_mal = 0
        seg_uniq_mal: set[int] = set()

        def _flush_segment() -> None:
            nonlocal seg_start, seg_end, seg_attack, seg_mech, seg_i_min, seg_i_max, seg_total_mal, seg_uniq_mal
            if seg_start is None:
                return
            lines.append(
                f"| {int(seg_start)} | {int(seg_end)} | `{seg_attack}` | `{seg_mech}` | {float(seg_i_min):.6g} | {float(seg_i_max):.6g} | {int(seg_total_mal)} | {int(len(seg_uniq_mal))} |\n"
            )
            seg_start = None
            seg_end = None
            seg_attack = None
            seg_mech = None
            seg_i_min = None
            seg_i_max = None
            seg_total_mal = 0
            seg_uniq_mal = set()

        for r in recs_sorted:
            rnd = int(r.get("round", 0))
            attack = str(r.get("attack_name", "none"))
            intensity = float(r.get("intensity", 0.0))
            details = r.get("attack_details") or {}
            mech = str(details.get("mechanism", "-")) if isinstance(details, dict) else "-"
            key = (attack, mech)
            if seg_start is None:
                seg_start = rnd
                seg_end = rnd
                seg_attack = attack
                seg_mech = mech
                seg_i_min = intensity
                seg_i_max = intensity
            elif key == (seg_attack, seg_mech) and rnd == int(seg_end) + 1:
                seg_end = rnd
                seg_i_min = float(min(float(seg_i_min), intensity))
                seg_i_max = float(max(float(seg_i_max), intensity))
            else:
                _flush_segment()
                seg_start = rnd
                seg_end = rnd
                seg_attack = attack
                seg_mech = mech
                seg_i_min = intensity
                seg_i_max = intensity

            seg_total_mal += int(r.get("num_malicious", 0))
            for x in (r.get("malicious_client_ids") or []):
                try:
                    seg_uniq_mal.add(int(x))
                except Exception:
                    pass
        _flush_segment()
        lines.append("\n")

        lines.append("## Meaning of Key Fields\n")
        lines.append(
            "- `intensity` is a unitless multiplier for attack strength. It does **not** mean \"% poisoned\".\n"
        )
        lines.append(
            "- For `sign_flip`: the malicious client delta $\\Delta$ becomes $-\\alpha_\\text{eff}\\Delta$ where $\\alpha_\\text{eff}=\\alpha\\cdot\\text{intensity}$.\n"
        )
        lines.append(
            "- For `gaussian_noise`: the malicious client delta becomes $\\Delta + \\epsilon$ where $\\epsilon\\sim\\mathcal{N}(0,\\sigma_\\text{eff}^2)$ and $\\sigma_\\text{eff}$ is what you see as `sigma_eff=...` in `param_effective`.\n"
        )
        lines.append(
            "- `median_norm`/`max_norm` summarize the L2 norms of client *deltas* (client update minus current global) for that round. These are outlier-style signals: unusually large norms can indicate unstable clients or attacks.\n"
        )
        lines.append("\n")

        # Per-round table
        lines.append("## Per-Round Timeline\n")
        lines.append(
            "| round | attack | intensity | mechanism | param_effective | #selected | #malicious | malicious_clients | median_norm | max_norm | max_norm_client | max_mal_norm_pre | max_mal_norm_post | top_norm_clients |\n"
        )
        lines.append(
            "|---:|---|---:|---|---|---:|---:|---|---:|---:|---|---:|---:|---|\n"
        )

        cmap = self._client_number_map()

        for r in self.records:
            rnd = int(r.get("round", 0))
            name = str(r.get("attack_name", "none"))
            intensity = float(r.get("intensity", 0.0))
            nsel = int(r.get("num_selected_clients", 0))
            nmal = int(r.get("num_malicious", 0))
            mids = [int(x) for x in (r.get("malicious_client_ids") or [])]
            mids_num = [cmap.get(cid) for cid in mids if cid in cmap]
            mids_num_s = ";".join(str(int(x)) for x in mids_num) if mids_num else ""
            mids_s = ";".join(str(x) for x in mids) if mids else ""
            mal_clients_s = (
                f"{mids_num_s} (ids: {mids_s})" if mids_num_s or mids_s else "-"
            )
            med = float(r.get("update_norm_median", 0.0))
            mx = float(r.get("update_norm_max", 0.0))
            mx_cid = int(r.get("update_norm_max_client_id", -1) or -1)
            mx_num = cmap.get(mx_cid)
            mx_is_mal = (mx_cid in mids)
            if mx_num is None:
                mx_cid_s = f"id:{mx_cid}{'*' if mx_is_mal else ''}" if mx_cid >= 0 else "-"
            else:
                mx_cid_s = f"{int(mx_num)} (id:{mx_cid}{'*' if mx_is_mal else ''})"
            mxm_pre = float(r.get("update_norm_max_malicious", 0.0))
            mxm_post_raw = r.get("update_norm_max_malicious_post", None)
            try:
                mxm_post = float(mxm_post_raw) if mxm_post_raw is not None else float("nan")
            except Exception:
                mxm_post = float("nan")

            details = r.get("attack_details") or {}
            mech = str(details.get("mechanism", "-")) if isinstance(details, dict) else "-"
            param_eff = "-"
            if isinstance(details, dict):
                if mech == "gaussian_noise" and "sigma_effective" in details:
                    try:
                        param_eff = f"sigma_eff={float(details['sigma_effective']):.3g}"
                    except Exception:
                        param_eff = "sigma_eff=?"
                if mech == "sign_flip" and "alpha_effective" in details:
                    try:
                        param_eff = f"alpha_eff={float(details['alpha_effective']):.3g}"
                    except Exception:
                        param_eff = "alpha_eff=?"
                if mech == "alie" and "z_effective" in details:
                    try:
                        param_eff = f"z_eff={float(details['z_effective']):.3g}"
                    except Exception:
                        param_eff = "z_eff=?"
                if mech == "mean_shift" and "beta_effective" in details:
                    try:
                        param_eff = f"beta_eff={float(details['beta_effective']):.3g}"
                    except Exception:
                        param_eff = "beta_eff=?"
                if mech == "label_flip" and "flip_rate_effective" in details:
                    try:
                        param_eff = f"flip_rate_eff={float(details['flip_rate_effective']):.3g}"
                    except Exception:
                        param_eff = "flip_rate_eff=?"
                if mech == "backdoor" and "poison_rate_effective" in details:
                    try:
                        param_eff = f"poison_rate_eff={float(details['poison_rate_effective']):.3g}"
                    except Exception:
                        param_eff = "poison_rate_eff=?"

            per = r.get("per_client_update_norm") or {}
            # top-5 by norm
            items: List[Tuple[int, float]] = []
            for k, v in per.items():
                try:
                    items.append((int(k), float(v)))
                except Exception:
                    continue
            items.sort(key=lambda x: x[1], reverse=True)
            top = []
            for cid, val in items[:5]:
                star = "*" if cid in mids else ""
                top.append(f"{cid}{star}:{val:.3g}")
            top_s = " ".join(top) if top else "-"

            if math.isnan(mxm_post):
                mxm_post_s = "-"
            else:
                mxm_post_s = f"{mxm_post:.3g}"

            lines.append(
                f"| {rnd} | `{name}` | {intensity:.6g} | `{mech}` | {param_eff} | {nsel} | {nmal} | {mal_clients_s} | {med:.3g} | {mx:.3g} | {mx_cid_s} | {mxm_pre:.3g} | {mxm_post_s} | {top_s} |\n"
            )

        lines.append("\n")
        lines.append("Notes:\n")
        lines.append("- `src_node_id` is the server-visible client identifier used in logs.\n")
        lines.append("- `top_norm_clients` marks malicious clients with `*`.\n")
        lines.append("- `max_mal_norm_pre` is computed before server-side update corruption; `max_mal_norm_post` is computed after corruption (only applicable to update-poisoning attacks).\n")

        self.md_path.write_text("".join(lines), encoding="utf-8")

    def finalize_and_plot(self) -> None:
        # Intentionally disabled: legacy plot generation lived under graphs/ and was
        # coupled to training. Plotting is now handled post-run by the runner
        # script via `pytorchexample.research_plots` into summaries/plots/.
        return


class AttackEngine:
    """Implements dynamic attack selection + injection and records provenance."""

    def __init__(
        self,
        *,
        run_config: Dict[str, Any],
        num_rounds: int,
    ) -> None:
        self.run_config = dict(run_config)
        self.num_rounds = int(num_rounds)
        self.attack_config = load_attack_config(run_config=self.run_config)

        artifact_dir_raw = self.run_config.get("artifact-dir") or self.run_config.get("artifact_dir")
        self.artifact_dir: Optional[Path] = Path(str(artifact_dir_raw)).resolve() if artifact_dir_raw else None

        self._sticky_malicious: Optional[List[int]] = None
        self._sticky_k_malicious: Optional[List[int]] = None
        self._sticky_k_window_start: Optional[int] = None
        self._prev_round_malicious: List[int] = []
        self._malicious_last_round: Dict[int, int] = {}
        self._last_global_state: Optional[Dict[str, torch.Tensor]] = None

        # Adaptive-mode bookkeeping (uses server evaluation metrics as feedback)
        self._attack_name_by_round: Dict[int, str] = {}
        self._eval_metrics_by_round: Dict[int, Dict[str, float]] = {}
        self._adaptive_rewards_by_attack: Dict[str, List[float]] = {}
        self._adaptive_current_attack: Optional[str] = None
        self._adaptive_consecutive_fails: int = 0

        # Cache per-round plan so configure_train and aggregate_train are consistent.
        self._round_plan: Dict[int, Dict[str, Any]] = {}
        # Per-round per-client attack assignments from configure_train.
        self._client_attack_by_round: Dict[int, Dict[int, Dict[str, Any]]] = {}

        self.recorder: Optional[AttackRecorder] = None
        if self.attack_config.enabled and self.artifact_dir is not None:
            self.recorder = AttackRecorder(
                artifact_dir=self.artifact_dir,
                resolved_config=self.run_config,
                attack_config=self.attack_config,
            )

        # Optional: defense-filter trace (logged by server strategy mixin).
        self._defense_filter_csv_path: Optional[Path] = None
        try:
            if self.artifact_dir is not None:
                p = self.artifact_dir / "summaries"
                p.mkdir(parents=True, exist_ok=True)
                self._defense_filter_csv_path = p / "defense_filter_by_round.csv"
                if not self._defense_filter_csv_path.exists():
                    self._defense_filter_csv_path.write_text(
                        "round,mode,num_before,num_after,num_rejected,kept_client_ids,rejected_client_ids,median_norm,mad,threshold,max_reject_fraction\n",
                        encoding="utf-8",
                    )
        except Exception:
            self._defense_filter_csv_path = None

    def log_defense_filter_round(
        self,
        *,
        server_round: int,
        mode: str,
        num_before: int,
        kept_client_ids: List[int],
        rejected_client_ids: List[int],
        median_norm: Optional[float] = None,
        mad: Optional[float] = None,
        threshold: Optional[float] = None,
        max_reject_fraction: Optional[float] = None,
    ) -> None:
        """Append a per-round defense-filter decision to summaries (best-effort)."""

        p = self._defense_filter_csv_path
        if p is None:
            return

        kept_s = ";".join(str(int(x)) for x in (kept_client_ids or []))
        rej_s = ";".join(str(int(x)) for x in (rejected_client_ids or []))
        n_after = int(len(kept_client_ids or []))
        n_rej = int(len(rejected_client_ids or []))
        try:
            med_s = "" if median_norm is None else f"{float(median_norm):.10g}"
        except Exception:
            med_s = ""
        try:
            mad_s = "" if mad is None else f"{float(mad):.10g}"
        except Exception:
            mad_s = ""
        try:
            thr_s = "" if threshold is None else f"{float(threshold):.10g}"
        except Exception:
            thr_s = ""
        try:
            mrf_s = "" if max_reject_fraction is None else f"{float(max_reject_fraction):.10g}"
        except Exception:
            mrf_s = ""

        try:
            with p.open("a", encoding="utf-8") as f:
                f.write(
                    f"{int(server_round)},{str(mode)},{int(num_before)},{n_after},{n_rej},"
                    f"{kept_s},{rej_s},{med_s},{mad_s},{thr_s},{mrf_s}\n"
                )
        except Exception:
            pass

    def _layer_schedule_multiplier(self, *, layer: str, server_round: int) -> float:
        """Return deterministic schedule multiplier for a given layer/round.

        Last matching schedule entry wins.
        """

        layer_key = str(layer or "").strip().lower().replace("-", "_")
        if not layer_key:
            return 1.0

        schedules = getattr(self.attack_config, "layer_multiplier_schedules", None) or []
        if not isinstance(schedules, list) or not schedules:
            return 1.0

        r = int(server_round)
        for sch in reversed(schedules):
            if not isinstance(sch, LayerMultiplierSchedule):
                continue
            if str(sch.layer).strip().lower().replace("-", "_") != layer_key:
                continue
            if int(sch.start_round) <= r <= int(sch.end_round):
                mode = str(sch.mode or "linear").strip().lower()
                if mode in {"constant", "const"}:
                    return float(max(0.0, float(sch.multiplier_value)))
                if mode in {"step", "stairs"}:
                    pts = sch.step_points or []
                    vals = sch.step_values or []
                    if pts and vals and len(pts) == len(vals):
                        chosen = float(vals[0])
                        for rr, vv in zip(pts, vals):
                            if r >= int(rr):
                                chosen = float(vv)
                        return float(max(0.0, chosen))
                    return float(max(0.0, float(sch.multiplier_value)))

                # linear/exp interpolation
                start_r = int(max(1, int(sch.start_round)))
                end_r = int(max(start_r, int(sch.end_round)))
                if r <= start_r:
                    t = 0.0
                elif r >= end_r:
                    t = 1.0
                else:
                    t = float(r - start_r) / float(max(1, end_r - start_r))

                m0 = float(max(0.0, float(sch.multiplier_start)))
                m1 = float(max(0.0, float(sch.multiplier_end)))
                if mode in {"exp", "exponential"} and m0 > 0.0 and m1 > 0.0:
                    return float(m0 * ((m1 / m0) ** t))
                return float(m0 + (m1 - m0) * t)

        return 1.0

    def set_current_global_arrays(self, arrays: Any) -> None:
        try:
            self._last_global_state = arrays.to_torch_state_dict()
        except Exception:
            self._last_global_state = None

    def _log(self, level: str, msg: str) -> None:
        levels = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
        cfg_level = levels.get(self.attack_config.log_level, 20)
        this_level = levels.get(level, 20)
        if this_level >= cfg_level:
            print(f"[attack:{level.lower()}] {msg}")

    def _choose_attack_layers_for_round(self, server_round: int) -> Tuple[List[str], float, bool]:
        """Return (attack_layers, intensity, relative_to_update_norm).

        `relative_to_update_norm` is only meaningful for gaussian_noise.
        """

        cfg = self.attack_config
        if not cfg.enabled:
            return ["none"], 0.0, False
        if not _round_in_windows(server_round, cfg.windows):
            return ["none"], 0.0, False

        # Choose a base attack and an intensity (as before)
        base_attack = "none"
        intensity = 0.0
        rel_to_norm = False
        if cfg.mode == "phase":
            phase = _find_phase(server_round, cfg.phases)
            base_attack = str(phase.attack_name or "none").strip().lower()
            intensity = float(_compute_intensity(server_round, phase))
            rel_to_norm = bool(phase.relative_to_update_norm)
        elif cfg.mode == "adaptive":
            base_attack = str(self._choose_attack_adaptive(server_round)).strip().lower()
            intensity = float(self._choose_intensity_for_round(server_round))
            rel_to_norm = bool(self._choose_rel_to_norm_for_round(server_round, base_attack))
        else:
            # weighted_random
            base_attack = str(self._choose_attack_weighted_random(server_round)).strip().lower()
            if base_attack in {"none", "off", "disabled"}:
                return ["none"], 0.0, False
            intensity = float(self._choose_intensity_for_round(server_round))
            rel_to_norm = bool(self._choose_rel_to_norm_for_round(server_round, base_attack))

        layering_mode = str(getattr(cfg, "layering_mode", "single") or "single").strip().lower()
        if layering_mode in {"", "none", "off", "disabled"}:
            layering_mode = "single"

        layers: List[str]
        if layering_mode == "fixed":
            raw = list(getattr(cfg, "layered_attacks", None) or [])
            layers = [str(x).strip().lower().replace("-", "_") for x in raw if str(x).strip()]
        elif layering_mode == "sample_k":
            # Sample K unique enabled attacks per round, using configured weights.
            k = int(getattr(cfg, "layered_k", 2) or 2)
            k = int(max(1, k))
            weights = {str(k2).strip().lower(): float(v2) for k2, v2 in (cfg.weights or {}).items()}
            pool = [a for a in self._candidate_attacks() if a not in {"none", "off", "disabled"}]
            if not pool:
                layers = [base_attack]
            else:
                rnd = random.Random(_stable_int_seed(cfg.seed, server_round, 0, 914))
                remaining = list(pool)
                layers = []
                for _ in range(min(k, len(remaining))):
                    total = float(sum(max(0.0, float(weights.get(a, 1.0))) for a in remaining))
                    if total <= 0.0:
                        pick = str(rnd.choice(remaining)).strip().lower()
                    else:
                        x = rnd.random() * total
                        acc = 0.0
                        pick = str(remaining[-1]).strip().lower()
                        for a in remaining:
                            acc += max(0.0, float(weights.get(a, 1.0)))
                            if x <= acc:
                                pick = str(a).strip().lower()
                                break
                    layers.append(pick)
                    remaining = [a for a in remaining if str(a).strip().lower() != pick]
        else:
            # single (default)
            layers = [base_attack]

        # Normalize/validate
        norm_layers: List[str] = []
        seen: set[str] = set()
        for a in layers:
            key = str(a or "none").strip().lower().replace("-", "_")
            if not key:
                continue
            if key in seen:
                continue
            seen.add(key)
            norm_layers.append(key)

        # Filter to enabled; keep "none" as a safe fallback
        enabled_layers: List[str] = []
        for a in norm_layers:
            if a in {"none", "off", "disabled"}:
                continue
            if self._attack_enabled(a):
                enabled_layers.append(a)

        if not enabled_layers:
            return ["none"], 0.0, False

        # rel_to_norm only applies if gaussian_noise is among layers
        rel_flag = bool(rel_to_norm) if "gaussian_noise" in set(enabled_layers) else False
        return enabled_layers, float(max(0.0, intensity)), bool(rel_flag)

    def _candidate_attacks(self) -> List[str]:
        cfg = self.attack_config
        weights = {str(k).strip().lower(): float(v) for k, v in (cfg.weights or {}).items()}
        candidates: List[str] = []
        for name in ["gaussian_noise", "sign_flip", "label_flip", "backdoor", "alie", "mean_shift"]:
            if not self._attack_enabled(name):
                continue
            w = float(weights.get(name, 1.0))
            if w <= 0.0:
                continue
            candidates.append(name)
        return candidates

    def _choose_attack_weighted_random(self, server_round: int) -> str:
        cfg = self.attack_config
        weights = {str(k).strip().lower(): float(v) for k, v in (cfg.weights or {}).items()}
        names = [n for n, w in weights.items() if w > 0 and self._attack_enabled(n)]
        if not names:
            # Fallback to all enabled attacks
            names = self._candidate_attacks()
            if not names:
                return "none"
            weights = {n: 1.0 for n in names}

        rnd = random.Random(_stable_int_seed(cfg.seed, server_round, 0, 911))
        total = float(sum(weights.get(n, 0.0) for n in names))
        if total <= 0.0:
            return "none"
        x = rnd.random() * total
        acc = 0.0
        chosen = "none"
        for n in names:
            acc += float(weights.get(n, 0.0))
            if x <= acc:
                chosen = n
                break
        return str(chosen).strip().lower()

    def _choose_intensity_for_round(self, server_round: int) -> float:
        cfg = self.attack_config
        irnd = random.Random(_stable_int_seed(cfg.seed, server_round, 0, 912))
        mode = str(cfg.random_intensity_mode or "fixed").strip().lower()
        if mode == "uniform":
            lo = float(min(cfg.random_intensity_min, cfg.random_intensity_max))
            hi = float(max(cfg.random_intensity_min, cfg.random_intensity_max))
            intensity = float(irnd.random() * (hi - lo) + lo)
        elif mode == "choice":
            choices = [float(x) for x in (cfg.random_intensity_choices or []) if float(x) >= 0]
            intensity = float(irnd.choice(choices)) if choices else float(cfg.random_intensity_value)
        else:
            intensity = float(cfg.random_intensity_value)

        intensity = float(max(0.0, float(intensity)))

        # Optional ramp escalation (for adaptive/weighted_random; phase mode uses per-phase schedules).
        ramp_mode = str(cfg.intensity_ramp_mode or "none").strip().lower()
        if ramp_mode not in {"", "none", "off", "disabled"}:
            start_r = int(max(1, cfg.intensity_ramp_start_round))
            end_r = int(cfg.intensity_ramp_end_round)
            if end_r <= 0:
                end_r = int(max(start_r, int(self.num_rounds)))
            end_r = int(max(start_r, end_r))

            if int(server_round) <= start_r:
                t = 0.0
            elif int(server_round) >= end_r:
                t = 1.0
            else:
                denom = float(max(1, end_r - start_r))
                t = float(int(server_round) - start_r) / denom

            m0 = float(max(0.0, cfg.intensity_ramp_multiplier_start))
            m1 = float(max(0.0, cfg.intensity_ramp_multiplier_end))
            if ramp_mode == "exp" and m0 > 0.0 and m1 > 0.0:
                ramp_mult = float(m0 * ((m1 / m0) ** t))
            else:
                # linear (default fallback)
                ramp_mult = float(m0 + (m1 - m0) * t)

            intensity *= float(max(0.0, ramp_mult))

        # Optional adaptive fail escalation.
        if bool(cfg.intensity_fail_escalation) and str(cfg.mode).strip().lower() == "adaptive":
            step = float(max(0.0, cfg.intensity_fail_multiplier_step))
            mx = float(max(1.0, cfg.intensity_fail_multiplier_max))
            fails = int(max(0, self._adaptive_consecutive_fails))
            fail_mult = float(min(mx, 1.0 + step * float(fails)))
            intensity *= float(max(0.0, fail_mult))

        cap = float(cfg.intensity_cap)
        if cap > 0.0:
            intensity = float(min(float(intensity), cap))

        return float(max(0.0, float(intensity)))

    def _choose_rel_to_norm_for_round(self, server_round: int, chosen_attack: str) -> bool:
        cfg = self.attack_config
        if str(chosen_attack).strip().lower() != "gaussian_noise":
            return False
        p = float(cfg.random_relative_to_update_norm_probability)
        p = max(0.0, min(1.0, p))
        rrnd = random.Random(_stable_int_seed(cfg.seed, server_round, 0, 913))
        return bool(rrnd.random() < p)

    def _choose_attack_adaptive(self, server_round: int) -> str:
        cfg = self.attack_config
        candidates = self._candidate_attacks()
        if not candidates:
            return "none"

        # Burn-in: behave like weighted_random for a few rounds until we have feedback.
        if int(server_round) <= int(cfg.adaptive_burn_in_rounds):
            chosen = self._choose_attack_weighted_random(server_round)
            return "none" if chosen in {"none", "off", "disabled"} else chosen

        rnd = random.Random(_stable_int_seed(cfg.seed, server_round, 0, 1911))

        # If we already hit the target (goal="below"), back off to "none".
        if str(cfg.adaptive_goal).strip().lower() == "below":
            mk = str(cfg.adaptive_metric).strip()
            last = self._eval_metrics_by_round.get(int(server_round) - 1, {}).get(mk)
            if last is not None and float(last) <= float(cfg.adaptive_target):
                return "none"

        # "Try each at least once" heuristic.
        untried = [a for a in candidates if len(self._adaptive_rewards_by_attack.get(a, [])) == 0]
        if untried:
            return str(rnd.choice(untried)).strip().lower()

        # If current attack isn't working for patience rounds, force a switch.
        force_switch = (
            self._adaptive_current_attack is not None
            and int(self._adaptive_consecutive_fails) >= int(cfg.adaptive_patience)
        )

        # Exploration.
        eps = max(0.0, min(1.0, float(cfg.adaptive_epsilon)))
        if (not force_switch) and (rnd.random() < eps):
            pool = [a for a in candidates if a != self._adaptive_current_attack] or list(candidates)
            return str(rnd.choice(pool)).strip().lower()

        # Exploitation: pick the attack with the best recent average reward.
        window = int(max(1, cfg.adaptive_window)) if int(cfg.adaptive_window) > 0 else 1

        def score(a: str) -> float:
            rs = self._adaptive_rewards_by_attack.get(a, [])
            if not rs:
                return float("-inf")
            recent = rs[-window:]
            return float(sum(float(x) for x in recent) / float(len(recent)))

        ranked = sorted(candidates, key=score, reverse=True)
        if not ranked:
            return str(rnd.choice(candidates)).strip().lower()

        best = ranked[0]
        if force_switch:
            # Pick the next-best that is different, else keep best.
            for a in ranked:
                if a != self._adaptive_current_attack:
                    best = a
                    break

        return str(best).strip().lower()

    def observe_server_evaluate(self, *, server_round: int, metrics: Any) -> None:
        """Provide server-side evaluation metrics for adaptive attack selection."""

        r = int(server_round)
        if metrics is None:
            return

        # Normalize MetricRecord/dict-like into float dict.
        md: Dict[str, float] = {}
        try:
            if isinstance(metrics, dict):
                items = metrics.items()
            else:
                items = [(k, metrics[k]) for k in metrics.keys()]  # type: ignore[attr-defined]
            for k, v in items:
                try:
                    md[str(k)] = float(v)
                except Exception:
                    continue
        except Exception:
            return

        self._eval_metrics_by_round[r] = dict(md)

        metric_key = str(self.attack_config.adaptive_metric).strip() or "accuracy"
        cur = md.get(metric_key)
        if cur is None:
            return

        prev = self._eval_metrics_by_round.get(r - 1, {}).get(metric_key)
        if prev is None:
            # First observation: reward encourages low metric.
            reward = -float(cur)
        else:
            # Reward is drop in the metric (positive means we reduced it).
            reward = float(prev) - float(cur)

        attack_used = str(self._attack_name_by_round.get(r, "none") or "none").strip().lower()
        self._adaptive_rewards_by_attack.setdefault(attack_used, []).append(float(reward))

        # Update "try something else" heuristic.
        if self._adaptive_current_attack is None:
            self._adaptive_current_attack = attack_used

        if attack_used == self._adaptive_current_attack:
            min_delta = float(self.attack_config.adaptive_min_delta)
            if float(reward) < float(min_delta):
                self._adaptive_consecutive_fails += 1
            else:
                self._adaptive_consecutive_fails = 0
        else:
            # Switching attacks resets the fail counter.
            self._adaptive_current_attack = attack_used
            self._adaptive_consecutive_fails = 0

    def plan_round(self, *, server_round: int, selected_client_ids: List[int]) -> Dict[str, Any]:
        """Plan the attack for this round once and cache it.

        This is used both to (a) send per-client instructions during
        configure_train (for dataset-poisoning attacks) and (b) inject
        update-poisoning during aggregate_train.
        """

        r = int(server_round)
        if r in self._round_plan:
            return dict(self._round_plan[r])

        cfg = self.attack_config
        attack_layers, intensity, rel_to_norm = self._choose_attack_layers_for_round(r)
        attack_layers = [str(a).strip().lower() for a in (attack_layers or [])]
        attack_layers = [a for a in attack_layers if a and a not in {"off", "disabled"}]
        attack_name = "+".join(attack_layers) if attack_layers and attack_layers != ["none"] else "none"

        # Per-layer intensity scaling
        multipliers = getattr(cfg, "layer_intensity_multipliers", None) or {}
        if not isinstance(multipliers, dict):
            multipliers = {}
        attack_layer_intensities: Dict[str, float] = {}
        for a in attack_layers:
            try:
                m = float(multipliers.get(str(a).strip().lower().replace("-", "_"), 1.0))
            except Exception:
                m = 1.0
            try:
                sched_m = float(self._layer_schedule_multiplier(layer=str(a), server_round=int(r)))
            except Exception:
                sched_m = 1.0
            attack_layer_intensities[str(a)] = float(
                max(0.0, float(intensity) * float(max(0.0, m)) * float(max(0.0, sched_m)))
            )

        attack_active = bool(attack_layers) and str(attack_name).strip().lower() not in {"none"} and float(intensity) != 0.0 and _round_in_windows(r, cfg.windows)

        malicious_fraction_used = 0.0
        malicious_k_target = 0
        if attack_active and selected_client_ids:
            malicious_fraction_used = float(self._choose_malicious_fraction_for_round(server_round=r))
            malicious_fraction_used = max(0.0, min(1.0, malicious_fraction_used))
            malicious_k_target = int(math.ceil(malicious_fraction_used * float(len(selected_client_ids))))

        malicious_ids = (
            self._select_malicious(
                server_round=r,
                selected_client_ids=list(selected_client_ids),
                k=malicious_k_target,
            )
            if (attack_active and malicious_k_target > 0)
            else []
        )

        # Track for cooldown/churn policies.
        for cid in malicious_ids:
            self._malicious_last_round[int(cid)] = int(r)
        self._prev_round_malicious = [int(x) for x in malicious_ids]

        plan = {
            "round": r,
            "attack_name": str(attack_name),
            "attack_layers": [str(a) for a in attack_layers],
            "intensity": float(intensity),
            "attack_layer_intensities": dict(attack_layer_intensities),
            "relative_to_update_norm": bool(rel_to_norm),
            "attack_active": bool(attack_active),
            "selected_client_ids": [int(x) for x in selected_client_ids],
            "malicious_client_ids": [int(x) for x in malicious_ids],
            "malicious_fraction_used": float(malicious_fraction_used),
            "malicious_k_target": int(malicious_k_target),
        }

        self._attack_name_by_round[r] = str(attack_name).strip().lower()

        self._round_plan[r] = dict(plan)
        return dict(plan)

    def apply_client_attack_config(self, *, server_round: int, client_id: int, config: Any) -> None:
        """Mutate a client's train ConfigRecord with attack instructions."""

        if not self.attack_config.enabled:
            return

        r = int(server_round)
        if r in self._round_plan:
            plan = dict(self._round_plan[r])
        else:
            # Best-effort: if configure_train didn't plan yet, emit attack type/intensity
            # but avoid selecting malicious clients from incomplete information.
            layers, intensity, rel = self._choose_attack_layers_for_round(r)
            name = "+".join([str(a).strip().lower() for a in (layers or []) if str(a).strip()]) if layers else "none"
            plan = {
                "round": r,
                "attack_name": str(name),
                "attack_layers": [str(a).strip().lower() for a in (layers or [])],
                "intensity": float(intensity),
                "attack_layer_intensities": {},
                "relative_to_update_norm": bool(rel),
                "attack_active": bool(str(name).strip().lower() not in {"none", "off", "disabled"} and float(intensity) != 0.0),
                "selected_client_ids": [],
                "malicious_client_ids": [],
                "malicious_fraction_used": 0.0,
                "malicious_k_target": 0,
            }
        # If we planned without selected_client_ids (shouldn't happen), just emit
        # the chosen type/intensity for visibility.
        attack_name = str(plan.get("attack_name", "none") or "none")
        attack_layers = plan.get("attack_layers") or []
        if not isinstance(attack_layers, list):
            attack_layers = []
        intensity = float(plan.get("intensity", 0.0) or 0.0)
        layer_intensities = plan.get("attack_layer_intensities") or {}
        if not isinstance(layer_intensities, dict):
            layer_intensities = {}
        rel = bool(plan.get("relative_to_update_norm", False))

        mids = set(int(x) for x in (plan.get("malicious_client_ids") or []))
        is_mal = int(client_id) in mids

        def _set(k: str, v: Any) -> None:
            try:
                config[k] = v
            except Exception:
                pass

        _set("attack_enabled", int(1 if bool(self.attack_config.enabled) else 0))
        _set("attack_seed", int(self.attack_config.seed))
        _set("attack_server_round", int(server_round))
        _set("attack_client_id", int(client_id))
        _set("attack_is_malicious", int(1 if bool(is_mal) else 0))
        _set("attack_name", str(attack_name))
        _set("attack_layers", ";".join([str(a).strip().lower() for a in attack_layers if str(a).strip()]))
        _set("attack_intensity", float(intensity))
        # Semicolon-separated list of k=v pairs, used by clients for per-layer intensity.
        try:
            pairs: List[str] = []
            for a in [str(x).strip().lower().replace("-", "_") for x in attack_layers if str(x).strip()]:
                if a in {"none", "off", "disabled"}:
                    continue
                if a in layer_intensities:
                    pairs.append(f"{a}={float(layer_intensities.get(a, intensity)):.10g}")
            _set("attack_layer_intensities", ";".join(pairs))
        except Exception:
            _set("attack_layer_intensities", "")
        _set("attack_relative_to_update_norm", int(1 if bool(rel) else 0))
        _set("attack_malicious_fraction_used", float(plan.get("malicious_fraction_used", 0.0) or 0.0))
        _set("attack_malicious_k_target", int(plan.get("malicious_k_target", 0) or 0))

        # Attack-specific knobs for client-side dataset poisoning.
        _set("label_flip_flip_rate", float(self.attack_config.label_flip.flip_rate))
        _set("label_flip_targeted", bool(self.attack_config.label_flip.targeted))
        _set("label_flip_source_class", int(self.attack_config.label_flip.source_class))
        _set("label_flip_target_class", int(self.attack_config.label_flip.target_class))

        _set("backdoor_poison_rate", float(self.attack_config.backdoor.poison_rate))
        _set("backdoor_target_label", int(self.attack_config.backdoor.target_label))
        _set("backdoor_trigger_type", str(self.attack_config.backdoor.trigger_type))
        _set("backdoor_patch_size", int(self.attack_config.backdoor.patch_size))
        _set("backdoor_blend_alpha", float(self.attack_config.backdoor.blend_alpha))

        # Record a per-client audit trail for this round.
        try:
            lf_int = float(layer_intensities.get("label_flip", intensity) or 0.0)
            lf_eff = float(self.attack_config.label_flip.flip_rate) * float(lf_int)
            lf_eff = float(max(0.0, min(1.0, lf_eff)))

            bd_int = float(layer_intensities.get("backdoor", intensity) or 0.0)
            bd_eff = float(self.attack_config.backdoor.poison_rate) * float(bd_int)
            bd_eff = float(max(0.0, min(1.0, bd_eff)))
            bd_alpha_eff = float(self.attack_config.backdoor.blend_alpha) * float(bd_int)
            bd_alpha_eff = float(max(0.0, min(1.0, bd_alpha_eff)))

            entry = {
                "client_id": int(client_id),
                "server_round": int(server_round),
                "attack_active": bool(plan.get("attack_active", False)),
                "attack_name": str(attack_name),
                "attack_layers": [str(a).strip().lower() for a in attack_layers if str(a).strip()],
                "attack_layer_intensities": dict(layer_intensities),
                "intensity": float(intensity),
                "relative_to_update_norm": bool(rel),
                "is_malicious": bool(is_mal),
                "malicious_fraction_used": float(plan.get("malicious_fraction_used", 0.0) or 0.0),
                "malicious_k_target": int(plan.get("malicious_k_target", 0) or 0),
                "label_flip_flip_rate": float(self.attack_config.label_flip.flip_rate),
                "label_flip_flip_rate_effective": float(lf_eff),
                "label_flip_targeted": bool(self.attack_config.label_flip.targeted),
                "label_flip_source_class": int(self.attack_config.label_flip.source_class),
                "label_flip_target_class": int(self.attack_config.label_flip.target_class),
                "backdoor_poison_rate": float(self.attack_config.backdoor.poison_rate),
                "backdoor_poison_rate_effective": float(bd_eff),
                "backdoor_blend_alpha": float(self.attack_config.backdoor.blend_alpha),
                "backdoor_blend_alpha_effective": float(bd_alpha_eff),
                "backdoor_target_label": int(self.attack_config.backdoor.target_label),
                "backdoor_trigger_type": str(self.attack_config.backdoor.trigger_type),
                "backdoor_patch_size": int(self.attack_config.backdoor.patch_size),
            }
            self._client_attack_by_round.setdefault(int(server_round), {})[int(client_id)] = entry
        except Exception:
            pass

    def _attack_enabled(self, attack_name: str) -> bool:
        a = str(attack_name).strip().lower()
        if a in {"none", "off", "disabled"}:
            return True
        if a == "gaussian_noise":
            return bool(self.attack_config.gaussian_noise.enabled)
        if a == "sign_flip":
            return bool(self.attack_config.sign_flip.enabled)
        if a == "label_flip":
            return bool(self.attack_config.label_flip.enabled)
        if a == "backdoor":
            return bool(self.attack_config.backdoor.enabled)
        if a == "alie":
            return bool(self.attack_config.alie.enabled)
        if a in {"mean_shift", "meanshift"}:
            return bool(self.attack_config.mean_shift.enabled)
        return False

    def _choose_malicious_fraction_for_round(self, *, server_round: int) -> float:
        cfg = self.attack_config

        # Optional per-round schedule (overrides malicious_fraction_mode).
        ramp_mode = str(getattr(cfg, "malicious_fraction_ramp_mode", "none") or "none").strip().lower()
        if ramp_mode not in {"", "none", "off", "disabled"}:
            start_r = int(max(1, int(getattr(cfg, "malicious_fraction_ramp_start_round", 1) or 1)))
            end_r = int(getattr(cfg, "malicious_fraction_ramp_end_round", 0) or 0)
            if end_r <= 0:
                end_r = int(max(start_r, int(self.num_rounds)))
            end_r = int(max(start_r, end_r))

            if int(server_round) <= start_r:
                t = 0.0
            elif int(server_round) >= end_r:
                t = 1.0
            else:
                denom = float(max(1, end_r - start_r))
                t = float(int(server_round) - start_r) / denom

            f0 = float(max(0.0, float(getattr(cfg, "malicious_fraction_ramp_value_start", 0.0) or 0.0)))
            f1 = float(max(0.0, float(getattr(cfg, "malicious_fraction_ramp_value_end", 0.0) or 0.0)))
            if ramp_mode == "exp" and f0 > 0.0 and f1 > 0.0:
                frac = float(f0 * ((f1 / f0) ** t))
            else:
                frac = float(f0 + (f1 - f0) * t)

            cap = float(max(0.0, float(getattr(cfg, "malicious_fraction_cap", 0.0) or 0.0)))
            if cap > 0.0:
                frac = float(min(frac, cap))
            return float(max(0.0, min(1.0, frac)))

        mode = str(cfg.malicious_fraction_mode or "fixed").strip().lower()
        if mode == "uniform":
            rnd = random.Random(_stable_int_seed(cfg.seed, server_round, 0, 1777))
            lo = float(min(cfg.malicious_fraction_min, cfg.malicious_fraction_max))
            hi = float(max(cfg.malicious_fraction_min, cfg.malicious_fraction_max))
            return float(rnd.random() * (hi - lo) + lo)
        if mode == "choice":
            choices = [float(x) for x in (cfg.malicious_fraction_choices or [])]
            choices = [x for x in choices if x >= 0.0]
            if not choices:
                return float(cfg.malicious_fraction)
            rnd = random.Random(_stable_int_seed(cfg.seed, server_round, 0, 1778))
            return float(rnd.choice(choices))
        return float(cfg.malicious_fraction)

    def _select_malicious(self, *, server_round: int, selected_client_ids: List[int], k: int) -> List[int]:
        cfg = self.attack_config
        if not cfg.enabled:
            return []
        if not _round_in_windows(server_round, cfg.windows):
            return []
        if not selected_client_ids:
            return []

        k = int(max(0, min(int(k), int(len(selected_client_ids)))))
        if k == 0:
            return []

        full_pool = sorted({int(x) for x in selected_client_ids})
        if not full_pool:
            return []

        # Cooldown pool: excludes recently-malicious clients.
        cooldown = int(getattr(cfg, "cooldown_rounds", 0) or 0)
        cooled_pool = list(full_pool)
        if cooldown > 0:
            cutoff = int(server_round) - int(cooldown)
            cooled_pool = [
                int(cid)
                for cid in full_pool
                if int(self._malicious_last_round.get(int(cid), -10**9)) < int(cutoff)
            ]

        # For sampling we prefer cooled_pool when it has enough clients,
        # otherwise fall back to the full_pool.
        sample_pool = cooled_pool if len(cooled_pool) >= k else full_pool

        k = int(max(0, min(int(k), int(len(full_pool)))))
        if k == 0:
            return []

        # Selection modes
        if cfg.selection_mode == "sticky":
            # One global set for the entire run; adjust size if k changes.
            if self._sticky_malicious is None:
                rnd = random.Random(cfg.seed)
                self._sticky_malicious = rnd.sample(sample_pool, k=k)
                return list(self._sticky_malicious)
            stored = [int(x) for x in self._sticky_malicious]
            # Only drop clients that are not participating this round.
            present = [int(x) for x in stored if int(x) in set(full_pool)]
            # If k decreased, do NOT shrink the stored cohort; return a prefix only.
            if len(present) >= k:
                return present[:k]
            if len(present) < k:
                # Top up with new candidates not already chosen
                need = int(k - len(present))
                remaining = [x for x in sample_pool if int(x) not in set(present)]
                if remaining:
                    rnd = random.Random(cfg.seed)
                    present.extend(rnd.sample(remaining, k=min(need, len(remaining))))
            # Persist expanded cohort (but never shrink it just because k got smaller)
            self._sticky_malicious = list(present)
            return list(present)

        if cfg.selection_mode in {"sticky_k", "sticky-window", "sticky_window"}:
            sticky_rounds = int(getattr(cfg, "sticky_rounds", 5) or 5)
            sticky_rounds = int(max(1, sticky_rounds))
            start = self._sticky_k_window_start
            if start is None:
                start = int(server_round)
            # Advance window if expired
            if int(server_round) >= int(start) + int(sticky_rounds):
                start = int(server_round)
                self._sticky_k_malicious = None
            self._sticky_k_window_start = int(start)

            if self._sticky_k_malicious is None:
                if cfg.deterministic_per_round:
                    rnd = random.Random(_stable_int_seed(cfg.seed, int(start), 0, 2776))
                else:
                    rnd = random.Random(cfg.seed)
                self._sticky_k_malicious = rnd.sample(sample_pool, k=k)
                return list(self._sticky_k_malicious)

            stored = [int(x) for x in self._sticky_k_malicious]
            present = [int(x) for x in stored if int(x) in set(full_pool)]

            # If k decreased, do NOT shrink the stored cohort; return a prefix only.
            if len(present) >= k:
                return present[:k]

            # If k increased, top up while staying within the same sticky window.
            if len(present) < k:
                remaining = [x for x in sample_pool if int(x) not in set(present)]
                if remaining:
                    if cfg.deterministic_per_round:
                        rnd = random.Random(_stable_int_seed(cfg.seed, int(server_round), 0, 2777))
                    else:
                        rnd = random.Random(cfg.seed)
                    present.extend(rnd.sample(remaining, k=min(int(k - len(present)), len(remaining))))

            # Persist expanded cohort (but never shrink it just because k got smaller)
            self._sticky_k_malicious = list(present)
            return list(present)

        if cfg.selection_mode in {"churn", "rotate", "rotating"}:
            churn_fraction = float(getattr(cfg, "churn_fraction", 0.3) or 0.3)
            churn_fraction = float(max(0.0, min(1.0, churn_fraction)))
            min_replace = int(getattr(cfg, "churn_min_replace", 1) or 0)
            min_replace = int(max(0, min_replace))

            prev = [int(x) for x in (self._prev_round_malicious or []) if int(x) in set(full_pool)]
            # How many to replace
            n_replace = int(math.ceil(churn_fraction * float(k)))
            if k > 0 and churn_fraction > 0.0:
                n_replace = int(max(n_replace, min_replace))
            n_replace = int(max(0, min(int(k), n_replace)))
            n_keep = int(max(0, int(k) - int(n_replace)))

            # Keep a subset of previous, then fill with new clients
            if cfg.deterministic_per_round:
                rnd = random.Random(_stable_int_seed(cfg.seed, int(server_round), 0, 2778))
            else:
                rnd = random.Random(cfg.seed)

            kept: List[int]
            if len(prev) <= n_keep:
                kept = list(prev)
            else:
                kept = rnd.sample(sorted(prev), k=n_keep)

            remaining = [x for x in sample_pool if int(x) not in set(kept)]
            fill = rnd.sample(remaining, k=min(int(k - len(kept)), len(remaining))) if remaining else []
            chosen = list(kept) + list(fill)
            # If we still couldn't fill (e.g., candidate_pool too small), truncate safely.
            return chosen[:k]

        # per_round_random
        if cfg.deterministic_per_round:
            rnd = random.Random(_stable_int_seed(cfg.seed, server_round, 0, 1776))
        else:
            rnd = random.Random(cfg.seed)
            for _ in range(server_round):
                rnd.random()
        return rnd.sample(sample_pool, k=k)

    def maybe_inject_attacks(
        self,
        *,
        server_round: int,
        selected_client_ids: List[int],
        replies: List[Any],
    ) -> List[Any]:
        """Potentially corrupt malicious client updates and emit provenance logs."""

        # True no-op when disabled.
        if not self.attack_config.enabled:
            return replies

        from flwr.app import ArrayRecord

        cfg = self.attack_config
        plan = self.plan_round(server_round=int(server_round), selected_client_ids=list(selected_client_ids))
        attack_name = str(plan.get("attack_name", "none") or "none")
        attack_layers = plan.get("attack_layers") or []
        if not isinstance(attack_layers, list):
            attack_layers = []
        attack_layers = [str(a).strip().lower().replace("-", "_") for a in attack_layers if str(a).strip()]
        # Backwards compatibility: split composite name if layers missing
        if not attack_layers and "+" in str(attack_name):
            attack_layers = [p.strip().lower().replace("-", "_") for p in str(attack_name).split("+") if p.strip()]
        intensity = float(plan.get("intensity", 0.0) or 0.0)

        # Per-layer effective intensity (base intensity scaled by config multipliers)
        layer_intensities = plan.get("attack_layer_intensities") or {}
        if not isinstance(layer_intensities, dict):
            layer_intensities = {}
        if not layer_intensities:
            mults = getattr(cfg, "layer_intensity_multipliers", None) or {}
            if not isinstance(mults, dict):
                mults = {}
            layer_intensities = {}
            for a in attack_layers:
                try:
                    m = float(mults.get(str(a).strip().lower().replace("-", "_"), 1.0))
                except Exception:
                    m = 1.0
                layer_intensities[str(a)] = float(max(0.0, float(intensity) * float(max(0.0, m))))

        rel_to_norm = bool(plan.get("relative_to_update_norm", False))
        attack_active = bool(plan.get("attack_active", False))
        malicious_fraction_used = float(plan.get("malicious_fraction_used", 0.0) or 0.0)
        malicious_k_target = int(plan.get("malicious_k_target", 0) or 0)
        malicious_ids = [int(x) for x in (plan.get("malicious_client_ids") or [])]
        malicious_set = set(int(x) for x in malicious_ids)

        def _metric_dict_from_msg(m: Any) -> Dict[str, Any]:
            try:
                mr = m.content.get("metrics")
            except Exception:
                mr = None
            if mr is None:
                return {}
            if isinstance(mr, dict):
                return dict(mr)
            # MetricRecord behaves like a mapping in most Flower versions
            try:
                return {k: mr[k] for k in mr.keys()}  # type: ignore[attr-defined]
            except Exception:
                pass
            try:
                return dict(mr)  # type: ignore[arg-type]
            except Exception:
                return {}

        # Aggregate actual dataset-poisoning counts (from client-side counters)
        poison_by_client: Dict[str, Dict[str, Any]] = {}
        poison_all_seen = 0
        poison_all_poisoned = 0
        poison_mal_seen = 0
        poison_mal_poisoned = 0
        poison_mal_plf = 0
        poison_mal_pbd = 0

        for msg in replies:
            node_id = int(getattr(getattr(msg, "metadata", None), "src_node_id", -1) or -1)
            md = _metric_dict_from_msg(msg)
            seen = int(md.get("poison_examples_seen", 0) or 0)
            pe = int(md.get("poisoned_examples", 0) or 0)
            plf = int(md.get("poisoned_label_flip_examples", 0) or 0)
            pbd = int(md.get("poisoned_backdoor_examples", 0) or 0)
            is_mal = bool(node_id in malicious_set)

            poison_by_client[str(node_id)] = {
                "is_malicious": bool(is_mal),
                "examples_seen": int(seen),
                "poisoned_examples": int(pe),
                "poisoned_label_flip_examples": int(plf),
                "poisoned_backdoor_examples": int(pbd),
            }

            poison_all_seen += int(seen)
            poison_all_poisoned += int(pe)
            if is_mal:
                poison_mal_seen += int(seen)
                poison_mal_poisoned += int(pe)
                poison_mal_plf += int(plf)
                poison_mal_pbd += int(pbd)

        attack_details: Dict[str, Any] = {
            "attack_name": str(attack_name),
            "attack_layers": list(attack_layers),
            "intensity": float(intensity),
            "attack_layer_intensities": dict(layer_intensities),
            "attack_active": bool(attack_active),
        }

        layer_details: Dict[str, Any] = {}

        # Describe dataset-poisoning attacks (executed client-side).
        if "label_flip" in set(attack_layers):
            lf_int = float(layer_intensities.get("label_flip", intensity) or 0.0)
            flip_eff = float(cfg.label_flip.flip_rate) * float(lf_int)
            flip_eff = max(0.0, min(1.0, flip_eff))
            layer_details["label_flip"] = {
                "type": "data_poisoning",
                "mechanism": "label_flip",
                "flip_rate": float(cfg.label_flip.flip_rate),
                "flip_rate_effective": float(flip_eff),
                "layer_intensity": float(lf_int),
                "targeted": bool(cfg.label_flip.targeted),
                "source_class": int(cfg.label_flip.source_class),
                "target_class": int(cfg.label_flip.target_class),
            }
        if "backdoor" in set(attack_layers):
            bd_int = float(layer_intensities.get("backdoor", intensity) or 0.0)
            poison_eff = float(cfg.backdoor.poison_rate) * float(bd_int)
            poison_eff = max(0.0, min(1.0, poison_eff))
            alpha_eff = float(cfg.backdoor.blend_alpha) * float(bd_int)
            alpha_eff = max(0.0, min(1.0, alpha_eff))
            layer_details["backdoor"] = {
                "type": "data_poisoning",
                "mechanism": "backdoor",
                "poison_rate": float(cfg.backdoor.poison_rate),
                "poison_rate_effective": float(poison_eff),
                "target_label": int(cfg.backdoor.target_label),
                "trigger_type": str(cfg.backdoor.trigger_type),
                "patch_size": int(cfg.backdoor.patch_size),
                "blend_alpha": float(cfg.backdoor.blend_alpha),
                "blend_alpha_effective": float(alpha_eff),
                "layer_intensity": float(bd_int),
            }

        # Compute client deltas and norms (pre-attack)
        current = self._last_global_state
        delta_norms: Dict[int, float] = {}
        delta_norms_post_malicious: Dict[int, float] = {}
        non_finite_clients: set[int] = set()
        non_finite_post_clients: set[int] = set()
        total_params = 0

        def percentile(values: List[float], q: float) -> float:
            if not values:
                return 0.0
            q = float(max(0.0, min(1.0, q)))
            xs = sorted(float(x) for x in values)
            if len(xs) == 1:
                return float(xs[0])
            pos = q * float(len(xs) - 1)
            lo = int(math.floor(pos))
            hi = int(math.ceil(pos))
            if lo == hi:
                return float(xs[lo])
            t = pos - float(lo)
            return float(xs[lo] * (1.0 - t) + xs[hi] * t)

        def is_float_tensor(t: torch.Tensor) -> bool:
            return torch.is_floating_point(t) or t.dtype.is_complex

        if current is not None:
            for t in current.values():
                if isinstance(t, torch.Tensor) and is_float_tensor(t):
                    total_params += int(t.numel())

        for msg in replies:
            node_id = int(getattr(getattr(msg, "metadata", None), "src_node_id", -1) or -1)
            try:
                arr: ArrayRecord = msg.content["arrays"]
                st = arr.to_torch_state_dict()
            except Exception:
                continue
            if current is None:
                continue
            s = 0.0
            non_finite = False
            for k, t_client in st.items():
                t_global = current.get(k)
                if not isinstance(t_client, torch.Tensor) or not isinstance(t_global, torch.Tensor):
                    continue
                if not is_float_tensor(t_client) or not is_float_tensor(t_global):
                    continue
                d = (t_client.detach().cpu() - t_global.detach().cpu()).float()
                if not torch.isfinite(d).all():
                    non_finite = True
                    break
                s += float(torch.sum(d * d).item())
            if non_finite:
                non_finite_clients.add(int(node_id))
                continue
            delta_norms[node_id] = float(math.sqrt(max(s, 0.0)))

        norm_values = sorted(delta_norms.values())
        if norm_values:
            mid = len(norm_values) // 2
            update_norm_median = norm_values[mid] if len(norm_values) % 2 else 0.5 * (norm_values[mid - 1] + norm_values[mid])
            update_norm_max = max(norm_values)
        else:
            update_norm_median = 0.0
            update_norm_max = 0.0

        update_norm_max_client_id = -1
        update_norm_max_client_is_malicious = False
        if delta_norms:
            try:
                update_norm_max_client_id = int(max(delta_norms.items(), key=lambda kv: float(kv[1]))[0])
                update_norm_max_client_is_malicious = bool(update_norm_max_client_id in malicious_set)
            except Exception:
                update_norm_max_client_id = -1
                update_norm_max_client_is_malicious = False

        update_norm_max_mal = 0.0
        for nid, v in delta_norms.items():
            if nid in malicious_set:
                update_norm_max_mal = max(update_norm_max_mal, float(v))

        # Honest norm summary (useful for stress/stealth visualization)
        honest_norms = [float(v) for nid, v in delta_norms.items() if int(nid) not in malicious_set]
        honest_p50 = percentile(honest_norms, 0.5)
        honest_p90 = percentile(honest_norms, 0.9)
        honest_max = float(max(honest_norms) if honest_norms else 0.0)

        # Defense assumption gap (e.g., Krum/MultiKrum expects fixed byzantine count)
        assumed_m = 0
        try:
            assumed_m = int(self.run_config.get("num-malicious-nodes", 0) or 0)
        except Exception:
            assumed_m = 0
        assumption_gap = int(len(malicious_set)) - int(assumed_m)

        stealth_applied = False
        stealth_cap = 0.0
        stealth_scale = 1.0

        # Apply update poisoning layers on malicious replies (can be multiple)
        update_layers = [a for a in attack_layers if a in {"gaussian_noise", "sign_flip", "alie", "mean_shift", "meanshift"}]
        if update_layers and current is not None and malicious_set:
            denom = float(math.sqrt(max(1, total_params)))
            baseline = float(update_norm_median)

            # If multiple update layers are active, expose as multi-layer in the summary.
            attack_details.update({"type": "update_poisoning", "mechanism": "multi_layer" if len(update_layers) > 1 else str(update_layers[0])})

            # Layer parameter summaries
            if "sign_flip" in set(update_layers):
                sf_int = float(layer_intensities.get("sign_flip", intensity) or 0.0)
                alpha_eff = float(cfg.sign_flip.alpha) * float(sf_int)
                layer_details["sign_flip"] = {
                    "type": "update_poisoning",
                    "mechanism": "sign_flip",
                    "alpha": float(cfg.sign_flip.alpha),
                    "alpha_effective": float(alpha_eff),
                    "layer_intensity": float(sf_int),
                }
            if "gaussian_noise" in set(update_layers):
                gn_int = float(layer_intensities.get("gaussian_noise", intensity) or 0.0)
                sigma_base = float(cfg.gaussian_noise.sigma) * float(gn_int)
                use_relative = bool(cfg.gaussian_noise.relative) or bool(rel_to_norm)
                sigma_eff = sigma_base * (baseline / denom if (use_relative and denom > 0) else 1.0)
                layer_details["gaussian_noise"] = {
                    "type": "update_poisoning",
                    "mechanism": "gaussian_noise",
                    "sigma": float(cfg.gaussian_noise.sigma),
                    "sigma_base": float(sigma_base),
                    "sigma_effective": float(sigma_eff),
                    "layer_intensity": float(gn_int),
                    "relative": bool(cfg.gaussian_noise.relative),
                    "relative_to_update_norm": bool(rel_to_norm),
                    "baseline_update_norm_median": float(baseline),
                    "denom_sqrt_num_params": float(denom),
                }
            if "alie" in set(update_layers):
                al_int = float(layer_intensities.get("alie", intensity) or 0.0)
                z_eff = float(cfg.alie.z) * float(al_int)
                layer_details["alie"] = {
                    "type": "update_poisoning",
                    "mechanism": "alie",
                    "z": float(cfg.alie.z),
                    "z_effective": float(z_eff),
                    "layer_intensity": float(al_int),
                }
            if ("mean_shift" in set(update_layers)) or ("meanshift" in set(update_layers)):
                ms_int = float(layer_intensities.get("mean_shift", layer_intensities.get("meanshift", intensity)) or 0.0)
                beta_eff = float(cfg.mean_shift.beta) * float(ms_int)
                layer_details["mean_shift"] = {
                    "type": "update_poisoning",
                    "mechanism": "mean_shift",
                    "beta": float(cfg.mean_shift.beta),
                    "beta_effective": float(beta_eff),
                    "layer_intensity": float(ms_int),
                }

            # Optional stealth cap based on honest update norm distribution
            if bool(cfg.stealth_mode) and honest_norms:
                q = float(cfg.stealth_norm_quantile)
                q = max(0.0, min(1.0, q))
                stealth_cap = float(percentile(honest_norms, q) * float(max(0.0, cfg.stealth_norm_multiplier)))
            else:
                stealth_cap = 0.0

            crafted_delta_by_key: Optional[Dict[str, torch.Tensor]] = None
            crafted_norm: Optional[float] = None
            # For ALIE/mean_shift we craft a single colluding delta using honest statistics.
            if any(a in {"alie", "mean_shift", "meanshift"} for a in update_layers):
                honest_ids = [nid for nid in delta_norms.keys() if nid not in malicious_set]
                if not honest_ids:
                    attack_details.update({"warning": "No honest clients available to craft adaptive attack"})
                    crafted_delta_by_key = None
                else:
                    crafted_delta_by_key = {}
                    s2 = 0.0
                    # Build mu/std per parameter key
                    for k, t_global in current.items():
                        if not isinstance(t_global, torch.Tensor) or not is_float_tensor(t_global):
                            continue
                        ds: List[torch.Tensor] = []
                        for msg in replies:
                            node_id = int(getattr(getattr(msg, "metadata", None), "src_node_id", -1) or -1)
                            if node_id in malicious_set:
                                continue
                            try:
                                st = msg.content["arrays"].to_torch_state_dict()
                            except Exception:
                                continue
                            t_client = st.get(k)
                            if not isinstance(t_client, torch.Tensor) or not is_float_tensor(t_client):
                                continue
                            d = (t_client.detach().cpu() - t_global.detach().cpu()).float()
                            ds.append(d)
                        if not ds:
                            continue
                        stack = torch.stack(ds, dim=0)
                        mu = torch.mean(stack, dim=0)
                        sigma = torch.std(stack, dim=0, unbiased=False)

                        # If both ALIE and mean_shift are requested simultaneously, ALIE wins.
                        if "alie" in set(update_layers):
                            al_int = float(layer_intensities.get("alie", intensity) or 0.0)
                            z_eff = float(cfg.alie.z) * float(al_int)
                            d2 = mu + float(z_eff) * sigma
                        else:
                            ms_int = float(layer_intensities.get("mean_shift", layer_intensities.get("meanshift", intensity)) or 0.0)
                            beta_eff = float(cfg.mean_shift.beta) * float(ms_int)
                            d2 = -float(beta_eff) * mu

                        crafted_delta_by_key[k] = d2
                        s2 += float(torch.sum(d2 * d2).item())

                    crafted_norm = float(math.sqrt(max(s2, 0.0)))
                    if not crafted_delta_by_key:
                        crafted_delta_by_key = None
                        crafted_norm = None
                        attack_details.update(
                            {
                                "warning": "Unable to craft adaptive attack (no valid parameter deltas)",
                                "adaptive_crafted": False,
                            }
                        )
                    else:
                        attack_details.update({"adaptive_crafted": True})

                    if stealth_cap > 0.0 and crafted_norm > 0.0:
                        stealth_scale = float(min(1.0, stealth_cap / crafted_norm))
                        if stealth_scale < 1.0:
                            stealth_applied = True
                            for kk in list(crafted_delta_by_key.keys()):
                                crafted_delta_by_key[kk] = crafted_delta_by_key[kk] * float(stealth_scale)
                            crafted_norm = crafted_norm * float(stealth_scale)
                    else:
                        stealth_scale = 1.0

                    attack_details.update(
                        {
                            "stealth_mode": bool(cfg.stealth_mode),
                            "stealth_cap": float(stealth_cap),
                            "stealth_scale": float(stealth_scale),
                            "crafted_update_norm": float(crafted_norm or 0.0),
                            "honest_norm_p50": float(honest_p50),
                            "honest_norm_p90": float(honest_p90),
                        }
                    )

            for msg in replies:
                node_id = int(getattr(getattr(msg, "metadata", None), "src_node_id", -1) or -1)
                if node_id not in malicious_set:
                    continue
                try:
                    arr = msg.content["arrays"]
                    st = arr.to_torch_state_dict()
                except Exception:
                    continue

                # Apply update-poisoning layers sequentially.
                st_cur: Dict[str, torch.Tensor] = dict(st)
                for layer in update_layers:
                    layer = str(layer).strip().lower()
                    if layer in {"mean_shift", "meanshift", "alie"}:
                        if crafted_delta_by_key is None:
                            continue
                        new_state: Dict[str, torch.Tensor] = {}
                        for k, t_client in st_cur.items():
                            t_global = current.get(k)
                            if not isinstance(t_client, torch.Tensor) or not isinstance(t_global, torch.Tensor):
                                new_state[k] = t_client
                                continue
                            if not is_float_tensor(t_client) or not is_float_tensor(t_global):
                                new_state[k] = t_client
                                continue
                            d2 = crafted_delta_by_key.get(k)
                            if d2 is None:
                                new_state[k] = t_client
                                continue
                            new_state[k] = (t_global.detach().cpu().float() + d2).to(t_client.dtype)
                        st_cur = new_state
                        continue

                    if layer in {"gaussian_noise", "sign_flip"}:
                        salt = 123 if layer == "gaussian_noise" else 456
                        gen = torch.Generator(device="cpu")
                        gen.manual_seed(_stable_int_seed(cfg.seed, server_round, node_id, salt))
                        new_state2: Dict[str, torch.Tensor] = {}
                        for k, t_client in st_cur.items():
                            t_global = current.get(k)
                            if not isinstance(t_client, torch.Tensor) or not isinstance(t_global, torch.Tensor):
                                new_state2[k] = t_client
                                continue
                            if not is_float_tensor(t_client) or not is_float_tensor(t_global):
                                new_state2[k] = t_client
                                continue

                            d = (t_client.detach().cpu() - t_global.detach().cpu()).float()
                            if layer == "sign_flip":
                                sf_int = float(layer_intensities.get("sign_flip", intensity) or 0.0)
                                alpha = float(cfg.sign_flip.alpha) * float(sf_int)
                                d2 = -alpha * d
                            else:
                                gn_int = float(layer_intensities.get("gaussian_noise", intensity) or 0.0)
                                sigma = float(cfg.gaussian_noise.sigma) * float(gn_int)
                                if bool(cfg.gaussian_noise.relative) or bool(rel_to_norm):
                                    sigma = sigma * (baseline / denom if denom > 0 else 0.0)
                                noise = torch.randn(d.shape, generator=gen, dtype=d.dtype) * float(sigma)
                                d2 = d + noise
                            new_state2[k] = (t_global.detach().cpu().float() + d2).to(t_client.dtype)
                        st_cur = new_state2
                        continue

                # Write back final state and compute post norm
                msg.content["arrays"] = ArrayRecord(st_cur)
                s2_post2 = 0.0
                non_finite_post = False
                for k, t_client in st_cur.items():
                    t_global = current.get(k)
                    if not isinstance(t_client, torch.Tensor) or not isinstance(t_global, torch.Tensor):
                        continue
                    if not is_float_tensor(t_client) or not is_float_tensor(t_global):
                        continue
                    d = (t_client.detach().cpu() - t_global.detach().cpu()).float()
                    if not torch.isfinite(d).all():
                        non_finite_post = True
                        break
                    s2_post2 += float(torch.sum(d * d).item())
                if non_finite_post:
                    non_finite_post_clients.add(int(node_id))
                    continue
                delta_norms_post_malicious[node_id] = float(math.sqrt(max(s2_post2, 0.0)))

        update_norm_max_mal_post: Optional[float] = None
        if delta_norms_post_malicious:
            update_norm_max_mal_post = float(max(delta_norms_post_malicious.values()))

        # Best-effort: infer which client updates the defense would select (post-attack)
        # so we can quantify "malicious slip-through" without relying on aggregated client metrics.
        defense_selection: Dict[str, Any] = {}
        try:
            strategy_name = str(self.run_config.get("strategy", "") or "").strip().lower()
            if strategy_name in {"multikrum", "multi-krum", "krum"}:
                from flwr.serverapp.strategy.multikrum import select_multikrum

                num_mal_assumed = int(self.run_config.get("num-malicious-nodes", 0) or 0)
                if strategy_name == "krum":
                    num_nodes_to_select = 1
                else:
                    num_nodes_to_select = int(self.run_config.get("num-nodes-to-select", 1) or 1)

                contents: List[Any] = []
                content_to_src: Dict[int, int] = {}
                for msg in replies:
                    try:
                        content = msg.content
                    except Exception:
                        continue
                    try:
                        src = int(getattr(getattr(msg, "metadata", None), "src_node_id", -1) or -1)
                    except Exception:
                        src = -1
                    contents.append(content)
                    content_to_src[id(content)] = int(src)

                selected_contents = select_multikrum(
                    contents,
                    num_malicious_nodes=int(num_mal_assumed),
                    num_nodes_to_select=int(max(1, num_nodes_to_select)),
                )

                selected_ids: List[int] = []
                for c in selected_contents:
                    src = content_to_src.get(id(c))
                    if src is None or int(src) < 0:
                        continue
                    selected_ids.append(int(src))

                # De-duplicate while preserving order
                seen_sel: set[int] = set()
                selected_ids_uniq: List[int] = []
                for x in selected_ids:
                    if int(x) in seen_sel:
                        continue
                    seen_sel.add(int(x))
                    selected_ids_uniq.append(int(x))

                num_selected = int(len(selected_ids_uniq))
                num_mal_selected = int(sum(1 for x in selected_ids_uniq if int(x) in malicious_set))
                frac_mal_selected = float(num_mal_selected) / float(num_selected) if num_selected > 0 else 0.0

                defense_selection = {
                    "defense_strategy": "krum" if strategy_name == "krum" else "multikrum",
                    "num_selected": int(num_selected),
                    "num_malicious_selected": int(num_mal_selected),
                    "malicious_selected_fraction": float(frac_mal_selected),
                    "selected_client_ids": [int(x) for x in selected_ids_uniq],
                }
        except Exception:
            defense_selection = {}

        # Record what happened
        rec: Dict[str, Any] = {
            "round": int(server_round),
            "selected_client_ids": [int(x) for x in selected_client_ids],
            "malicious_client_ids": [int(x) for x in sorted(malicious_set)],
            "num_selected_clients": int(len(selected_client_ids)),
            "num_malicious": int(len(malicious_set)),
            "malicious_fraction_used": float(malicious_fraction_used),
            "malicious_k_target": int(malicious_k_target),
            "attack_name": str(attack_name),
            "attack_layers": list(attack_layers),
            "intensity": float(intensity),
            "relative_to_update_norm": bool(rel_to_norm),
            "attack_details": attack_details,
            "defense_selection": dict(defense_selection) if isinstance(defense_selection, dict) else {},
            "update_norm_median": float(update_norm_median),
            "update_norm_max": float(update_norm_max),
            "update_norm_max_client_id": int(update_norm_max_client_id),
            "update_norm_max_client_is_malicious": bool(update_norm_max_client_is_malicious),
            "update_norm_max_malicious": float(update_norm_max_mal),
            "update_norm_max_malicious_post": None if update_norm_max_mal_post is None else float(update_norm_max_mal_post),
            "honest_update_norm_p50": float(honest_p50),
            "honest_update_norm_p90": float(honest_p90),
            "honest_update_norm_max": float(honest_max),
            "defense_assumed_num_malicious_nodes": int(assumed_m),
            "defense_assumption_gap": int(assumption_gap),
            "stealth_applied": bool(stealth_applied),
            "stealth_cap": float(stealth_cap),
            "stealth_scale": float(stealth_scale),
            "per_client_update_norm": {str(k): float(v) for k, v in delta_norms.items()},
            "non_finite_client_ids": [int(x) for x in sorted(non_finite_clients)],
            "non_finite_post_client_ids": [int(x) for x in sorted(non_finite_post_clients)],
            # Client-reported dataset poisoning counters
            "poison_all_examples_seen": int(poison_all_seen),
            "poison_all_poisoned_examples": int(poison_all_poisoned),
            "poison_malicious_examples_seen": int(poison_mal_seen),
            "poison_malicious_poisoned_examples": int(poison_mal_poisoned),
            "poison_malicious_poisoned_label_flip": int(poison_mal_plf),
            "poison_malicious_poisoned_backdoor": int(poison_mal_pbd),
            "poison_by_client": poison_by_client,
            "attack_by_client": self._client_attack_by_round.get(int(server_round), {}),
        }

        if layer_details:
            try:
                attack_details["layer_details"] = dict(layer_details)
            except Exception:
                pass

        if self.recorder is not None:
            self.recorder.log_round(rec)
            if int(server_round) >= int(self.num_rounds):
                self.recorder.finalize_and_plot()
        else:
            # Still emit to stdout for visibility
            self._log(
                "INFO",
                f"Round {server_round}: attack={attack_name} intensity={intensity:.4g} malicious={sorted(malicious_set)}",
            )

        # Release per-round client assignment cache to keep memory bounded.
        try:
            self._client_attack_by_round.pop(int(server_round), None)
        except Exception:
            pass

        return replies


@dataclass(frozen=True)
class DatasetSpec:
    dataset: str
    modality: str  # vision|text|tabular|audio

    # Common label key (will be standardized to batch["label"] by transforms)
    label_key: str
    num_classes: int

    # Vision
    image_key: Optional[str] = None
    input_channels: Optional[int] = None

    # Text
    text_key: Optional[str] = None

    # Audio
    audio_key: Optional[str] = None

    # Splits
    train_split: str = "train"
    central_eval_split: str = "test"


def get_dataset_spec(dataset: str) -> DatasetSpec:
    ds = str(dataset).strip()
    if ds == "uoft-cs/cifar10":
        return DatasetSpec(
            dataset=ds,
            modality="vision",
            image_key="img",
            label_key="label",
            input_channels=3,
            num_classes=10,
            central_eval_split="test",
        )
    if ds == "uoft-cs/cifar100":
        return DatasetSpec(
            dataset=ds,
            label_key="fine_label",
            num_classes=100,
            modality="vision",
            image_key="img",
            input_channels=3,
            central_eval_split="test",
        )
    if ds == "ylecun/mnist":
        return DatasetSpec(
            dataset=ds,
            label_key="label",
            num_classes=10,
            modality="vision",
            image_key="image",
            input_channels=1,
            central_eval_split="test",
        )
    if ds == "zalando-datasets/fashion_mnist":
        return DatasetSpec(
            dataset=ds,
            label_key="label",
            num_classes=10,
            modality="vision",
            image_key="image",
            input_channels=1,
            central_eval_split="test",
        )

    # Known recommended datasets (cataloged) - these will rely on auto key inference
    # or explicit run config overrides.
    if ds == "sentiment140":
        # Labels are {0, 2, 4} (neg/neutral/pos)
        return DatasetSpec(
            dataset=ds,
            modality="text",
            text_key="text",
            label_key="sentiment",
            num_classes=3,
            central_eval_split="test",
        )

    if ds in {
        "takala/financial_phrasebank",
        "pauri32/fiqa-2018",
        "zeroshot/twitter-financial-news-sentiment",
        "bigbio/pubmed_qa",
        "openlifescienceai/medmcqa",
        "bigbio/med_qa",
        "google-research-datasets/mbpp",
    }:
        return DatasetSpec(dataset=ds, modality="text", label_key="label", num_classes=2)

    if ds in {
        "scikit-learn/adult-census-income",
        "jlh/uci-mushrooms",
        "scikit-learn/iris",
        "jiahborcn/chembl_aqsol",
        "jiahborcn/chembl_multiassay_activity",
    }:
        return DatasetSpec(dataset=ds, modality="tabular", label_key="label", num_classes=2)

    if ds in {
        "google/speech_commands",
        "flwrlabs/ambient-acoustic-context",
        "fixie-ai/common_voice_17_0",
        "fixie-ai/librispeech_asr",
    }:
        return DatasetSpec(dataset=ds, modality="audio", label_key="label", num_classes=2)

    # Fallback: infer modality/keys at runtime.
    return DatasetSpec(dataset=ds, modality="auto", label_key="label", num_classes=0)


def _infer_from_hf(
    dataset: str,
    subset: Optional[str],
    train_split: str,
    eval_split: str,
    modality_hint: str,
    overrides: Dict[str, Any],
    trust_remote_code: bool,
) -> DatasetSpec:
    """Infer dataset keys and modality from a tiny HF sample (best-effort)."""

    # Read one sample (fast) to infer columns/modes.
    ds_kwargs: Dict[str, Any] = {"trust_remote_code": bool(trust_remote_code)}
    if subset:
        ds_kwargs["name"] = subset

    sample = load_dataset(dataset, split=f"{train_split}[:1]", **ds_kwargs)[0]
    columns = set(sample.keys())

    def first_existing(names: Iterable[str]) -> Optional[str]:
        for n in names:
            if n in columns:
                return n
        return None

    # Apply explicit overrides first
    label_key = overrides.get("label-key") or overrides.get("dataset-label-key")
    if not label_key:
        label_key = first_existing(
            [
                "label",
                "fine_label",
                "coarse_label",
                "sentiment",
                "target",
                "y",
            ]
        )
    if not label_key:
        raise ValueError(
            f"Could not infer label column for dataset {dataset!r}. "
            "Set run config key label-key=\"...\"."
        )

    modality = str(modality_hint or "auto").strip().lower()
    if modality == "auto":
        if (overrides.get("image-key") or overrides.get("dataset-image-key")) or first_existing(
            ["img", "image"]
        ):
            modality = "vision"
        elif (overrides.get("audio-key") or overrides.get("dataset-audio-key")) or "audio" in columns:
            modality = "audio"
        elif (overrides.get("text-key") or overrides.get("dataset-text-key")) or first_existing(
            ["text", "sentence", "review", "content", "question", "prompt"]
        ):
            modality = "text"
        else:
            modality = "tabular"

    if modality == "vision":
        image_key = overrides.get("image-key") or overrides.get("dataset-image-key") or first_existing(
            ["img", "image"]
        )
        if not image_key:
            raise ValueError(
                f"Could not infer image column for dataset {dataset!r}. "
                "Set run config key image-key=\"img\" (or similar)."
            )
        # Infer channels from PIL image mode.
        img = sample[image_key]
        channels = 3
        try:
            mode = getattr(img, "mode", None)
            if mode in {"L", "1"}:
                channels = 1
            elif mode in {"RGB", "RGBA"}:
                channels = 3
        except Exception:
            channels = 3

        num_classes = int(overrides.get("num-classes") or 0)
        if num_classes <= 0:
            # Try to infer from HF features
            try:
                ds0 = load_dataset(dataset, split=f"{train_split}[:100]", **ds_kwargs)
                feat = ds0.features.get(label_key)
                names = getattr(feat, "names", None)
                if names:
                    num_classes = int(len(names))
            except Exception:
                num_classes = 10

        return DatasetSpec(
            dataset=dataset,
            modality="vision",
            image_key=str(image_key),
            label_key=str(label_key),
            input_channels=int(channels),
            num_classes=int(num_classes or 10),
            train_split=str(train_split),
            central_eval_split=str(eval_split),
        )

    if modality == "text":
        text_key = overrides.get("text-key") or overrides.get("dataset-text-key") or first_existing(
            ["text", "sentence", "review", "content", "question", "prompt"]
        )
        if not text_key:
            raise ValueError(
                f"Could not infer text column for dataset {dataset!r}. "
                "Set run config key text-key=\"text\" (or similar)."
            )
        num_classes = int(overrides.get("num-classes") or 0) or 2
        return DatasetSpec(
            dataset=dataset,
            modality="text",
            text_key=str(text_key),
            label_key=str(label_key),
            num_classes=int(num_classes),
            train_split=str(train_split),
            central_eval_split=str(eval_split),
        )

    if modality == "audio":
        audio_key = overrides.get("audio-key") or overrides.get("dataset-audio-key") or (
            "audio" if "audio" in columns else None
        )
        if not audio_key:
            raise ValueError(
                f"Could not infer audio column for dataset {dataset!r}. "
                "Set run config key audio-key=\"audio\" (or similar)."
            )
        num_classes = int(overrides.get("num-classes") or 0) or 2
        return DatasetSpec(
            dataset=dataset,
            modality="audio",
            audio_key=str(audio_key),
            label_key=str(label_key),
            num_classes=int(num_classes),
            train_split=str(train_split),
            central_eval_split=str(eval_split),
        )

    # tabular
    num_classes = int(overrides.get("num-classes") or 0) or 2
    return DatasetSpec(
        dataset=dataset,
        modality="tabular",
        label_key=str(label_key),
        num_classes=int(num_classes),
        train_split=str(train_split),
        central_eval_split=str(eval_split),
    )


def _resolve_spec(
    *,
    dataset: str,
    dataset_subset: Optional[str],
    dataset_modality: str,
    train_split: str,
    eval_split: str,
    overrides: Dict[str, Any],
    trust_remote_code: bool,
) -> DatasetSpec:
    """Resolve DatasetSpec from registry + overrides, falling back to inference."""

    base = get_dataset_spec(dataset)
    modality = str(dataset_modality or base.modality).strip().lower()
    if modality == "auto":
        modality = str(base.modality).strip().lower()

    # Start with base and apply splits/modality/overrides.
    spec = DatasetSpec(
        dataset=base.dataset,
        modality=modality,
        label_key=str(overrides.get("label-key") or base.label_key),
        num_classes=int(overrides.get("num-classes") or base.num_classes),
        image_key=base.image_key,
        input_channels=base.input_channels,
        text_key=base.text_key,
        audio_key=base.audio_key,
        train_split=str(train_split or base.train_split),
        central_eval_split=str(eval_split or base.central_eval_split),
    )

    # Apply key overrides
    if overrides.get("image-key"):
        spec = DatasetSpec(
            **{**spec.__dict__, "image_key": str(overrides["image-key"])}  # type: ignore[arg-type]
        )
    if overrides.get("text-key"):
        spec = DatasetSpec(
            **{**spec.__dict__, "text_key": str(overrides["text-key"])}  # type: ignore[arg-type]
        )
    if overrides.get("audio-key"):
        spec = DatasetSpec(
            **{**spec.__dict__, "audio_key": str(overrides["audio-key"])}  # type: ignore[arg-type]
        )

    # If required fields are still missing, infer from HF (opt-in for remote code).
    needs_infer = False
    if spec.num_classes <= 0:
        needs_infer = True
    if spec.modality == "vision" and (not spec.image_key or not spec.input_channels):
        needs_infer = True
    if spec.modality == "text" and not spec.text_key:
        needs_infer = True
    if spec.modality == "audio" and not spec.audio_key:
        needs_infer = True

    if not needs_infer:
        return spec

    inferred = _infer_from_hf(
        dataset=dataset,
        subset=dataset_subset,
        train_split=spec.train_split,
        eval_split=spec.central_eval_split,
        modality_hint=spec.modality,
        overrides=overrides,
        trust_remote_code=trust_remote_code,
    )
    return inferred

class Net(nn.Module):
    """Simple CNN adapted from 'PyTorch: A 60 Minute Blitz'.

    This version supports configurable input channels and number of classes.
    """

    def __init__(self, input_channels: int = 3, num_classes: int = 10):
        super().__init__()
        self.conv1 = nn.Conv2d(int(input_channels), 6, 5)
        self.pool = nn.MaxPool2d(2, 2)
        self.conv2 = nn.Conv2d(6, 16, 5)
        self.adapt = nn.AdaptiveAvgPool2d((5, 5))
        self.fc1 = nn.Linear(16 * 5 * 5, 120)
        self.fc2 = nn.Linear(120, 84)
        self.fc3 = nn.Linear(84, int(num_classes))

    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = self.adapt(x)
        x = x.view(-1, 16 * 5 * 5)
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.fc3(x)

def create_model(dataset: str) -> Net:
    spec = get_dataset_spec(dataset)
    if spec.modality not in {"vision", "auto"}:
        raise ValueError("create_model() is vision-only; use get_task().")
    input_channels = int(spec.input_channels or 3)
    num_classes = int(spec.num_classes or 10)
    return Net(input_channels=input_channels, num_classes=num_classes)


fds: Optional[FederatedDataset] = None  # Cache FederatedDataset
_fds_key: Optional[tuple] = None


def _make_pytorch_transforms(channels: int) -> Compose:
    mean = tuple([0.5] * int(channels))
    std = tuple([0.5] * int(channels))
    return Compose([ToTensor(), Normalize(mean, std)])


def _apply_transforms_factory(spec: DatasetSpec) -> Callable:
    assert spec.input_channels is not None
    assert spec.image_key is not None
    pytorch_transforms = _make_pytorch_transforms(spec.input_channels)

    def apply_transforms(batch):
        imgs = batch.get(spec.image_key)
        if imgs is None:
            # Best-effort fallback for common HF vision datasets
            imgs = batch.get("img")
        if imgs is None:
            imgs = batch.get("image")
        if imgs is None:
            raise KeyError(
                f"Expected image column {spec.image_key!r} (or img/image fallback)"
            )

        tensors = []
        for img in imgs:
            t = pytorch_transforms(img)
            if spec.input_channels == 3 and t.shape[0] == 1:
                t = t.repeat(3, 1, 1)
            if spec.input_channels == 1 and t.shape[0] == 3:
                t = t.mean(dim=0, keepdim=True)
            tensors.append(t)

        # Standardize the image column to tensors.
        # IMPORTANT: also overwrite the original image column (e.g. MNIST uses
        # "image") so PyTorch's default collate never sees PIL objects.
        batch["img"] = tensors
        batch[spec.image_key] = tensors

        # Standardize label key for downstream train/test code.
        if spec.label_key != "label" and spec.label_key in batch:
            batch["label"] = batch[spec.label_key]
        return batch

    return apply_transforms


def load_data(
    partition_id: int,
    num_partitions: int,
    batch_size: int,
    dataset: str = "uoft-cs/cifar10",
    dataset_subset: str = "",
    dataset_modality: str = "auto",
    train_split: str = "train",
    eval_split: str = "test",
    image_key: str = "",
    text_key: str = "",
    audio_key: str = "",
    label_key: str = "",
    num_classes: int = 0,
    hf_trust_remote_code: bool = False,
    partitioner: str = "iid",
    dirichlet_alpha: float = 0.5,
    max_train_examples: int = 0,
    max_val_examples: int = 0,
) -> Tuple[DataLoader, DataLoader]:
    """Load a client partition.

    For vision datasets, this mirrors the original CIFAR-10 behavior by default.
    """

    overrides: Dict[str, Any] = {
        "image-key": image_key or None,
        "text-key": text_key or None,
        "audio-key": audio_key or None,
        "label-key": label_key or None,
        "num-classes": int(num_classes or 0),
    }

    spec = _resolve_spec(
        dataset=dataset,
        dataset_subset=dataset_subset or None,
        dataset_modality=dataset_modality,
        train_split=train_split,
        eval_split=eval_split,
        overrides=overrides,
        trust_remote_code=bool(hf_trust_remote_code),
    )

    global fds, _fds_key
    key = (
        spec.dataset,
        spec.train_split,
        spec.modality,
        spec.label_key,
        str(partitioner).strip().lower(),
        float(dirichlet_alpha),
        int(num_partitions),
    )
    if fds is None or _fds_key != key:
        part_name = str(partitioner).strip().lower()
        if part_name in {"iid"}:
            part = IidPartitioner(num_partitions=num_partitions)
        elif part_name in {"dirichlet", "noniid", "non-iid"}:
            part = DirichletPartitioner(
                num_partitions=num_partitions,
                partition_by=spec.label_key,
                alpha=dirichlet_alpha,
            )
        else:
            raise ValueError(
                f"Unknown partitioner {part_name!r}. Supported: iid, dirichlet."
            )

        fds = FederatedDataset(
            dataset=spec.dataset,
            subset=(dataset_subset or None),
            partitioners={spec.train_split: part},
            trust_remote_code=bool(hf_trust_remote_code),
        )
        _fds_key = key

    partition = fds.load_partition(partition_id)

    # Divide data on each node: 80% train, 20% val
    partition_train_test = partition.train_test_split(test_size=0.2, seed=42)

    def _cap(ds: Any, cap: int) -> Any:
        cap_i = int(cap or 0)
        if cap_i <= 0:
            return ds
        n = len(ds)
        if cap_i >= n:
            return ds
        # Deterministic: take the first cap_i examples.
        return ds.select(range(cap_i))

    if spec.modality == "vision":
        partition_train_test = partition_train_test.with_transform(
            _apply_transforms_factory(spec)
        )
        train_ds = _cap(partition_train_test["train"], max_train_examples)
        val_ds = _cap(partition_train_test["test"], max_val_examples)
        trainloader = DataLoader(
            train_ds, batch_size=batch_size, shuffle=True
        )
        valloader = DataLoader(val_ds, batch_size=batch_size)
        return trainloader, valloader

    if spec.modality == "text":
        partition_train_test = partition_train_test.with_transform(
            _apply_text_transforms_factory(spec)
        )
        train_ds = _cap(partition_train_test["train"], max_train_examples)
        val_ds = _cap(partition_train_test["test"], max_val_examples)
        trainloader = DataLoader(
            train_ds, batch_size=batch_size, shuffle=True
        )
        valloader = DataLoader(val_ds, batch_size=batch_size)
        return trainloader, valloader

    if spec.modality == "tabular":
        partition_train_test = partition_train_test.with_transform(
            _apply_tabular_transforms_factory(spec)
        )
        train_ds = _cap(partition_train_test["train"], max_train_examples)
        val_ds = _cap(partition_train_test["test"], max_val_examples)
        trainloader = DataLoader(
            train_ds, batch_size=batch_size, shuffle=True
        )
        valloader = DataLoader(val_ds, batch_size=batch_size)
        return trainloader, valloader

    if spec.modality == "audio":
        partition_train_test = partition_train_test.with_transform(
            _apply_audio_transforms_factory(spec)
        )
        train_ds = _cap(partition_train_test["train"], max_train_examples)
        val_ds = _cap(partition_train_test["test"], max_val_examples)
        trainloader = DataLoader(
            train_ds, batch_size=batch_size, shuffle=True
        )
        valloader = DataLoader(val_ds, batch_size=batch_size)
        return trainloader, valloader

    raise ValueError(f"Unsupported modality: {spec.modality!r}")


def load_centralized_dataset(
    dataset: str = "uoft-cs/cifar10",
    dataset_subset: str = "",
    dataset_modality: str = "auto",
    train_split: str = "train",
    eval_split: str = "test",
    image_key: str = "",
    text_key: str = "",
    audio_key: str = "",
    label_key: str = "",
    num_classes: int = 0,
    hf_trust_remote_code: bool = False,
    batch_size: int = 128,
    max_eval_examples: int = 0,
) -> DataLoader:
    """Load the centralized eval split (defaults to CIFAR-10 test)."""

    overrides: Dict[str, Any] = {
        "image-key": image_key or None,
        "text-key": text_key or None,
        "audio-key": audio_key or None,
        "label-key": label_key or None,
        "num-classes": int(num_classes or 0),
    }

    spec = _resolve_spec(
        dataset=dataset,
        dataset_subset=dataset_subset or None,
        dataset_modality=dataset_modality,
        train_split=train_split,
        eval_split=eval_split,
        overrides=overrides,
        trust_remote_code=bool(hf_trust_remote_code),
    )

    split = eval_split or spec.central_eval_split
    ds_kwargs: Dict[str, Any] = {"trust_remote_code": bool(hf_trust_remote_code)}
    if dataset_subset:
        ds_kwargs["name"] = dataset_subset
    try:
        eval_dataset = load_dataset(spec.dataset, split=split, **ds_kwargs)
    except Exception:
        eval_dataset = load_dataset(spec.dataset, split="validation", **ds_kwargs)

    if spec.modality == "vision":
        eval_dataset = eval_dataset.with_format("torch").with_transform(
            _apply_transforms_factory(spec)
        )
    elif spec.modality == "text":
        eval_dataset = eval_dataset.with_format("torch").with_transform(
            _apply_text_transforms_factory(spec)
        )
    elif spec.modality == "tabular":
        eval_dataset = eval_dataset.with_format("torch").with_transform(
            _apply_tabular_transforms_factory(spec)
        )
    elif spec.modality == "audio":
        eval_dataset = eval_dataset.with_format("torch").with_transform(
            _apply_audio_transforms_factory(spec)
        )
    else:
        raise ValueError(f"Unsupported modality: {spec.modality!r}")

    cap = int(max_eval_examples or 0)
    if cap > 0 and cap < len(eval_dataset):
        eval_dataset = eval_dataset.select(range(cap))

    return DataLoader(eval_dataset, batch_size=int(batch_size))


def _stable_hash_32(text: str) -> int:
    # Deterministic across processes (avoid Python's randomized hash())
    import zlib

    return zlib.crc32(text.encode("utf-8", errors="ignore")) & 0xFFFFFFFF


def _normalize_classification_labels(values: Any, *, num_classes: int) -> List[int]:
    """Map label values into [0..num_classes-1] for CrossEntropyLoss.

    This is intentionally conservative and only applies a few deterministic
    conversions that do not depend on seeing the full dataset:
    - Sentiment140-style binary labels {0, 4} -> {0, 1}
    - Binary labels {-1, 1} -> {0, 1}
    - Bool -> {0, 1}

    For other cases, users should provide labels already in range or add an
    explicit preprocessing step.
    """

    if num_classes <= 0:
        raise ValueError("num_classes must be a positive integer")

    if isinstance(values, torch.Tensor):
        # Works for both scalar tensors and 1D label tensors.
        raw_values: List[Any] = list(values)
    elif isinstance(values, (list, tuple)):
        raw_values = list(values)
    else:
        raw_values = [values]

    normalized: List[int] = []
    for v in raw_values:
        if isinstance(v, torch.Tensor):
            if v.numel() != 1:
                raise ValueError(f"Expected scalar label, got shape {tuple(v.shape)}")
            v = v.item()

        if isinstance(v, bool):
            vi = int(v)
        else:
            try:
                vi = int(v)
            except Exception as exc:
                raise ValueError(f"Non-integer label value: {v!r}") from exc

        if 0 <= vi < num_classes:
            normalized.append(vi)
            continue

        if num_classes == 2:
            # Common binary conventions.
            if vi in (0, 4):
                normalized.append(0 if vi == 0 else 1)
                continue
            if vi in (-1, 1):
                normalized.append(0 if vi == -1 else 1)
                continue

        if num_classes == 3:
            # Sentiment140-style labels {0,2,4} -> {0,1,2}
            if vi in (0, 2, 4):
                normalized.append({0: 0, 2: 1, 4: 2}[vi])
                continue

        raise ValueError(
            f"Label value {vi} is out of range for num_classes={num_classes}. "
            "Provide labels in [0..num_classes-1] or adjust run config (e.g., num-classes)."
        )

    return normalized


def _apply_text_transforms_factory(spec: DatasetSpec) -> Callable:
    assert spec.text_key is not None

    hash_dim = 2 ** 15

    def apply_transforms(batch: Dict[str, Any]) -> Dict[str, Any]:
        texts = batch.get(spec.text_key)
        if texts is None:
            raise KeyError(f"Expected text column {spec.text_key!r}")
        vectors: List[torch.Tensor] = []
        for t in texts:
            s = str(t)
            vec = torch.zeros(hash_dim, dtype=torch.float32)
            for tok in s.lower().split():
                idx = _stable_hash_32(tok) % hash_dim
                vec[idx] += 1.0
            vectors.append(vec)
        batch["x"] = vectors

        labels = batch.get(spec.label_key)
        if labels is None:
            raise KeyError(f"Expected label column {spec.label_key!r}")
        batch["label"] = _normalize_classification_labels(labels, num_classes=spec.num_classes)
        return batch

    return apply_transforms


def _apply_tabular_transforms_factory(spec: DatasetSpec) -> Callable:
    hash_dim = 2 ** 14

    def apply_transforms(batch: Dict[str, Any]) -> Dict[str, Any]:
        labels = batch.get(spec.label_key)
        if labels is None:
            raise KeyError(f"Expected label column {spec.label_key!r}")

        # Determine feature columns from this batch.
        feature_cols = [k for k in batch.keys() if k not in {spec.label_key, "label"}]
        # Build a hashed feature vector per row.
        n = len(labels)
        xs: List[torch.Tensor] = []
        for i in range(n):
            vec = torch.zeros(hash_dim, dtype=torch.float32)
            for col in feature_cols:
                val = batch[col][i]
                if val is None:
                    continue
                if isinstance(val, (int, float)):
                    # numeric -> hashed with value
                    idx = _stable_hash_32(f"{col}") % hash_dim
                    vec[idx] += float(val)
                else:
                    # categorical/string
                    idx = _stable_hash_32(f"{col}={val}") % hash_dim
                    vec[idx] += 1.0
            xs.append(vec)

        batch["x"] = xs
        batch["label"] = _normalize_classification_labels(labels, num_classes=spec.num_classes)
        return batch

    return apply_transforms


def _apply_audio_transforms_factory(spec: DatasetSpec) -> Callable:
    # Audio support is optional to keep the default environment fast/light.
    try:
        import importlib

        importlib.import_module("torchaudio")
    except Exception as exc:
        raise RuntimeError(
            "Audio datasets require torchaudio. Install: pip install torchaudio"
        ) from exc

    assert spec.audio_key is not None

    def apply_transforms(batch: Dict[str, Any]) -> Dict[str, Any]:
        audio = batch.get(spec.audio_key)
        if audio is None:
            raise KeyError(f"Expected audio column {spec.audio_key!r}")
        # Placeholder: keep raw audio dicts for now. A real pipeline would compute
        # mel-spectrograms or embeddings.
        batch["audio"] = audio

        labels = batch.get(spec.label_key)
        if labels is None:
            raise KeyError(f"Expected label column {spec.label_key!r}")
        batch["label"] = _normalize_classification_labels(labels, num_classes=spec.num_classes)
        return batch

    return apply_transforms


class TextClassifier(nn.Module):
    def __init__(self, input_dim: int, num_classes: int, hidden: int = 128):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden)
        self.fc2 = nn.Linear(hidden, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = F.relu(self.fc1(x))
        return self.fc2(x)


def get_task_from_run_config(run_config: Dict[str, Any]) -> Tuple[DatasetSpec, Callable[[], nn.Module]]:
    """Resolve a DatasetSpec and return (spec, model_factory)."""
    dataset = str(run_config.get("dataset", "uoft-cs/cifar10"))
    dataset_modality = str(run_config.get("dataset-modality", "auto"))
    train_split = str(run_config.get("dataset-train-split", "train"))
    eval_split = str(run_config.get("dataset-eval-split", "test"))
    dataset_subset = str(run_config.get("dataset-subset", ""))
    trust_remote_code = bool(run_config.get("hf-trust-remote-code", False))

    overrides = {
        "image-key": str(run_config.get("image-key", "")) or None,
        "text-key": str(run_config.get("text-key", "")) or None,
        "audio-key": str(run_config.get("audio-key", "")) or None,
        "label-key": str(run_config.get("label-key", "")) or None,
        "num-classes": int(run_config.get("num-classes", 0) or 0),
    }

    spec = _resolve_spec(
        dataset=dataset,
        dataset_subset=dataset_subset or None,
        dataset_modality=dataset_modality,
        train_split=train_split,
        eval_split=eval_split,
        overrides=overrides,
        trust_remote_code=trust_remote_code,
    )

    if spec.modality == "vision":
        assert spec.input_channels is not None
        return spec, lambda: Net(input_channels=spec.input_channels, num_classes=spec.num_classes)

    if spec.modality == "text":
        # Hash dim must match _apply_text_transforms_factory
        return spec, lambda: TextClassifier(input_dim=2 ** 15, num_classes=spec.num_classes)

    if spec.modality == "tabular":
        return spec, lambda: TextClassifier(input_dim=2 ** 14, num_classes=spec.num_classes)

    if spec.modality == "audio":
        raise RuntimeError(
            "Audio modality is scaffolded only. Install torchaudio and implement a feature extractor/model."
        )

    raise ValueError(f"Unsupported modality: {spec.modality!r}")


def train(net, trainloader, epochs, lr, device, *, attack: Optional[Dict[str, Any]] = None):
    """Train the model on the training set.

    Returns:
        (avg_train_loss, poison_stats)
    """
    net.to(device)  # move model to GPU if available
    criterion = torch.nn.CrossEntropyLoss().to(device)
    optimizer = torch.optim.SGD(net.parameters(), lr=lr, momentum=0.9)
    net.train()
    running_loss = 0.0

    poison_examples_seen = 0
    poison_examples_poisoned = 0
    poison_label_flip_poisoned = 0
    poison_backdoor_poisoned = 0

    def _maybe_poison_batch(
        *,
        inputs: torch.Tensor,
        labels: torch.Tensor,
        attack: Optional[Dict[str, Any]],
        step: int,
    ) -> Tuple[torch.Tensor, torch.Tensor, Dict[str, int]]:
        if not attack:
            return inputs, labels, {"poisoned": 0, "label_flip": 0, "backdoor": 0}
        if not bool(attack.get("enabled", False)):
            return inputs, labels, {"poisoned": 0, "label_flip": 0, "backdoor": 0}
        if not bool(attack.get("is_malicious", False)):
            return inputs, labels, {"poisoned": 0, "label_flip": 0, "backdoor": 0}

        # Multi-layer support (client-side poisoning only cares about label_flip/backdoor).
        layers_raw = attack.get("layers")
        layers: List[str] = []
        if isinstance(layers_raw, list):
            layers = [str(x).strip().lower().replace("-", "_") for x in layers_raw if str(x).strip()]
        elif isinstance(layers_raw, str) and layers_raw.strip():
            s = layers_raw.strip().lower()
            if ";" in s:
                layers = [p.strip().replace("-", "_") for p in s.split(";") if p.strip()]
            elif "+" in s:
                layers = [p.strip().replace("-", "_") for p in s.split("+") if p.strip()]

        name = str(attack.get("name", "none") or "none").strip().lower().replace("-", "_")
        if not layers:
            layers = [name]

        intensity = float(attack.get("intensity", 0.0) or 0.0)
        if intensity <= 0.0 or all(str(x).strip().lower() in {"none", "off", "disabled"} for x in layers):
            return inputs, labels, {"poisoned": 0, "label_flip": 0, "backdoor": 0}

        # Optional per-layer intensities (effective intensity per layer).
        # If absent, fall back to the global intensity.
        li_raw = attack.get("layer_intensities")
        if li_raw is None:
            li_raw = attack.get("attack_layer_intensities")
        layer_intensities: Dict[str, float] = {}
        if isinstance(li_raw, dict):
            for k, v in li_raw.items():
                try:
                    kk = str(k).strip().lower().replace("-", "_")
                    if not kk:
                        continue
                    layer_intensities[kk] = float(max(0.0, float(v)))
                except Exception:
                    continue
        elif isinstance(li_raw, str) and li_raw.strip():
            parts = li_raw.replace(",", ";").split(";")
            for p in parts:
                if "=" not in p:
                    continue
                k, v = p.split("=", 1)
                kk = str(k).strip().lower().replace("-", "_")
                if not kk:
                    continue
                try:
                    layer_intensities[kk] = float(max(0.0, float(v)))
                except Exception:
                    continue

        seed = int(attack.get("seed", 0) or 0)
        server_round = int(attack.get("server_round", 0) or 0)
        client_id = int(attack.get("client_id", 0) or 0)
        gen = torch.Generator(device="cpu")

        poisoned_any = torch.zeros((labels.shape[0],), dtype=torch.bool, device="cpu")
        poisoned_lf = 0
        poisoned_bd = 0

        # Apply layers in order
        for layer in layers:
            layer = str(layer).strip().lower().replace("-", "_")

            # Label flipping (classification)
            if layer == "label_flip":
                num_classes = int(attack.get("num_classes", 0) or 0)
                if num_classes <= 1:
                    continue

                layer_intensity = float(layer_intensities.get("label_flip", intensity) or 0.0)
                if layer_intensity <= 0.0:
                    continue

                flip_rate = float(attack.get("label_flip_flip_rate", 0.0) or 0.0)
                flip_rate = max(0.0, min(1.0, flip_rate * layer_intensity))
                if flip_rate <= 0.0:
                    continue

                targeted = bool(attack.get("label_flip_targeted", False))
                src = int(attack.get("label_flip_source_class", 0) or 0)
                tgt = int(attack.get("label_flip_target_class", 1) or 1)
                src = int(max(0, min(num_classes - 1, src)))
                tgt = int(max(0, min(num_classes - 1, tgt)))

                gen.manual_seed(_stable_int_seed(seed, server_round, client_id, 31001 + int(step)))
                labels_cpu = labels.detach().to("cpu")
                mask = (torch.rand((labels_cpu.shape[0],), generator=gen) < float(flip_rate))
                if targeted:
                    mask = mask & (labels_cpu == int(src))
                    if not bool(mask.any().item()):
                        continue
                    new_labels = labels_cpu.clone()
                    new_labels[mask] = int(tgt)
                    labels = new_labels.to(device)
                    poisoned_any |= mask
                    poisoned_lf += int(mask.sum().item())
                    continue

                # Untargeted: flip to any other class
                if not bool(mask.any().item()):
                    continue
                r = torch.randint(
                    0,
                    int(num_classes - 1),
                    size=labels_cpu.shape,
                    generator=gen,
                    dtype=labels_cpu.dtype,
                )
                new_vals = r + (r >= labels_cpu).to(labels_cpu.dtype)
                new_labels = labels_cpu.clone()
                new_labels[mask] = new_vals[mask]
                labels = new_labels.to(device)
                poisoned_any |= mask
                poisoned_lf += int(mask.sum().item())
                continue

            # Backdoor (vision only)
            if layer == "backdoor":
                if inputs.ndim != 4:
                    continue

                layer_intensity = float(layer_intensities.get("backdoor", intensity) or 0.0)
                if layer_intensity <= 0.0:
                    continue

                poison_rate = float(attack.get("backdoor_poison_rate", 0.0) or 0.0)
                poison_rate = max(0.0, min(1.0, poison_rate * layer_intensity))
                if poison_rate <= 0.0:
                    continue
                target_label = int(attack.get("backdoor_target_label", 0) or 0)
                patch_size = int(attack.get("backdoor_patch_size", 4) or 4)
                blend_alpha = float(attack.get("backdoor_blend_alpha", 0.0) or 0.0)
                alpha = max(0.0, min(1.0, blend_alpha * layer_intensity))
                if alpha <= 0.0:
                    continue

                gen.manual_seed(_stable_int_seed(seed, server_round, client_id, 31002 + int(step)))
                b, c, h, w = inputs.shape
                ps = int(max(1, min(patch_size, h, w)))

                mask = (torch.rand((b,), generator=gen) < float(poison_rate))
                if not bool(mask.any().item()):
                    continue

                poisoned = inputs.clone()
                labels2 = labels.clone()

                idxs = [int(i) for i in torch.nonzero(mask, as_tuple=False).flatten().tolist()]
                for i in idxs:
                    # Simple bottom-right patch trigger in tensor space.
                    region = poisoned[i, :, (h - ps) : h, (w - ps) : w]
                    patch = torch.ones_like(region)
                    poisoned[i, :, (h - ps) : h, (w - ps) : w] = (1.0 - float(alpha)) * region + float(alpha) * patch
                    labels2[i] = int(target_label)

                inputs = poisoned
                labels = labels2
                poisoned_any |= mask
                poisoned_bd += int(mask.sum().item())
                continue

        poisoned_total = int(poisoned_any.sum().item()) if poisoned_any.numel() else 0
        return inputs, labels, {"poisoned": int(poisoned_total), "label_flip": int(poisoned_lf), "backdoor": int(poisoned_bd)}

    step = 0
    for _ in range(epochs):
        for batch in trainloader:
            # Vision uses batch["img"], text/tabular use batch["x"].
            if "img" in batch:
                inputs = batch["img"].to(device)
            else:
                inputs = batch["x"].to(device)
            labels = batch["label"].to(device)

            poison_examples_seen += int(labels.shape[0])

            # Apply client-side dataset poisoning if instructed.
            inputs, labels, poisoned_counts = _maybe_poison_batch(
                inputs=inputs,
                labels=labels,
                attack=attack,
                step=step,
            )
            step += 1
            pc = int((poisoned_counts or {}).get("poisoned", 0) or 0)
            if pc > 0:
                poison_examples_poisoned += int(pc)
            poison_label_flip_poisoned += int((poisoned_counts or {}).get("label_flip", 0) or 0)
            poison_backdoor_poisoned += int((poisoned_counts or {}).get("backdoor", 0) or 0)

            optimizer.zero_grad()
            loss = criterion(net(inputs), labels)
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
    avg_trainloss = running_loss / len(trainloader)
    poison_stats = {
        "examples_seen": int(poison_examples_seen),
        "poisoned_examples": int(poison_examples_poisoned),
        "poisoned_label_flip_examples": int(poison_label_flip_poisoned),
        "poisoned_backdoor_examples": int(poison_backdoor_poisoned),
    }
    return avg_trainloss, poison_stats


def test(net, testloader, device):
    """Validate the model on the test set."""
    net.to(device)
    criterion = torch.nn.CrossEntropyLoss()
    correct, loss = 0, 0.0
    with torch.no_grad():
        for batch in testloader:
            if "img" in batch:
                inputs = batch["img"].to(device)
            else:
                inputs = batch["x"].to(device)
            labels = batch["label"].to(device)
            outputs = net(inputs)
            loss += criterion(outputs, labels).item()
            correct += (torch.max(outputs.data, 1)[1] == labels).sum().item()
    accuracy = correct / len(testloader.dataset)
    loss = loss / len(testloader)
    return loss, accuracy


def test_backdoor(
    net,
    testloader,
    device,
    *,
    target_label: int,
    trigger_type: str = "patch",
    patch_size: int = 4,
    blend_alpha: float = 0.2,
):
    """Evaluate *backdoor attack success rate* (ASR) on a central test set.

    Definition used here (standard in backdoor literature):
    - Apply a trigger to every input.
    - Set the label to `target_label` for evaluation purposes.
    - ASR is the fraction of triggered inputs classified as `target_label`.

    Returns (triggered_loss, backdoor_asr). If the dataloader does not provide
    image tensors (no `batch["img"]`), returns (nan, nan).
    """

    net.to(device)
    criterion = torch.nn.CrossEntropyLoss()

    trigger_type = str(trigger_type or "patch").strip().lower()
    patch_size = int(patch_size)
    patch_size = max(1, patch_size)
    blend_alpha = float(blend_alpha)
    blend_alpha = max(0.0, min(1.0, blend_alpha))
    target_label = int(target_label)

    total = 0
    correct = 0
    loss = 0.0
    batches = 0

    def _apply_patch_trigger(x: torch.Tensor) -> torch.Tensor:
        # x: [B, C, H, W]
        if x.dim() != 4:
            return x
        b, c, h, w = x.shape
        ps = min(patch_size, h, w)
        if ps <= 0:
            return x
        patch = torch.ones((b, c, ps, ps), device=x.device, dtype=x.dtype)
        x2 = x.clone()
        x2[:, :, h - ps : h, w - ps : w] = (1.0 - blend_alpha) * x2[:, :, h - ps : h, w - ps : w] + blend_alpha * patch
        return x2

    with torch.no_grad():
        for batch in testloader:
            if "img" not in batch:
                continue
            inputs = batch["img"].to(device)
            labels = batch["label"].to(device)

            if trigger_type == "patch":
                poisoned = _apply_patch_trigger(inputs)
            else:
                # Unknown trigger type; fall back to patch.
                poisoned = _apply_patch_trigger(inputs)

            labels2 = torch.full_like(labels, target_label)
            outputs = net(poisoned)
            loss += criterion(outputs, labels2).item()
            preds = torch.max(outputs.data, 1)[1]
            correct += (preds == labels2).sum().item()
            total += int(labels2.shape[0])
            batches += 1

    if total <= 0 or batches <= 0:
        return float("nan"), float("nan")
    return loss / float(batches), float(correct) / float(total)
