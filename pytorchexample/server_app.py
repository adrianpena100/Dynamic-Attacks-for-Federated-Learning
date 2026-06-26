"""pytorchexample: A Flower / PyTorch app."""

from __future__ import annotations

import copy
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
from flwr.app import ArrayRecord, ConfigRecord, Context, MetricRecord, RecordDict
from flwr.serverapp import Grid, ServerApp
from flwr.serverapp.strategy import (
    Bulyan,
    FedAdagrad,
    FedAdam,
    FedAvg,
    FedAvgM,
    FedMedian,
    FedProx,
    FedTrimmedAvg,
    FedYogi,
    Krum,
    MultiKrum,
    QFedAvg,
)
from pytorchexample.task import (
    AttackEngine,
    get_task_from_run_config,
    load_attack_config,
    load_centralized_dataset,
    test,
    test_backdoor,
)

# Create ServerApp
app = ServerApp()


def _arrays_all_finite(arrays: ArrayRecord) -> bool:
    """Return True if all array values are finite (no NaN/Inf)."""
    try:
        for nd in arrays.to_numpy_ndarrays():
            if not np.isfinite(nd).all():
                return False
        return True
    except Exception:
        # Best-effort: if we can't check, don't block training.
        return True


class AttackInjectedStrategyMixin:
    """Mixin that injects dynamic attacks in `aggregate_train`.

    Works with Flower ServerApp strategies (FedAvg/FedAdam/etc) which expose
    `configure_train` and `aggregate_train`.
    """

    def set_attack_engine(self, engine: AttackEngine) -> None:
        self._attack_engine = engine
        self._selected_by_round: dict[int, list[int]] = {}
        self._last_finite_global_arrays: ArrayRecord | None = None
        self._trust_csv_path: Path | None = None
        try:
            artifact_dir = getattr(engine, "artifact_dir", None)
            if artifact_dir is not None:
                summaries_dir = Path(artifact_dir) / "summaries"
                summaries_dir.mkdir(parents=True, exist_ok=True)
                self._trust_csv_path = summaries_dir / "trust_strategy_by_round.csv"
                if not self._trust_csv_path.exists():
                    self._trust_csv_path.write_text(
                        "round,strategy,client_id,trust_score,selected_for_aggregation,"
                        "update_norm,cosine_to_center,history_score,reputation,num_examples,details_json\n",
                        encoding="utf-8",
                    )
        except Exception:
            self._trust_csv_path = None

    def _log_trust_round(self, *, server_round: int, strategy: str, rows: List[Dict[str, Any]]) -> None:
        p = getattr(self, "_trust_csv_path", None)
        if p is None:
            return
        try:
            with p.open("a", encoding="utf-8") as f:
                for row in rows:
                    details = row.get("details") or {}
                    if not isinstance(details, dict):
                        details = {"value": str(details)}
                    f.write(
                        f"{int(server_round)},{str(strategy)},"
                        f"{int(row.get('client_id', -1))},"
                        f"{float(row.get('trust_score', 0.0)):.10g},"
                        f"{int(1 if bool(row.get('selected_for_aggregation', False)) else 0)},"
                        f"{float(row.get('update_norm', 0.0)):.10g},"
                        f"{float(row.get('cosine_to_center', 0.0)):.10g},"
                        f"{float(row.get('history_score', 0.0)):.10g},"
                        f"{float(row.get('reputation', 0.0)):.10g},"
                        f"{int(row.get('num_examples', 0) or 0)},"
                        f"{json.dumps(details, sort_keys=True).replace(',', ';')}\n"
                    )
        except Exception:
            pass

    def configure_train(self, server_round: int, arrays: ArrayRecord, config: ConfigRecord, grid: Grid):
        engine = getattr(self, "_attack_engine", None)
        if engine is not None:
            engine.set_current_global_arrays(arrays)

        # Keep a rollback checkpoint of the last known-finite global model.
        if _arrays_all_finite(arrays):
            self._last_finite_global_arrays = arrays

        messages = list(super().configure_train(server_round, arrays, config, grid))
        selected: list[int] = []
        for m in messages:
            dst = getattr(getattr(m, "metadata", None), "dst_node_id", None)
            if dst is not None:
                try:
                    selected.append(int(dst))
                except Exception:
                    pass
        self._selected_by_round[int(server_round)] = selected

        # Plan round attack once here so clients can receive instructions
        # for dataset-poisoning attacks (label_flip/backdoor).
        if engine is not None:
            try:
                plan = engine.plan_round(server_round=int(server_round), selected_client_ids=list(selected))
            except Exception:
                plan = None

            if plan is not None:
                def _copy_config_record(cfg_rec: ConfigRecord) -> ConfigRecord:
                    """Return a fresh ConfigRecord instance with the same contents.

                    Some Flower strategies reuse the same ConfigRecord/RecordDict object across
                    all messages in a round. If we mutate in-place, values from the last client
                    can leak to all clients. This helper makes copying robust.
                    """
                    # 1) Try deepcopy (often works and preserves types)
                    try:
                        cfg_dc = copy.deepcopy(cfg_rec)
                        if isinstance(cfg_dc, ConfigRecord) and (cfg_dc is not cfg_rec):
                            return cfg_dc
                    except Exception:
                        pass

                    # 2) Try to rebuild from keys
                    try:
                        cfg_dict: dict = {}
                        keys = getattr(cfg_rec, "keys", None)
                        if callable(keys):
                            for k in list(keys()):
                                try:
                                    cfg_dict[k] = cfg_rec[k]
                                except Exception:
                                    continue
                            return ConfigRecord(cfg_dict)
                    except Exception:
                        pass

                    # 3) Final fallback: best-effort cast
                    try:
                        return ConfigRecord(dict(cfg_rec))  # type: ignore[arg-type]
                    except Exception:
                        return ConfigRecord({})

                for m in messages:
                    dst = getattr(getattr(m, "metadata", None), "dst_node_id", None)
                    if dst is None:
                        continue
                    try:
                        cid = int(dst)
                    except Exception:
                        continue

                    try:
                        cfg_rec = m.content["config"]
                    except Exception:
                        continue

                    # Always rebuild a fresh RecordDict per message with a copied ConfigRecord.
                    # This avoids cross-client leakage when Flower reuses objects.
                    cfg_rec_copy = _copy_config_record(cfg_rec)
                    try:
                        arrays_rec = m.content["arrays"]
                    except Exception:
                        arrays_rec = None

                    if arrays_rec is not None:
                        m.content = RecordDict({"arrays": arrays_rec, "config": cfg_rec_copy})
                    else:
                        m.content = RecordDict({"config": cfg_rec_copy})

                    cfg_rec = cfg_rec_copy

                    try:
                        engine.apply_client_attack_config(
                            server_round=int(server_round),
                            client_id=cid,
                            config=cfg_rec,
                        )
                    except Exception:
                        # Best-effort only; never block training.
                        pass
        return messages

    def configure_evaluate(self, server_round: int, arrays: ArrayRecord, config: ConfigRecord, grid: Grid):
        messages = list(super().configure_evaluate(server_round, arrays, config, grid))

        # Add server_round to evaluation config so client-side eval metrics can be
        # plotted against true rounds (instead of inferred event indices).
        for m in messages:
            try:
                cfg_rec = m.content["config"]
            except Exception:
                continue

            dst = getattr(getattr(m, "metadata", None), "dst_node_id", None)
            client_id = None
            if dst is not None:
                try:
                    client_id = int(dst)
                except Exception:
                    client_id = None

            try:
                cfg_dict = {k: cfg_rec[k] for k in cfg_rec.keys()}  # type: ignore[attr-defined]
                cfg_dict["server_round"] = int(server_round)
                if client_id is not None:
                    cfg_dict["client_id"] = int(client_id)
                cfg_rec_copy = ConfigRecord(cfg_dict)

                try:
                    arrays_rec = m.content["arrays"]
                except Exception:
                    arrays_rec = None

                if arrays_rec is not None:
                    m.content = RecordDict({"arrays": arrays_rec, "config": cfg_rec_copy})
                else:
                    m.content = RecordDict({"config": cfg_rec_copy})
            except Exception:
                # Best-effort: fall back to in-place mutation.
                try:
                    cfg_rec["server_round"] = int(server_round)
                    if client_id is not None:
                        cfg_rec["client_id"] = int(client_id)
                except Exception:
                    pass

        return messages

    def aggregate_train(self, server_round: int, replies):
        replies_list = list(replies)
        engine = getattr(self, "_attack_engine", None)
        if engine is not None:
            selected = self._selected_by_round.get(int(server_round))
            if not selected:
                selected = []
                for r in replies_list:
                    src = getattr(getattr(r, "metadata", None), "src_node_id", None)
                    if src is not None:
                        try:
                            selected.append(int(src))
                        except Exception:
                            pass
            engine.maybe_inject_attacks(
                server_round=int(server_round),
                selected_client_ids=list(selected),
                replies=replies_list,
            )

            try:
                kept_ids: list[int] = []
                for r in replies_list:
                    src = getattr(getattr(r, "metadata", None), "src_node_id", None)
                    if src is None:
                        continue
                    try:
                        kept_ids.append(int(src))
                    except Exception:
                        continue
                mode = str(engine.run_config.get("defense-filter-mode", engine.run_config.get("defense_filter_mode", "none")) or "none")
                engine.log_defense_filter_round(
                    server_round=int(server_round),
                    mode=mode,
                    num_before=int(len(replies_list)),
                    kept_client_ids=kept_ids,
                    rejected_client_ids=[],
                )
            except Exception:
                pass

        aggregated_arrays, aggregated_metrics = super().aggregate_train(server_round, replies_list)

        # If the aggregated global model becomes non-finite, training metrics can
        # collapse into constant accuracy (~class-0 fraction on MNIST) and NaN loss.
        # Reject the update and roll back to the last known-finite global model.
        if aggregated_arrays is not None and not _arrays_all_finite(aggregated_arrays):
            fallback = getattr(self, "_last_finite_global_arrays", None)
            print(
                "WARNING: Aggregated global arrays contain NaN/Inf; "
                "reverting to last finite global model.",
                flush=True,
            )
            if aggregated_metrics is None:
                aggregated_metrics = MetricRecord({})
            try:
                aggregated_metrics["non_finite_global_update"] = 1.0
            except Exception:
                pass
            if fallback is not None:
                return fallback, aggregated_metrics
            return aggregated_arrays, aggregated_metrics

        if aggregated_arrays is not None and _arrays_all_finite(aggregated_arrays):
            self._last_finite_global_arrays = aggregated_arrays

        return aggregated_arrays, aggregated_metrics


class AttackFedAvg(AttackInjectedStrategyMixin, FedAvg):
    pass


class AttackFedAvgM(AttackInjectedStrategyMixin, FedAvgM):
    pass


class AttackFedProx(AttackInjectedStrategyMixin, FedProx):
    pass


class AttackQFedAvg(AttackInjectedStrategyMixin, QFedAvg):
    pass


class AttackFedAdagrad(AttackInjectedStrategyMixin, FedAdagrad):
    pass


class AttackFedAdam(AttackInjectedStrategyMixin, FedAdam):
    pass


class AttackFedYogi(AttackInjectedStrategyMixin, FedYogi):
    pass


class AttackFedMedian(AttackInjectedStrategyMixin, FedMedian):
    pass


class AttackFedTrimmedAvg(AttackInjectedStrategyMixin, FedTrimmedAvg):
    pass


class AttackKrum(AttackInjectedStrategyMixin, Krum):
    pass


class AttackMultiKrum(AttackInjectedStrategyMixin, MultiKrum):
    pass


class AttackBulyan(AttackInjectedStrategyMixin, Bulyan):
    pass


# ---------------------------------------------------------------------------
# FLTrust (Cao et al., 2021) — trust-score robust aggregation
# ---------------------------------------------------------------------------
# The server maintains a small clean "root" dataset.  Each round it trains a
# local copy of the global model on the root data to obtain a server update.
# Client updates are scored by cosine similarity to the server update (ReLU-
# clipped), normalised to the server update norm, then trust-weighted averaged.

class FLTrustStrategy(FedAvg):
    """FLTrust aggregation built on top of FedAvg's client selection logic."""

    def __init__(
        self,
        root_dataloader,
        model_factory,
        device,
        server_lr: float = 0.1,
        server_epochs: int = 1,
        trust_strength: float = 0.15,
        min_weight: float = 0.75,
        warmup_rounds: int = 5,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._fltrust_root_loader = root_dataloader
        self._fltrust_model_factory = model_factory
        self._fltrust_device = device
        self._fltrust_lr = server_lr
        self._fltrust_epochs = server_epochs
        self._trust_strength = float(max(0.0, min(1.0, trust_strength)))
        self._trust_min_weight = float(max(0.0, min(1.0, min_weight)))
        self._trust_warmup_rounds = int(max(0, warmup_rounds))

    # -- aggregation ---------------------------------------------------------
    def aggregate_train(self, server_round: int, replies):
        replies_list = list(replies)
        global_arrays = getattr(self, "_last_finite_global_arrays", None)
        if global_arrays is None or not replies_list:
            return super().aggregate_train(server_round, replies_list)

        global_sd = global_arrays.to_torch_state_dict()
        param_keys = list(global_sd.keys())

        # 1. Server update via training on root data ----------------------
        srv = self._fltrust_model_factory()
        srv.load_state_dict({k: v.clone() for k, v in global_sd.items()})
        srv.to(self._fltrust_device)
        srv.train()
        opt = torch.optim.SGD(srv.parameters(), lr=self._fltrust_lr)
        crit = torch.nn.CrossEntropyLoss()
        for _epoch in range(self._fltrust_epochs):
            for batch in self._fltrust_root_loader:
                inputs = batch["img"].to(self._fltrust_device) if "img" in batch else batch["x"].to(self._fltrust_device)
                labels = batch["label"].to(self._fltrust_device)
                opt.zero_grad()
                crit(srv(inputs), labels).backward()
                opt.step()

        srv_sd = srv.state_dict()
        srv_flat = torch.cat([(srv_sd[k].cpu().float() - global_sd[k].cpu().float()).flatten() for k in param_keys])
        srv_norm = torch.norm(srv_flat).item()
        if srv_norm < 1e-10:
            return super().aggregate_train(server_round, replies_list)

        # 2. Score each client update -------------------------------------
        client_flats: list[torch.Tensor] = []
        client_ids: list[int] = []
        trust_scores: list[float] = []
        trust_rows: list[dict[str, Any]] = []
        for reply in replies_list:
            try:
                c_sd = reply.content["arrays"].to_torch_state_dict()
            except Exception:
                continue
            c_flat = torch.cat([(c_sd[k].cpu().float() - global_sd[k].cpu().float()).flatten() for k in param_keys])
            c_norm = torch.norm(c_flat).item()
            if c_norm < 1e-10:
                ts = 0.0
            else:
                ts = max(0.0, float(torch.dot(srv_flat, c_flat) / (srv_norm * c_norm)))
            client_flats.append(c_flat)
            cid = _src_node_id(reply)
            client_ids.append(int(cid))
            trust_scores.append(ts)
            trust_rows.append(
                {
                    "client_id": int(cid),
                    "trust_score": float(ts),
                    "selected_for_aggregation": bool(ts > 1e-10),
                    "update_norm": float(c_norm),
                    "cosine_to_center": float(ts),
                    "history_score": 0.0,
                    "reputation": float(ts),
                    "num_examples": int(_num_examples(reply)),
                    "details": {
                        "server_update_norm": float(srv_norm),
                        "trust_strength": float(self._trust_strength),
                        "min_weight": float(self._trust_min_weight),
                        "warmup_rounds": int(self._trust_warmup_rounds),
                    },
                }
            )

        total_ts = sum(trust_scores)
        if not client_flats:
            return super().aggregate_train(server_round, replies_list)

        raw_weights = {
            int(cid): float(max(0.0, min(1.0, ts)))
            for cid, ts in zip(client_ids, trust_scores)
        }
        effective_weights = _effective_trust_weights(
            raw_weights=raw_weights,
            client_ids=client_ids,
            server_round=int(server_round),
            trust_strength=self._trust_strength,
            min_weight=self._trust_min_weight,
            warmup_rounds=self._trust_warmup_rounds,
        )
        for row in trust_rows:
            cid = int(row.get("client_id", -1))
            eff = float(effective_weights.get(cid, 0.0))
            row["selected_for_aggregation"] = bool(eff > 0.0)
            row["reputation"] = eff
            try:
                row["details"]["effective_weight"] = eff
            except Exception:
                pass

        # Default framework mode: aggregate ordinary client deltas with a
        # FedAvg-compatible soft trust multiplier. Setting strength=1 and
        # min_weight=0 gives hard trust weighting.
        arrays = _aggregate_state_from_weights(
            replies=replies_list,
            global_state=global_sd,
            weights_by_client=effective_weights,
        )
        if arrays is None:
            return super().aggregate_train(server_round, replies_list)

        selected_count = sum(1 for w in effective_weights.values() if float(w) > 0.0)
        agg_metrics = MetricRecord({
            "fltrust_avg_trust": float(total_ts / len(trust_scores)),
            "fltrust_zero_trust_count": float(sum(1 for t in trust_scores if t < 1e-10)),
            "fltrust_selected_count": float(selected_count),
        })
        if hasattr(self, "_log_trust_round"):
            self._log_trust_round(server_round=int(server_round), strategy="fltrust", rows=trust_rows)
        return arrays, agg_metrics


class AttackFLTrust(AttackInjectedStrategyMixin, FLTrustStrategy):
    pass


# ---------------------------------------------------------------------------
# Trust-based robust aggregation helpers and strategies
# ---------------------------------------------------------------------------

def _src_node_id(reply: Any) -> int:
    try:
        return int(getattr(getattr(reply, "metadata", None), "src_node_id", -1) or -1)
    except Exception:
        return -1


def _num_examples(reply: Any) -> int:
    try:
        metrics = reply.content.get("metrics")
    except Exception:
        metrics = None
    if metrics is None:
        return 1
    for key in ("num-examples", "num_examples"):
        try:
            return int(metrics[key])
        except Exception:
            pass
        try:
            getter = getattr(metrics, "get", None)
            if callable(getter):
                return int(getter(key, 1))
        except Exception:
            pass
    return 1


def _is_float_tensor(t: torch.Tensor) -> bool:
    return torch.is_floating_point(t) or t.dtype.is_complex


def _reply_state(reply: Any) -> Optional[Dict[str, torch.Tensor]]:
    try:
        return reply.content["arrays"].to_torch_state_dict()
    except Exception:
        return None


def _flatten_delta(
    state: Dict[str, torch.Tensor],
    global_state: Dict[str, torch.Tensor],
) -> Tuple[Optional[torch.Tensor], List[str]]:
    parts: List[torch.Tensor] = []
    keys: List[str] = []
    for k, t_global in global_state.items():
        t_client = state.get(k)
        if not isinstance(t_client, torch.Tensor) or not isinstance(t_global, torch.Tensor):
            continue
        if not _is_float_tensor(t_client) or not _is_float_tensor(t_global):
            continue
        d = (t_client.detach().cpu().float() - t_global.detach().cpu().float()).flatten()
        if not torch.isfinite(d).all():
            return None, []
        parts.append(d)
        keys.append(k)
    if not parts:
        return None, []
    return torch.cat(parts), keys


def _cosine(a: torch.Tensor, b: torch.Tensor) -> float:
    an = float(torch.norm(a).item())
    bn = float(torch.norm(b).item())
    if an <= 1e-12 or bn <= 1e-12:
        return 0.0
    return float(torch.dot(a, b).item() / (an * bn))


def _aggregate_state_from_weights(
    *,
    replies: List[Any],
    global_state: Dict[str, torch.Tensor],
    weights_by_client: Dict[int, float],
) -> Optional[ArrayRecord]:
    weighted_total = 0.0
    agg: Dict[str, torch.Tensor] = {}
    initialized = False

    for reply in replies:
        cid = _src_node_id(reply)
        trust = float(max(0.0, weights_by_client.get(cid, 0.0)))
        if trust <= 0.0:
            continue
        state = _reply_state(reply)
        if state is None:
            continue
        weight = trust * float(max(1, _num_examples(reply)))
        if weight <= 0.0:
            continue

        if not initialized:
            for k, t_global in global_state.items():
                if isinstance(t_global, torch.Tensor) and _is_float_tensor(t_global):
                    agg[k] = torch.zeros_like(t_global.detach().cpu().float())
            initialized = True

        for k, t_global in global_state.items():
            t_client = state.get(k)
            if not isinstance(t_client, torch.Tensor) or not isinstance(t_global, torch.Tensor):
                continue
            if not _is_float_tensor(t_client) or not _is_float_tensor(t_global):
                continue
            d = t_client.detach().cpu().float() - t_global.detach().cpu().float()
            if not torch.isfinite(d).all():
                continue
            agg[k] += d * float(weight)
        weighted_total += float(weight)

    if weighted_total <= 0.0 or not initialized:
        return None

    out: Dict[str, torch.Tensor] = {}
    for k, t_global in global_state.items():
        if isinstance(t_global, torch.Tensor) and _is_float_tensor(t_global) and k in agg:
            out[k] = (t_global.detach().cpu().float() + agg[k] / float(weighted_total)).to(t_global.dtype)
        else:
            out[k] = t_global.detach().cpu() if isinstance(t_global, torch.Tensor) else t_global
    return ArrayRecord(out)


def _effective_trust_weights(
    *,
    raw_weights: Dict[int, float],
    client_ids: List[int],
    server_round: int,
    trust_strength: float,
    min_weight: float,
    warmup_rounds: int,
) -> Dict[int, float]:
    """Blend trust scores with FedAvg-compatible weights.

    trust_strength=0.0 is pure FedAvg, trust_strength=1.0 is full trust
    weighting. min_weight prevents benign clients from being hard-dropped by
    noisy trust estimates unless explicitly set to 0.
    """

    ids = [int(x) for x in client_ids]
    if int(server_round) <= int(max(0, warmup_rounds)):
        return {cid: 1.0 for cid in ids}

    strength = float(max(0.0, min(1.0, trust_strength)))
    floor = float(max(0.0, min(1.0, min_weight)))
    out: Dict[int, float] = {}
    for cid in ids:
        raw = float(max(0.0, min(1.0, raw_weights.get(int(cid), 0.0))))
        effective = (1.0 - strength) + strength * raw
        if effective > 0.0:
            effective = max(floor, effective)
        out[int(cid)] = float(max(0.0, min(1.0, effective)))
    return out


def _collect_update_records(
    replies: List[Any],
    global_arrays: Optional[ArrayRecord],
) -> Tuple[Optional[Dict[str, torch.Tensor]], List[Dict[str, Any]]]:
    if global_arrays is None:
        return None, []
    try:
        global_state = global_arrays.to_torch_state_dict()
    except Exception:
        return None, []

    records: List[Dict[str, Any]] = []
    for reply in replies:
        state = _reply_state(reply)
        if state is None:
            continue
        delta, _keys = _flatten_delta(state, global_state)
        if delta is None:
            continue
        cid = _src_node_id(reply)
        records.append(
            {
                "reply": reply,
                "client_id": int(cid),
                "num_examples": int(max(1, _num_examples(reply))),
                "delta": delta,
                "norm": float(torch.norm(delta).item()),
            }
        )
    return global_state, records


def _metric_record_from_trust(
    *,
    strategy: str,
    trust_scores: List[float],
    selected_count: int,
    total_count: int,
) -> MetricRecord:
    vals = [float(x) for x in trust_scores]
    if vals:
        avg = float(sum(vals) / len(vals))
        mn = float(min(vals))
        mx = float(max(vals))
    else:
        avg = mn = mx = 0.0
    prefix = str(strategy).replace("-", "_")
    return MetricRecord(
        {
            f"{prefix}_avg_trust": avg,
            f"{prefix}_min_trust": mn,
            f"{prefix}_max_trust": mx,
            f"{prefix}_selected_count": float(selected_count),
            f"{prefix}_total_count": float(total_count),
        }
    )


class FoolsGoldStrategy(FedAvg):
    """FoolsGold-inspired historical-similarity trust weighting.

    This compact implementation keeps cumulative client update histories and
    down-weights clients whose histories are highly cosine-similar to others.
    """

    def __init__(
        self,
        *,
        epsilon: float = 1e-6,
        trust_strength: float = 0.15,
        min_weight: float = 0.75,
        warmup_rounds: int = 5,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._fg_history: Dict[int, torch.Tensor] = {}
        self._fg_epsilon = float(epsilon)
        self._trust_strength = float(max(0.0, min(1.0, trust_strength)))
        self._trust_min_weight = float(max(0.0, min(1.0, min_weight)))
        self._trust_warmup_rounds = int(max(0, warmup_rounds))

    def aggregate_train(self, server_round: int, replies):
        replies_list = list(replies)
        global_arrays = getattr(self, "_last_finite_global_arrays", None)
        global_state, records = _collect_update_records(replies_list, global_arrays)
        if global_state is None or not records:
            return super().aggregate_train(server_round, replies_list)

        for rec in records:
            cid = int(rec["client_id"])
            d = rec["delta"].detach().cpu().float()
            old = self._fg_history.get(cid)
            self._fg_history[cid] = d.clone() if old is None or old.shape != d.shape else old + d

        ids = [int(r["client_id"]) for r in records]
        hist = [self._fg_history[int(cid)].detach().cpu().float() for cid in ids]
        max_sims: Dict[int, float] = {int(cid): 0.0 for cid in ids}
        for i, cid_i in enumerate(ids):
            for j, cid_j in enumerate(ids):
                if i == j:
                    continue
                sim = max(0.0, _cosine(hist[i], hist[j]))
                max_sims[int(cid_i)] = max(float(max_sims[int(cid_i)]), float(sim))

        raw = {cid: max(0.0, 1.0 - float(max_sims[cid])) for cid in ids}
        mx = max(raw.values()) if raw else 0.0
        raw_weights = {cid: (raw[cid] / mx if mx > self._fg_epsilon else 1.0) for cid in ids}
        raw_weights = {cid: float(max(0.0, min(1.0, w))) for cid, w in raw_weights.items()}
        weights = _effective_trust_weights(
            raw_weights=raw_weights,
            client_ids=ids,
            server_round=int(server_round),
            trust_strength=self._trust_strength,
            min_weight=self._trust_min_weight,
            warmup_rounds=self._trust_warmup_rounds,
        )

        arrays = _aggregate_state_from_weights(
            replies=replies_list,
            global_state=global_state,
            weights_by_client=weights,
        )
        if arrays is None:
            return super().aggregate_train(server_round, replies_list)

        rows: List[Dict[str, Any]] = []
        for rec in records:
            cid = int(rec["client_id"])
            rows.append(
                {
                    "client_id": cid,
                    "trust_score": float(raw_weights.get(cid, 0.0)),
                    "selected_for_aggregation": float(weights.get(cid, 0.0)) > 0.0,
                    "update_norm": float(rec["norm"]),
                    "cosine_to_center": 0.0,
                    "history_score": float(max_sims.get(cid, 0.0)),
                    "reputation": float(weights.get(cid, 0.0)),
                    "num_examples": int(rec["num_examples"]),
                    "details": {
                        "max_history_cosine": float(max_sims.get(cid, 0.0)),
                        "effective_weight": float(weights.get(cid, 0.0)),
                        "trust_strength": float(self._trust_strength),
                        "min_weight": float(self._trust_min_weight),
                        "warmup_rounds": int(self._trust_warmup_rounds),
                    },
                }
            )
        if hasattr(self, "_log_trust_round"):
            self._log_trust_round(server_round=int(server_round), strategy="foolsgold", rows=rows)

        metrics = _metric_record_from_trust(
            strategy="foolsgold",
            trust_scores=[float(raw_weights.get(cid, 0.0)) for cid in ids],
            selected_count=sum(1 for cid in ids if float(weights.get(cid, 0.0)) > 0.0),
            total_count=len(ids),
        )
        return arrays, metrics


class FLRAMStrategy(FedAvg):
    """FLRAM-inspired credibility-weighted aggregation.

    Scores each update by robust norm consistency, direction agreement with the
    median update, and sign agreement. Updates below `min_score` are excluded.
    """

    def __init__(
        self,
        *,
        min_score: float = 0.05,
        trust_strength: float = 0.15,
        min_weight: float = 0.75,
        warmup_rounds: int = 5,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._flram_min_score = float(max(0.0, min_score))
        self._trust_strength = float(max(0.0, min(1.0, trust_strength)))
        self._trust_min_weight = float(max(0.0, min(1.0, min_weight)))
        self._trust_warmup_rounds = int(max(0, warmup_rounds))

    def aggregate_train(self, server_round: int, replies):
        replies_list = list(replies)
        global_arrays = getattr(self, "_last_finite_global_arrays", None)
        global_state, records = _collect_update_records(replies_list, global_arrays)
        if global_state is None or not records:
            return super().aggregate_train(server_round, replies_list)

        stack = torch.stack([r["delta"] for r in records], dim=0)
        center = torch.median(stack, dim=0).values
        center_sign = torch.sign(center)
        norms = [float(r["norm"]) for r in records]
        med_norm = float(np.median(norms)) if norms else 0.0
        mad = float(np.median([abs(x - med_norm) for x in norms])) if norms else 0.0
        scale = max(mad * 1.4826, 1e-8)

        raw_weights: Dict[int, float] = {}
        rows: List[Dict[str, Any]] = []
        for rec in records:
            cid = int(rec["client_id"])
            d = rec["delta"]
            norm = float(rec["norm"])
            z = abs(norm - med_norm) / scale
            norm_score = math.exp(-0.5 * min(25.0, z * z))
            cos = _cosine(d, center)
            dir_score = max(0.0, (cos + 1.0) / 2.0)
            if center_sign.numel() > 0:
                sign_score = float(torch.mean((torch.sign(d) == center_sign).float()).item())
            else:
                sign_score = 0.0
            score = float(max(0.0, min(1.0, norm_score * dir_score * sign_score)))
            if score < self._flram_min_score:
                score = 0.0
            raw_weights[cid] = score
            rows.append(
                {
                    "client_id": cid,
                    "trust_score": score,
                    "selected_for_aggregation": score > 0.0,
                    "update_norm": norm,
                    "cosine_to_center": cos,
                    "history_score": sign_score,
                    "reputation": score,
                    "num_examples": int(rec["num_examples"]),
                    "details": {
                        "norm_z": float(z),
                        "norm_score": float(norm_score),
                        "direction_score": float(dir_score),
                        "sign_score": float(sign_score),
                        "median_norm": float(med_norm),
                        "mad": float(mad),
                        "trust_strength": float(self._trust_strength),
                        "min_weight": float(self._trust_min_weight),
                        "warmup_rounds": int(self._trust_warmup_rounds),
                    },
                }
            )

        weights = _effective_trust_weights(
            raw_weights=raw_weights,
            client_ids=[int(r["client_id"]) for r in records],
            server_round=int(server_round),
            trust_strength=self._trust_strength,
            min_weight=self._trust_min_weight,
            warmup_rounds=self._trust_warmup_rounds,
        )
        for row in rows:
            cid = int(row["client_id"])
            row["selected_for_aggregation"] = float(weights.get(cid, 0.0)) > 0.0
            row["reputation"] = float(weights.get(cid, 0.0))
            row.setdefault("details", {})["effective_weight"] = float(weights.get(cid, 0.0))

        arrays = _aggregate_state_from_weights(
            replies=replies_list,
            global_state=global_state,
            weights_by_client=weights,
        )
        if arrays is None:
            return super().aggregate_train(server_round, replies_list)

        if hasattr(self, "_log_trust_round"):
            self._log_trust_round(server_round=int(server_round), strategy="flram", rows=rows)
        metrics = _metric_record_from_trust(
            strategy="flram",
            trust_scores=[float(raw_weights.get(int(r["client_id"]), 0.0)) for r in records],
            selected_count=sum(1 for v in weights.values() if float(v) > 0.0),
            total_count=len(records),
        )
        return arrays, metrics


class MABRFLStrategy(FedAvg):
    """MAB-RFL-inspired reputation trust weighting.

    A lightweight centralized adaptation: current-round coherence scores update a
    per-client reputation, and aggregation weights mix reputation with the current
    score. This makes delayed-onset and reputation-farming attacks measurable.
    """

    def __init__(
        self,
        *,
        reputation_decay: float = 0.8,
        current_weight: float = 0.5,
        min_score: float = 0.05,
        trust_strength: float = 0.15,
        min_weight: float = 0.75,
        warmup_rounds: int = 5,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._mab_reputation: Dict[int, float] = {}
        self._mab_decay = float(max(0.0, min(0.999, reputation_decay)))
        self._mab_current_weight = float(max(0.0, min(1.0, current_weight)))
        self._mab_min_score = float(max(0.0, min_score))
        self._trust_strength = float(max(0.0, min(1.0, trust_strength)))
        self._trust_min_weight = float(max(0.0, min(1.0, min_weight)))
        self._trust_warmup_rounds = int(max(0, warmup_rounds))

    def aggregate_train(self, server_round: int, replies):
        replies_list = list(replies)
        global_arrays = getattr(self, "_last_finite_global_arrays", None)
        global_state, records = _collect_update_records(replies_list, global_arrays)
        if global_state is None or not records:
            return super().aggregate_train(server_round, replies_list)

        stack = torch.stack([r["delta"] for r in records], dim=0)
        center = torch.median(stack, dim=0).values
        norms = [float(r["norm"]) for r in records]
        med_norm = float(np.median(norms)) if norms else 0.0
        mad = float(np.median([abs(x - med_norm) for x in norms])) if norms else 0.0
        scale = max(mad * 1.4826, 1e-8)

        raw_weights: Dict[int, float] = {}
        rows: List[Dict[str, Any]] = []
        cw = float(self._mab_current_weight)
        for rec in records:
            cid = int(rec["client_id"])
            d = rec["delta"]
            norm = float(rec["norm"])
            cos = _cosine(d, center)
            dir_score = max(0.0, (cos + 1.0) / 2.0)
            z = abs(norm - med_norm) / scale
            norm_score = math.exp(-0.5 * min(25.0, z * z))
            current_score = float(max(0.0, min(1.0, dir_score * norm_score)))

            old_rep = float(self._mab_reputation.get(cid, 0.5))
            new_rep = float(self._mab_decay * old_rep + (1.0 - self._mab_decay) * current_score)
            self._mab_reputation[cid] = new_rep
            trust = float((1.0 - cw) * new_rep + cw * current_score)
            if trust < self._mab_min_score:
                trust = 0.0
            raw_weights[cid] = trust
            rows.append(
                {
                    "client_id": cid,
                    "trust_score": trust,
                    "selected_for_aggregation": trust > 0.0,
                    "update_norm": norm,
                    "cosine_to_center": cos,
                    "history_score": current_score,
                    "reputation": new_rep,
                    "num_examples": int(rec["num_examples"]),
                    "details": {
                        "old_reputation": float(old_rep),
                        "current_score": float(current_score),
                        "norm_score": float(norm_score),
                        "direction_score": float(dir_score),
                        "reputation_decay": float(self._mab_decay),
                        "current_weight": float(cw),
                        "trust_strength": float(self._trust_strength),
                        "min_weight": float(self._trust_min_weight),
                        "warmup_rounds": int(self._trust_warmup_rounds),
                    },
                }
            )

        weights = _effective_trust_weights(
            raw_weights=raw_weights,
            client_ids=[int(r["client_id"]) for r in records],
            server_round=int(server_round),
            trust_strength=self._trust_strength,
            min_weight=self._trust_min_weight,
            warmup_rounds=self._trust_warmup_rounds,
        )
        for row in rows:
            cid = int(row["client_id"])
            row["selected_for_aggregation"] = float(weights.get(cid, 0.0)) > 0.0
            row["details"]["effective_weight"] = float(weights.get(cid, 0.0))

        arrays = _aggregate_state_from_weights(
            replies=replies_list,
            global_state=global_state,
            weights_by_client=weights,
        )
        if arrays is None:
            return super().aggregate_train(server_round, replies_list)

        if hasattr(self, "_log_trust_round"):
            self._log_trust_round(server_round=int(server_round), strategy="mab-rfl", rows=rows)
        metrics = _metric_record_from_trust(
            strategy="mab_rfl",
            trust_scores=[float(raw_weights.get(int(r["client_id"]), 0.0)) for r in records],
            selected_count=sum(1 for v in weights.values() if float(v) > 0.0),
            total_count=len(records),
        )
        return arrays, metrics


class AttackFoolsGold(AttackInjectedStrategyMixin, FoolsGoldStrategy):
    pass


class AttackFLRAM(AttackInjectedStrategyMixin, FLRAMStrategy):
    pass


class AttackMABRFL(AttackInjectedStrategyMixin, MABRFLStrategy):
    pass


@app.main()
def main(grid: Grid, context: Context) -> None:
    """Main entry point for the ServerApp."""

    # Read run config
    strategy_name = str(context.run_config.get("strategy", "fedavg")).strip().lower()
    spec, model_factory = get_task_from_run_config(dict(context.run_config))
    fraction_evaluate: float = context.run_config["fraction-evaluate"]
    num_rounds: int = context.run_config["num-server-rounds"]
    lr: float = context.run_config["learning-rate"]

    # Attack engine (no-op if disabled or if artifact-dir not provided)
    attack_engine = AttackEngine(run_config=dict(context.run_config), num_rounds=int(num_rounds))

    fraction_train: float = float(context.run_config.get("fraction-train", 1.0))
    min_train_nodes: int = int(context.run_config.get("min-train-nodes", 2))
    min_evaluate_nodes: int = int(context.run_config.get("min-evaluate-nodes", 2))
    min_available_nodes: int = int(context.run_config.get("min-available-nodes", 2))

    # Load global model
    global_model = model_factory()
    arrays = ArrayRecord(global_model.state_dict())

    # Initialize strategy (selectable via `strategy` in run config)
    common_kwargs = dict(
        fraction_train=fraction_train,
        fraction_evaluate=fraction_evaluate,
        min_train_nodes=min_train_nodes,
        min_evaluate_nodes=min_evaluate_nodes,
        min_available_nodes=min_available_nodes,
    )

    if strategy_name in {"fedavg", "avg"}:
        strategy = AttackFedAvg(**common_kwargs)
    elif strategy_name in {"fedavgm", "avgm"}:
        strategy = AttackFedAvgM(**common_kwargs)
    elif strategy_name in {"fedprox", "prox"}:
        proximal_mu: float = float(context.run_config.get("proximal-mu", 0.0))
        strategy = AttackFedProx(proximal_mu=proximal_mu, **common_kwargs)
    elif strategy_name in {"qfedavg", "qffl"}:
        q_param: float = float(context.run_config.get("q-param", 0.2))
        strategy = AttackQFedAvg(q_param=q_param, **common_kwargs)
    elif strategy_name in {"fedadagrad", "adagrad"}:
        eta: float = float(context.run_config.get("eta", 0.1))
        eta_l: float = float(context.run_config.get("eta-l", 0.1))
        tau: float = float(context.run_config.get("tau", 0.001))
        strategy = AttackFedAdagrad(eta=eta, eta_l=eta_l, tau=tau, **common_kwargs)
    elif strategy_name in {"fedadam", "adam"}:
        eta: float = float(context.run_config.get("eta", 0.1))
        eta_l: float = float(context.run_config.get("eta-l", 0.1))
        tau: float = float(context.run_config.get("tau", 0.001))
        beta_1: float = float(context.run_config.get("beta-1", 0.9))
        beta_2: float = float(context.run_config.get("beta-2", 0.99))
        strategy = AttackFedAdam(
            eta=eta,
            eta_l=eta_l,
            tau=tau,
            beta_1=beta_1,
            beta_2=beta_2,
            **common_kwargs,
        )
    elif strategy_name in {"fedyogi", "yogi"}:
        eta: float = float(context.run_config.get("eta", 0.1))
        eta_l: float = float(context.run_config.get("eta-l", 0.1))
        tau: float = float(context.run_config.get("tau", 0.001))
        beta_1: float = float(context.run_config.get("beta-1", 0.9))
        beta_2: float = float(context.run_config.get("beta-2", 0.99))
        strategy = AttackFedYogi(
            eta=eta,
            eta_l=eta_l,
            tau=tau,
            beta_1=beta_1,
            beta_2=beta_2,
            **common_kwargs,
        )
    elif strategy_name in {"fedmedian", "median"}:
        strategy = AttackFedMedian(**common_kwargs)
    elif strategy_name in {"fedtrimmedavg", "trimmedavg", "trimmed"}:
        beta: float = float(context.run_config.get("trimmed-beta", 0.2))
        strategy = AttackFedTrimmedAvg(beta=beta, **common_kwargs)
    elif strategy_name in {"krum"}:
        num_malicious_nodes: int = int(context.run_config.get("num-malicious-nodes", 0))
        strategy = AttackKrum(num_malicious_nodes=num_malicious_nodes, **common_kwargs)
    elif strategy_name in {"multikrum", "multi-krum"}:
        num_malicious_nodes: int = int(context.run_config.get("num-malicious-nodes", 0))
        num_nodes_to_select: int = int(context.run_config.get("num-nodes-to-select", 1))
        strategy = AttackMultiKrum(
            num_malicious_nodes=num_malicious_nodes,
            num_nodes_to_select=num_nodes_to_select,
            **common_kwargs,
        )
    elif strategy_name in {"bulyan"}:
        num_malicious_nodes: int = int(context.run_config.get("num-malicious-nodes", 0))
        strategy = AttackBulyan(num_malicious_nodes=num_malicious_nodes, **common_kwargs)
    elif strategy_name in {"foolsgold", "fools-gold"}:
        trust_strength = float(context.run_config.get("trust-aggregation-strength", 0.15))
        trust_min_weight = float(context.run_config.get("trust-min-weight", 0.75))
        trust_warmup_rounds = int(context.run_config.get("trust-warmup-rounds", 5))
        strategy = AttackFoolsGold(
            trust_strength=trust_strength,
            min_weight=trust_min_weight,
            warmup_rounds=trust_warmup_rounds,
            **common_kwargs,
        )
    elif strategy_name in {"flram", "flram-lite"}:
        flram_min_score: float = float(context.run_config.get("flram-min-score", 0.05))
        trust_strength = float(context.run_config.get("trust-aggregation-strength", 0.15))
        trust_min_weight = float(context.run_config.get("trust-min-weight", 0.75))
        trust_warmup_rounds = int(context.run_config.get("trust-warmup-rounds", 5))
        strategy = AttackFLRAM(
            min_score=flram_min_score,
            trust_strength=trust_strength,
            min_weight=trust_min_weight,
            warmup_rounds=trust_warmup_rounds,
            **common_kwargs,
        )
    elif strategy_name in {"mab-rfl", "mabrfl", "mab_rfl"}:
        mab_decay: float = float(context.run_config.get("mab-rfl-reputation-decay", 0.8))
        mab_current: float = float(context.run_config.get("mab-rfl-current-weight", 0.5))
        mab_min_score: float = float(context.run_config.get("mab-rfl-min-score", 0.05))
        trust_strength = float(context.run_config.get("trust-aggregation-strength", 0.15))
        trust_min_weight = float(context.run_config.get("trust-min-weight", 0.75))
        trust_warmup_rounds = int(context.run_config.get("trust-warmup-rounds", 5))
        strategy = AttackMABRFL(
            reputation_decay=mab_decay,
            current_weight=mab_current,
            min_score=mab_min_score,
            trust_strength=trust_strength,
            min_weight=trust_min_weight,
            warmup_rounds=trust_warmup_rounds,
            **common_kwargs,
        )
    elif strategy_name in {"fltrust", "fl-trust"}:
        _nc = spec.num_classes or 10
        # Auto-compute root size: ~30 samples per class, min 500 (for class coverage)
        _raw_root = int(context.run_config.get("fltrust-root-size", 0) or 0)
        fltrust_root_size = _raw_root if _raw_root > 0 else max(500, _nc * 30)
        # Server epochs: 1 by default (paper-faithful). Override with fltrust-server-epochs.
        fltrust_epochs = int(context.run_config.get("fltrust-server-epochs", 0) or 0) or 1
        fltrust_batch_size: int = int(context.run_config.get("fltrust-root-batch-size", 32) or 32)
        fltrust_lr: float = float(context.run_config.get("fltrust-server-lr", lr) or lr)
        trust_strength = float(context.run_config.get("trust-aggregation-strength", 0.15))
        trust_min_weight = float(context.run_config.get("trust-min-weight", 0.75))
        trust_warmup_rounds = int(context.run_config.get("trust-warmup-rounds", 5) or 0)
        print(f"[FLTrust] auto-config: num_classes={_nc}, root_size={fltrust_root_size}, "
              f"server_epochs={fltrust_epochs}, batch_size={fltrust_batch_size}, lr={fltrust_lr}, "
              f"trust_strength={trust_strength}, min_weight={trust_min_weight}, "
              f"warmup_rounds={trust_warmup_rounds}")
        _rc = dict(context.run_config)
        _root_loader = load_centralized_dataset(
            dataset=spec.dataset,
            dataset_subset=str(_rc.get("dataset-subset", "")),
            dataset_modality=str(_rc.get("dataset-modality", "auto")),
            train_split=str(_rc.get("dataset-train-split", "train")),
            eval_split=str(_rc.get("dataset-train-split", "train")),  # root = train split
            image_key=str(_rc.get("image-key", "")),
            text_key=str(_rc.get("text-key", "")),
            audio_key=str(_rc.get("audio-key", "")),
            label_key=str(_rc.get("label-key", "")),
            num_classes=int(_rc.get("num-classes", 0) or 0),
            hf_trust_remote_code=bool(_rc.get("hf-trust-remote-code", False)),
            batch_size=fltrust_batch_size,
            max_eval_examples=fltrust_root_size,
        )
        _device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        strategy = AttackFLTrust(
            root_dataloader=_root_loader,
            model_factory=model_factory,
            device=_device,
            server_lr=fltrust_lr,
            server_epochs=fltrust_epochs,
            trust_strength=trust_strength,
            min_weight=trust_min_weight,
            warmup_rounds=trust_warmup_rounds,
            **common_kwargs,
        )
    else:
        print(
            "WARNING: Unknown strategy in run config: "
            f"{strategy_name!r}. Falling back to 'fedavg'. "
            "(Supported: fedavg, fedavgm, fedprox, qfedavg, fedadagrad, fedadam, "
            "fedyogi, fedmedian, fedtrimmedavg, krum, multikrum, bulyan, "
            "fltrust, foolsgold, flram, mab-rfl.)"
        )
        strategy = AttackFedAvg(**common_kwargs)

    # Attach the engine to the (attack-capable) strategy.
    if hasattr(strategy, "set_attack_engine"):
        strategy.set_attack_engine(attack_engine)

    # Start strategy, run for `num_rounds`
    def evaluate_fn(server_round: int, arrays: ArrayRecord) -> MetricRecord:
        metrics = global_evaluate(server_round, arrays, dict(context.run_config))
        # Feed evaluation metrics back into the attack engine (used by mode="adaptive").
        try:
            attack_engine.observe_server_evaluate(server_round=int(server_round), metrics=metrics)
        except Exception:
            pass
        return metrics

    result = strategy.start(
        grid=grid,
        initial_arrays=arrays,
        train_config=ConfigRecord({"lr": lr}),
        num_rounds=num_rounds,
        evaluate_fn=evaluate_fn,
    )

    # Save final model to disk
    print("\nSaving final model to disk...")
    state_dict = result.arrays.to_torch_state_dict()
    torch.save(state_dict, "final_model.pt")


def global_evaluate(
    server_round: int, arrays: ArrayRecord, run_config: dict
) -> MetricRecord:
    """Evaluate model on central data."""

    spec, model_factory = get_task_from_run_config(dict(run_config))
    model = model_factory()
    model.load_state_dict(arrays.to_torch_state_dict())
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model.to(device)

    dataset_modality: str = str(run_config.get("dataset-modality", "auto"))
    train_split: str = str(run_config.get("dataset-train-split", "train"))
    eval_split: str = str(run_config.get("dataset-eval-split", "test"))
    dataset_subset: str = str(run_config.get("dataset-subset", ""))
    hf_trust_remote_code: bool = bool(run_config.get("hf-trust-remote-code", False))
    image_key: str = str(run_config.get("image-key", ""))
    text_key: str = str(run_config.get("text-key", ""))
    audio_key: str = str(run_config.get("audio-key", ""))
    label_key: str = str(run_config.get("label-key", ""))
    num_classes: int = int(run_config.get("num-classes", 0) or 0)
    max_central_eval_examples: int = int(run_config.get("max-central-eval-examples", 0) or 0)

    test_dataloader = load_centralized_dataset(
        dataset=spec.dataset,
        dataset_subset=dataset_subset,
        dataset_modality=dataset_modality,
        train_split=train_split,
        eval_split=eval_split,
        image_key=image_key,
        text_key=text_key,
        audio_key=audio_key,
        label_key=label_key,
        num_classes=num_classes,
        hf_trust_remote_code=hf_trust_remote_code,
        max_eval_examples=max_central_eval_examples,
    )
    test_loss, test_acc, per_class_acc, clf_metrics = test(model, test_dataloader, device)

    # Optional: backdoor-triggered evaluation (ASR).
    # This uses the backdoor config from `[tool.flwr.attack.attacks.backdoor]`.
    attack_cfg = load_attack_config(run_config=dict(run_config))
    metrics: dict[str, float] = {"accuracy": float(test_acc), "loss": float(test_loss)}
    metrics.update(clf_metrics)
    for cls_id, cls_acc in per_class_acc.items():
        metrics[f"class_{cls_id}_accuracy"] = float(cls_acc)

    if attack_cfg.backdoor.enabled:
        bd = attack_cfg.backdoor
        bd_loss, bd_asr = test_backdoor(
            model,
            test_dataloader,
            device,
            target_label=int(bd.target_label),
            trigger_type=str(bd.trigger_type),
            patch_size=int(bd.patch_size),
            blend_alpha=float(bd.blend_alpha),
        )
        metrics["backdoor_asr"] = float(bd_asr)
        metrics["backdoor_loss"] = float(bd_loss)

    return MetricRecord(metrics)
