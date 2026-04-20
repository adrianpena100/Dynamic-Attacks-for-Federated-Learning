"""pytorchexample: A Flower / PyTorch app."""

from __future__ import annotations

import copy
from pathlib import Path

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
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._fltrust_root_loader = root_dataloader
        self._fltrust_model_factory = model_factory
        self._fltrust_device = device
        self._fltrust_lr = server_lr
        self._fltrust_epochs = server_epochs

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
        trust_scores: list[float] = []
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
            trust_scores.append(ts)

        total_ts = sum(trust_scores)
        if not client_flats or total_ts < 1e-10:
            return super().aggregate_train(server_round, replies_list)

        # 3. Trust-weighted aggregation (normalised to server norm) --------
        agg_flat = torch.zeros_like(srv_flat)
        for c_flat, ts in zip(client_flats, trust_scores):
            if ts < 1e-10:
                continue
            c_norm = torch.norm(c_flat).item()
            scale = (srv_norm / c_norm) if c_norm > 1e-10 else 0.0
            agg_flat += (ts / total_ts) * scale * c_flat

        offset = 0
        agg_sd: dict = {}
        for k in param_keys:
            numel = global_sd[k].numel()
            agg_sd[k] = global_sd[k].cpu().float() + agg_flat[offset : offset + numel].reshape(global_sd[k].shape)
            offset += numel

        agg_metrics = MetricRecord({
            "fltrust_avg_trust": float(total_ts / len(trust_scores)),
            "fltrust_zero_trust_count": float(sum(1 for t in trust_scores if t < 1e-10)),
        })
        return ArrayRecord(agg_sd), agg_metrics


class AttackFLTrust(AttackInjectedStrategyMixin, FLTrustStrategy):
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
    elif strategy_name in {"fltrust", "fl-trust"}:
        _nc = spec.num_classes or 10
        # Auto-compute root size: ~30 samples per class, min 500 (for class coverage)
        _raw_root = int(context.run_config.get("fltrust-root-size", 0) or 0)
        fltrust_root_size = _raw_root if _raw_root > 0 else max(500, _nc * 30)
        # Server epochs: 1 by default (paper-faithful). Override with fltrust-server-epochs.
        fltrust_epochs = int(context.run_config.get("fltrust-server-epochs", 0) or 0) or 1
        fltrust_batch_size: int = int(context.run_config.get("fltrust-root-batch-size", 32) or 32)
        fltrust_lr: float = float(context.run_config.get("fltrust-server-lr", lr) or lr)
        print(f"[FLTrust] auto-config: num_classes={_nc}, root_size={fltrust_root_size}, "
              f"server_epochs={fltrust_epochs}, batch_size={fltrust_batch_size}, lr={fltrust_lr}")
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
            **common_kwargs,
        )
    else:
        print(
            "WARNING: Unknown strategy in run config: "
            f"{strategy_name!r}. Falling back to 'fedavg'. "
            "(Supported: fedavg, fedavgm, fedprox, qfedavg, fedadagrad, fedadam, "
            "fedyogi, fedmedian, fedtrimmedavg, krum, multikrum, bulyan, fltrust.)"
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
    test_loss, test_acc = test(model, test_dataloader, device)

    # Optional: backdoor-triggered evaluation (ASR).
    # This uses the backdoor config from `[tool.flwr.attack.attacks.backdoor]`.
    attack_cfg = load_attack_config(run_config=dict(run_config))
    metrics: dict[str, float] = {"accuracy": float(test_acc), "loss": float(test_loss)}

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
