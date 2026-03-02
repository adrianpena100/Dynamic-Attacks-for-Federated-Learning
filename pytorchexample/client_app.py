"""pytorchexample: A Flower / PyTorch app."""

import torch
from flwr.app import ArrayRecord, Context, Message, MetricRecord, RecordDict
from flwr.clientapp import ClientApp

from pytorchexample.task import get_task_from_run_config, load_data
from pytorchexample.task import test as test_fn
from pytorchexample.task import train as train_fn

# Flower ClientApp
app = ClientApp()


@app.train()
def train(msg: Message, context: Context):
    """Train the model on local data."""

    # Load the model and initialize it with the received weights
    spec, model_factory = get_task_from_run_config(dict(context.run_config))
    model = model_factory()
    model.load_state_dict(msg.content["arrays"].to_torch_state_dict())
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model.to(device)

    # Load the data
    partition_id = context.node_config["partition-id"]
    num_partitions = context.node_config["num-partitions"]
    batch_size = context.run_config["batch-size"]
    partitioner: str = str(context.run_config.get("partitioner", "iid"))
    dirichlet_alpha: float = float(context.run_config.get("dirichlet-alpha", 0.5))

    dataset_modality: str = str(context.run_config.get("dataset-modality", "auto"))
    train_split: str = str(context.run_config.get("dataset-train-split", "train"))
    eval_split: str = str(context.run_config.get("dataset-eval-split", "test"))
    dataset_subset: str = str(context.run_config.get("dataset-subset", ""))
    hf_trust_remote_code: bool = bool(context.run_config.get("hf-trust-remote-code", False))
    image_key: str = str(context.run_config.get("image-key", ""))
    text_key: str = str(context.run_config.get("text-key", ""))
    audio_key: str = str(context.run_config.get("audio-key", ""))
    label_key: str = str(context.run_config.get("label-key", ""))
    num_classes: int = int(context.run_config.get("num-classes", 0) or 0)
    max_train_examples: int = int(context.run_config.get("max-train-examples", 0) or 0)
    max_val_examples: int = int(context.run_config.get("max-val-examples", 0) or 0)

    trainloader, _ = load_data(
        partition_id,
        num_partitions,
        batch_size,
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
        partitioner=partitioner,
        dirichlet_alpha=dirichlet_alpha,
        max_train_examples=max_train_examples,
        max_val_examples=max_val_examples,
    )

    # Call the training function
    try:
        cfg = msg.content["config"]
    except Exception:
        cfg = None

    def _cfg_get(obj, key: str, default=None):
        if obj is None:
            return default
        try:
            getter = getattr(obj, "get", None)
            if callable(getter):
                return getter(key, default)
        except Exception:
            pass
        try:
            return obj[key]
        except Exception:
            return default

    def _as_bool(v) -> bool:
        if isinstance(v, bool):
            return bool(v)
        if isinstance(v, (int, float)):
            return bool(int(v))
        if isinstance(v, str):
            s = v.strip().lower()
            if s in {"1", "true", "yes", "y", "t", "on"}:
                return True
            if s in {"0", "false", "no", "n", "f", "", "off", "none"}:
                return False
            # Unknown string -> treat as truthy only if non-empty
            return True
        return bool(v)

    def _parse_attack_layers(v):
        if v is None:
            return []
        if isinstance(v, (list, tuple)):
            parts = [str(x) for x in v]
        else:
            s = str(v)
            if not s.strip():
                return []
            # Server sends a semicolon-separated string; older logs may use '+'.
            parts = s.replace("+", ";").split(";")
        layers = []
        for p in parts:
            name = str(p).strip().lower().replace("-", "_")
            if not name or name == "none":
                continue
            layers.append(name)
        # Preserve order but remove duplicates.
        dedup = []
        seen = set()
        for name in layers:
            if name in seen:
                continue
            seen.add(name)
            dedup.append(name)
        return dedup

    def _parse_layer_intensities(v):
        if v is None:
            return {}
        s = str(v).strip()
        if not s:
            return {}
        # Format: "layer=1.0;other=0.5" (server emits semicolon-separated)
        parts = s.replace(",", ";").split(";")
        out = {}
        for p in parts:
            if "=" not in p:
                continue
            k, val = p.split("=", 1)
            kk = str(k).strip().lower().replace("-", "_")
            if not kk:
                continue
            try:
                out[kk] = float(val)
            except Exception:
                continue
        return out
    # Per-round attack instruction injected by the server. Most attacks are
    # server-side update poisoning, but label_flip/backdoor are client-side.
    attack_instruction = {
        "enabled": _as_bool(_cfg_get(cfg, "attack_enabled", False)),
        "name": str(_cfg_get(cfg, "attack_name", "none") or "none").strip().lower(),
        "layers": _parse_attack_layers(_cfg_get(cfg, "attack_layers", "")),
        "intensity": float(_cfg_get(cfg, "attack_intensity", 0.0) or 0.0),
        "layer_intensities": _parse_layer_intensities(_cfg_get(cfg, "attack_layer_intensities", "")),
        "is_malicious": _as_bool(_cfg_get(cfg, "attack_is_malicious", False)),
        "seed": int(_cfg_get(cfg, "attack_seed", 0) or 0),
        "server_round": int(_cfg_get(cfg, "attack_server_round", 0) or 0),
        "client_id": int(_cfg_get(cfg, "attack_client_id", int(partition_id)) or 0),
        "num_classes": int(spec.num_classes),
        # Label-flip config
        "label_flip_flip_rate": float(_cfg_get(cfg, "label_flip_flip_rate", 0.0) or 0.0),
        "label_flip_targeted": _as_bool(_cfg_get(cfg, "label_flip_targeted", False)),
        "label_flip_source_class": int(_cfg_get(cfg, "label_flip_source_class", 0) or 0),
        "label_flip_target_class": int(_cfg_get(cfg, "label_flip_target_class", 1) or 1),
        # Backdoor config (vision-only)
        "backdoor_poison_rate": float(_cfg_get(cfg, "backdoor_poison_rate", 0.0) or 0.0),
        "backdoor_target_label": int(_cfg_get(cfg, "backdoor_target_label", 0) or 0),
        "backdoor_trigger_type": str(_cfg_get(cfg, "backdoor_trigger_type", "patch") or "patch"),
        "backdoor_patch_size": int(_cfg_get(cfg, "backdoor_patch_size", 4) or 4),
        "backdoor_blend_alpha": float(_cfg_get(cfg, "backdoor_blend_alpha", 0.0) or 0.0),
    }

    train_loss, poison_stats = train_fn(
        model,
        trainloader,
        context.run_config["local-epochs"],
        msg.content["config"]["lr"],
        device,
        attack=attack_instruction,
    )

    if bool(context.run_config.get("emit-client-metrics", False)):
        # Compact, parseable line (kept short to avoid Ray line-wrapping/dedup issues)
        client_id = int(attack_instruction.get("client_id", int(partition_id)) or int(partition_id))
        gid = client_id
        rnd = int(attack_instruction.get("server_round", 0) or 0)
        pe = int((poison_stats or {}).get("poisoned_examples", 0) or 0)
        pse = int((poison_stats or {}).get("examples_seen", 0) or 0)
        plf = int((poison_stats or {}).get("poisoned_label_flip_examples", 0) or 0)
        pbd = int((poison_stats or {}).get("poisoned_backdoor_examples", 0) or 0)
        layers = "+".join([str(x) for x in (attack_instruction.get("layers", []) or [])])
        aname = str(attack_instruction.get("name", "none") or "none")
        inten = float(attack_instruction.get("intensity", 0.0) or 0.0)
        rel = int(1 if bool(attack_instruction.get("relative_to_update_norm", False)) else 0)
        mal = int(1 if bool(attack_instruction.get("is_malicious", False)) else 0)
        print(
            f"CM s=train pid={client_id} gid={gid} part={int(partition_id)} r={rnd} "
            f"tl={float(train_loss):.10g} pse={pse} pe={pe} plf={plf} pbd={pbd} "
            f"mal={mal} an={aname} layers={layers} int={inten:.10g} rel={rel}",
            flush=True,
        )

    # Construct and return reply Message
    model_record = ArrayRecord(model.state_dict())
    metrics = {
        "train_loss": float(train_loss),
        "num-examples": int(len(trainloader.dataset)),
        # Poisoning provenance (0 for honest clients or update-only attacks)
        "poison_examples_seen": int((poison_stats or {}).get("examples_seen", 0) or 0),
        "poisoned_examples": int((poison_stats or {}).get("poisoned_examples", 0) or 0),
        "poisoned_label_flip_examples": int((poison_stats or {}).get("poisoned_label_flip_examples", 0) or 0),
        "poisoned_backdoor_examples": int((poison_stats or {}).get("poisoned_backdoor_examples", 0) or 0),
        "attack_is_malicious": int(1 if attack_instruction.get("is_malicious", False) else 0),
    }
    metric_record = MetricRecord(metrics)
    content = RecordDict({"arrays": model_record, "metrics": metric_record})
    return Message(content=content, reply_to=msg)


@app.evaluate()
def evaluate(msg: Message, context: Context):
    """Evaluate the model on local data."""

    # Load the model and initialize it with the received weights
    spec, model_factory = get_task_from_run_config(dict(context.run_config))
    model = model_factory()
    model.load_state_dict(msg.content["arrays"].to_torch_state_dict())
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model.to(device)

    # Load the data
    partition_id = context.node_config["partition-id"]
    num_partitions = context.node_config["num-partitions"]
    batch_size = context.run_config["batch-size"]
    partitioner: str = str(context.run_config.get("partitioner", "iid"))
    dirichlet_alpha: float = float(context.run_config.get("dirichlet-alpha", 0.5))

    dataset_modality: str = str(context.run_config.get("dataset-modality", "auto"))
    train_split: str = str(context.run_config.get("dataset-train-split", "train"))
    eval_split: str = str(context.run_config.get("dataset-eval-split", "test"))
    dataset_subset: str = str(context.run_config.get("dataset-subset", ""))
    hf_trust_remote_code: bool = bool(context.run_config.get("hf-trust-remote-code", False))
    image_key: str = str(context.run_config.get("image-key", ""))
    text_key: str = str(context.run_config.get("text-key", ""))
    audio_key: str = str(context.run_config.get("audio-key", ""))
    label_key: str = str(context.run_config.get("label-key", ""))
    num_classes: int = int(context.run_config.get("num-classes", 0) or 0)
    max_train_examples: int = int(context.run_config.get("max-train-examples", 0) or 0)
    max_val_examples: int = int(context.run_config.get("max-val-examples", 0) or 0)

    _, valloader = load_data(
        partition_id,
        num_partitions,
        batch_size,
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
        partitioner=partitioner,
        dirichlet_alpha=dirichlet_alpha,
        max_train_examples=max_train_examples,
        max_val_examples=max_val_examples,
    )

    # Call the evaluation function
    eval_loss, eval_acc = test_fn(
        model,
        valloader,
        device,
    )

    if bool(context.run_config.get("emit-client-metrics", False)):
        rnd = 0
        client_id = partition_id
        try:
            cfg = msg.content["config"]
            getter = getattr(cfg, "get", None)
            if callable(getter):
                rnd = int(getter("server_round", getter("attack_server_round", 0)) or 0)
                client_id = int(getter("client_id", getter("attack_client_id", partition_id)) or partition_id)
            else:
                try:
                    rnd = int(cfg["server_round"])
                except Exception:
                    rnd = int(cfg["attack_server_round"])
                try:
                    client_id = int(cfg.get("client_id", cfg.get("attack_client_id", partition_id)))
                except Exception:
                    client_id = partition_id
        except Exception:
            rnd = 0
            client_id = partition_id
        gid = int(client_id)
        print(
            f"CM s=evaluate pid={int(client_id)} gid={gid} part={int(partition_id)} "
            f"r={rnd} el={float(eval_loss):.10g} ea={float(eval_acc):.10g}",
            flush=True,
        )

    # Construct and return reply Message
    metrics = {
        "eval_loss": eval_loss,
        "eval_acc": eval_acc,
        "num-examples": len(valloader.dataset),
    }
    metric_record = MetricRecord(metrics)
    content = RecordDict({"metrics": metric_record})
    return Message(content=content, reply_to=msg)
