import os
from pathlib import Path
from types import SimpleNamespace

import torch
from flwr.app import ArrayRecord

os.environ.setdefault("MPLCONFIGDIR", "/tmp")

from pytorchexample.server_app import (  # noqa: E402
    AttackFLRAM,
    AttackFLTrust,
    AttackFoolsGold,
    AttackMABRFL,
)
from pytorchexample.task import AttackEngine  # noqa: E402


class Reply:
    def __init__(self, cid, state, n=5):
        self.metadata = SimpleNamespace(src_node_id=cid)
        self.content = {"arrays": ArrayRecord(state), "metrics": {"num-examples": n}}


class TinyModel(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = torch.nn.Linear(2, 2, bias=False)

    def forward(self, x):
        return self.fc(x.view(-1, 2).float())


def _common_kwargs():
    return {
        "fraction_train": 1.0,
        "fraction_evaluate": 1.0,
        "min_train_nodes": 1,
        "min_evaluate_nodes": 1,
        "min_available_nodes": 1,
    }


def _attach_engine(strategy, tmp_path: Path):
    engine = AttackEngine(
        run_config={"artifact-dir": str(tmp_path), "attack-enabled": False},
        num_rounds=2,
    )
    strategy.set_attack_engine(engine)


def _assert_trust_strategy_outputs(strategy, name: str, global_state, replies, tmp_path: Path):
    _attach_engine(strategy, tmp_path)
    strategy._last_finite_global_arrays = ArrayRecord(global_state)

    arrays, metrics = strategy.aggregate_train(2, replies)

    assert arrays is not None
    for tensor in arrays.to_torch_state_dict().values():
        assert torch.isfinite(tensor).all()
    assert metrics is not None
    assert dict(metrics)

    trust_csv = tmp_path / "summaries" / "trust_strategy_by_round.csv"
    assert trust_csv.exists()
    lines = trust_csv.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(replies) + 1
    assert all(f",{name}," in line for line in lines[1:])


def test_foolsgold_trust_weighted_aggregation(tmp_path):
    strategy = AttackFoolsGold(
        trust_strength=1.0,
        min_weight=0.0,
        warmup_rounds=0,
        **_common_kwargs(),
    )
    global_state = {"w": torch.tensor([0.0, 0.0])}
    replies = [
        Reply(1, {"w": torch.tensor([1.0, 0.0])}),
        Reply(2, {"w": torch.tensor([1.0, 0.05])}),
        Reply(3, {"w": torch.tensor([-1.0, 0.0])}),
    ]

    _assert_trust_strategy_outputs(strategy, "foolsgold", global_state, replies, tmp_path)


def test_flram_trust_weighted_aggregation(tmp_path):
    strategy = AttackFLRAM(
        trust_strength=1.0,
        min_weight=0.0,
        warmup_rounds=0,
        **_common_kwargs(),
    )
    global_state = {"w": torch.tensor([0.0, 0.0])}
    replies = [
        Reply(1, {"w": torch.tensor([1.0, 0.0])}),
        Reply(2, {"w": torch.tensor([1.0, 0.05])}),
        Reply(3, {"w": torch.tensor([-1.0, 0.0])}),
    ]

    _assert_trust_strategy_outputs(strategy, "flram", global_state, replies, tmp_path)


def test_mab_rfl_trust_weighted_aggregation(tmp_path):
    strategy = AttackMABRFL(
        trust_strength=1.0,
        min_weight=0.0,
        warmup_rounds=0,
        **_common_kwargs(),
    )
    global_state = {"w": torch.tensor([0.0, 0.0])}
    replies = [
        Reply(1, {"w": torch.tensor([1.0, 0.0])}),
        Reply(2, {"w": torch.tensor([1.0, 0.05])}),
        Reply(3, {"w": torch.tensor([-1.0, 0.0])}),
    ]

    _assert_trust_strategy_outputs(strategy, "mab-rfl", global_state, replies, tmp_path)


def test_fltrust_trust_weighted_aggregation(tmp_path):
    root_loader = [
        {
            "x": torch.tensor([[1.0, 0.0], [0.0, 1.0], [1.0, 1.0], [-1.0, 0.0]]),
            "label": torch.tensor([0, 1, 0, 1]),
        }
    ]
    strategy = AttackFLTrust(
        root_dataloader=root_loader,
        model_factory=TinyModel,
        device=torch.device("cpu"),
        server_lr=0.1,
        server_epochs=1,
        trust_strength=1.0,
        min_weight=0.0,
        warmup_rounds=0,
        **_common_kwargs(),
    )
    global_state = {"fc.weight": torch.zeros_like(TinyModel().state_dict()["fc.weight"])}
    replies = [
        Reply(1, {"fc.weight": torch.tensor([[0.1, -0.1], [-0.1, 0.1]])}),
        Reply(2, {"fc.weight": torch.tensor([[0.08, -0.12], [-0.08, 0.12]])}),
        Reply(3, {"fc.weight": torch.tensor([[-0.1, 0.1], [0.1, -0.1]])}),
    ]

    _assert_trust_strategy_outputs(strategy, "fltrust", global_state, replies, tmp_path)
