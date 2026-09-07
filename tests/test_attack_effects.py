"""
tests/test_attack_effects.py

Verifies that each of the 6 attack primitives actually modifies model updates
or training data in the expected direction.

Data-poisoning attacks (label_flip, backdoor):
  Tested through the module-level _maybe_poison_batch function.

Update-poisoning attacks (gaussian_noise, sign_flip, alie, mean_shift):
  Tested through AttackEngine.maybe_inject_attacks with lightweight mock
  Flower messages built from real torch tensors and ArrayRecord.
"""

import types
import unittest.mock

import pytest
import torch

_has_torch = True
try:
    import torch
    import torch.nn as nn
    from flwr.app import ArrayRecord
except ImportError:
    _has_torch = False

needs_torch = pytest.mark.skipif(not _has_torch, reason="torch or flwr not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_msg(node_id: int, state_dict: dict) -> object:
    """Minimal mock of a Flower RecordSet message."""
    meta = types.SimpleNamespace(src_node_id=node_id)
    content = {"arrays": ArrayRecord(state_dict)}
    return types.SimpleNamespace(metadata=meta, content=content)


def _get_state(msg) -> dict:
    return msg.content["arrays"].to_torch_state_dict()


def _simple_state(seed: int = 0, size: int = 8) -> dict:
    torch.manual_seed(seed)
    return {"w": torch.randn(size), "b": torch.randn(size // 2)}


def _attack_plan(attack_name: str, malicious_ids: list, intensity: float = 1.0) -> dict:
    return {
        "attack_name": attack_name,
        "attack_layers": [attack_name],
        "attack_active": True,
        "intensity": intensity,
        "malicious_fraction_used": len(malicious_ids) / max(1, len(malicious_ids) + 2),
        "malicious_k_target": len(malicious_ids),
        "malicious_client_ids": malicious_ids,
        "relative_to_update_norm": False,
        "attack_layer_intensities": {attack_name: intensity},
    }


# ---------------------------------------------------------------------------
# 1. Data poisoning — label_flip
# ---------------------------------------------------------------------------

@needs_torch
class TestLabelFlip:
    def _poison(self, labels, flip_rate=1.0, targeted=False, src=0, tgt=1, num_classes=10):
        from pytorchexample.task import _maybe_poison_batch
        inputs = torch.zeros(len(labels), 1, 4, 4)
        attack = {
            "enabled": True,
            "is_malicious": True,
            "layers": ["label_flip"],
            "intensity": 1.0,
            "num_classes": num_classes,
            "label_flip_flip_rate": flip_rate,
            "label_flip_targeted": targeted,
            "label_flip_source_class": src,
            "label_flip_target_class": tgt,
            "seed": 42,
            "server_round": 1,
            "client_id": 0,
        }
        return _maybe_poison_batch(inputs=inputs, labels=labels, attack=attack, step=0)

    def test_untargeted_flip_rate_1_changes_all_labels(self):
        labels = torch.arange(10) % 5  # classes 0-4
        _, out_labels, counts = self._poison(labels, flip_rate=1.0)
        assert counts["label_flip"] == len(labels)
        # Every label should differ from original
        assert not torch.equal(out_labels.cpu(), labels)

    def test_untargeted_label_flip_never_maps_to_same_class(self):
        labels = torch.zeros(200, dtype=torch.long)  # all class 0
        _, out_labels, counts = self._poison(labels, flip_rate=1.0, num_classes=5)
        assert counts["label_flip"] > 0
        # No flipped label should equal the original class
        assert (out_labels.cpu() == 0).sum().item() == 0

    def test_targeted_flip_only_changes_source_class(self):
        labels = torch.tensor([0, 1, 0, 2, 0, 3], dtype=torch.long)
        _, out_labels, counts = self._poison(
            labels, flip_rate=1.0, targeted=True, src=0, tgt=4, num_classes=5
        )
        # All class-0 examples should become class 4
        src_mask = labels == 0
        assert (out_labels.cpu()[src_mask] == 4).all()
        # Non-source classes should be unchanged
        assert torch.equal(out_labels.cpu()[~src_mask], labels[~src_mask])

    def test_disabled_attack_leaves_labels_unchanged(self):
        from pytorchexample.task import _maybe_poison_batch
        labels = torch.arange(5, dtype=torch.long)
        inputs = torch.zeros(5, 1, 4, 4)
        _, out_labels, counts = _maybe_poison_batch(
            inputs=inputs,
            labels=labels,
            attack={"enabled": False, "is_malicious": True},
            step=0,
        )
        assert torch.equal(out_labels, labels)
        assert counts["label_flip"] == 0

    def test_non_malicious_client_unchanged(self):
        from pytorchexample.task import _maybe_poison_batch
        labels = torch.arange(5, dtype=torch.long)
        inputs = torch.zeros(5, 1, 4, 4)
        _, out_labels, counts = _maybe_poison_batch(
            inputs=inputs,
            labels=labels,
            attack={"enabled": True, "is_malicious": False, "layers": ["label_flip"],
                    "intensity": 1.0, "num_classes": 10, "label_flip_flip_rate": 1.0},
            step=0,
        )
        assert torch.equal(out_labels, labels)


# ---------------------------------------------------------------------------
# 2. Data poisoning — backdoor
# ---------------------------------------------------------------------------

@needs_torch
class TestBackdoor:
    def _poison(self, inputs, labels, poison_rate=1.0, target_label=9,
                patch_size=2, blend_alpha=0.5):
        from pytorchexample.task import _maybe_poison_batch
        attack = {
            "enabled": True,
            "is_malicious": True,
            "layers": ["backdoor"],
            "intensity": 1.0,
            "backdoor_poison_rate": poison_rate,
            "backdoor_target_label": target_label,
            "backdoor_patch_size": patch_size,
            "backdoor_blend_alpha": blend_alpha,
            "seed": 42,
            "server_round": 1,
            "client_id": 0,
        }
        return _maybe_poison_batch(inputs=inputs, labels=labels, attack=attack, step=0)

    def test_all_labels_become_target_at_full_rate(self):
        B, C, H, W = 16, 1, 8, 8
        inputs = torch.rand(B, C, H, W)
        labels = torch.randint(0, 9, (B,))
        _, out_labels, counts = self._poison(inputs, labels, poison_rate=1.0, target_label=9)
        assert counts["backdoor"] == B
        assert (out_labels.cpu() == 9).all()

    def test_patch_applied_to_bottom_right_corner(self):
        B, C, H, W = 4, 1, 8, 8
        inputs = torch.zeros(B, C, H, W)
        labels = torch.zeros(B, dtype=torch.long)
        out_inputs, _, counts = self._poison(
            inputs, labels, poison_rate=1.0, patch_size=2, blend_alpha=1.0
        )
        # Bottom-right 2x2 should be all-ones (blend_alpha=1.0 => pure patch)
        corner = out_inputs[:, :, H - 2:H, W - 2:W]
        assert counts["backdoor"] > 0
        assert torch.allclose(corner.cpu(), torch.ones_like(corner))

    def test_backdoor_skips_non_vision_input(self):
        # 2D input (text/tabular) should be ignored
        from pytorchexample.task import _maybe_poison_batch
        inputs = torch.rand(16, 32768)  # non-4D
        labels = torch.zeros(16, dtype=torch.long)
        attack = {
            "enabled": True,
            "is_malicious": True,
            "layers": ["backdoor"],
            "intensity": 1.0,
            "backdoor_poison_rate": 1.0,
            "backdoor_target_label": 0,
            "backdoor_patch_size": 4,
            "backdoor_blend_alpha": 0.5,
            "seed": 0,
            "server_round": 1,
            "client_id": 0,
        }
        out_inputs, out_labels, counts = _maybe_poison_batch(
            inputs=inputs, labels=labels, attack=attack, step=0
        )
        assert counts["backdoor"] == 0
        assert torch.equal(out_labels, labels)

    def test_zero_blend_alpha_is_noop(self):
        B, C, H, W = 8, 1, 8, 8
        inputs = torch.rand(B, C, H, W)
        labels = torch.zeros(B, dtype=torch.long)
        _, _, counts = self._poison(inputs, labels, poison_rate=1.0, blend_alpha=0.0)
        assert counts["backdoor"] == 0


# ---------------------------------------------------------------------------
# 3. Update poisoning — gaussian_noise
# ---------------------------------------------------------------------------

@needs_torch
class TestGaussianNoise:
    def _run(self, sigma=1.0):
        from pytorchexample.task import AttackEngine

        global_sd = _simple_state(seed=0)
        honest_sd = _simple_state(seed=1)
        malicious_sd = _simple_state(seed=2)

        global_msg = _make_msg(99, global_sd)   # used as "current" global model
        honest_msg = _make_msg(1, honest_sd)
        mal_msg = _make_msg(2, malicious_sd)

        engine = AttackEngine(
            run_config={
                "attack-enabled": True,
                "attack-malicious-fraction": 0.5,
                "attack-gaussian-noise-sigma": sigma,
                "attack-gaussian-noise-relative": False,
                "attack-stealth-mode": False,
            },
            num_rounds=10,
        )
        engine.attack_config = engine.attack_config  # no-op; just check it exists

        plan = _attack_plan("gaussian_noise", malicious_ids=[2])
        with unittest.mock.patch.object(engine, "plan_round", return_value=plan):
            with unittest.mock.patch.object(engine, "_current_global_state",
                                            return_value=global_sd, create=True):
                engine._last_global_state = {k: v.clone() for k, v in global_sd.items()}
                replies = engine.maybe_inject_attacks(
                    server_round=1,
                    selected_client_ids=[1, 2],
                    replies=[honest_msg, mal_msg],
                )
        return honest_sd, malicious_sd, global_sd, replies

    def test_gaussian_noise_changes_malicious_update(self):
        _, mal_orig, _, replies = self._run(sigma=2.0)
        # Find the malicious reply (node_id=2)
        mal_reply = next(r for r in replies
                         if getattr(r.metadata, "src_node_id", -1) == 2)
        mal_out = _get_state(mal_reply)
        assert not all(
            torch.allclose(mal_out[k].cpu(), mal_orig[k].cpu())
            for k in mal_orig
        ), "Gaussian noise attack did not change the malicious update"

    def test_gaussian_noise_leaves_honest_update_unchanged(self):
        honest_orig, _, _, replies = self._run(sigma=2.0)
        hon_reply = next(r for r in replies
                         if getattr(r.metadata, "src_node_id", -1) == 1)
        hon_out = _get_state(hon_reply)
        assert all(
            torch.allclose(hon_out[k].cpu(), honest_orig[k].cpu())
            for k in honest_orig
        ), "Gaussian noise attack modified an honest client update"


# ---------------------------------------------------------------------------
# 4. Update poisoning — sign_flip
# ---------------------------------------------------------------------------

@needs_torch
class TestSignFlip:
    def _run(self, alpha=1.0):
        from pytorchexample.task import AttackEngine

        global_sd = {k: torch.zeros_like(v) for k, v in _simple_state(seed=0).items()}
        # Malicious client has positive delta away from zero global
        malicious_sd = {k: torch.ones_like(v) for k, v in global_sd.items()}
        honest_sd = {k: torch.ones_like(v) * 0.5 for k, v in global_sd.items()}

        honest_msg = _make_msg(1, honest_sd)
        mal_msg = _make_msg(2, malicious_sd)

        engine = AttackEngine(
            run_config={
                "attack-enabled": True,
                "attack-malicious-fraction": 0.5,
                "attack-sign-flip-alpha": alpha,
                "attack-stealth-mode": False,
            },
            num_rounds=10,
        )
        engine._last_global_state = {k: v.clone() for k, v in global_sd.items()}

        plan = _attack_plan("sign_flip", malicious_ids=[2])
        with unittest.mock.patch.object(engine, "plan_round", return_value=plan):
            replies = engine.maybe_inject_attacks(
                server_round=1,
                selected_client_ids=[1, 2],
                replies=[honest_msg, mal_msg],
            )
        return global_sd, malicious_sd, replies

    def test_sign_flip_negates_malicious_delta(self):
        global_sd, mal_orig, replies = self._run(alpha=1.0)
        mal_reply = next(r for r in replies
                         if getattr(r.metadata, "src_node_id", -1) == 2)
        mal_out = _get_state(mal_reply)
        # Original delta = malicious - global = 1 - 0 = 1
        # After sign flip (alpha=1): new_state = global + (-1 * delta) = 0 - 1 = -1
        for k in global_sd:
            expected = global_sd[k] - (mal_orig[k] - global_sd[k])  # = -1
            assert torch.allclose(mal_out[k].cpu().float(), expected.float(), atol=1e-5), \
                f"Sign flip output mismatch for key '{k}'"

    def test_sign_flip_does_not_touch_honest_updates(self):
        _, _, replies = self._run()
        hon_reply = next(r for r in replies
                         if getattr(r.metadata, "src_node_id", -1) == 1)
        # Honest client should have its original state (0.5 * ones)
        hon_out = _get_state(hon_reply)
        for k in hon_out:
            assert torch.allclose(hon_out[k].cpu().float(),
                                  torch.ones_like(hon_out[k]) * 0.5, atol=1e-5)


# ---------------------------------------------------------------------------
# 5. Update poisoning — ALIE
# ---------------------------------------------------------------------------

@needs_torch
class TestALIE:
    def _run(self, z=-2.0, n_honest=4):
        from pytorchexample.task import AttackEngine

        global_sd = {k: torch.zeros(8) for k in ["w"]}
        # Honest clients have updates scattered around 1.0
        honest_msgs = []
        for i in range(n_honest):
            sd = {"w": torch.ones(8) * (1.0 + 0.1 * i)}
            honest_msgs.append(_make_msg(i + 1, sd))

        mal_sd = {"w": torch.ones(8) * 5.0}
        mal_msg = _make_msg(99, mal_sd)

        engine = AttackEngine(
            run_config={
                "attack-enabled": True,
                "attack-malicious-fraction": 1 / (n_honest + 1),
                "attack-alie-z": z,
                "attack-stealth-mode": False,
            },
            num_rounds=10,
        )
        engine._last_global_state = {k: v.clone() for k, v in global_sd.items()}

        plan = _attack_plan("alie", malicious_ids=[99])
        with unittest.mock.patch.object(engine, "plan_round", return_value=plan):
            replies = engine.maybe_inject_attacks(
                server_round=1,
                selected_client_ids=list(range(1, n_honest + 1)) + [99],
                replies=honest_msgs + [mal_msg],
            )
        return global_sd, mal_sd, replies

    def test_alie_changes_malicious_update(self):
        _, mal_orig, replies = self._run()
        mal_reply = next(r for r in replies
                         if getattr(r.metadata, "src_node_id", -1) == 99)
        mal_out = _get_state(mal_reply)
        assert not torch.allclose(mal_out["w"].cpu(), mal_orig["w"].cpu()), \
            "ALIE did not change the malicious update"

    def test_alie_output_differs_from_honest_mean(self):
        global_sd, _, replies = self._run(z=-2.0)
        # Honest deltas are ~[1,1.1,1.2,1.3], mean ~1.15
        # ALIE output should not equal the honest mean delta
        mal_reply = next(r for r in replies
                         if getattr(r.metadata, "src_node_id", -1) == 99)
        mal_out = _get_state(mal_reply)
        honest_mean_delta = torch.tensor([1.15])
        expected_honest_output = global_sd["w"] + honest_mean_delta
        assert not torch.allclose(mal_out["w"].cpu().float(),
                                  expected_honest_output.float(), atol=0.05), \
            "ALIE output matches honest mean — attack had no effect"

    def test_alie_noop_when_all_malicious(self):
        from pytorchexample.task import AttackEngine

        global_sd = {"w": torch.zeros(4)}
        mal_msg = _make_msg(1, {"w": torch.ones(4)})

        engine = AttackEngine(
            run_config={"attack-enabled": True, "attack-stealth-mode": False},
            num_rounds=5,
        )
        engine._last_global_state = {"w": torch.zeros(4)}

        plan = _attack_plan("alie", malicious_ids=[1])
        with unittest.mock.patch.object(engine, "plan_round", return_value=plan):
            replies = engine.maybe_inject_attacks(
                server_round=1,
                selected_client_ids=[1],
                replies=[mal_msg],
            )
        # No honest clients → ALIE is a no-op; state should be unchanged
        out = _get_state(replies[0])
        assert torch.allclose(out["w"].cpu(), torch.ones(4)), \
            "ALIE with no honest clients should leave malicious state unchanged"


# ---------------------------------------------------------------------------
# 6. Update poisoning — mean_shift
# ---------------------------------------------------------------------------

@needs_torch
class TestMeanShift:
    def _run(self, beta=1.0, n_honest=3):
        from pytorchexample.task import AttackEngine

        global_sd = {"w": torch.zeros(8)}
        # All honest clients push in the +1 direction (delta = 1)
        honest_msgs = [_make_msg(i + 1, {"w": torch.ones(8)}) for i in range(n_honest)]
        mal_msg = _make_msg(99, {"w": torch.ones(8) * 3.0})

        engine = AttackEngine(
            run_config={
                "attack-enabled": True,
                "attack-mean-shift-beta": beta,
                "attack-stealth-mode": False,
            },
            num_rounds=10,
        )
        engine._last_global_state = {"w": torch.zeros(8)}

        plan = _attack_plan("mean_shift", malicious_ids=[99])
        with unittest.mock.patch.object(engine, "plan_round", return_value=plan):
            replies = engine.maybe_inject_attacks(
                server_round=1,
                selected_client_ids=list(range(1, n_honest + 1)) + [99],
                replies=honest_msgs + [mal_msg],
            )
        return global_sd, replies

    def test_mean_shift_output_opposes_honest_mean(self):
        global_sd, replies = self._run(beta=1.0)
        mal_reply = next(r for r in replies
                         if getattr(r.metadata, "src_node_id", -1) == 99)
        mal_out = _get_state(mal_reply)
        # Honest mean delta = 1.0; expected crafted delta = -1.0 * 1.0 = -1.0
        # Expected output state = global (0) + (-1.0) = -1.0
        assert torch.allclose(mal_out["w"].cpu().float(),
                               torch.full((8,), -1.0), atol=1e-5), \
            f"Mean shift output: expected -1.0, got {mal_out['w']}"

    def test_mean_shift_leaves_honest_unchanged(self):
        _, replies = self._run()
        for r in replies:
            if getattr(r.metadata, "src_node_id", -1) != 99:
                out = _get_state(r)
                assert torch.allclose(out["w"].cpu(), torch.ones(8)), \
                    "Mean shift modified an honest client update"
