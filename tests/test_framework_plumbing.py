"""
Framework plumbing tests: verify TOML config wiring, strategy dispatch,
dataset specs, model factories, and attack config parsing all work correctly.

These tests are offline — they don't download datasets or start Flower servers.
Tests requiring torch/flwr skip cleanly on machines without those packages.
"""

import pathlib

import pytest
import tomli

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOML_PATH = ROOT / "pyproject.toml"

_has_torch = True
try:
    import torch
except ImportError:
    _has_torch = False

needs_torch = pytest.mark.skipif(not _has_torch, reason="torch not installed")


def _load_toml():
    with open(TOML_PATH, "rb") as f:
        return tomli.load(f)


# ---------------------------------------------------------------------------
# 1. TOML round-trip (no torch needed)
# ---------------------------------------------------------------------------


class TestTomlRoundTrip:
    def test_all_core_config_keys_present(self):
        data = _load_toml()
        config = data["tool"]["flwr"]["app"]["config"]
        required = [
            "model", "dataset", "num-server-rounds", "batch-size",
            "learning-rate", "strategy", "local-epochs",
            "fraction-evaluate", "fraction-train",
            "partitioner", "dirichlet-alpha", "data-seed",
            "num-total-clients",
        ]
        for key in required:
            assert key in config, f"Missing required TOML key: {key}"

    def test_all_strategy_config_keys_present(self):
        data = _load_toml()
        config = data["tool"]["flwr"]["app"]["config"]
        strategy_keys = [
            "fltrust-root-size", "fltrust-server-epochs",
            "fltrust-root-batch-size", "fltrust-server-lr",
            "trust-aggregation-strength", "trust-min-weight", "trust-warmup-rounds",
            "mab-rfl-reputation-decay", "mab-rfl-current-weight", "mab-rfl-min-score",
            "flram-min-score", "trimmed-beta",
            "num-malicious-nodes", "num-nodes-to-select",
        ]
        for key in strategy_keys:
            assert key in config, f"Missing strategy TOML key: {key}"

    def test_attack_section_exists(self):
        data = _load_toml()
        attack = data["tool"]["flwr"]["attack"]
        assert "enabled" in attack
        assert "seed" in attack

    def test_attack_types_section_exists(self):
        data = _load_toml()
        attacks = data["tool"]["flwr"]["attack"]["attacks"]
        expected = {"gaussian_noise", "sign_flip", "label_flip", "backdoor", "alie", "mean_shift"}
        assert expected == set(attacks.keys()), f"Attack types mismatch: {set(attacks.keys())}"

    def test_numeric_config_values_parse(self):
        data = _load_toml()
        config = data["tool"]["flwr"]["app"]["config"]
        assert isinstance(int(config["num-server-rounds"]), int)
        assert isinstance(int(config["batch-size"]), int)
        assert isinstance(float(config["learning-rate"]), float)
        assert isinstance(float(config["dirichlet-alpha"]), float)
        assert isinstance(int(config["local-epochs"]), int)
        assert isinstance(int(config["data-seed"]), int)


# ---------------------------------------------------------------------------
# 2. Dataset spec registry (needs torch for import)
# ---------------------------------------------------------------------------


@needs_torch
class TestDatasetSpecs:
    @pytest.mark.parametrize(
        "ds, modality, num_classes, channels",
        [
            ("uoft-cs/cifar10", "vision", 10, 3),
            ("uoft-cs/cifar100", "vision", 100, 3),
            ("ylecun/mnist", "vision", 10, 1),
            ("zalando-datasets/fashion_mnist", "vision", 10, 1),
            ("flwrlabs/femnist", "vision", 62, 1),
        ],
    )
    def test_vision_dataset_spec(self, ds, modality, num_classes, channels):
        from pytorchexample.task import get_dataset_spec
        spec = get_dataset_spec(ds)
        assert spec.modality == modality
        assert spec.num_classes == num_classes
        assert spec.input_channels == channels
        assert spec.image_key is not None
        assert spec.label_key is not None

    def test_sentiment140_spec(self):
        from pytorchexample.task import get_dataset_spec
        spec = get_dataset_spec("sentiment140")
        assert spec.modality == "text"
        assert spec.num_classes == 3
        assert spec.text_key == "text"
        assert spec.label_key == "sentiment"

    def test_financial_phrasebank_spec(self):
        from pytorchexample.task import get_dataset_spec
        spec = get_dataset_spec("takala/financial_phrasebank")
        assert spec.modality == "text"
        assert spec.num_classes == 3

    def test_twitter_financial_sentiment_spec(self):
        from pytorchexample.task import get_dataset_spec
        spec = get_dataset_spec("zeroshot/twitter-financial-news-sentiment")
        assert spec.modality == "text"
        assert spec.num_classes == 3

    def test_tabular_datasets_return_tabular(self):
        from pytorchexample.task import get_dataset_spec
        for ds in ["scikit-learn/adult-census-income", "jlh/uci-mushrooms", "scikit-learn/iris"]:
            spec = get_dataset_spec(ds)
            assert spec.modality == "tabular", f"{ds} should be tabular"

    def test_audio_datasets_return_audio(self):
        from pytorchexample.task import get_dataset_spec
        for ds in ["google/speech_commands", "flwrlabs/ambient-acoustic-context"]:
            spec = get_dataset_spec(ds)
            assert spec.modality == "audio", f"{ds} should be audio"

    def test_unknown_dataset_returns_auto(self):
        from pytorchexample.task import get_dataset_spec
        spec = get_dataset_spec("totally/unknown-dataset")
        assert spec.modality == "auto"
        assert spec.num_classes == 0

    def test_femnist_eval_split_is_train(self):
        from pytorchexample.task import get_dataset_spec
        spec = get_dataset_spec("flwrlabs/femnist")
        assert spec.central_eval_split == "train"


# ---------------------------------------------------------------------------
# 3. Model factory dispatch (needs torch)
# ---------------------------------------------------------------------------


@needs_torch
class TestModelFactory:
    @pytest.mark.parametrize(
        "dataset, model_name, expected_out_classes, input_shape",
        [
            ("uoft-cs/cifar10", "simple-cnn", 10, (1, 3, 32, 32)),
            ("uoft-cs/cifar10", "resnet18", 10, (1, 3, 32, 32)),
            ("uoft-cs/cifar100", "simple-cnn", 100, (1, 3, 32, 32)),
            ("ylecun/mnist", "simple-cnn", 10, (1, 1, 28, 28)),
            ("ylecun/mnist", "resnet18", 10, (1, 1, 28, 28)),
            ("flwrlabs/femnist", "simple-cnn", 62, (1, 1, 28, 28)),
            ("flwrlabs/femnist", "resnet18", 62, (1, 1, 28, 28)),
            ("zalando-datasets/fashion_mnist", "simple-cnn", 10, (1, 1, 28, 28)),
        ],
    )
    def test_vision_model_output_shape(self, dataset, model_name, expected_out_classes, input_shape):
        from pytorchexample.task import get_task_from_run_config
        spec, factory = get_task_from_run_config({"dataset": dataset, "model": model_name})
        assert spec.modality == "vision"
        model = factory()
        model.eval()
        x = torch.randn(*input_shape)
        out = model(x)
        assert out.shape == (1, expected_out_classes)

    def test_text_model_output_shape(self):
        from pytorchexample.task import get_task_from_run_config
        spec, factory = get_task_from_run_config({"dataset": "sentiment140"})
        assert spec.modality == "text"
        model = factory()
        model.eval()
        x = torch.randn(2, 2 ** 15)
        out = model(x)
        assert out.shape == (2, 3)

    def test_tabular_model_output_shape(self):
        from pytorchexample.task import get_task_from_run_config
        spec, factory = get_task_from_run_config({"dataset": "scikit-learn/iris"})
        assert spec.modality == "tabular"
        model = factory()
        model.eval()
        x = torch.randn(2, 2 ** 14)
        out = model(x)
        assert out.shape[0] == 2

    def test_audio_raises(self):
        from pytorchexample.task import get_task_from_run_config
        with pytest.raises(RuntimeError, match="scaffolded"):
            get_task_from_run_config({"dataset": "google/speech_commands"})

    def test_text_ignores_model_key(self):
        from pytorchexample.task import get_task_from_run_config
        for model_name in ["simple-cnn", "resnet18", "garbage"]:
            spec, factory = get_task_from_run_config(
                {"dataset": "sentiment140", "model": model_name}
            )
            model = factory()
            assert type(model).__name__ == "TextClassifier"


# ---------------------------------------------------------------------------
# 4. Attack config parsing (needs torch)
# ---------------------------------------------------------------------------


@needs_torch
class TestAttackConfigParsing:
    def test_default_config_loads(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={})
        assert isinstance(cfg.enabled, bool)
        assert isinstance(cfg.seed, int)
        assert cfg.layering_mode in {"single", "fixed", "sample_k"}
        assert cfg.selection_mode in {
            "per_round_random", "sticky", "sticky_k", "churn",
        }

    def test_run_config_override_mode(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={"attack-mode": "adaptive"})
        assert cfg.mode == "adaptive"

    def test_run_config_override_selection(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={"attack-selection-mode": "churn"})
        assert cfg.selection_mode == "churn"

    def test_run_config_override_layering(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={"attack-layering-mode": "sample_k"})
        assert cfg.layering_mode == "sample_k"

    def test_run_config_override_stealth(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={"attack-stealth-mode": True})
        assert cfg.stealth_mode is True

    def test_run_config_override_malicious_fraction(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={"attack-malicious-fraction": 0.4})
        assert abs(cfg.malicious_fraction - 0.4) < 1e-9

    def test_run_config_override_intensity_ramp(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={
            "attack-intensity-ramp-mode": "linear",
            "attack-intensity-ramp-start-round": 5,
            "attack-intensity-ramp-end-round": 20,
            "attack-intensity-ramp-multiplier-start": 0.5,
            "attack-intensity-ramp-multiplier-end": 2.0,
        })
        assert cfg.intensity_ramp_mode == "linear"
        assert cfg.intensity_ramp_start_round == 5
        assert cfg.intensity_ramp_end_round == 20
        assert abs(cfg.intensity_ramp_multiplier_start - 0.5) < 1e-9
        assert abs(cfg.intensity_ramp_multiplier_end - 2.0) < 1e-9

    def test_run_config_override_churn_params(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={
            "attack-selection-mode": "churn",
            "attack-churn-fraction": 0.5,
            "attack-churn-min-replace": 2,
        })
        assert cfg.selection_mode == "churn"
        assert abs(cfg.churn_fraction - 0.5) < 1e-9
        assert cfg.churn_min_replace == 2

    def test_run_config_override_layered_attacks(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={
            "attack-layering-mode": "fixed",
            "attack-layered-attacks": "gaussian_noise,sign_flip,alie",
        })
        assert cfg.layering_mode == "fixed"
        assert cfg.layered_attacks == ["gaussian_noise", "sign_flip", "alie"]

    def test_all_six_attack_types_have_config(self):
        from pytorchexample.task import load_attack_config
        cfg = load_attack_config(run_config={})
        for name in ["gaussian_noise", "sign_flip", "label_flip", "backdoor", "alie", "mean_shift"]:
            assert hasattr(cfg, name), f"AttackConfig missing sub-config for {name}"

    def test_enabled_override(self):
        from pytorchexample.task import load_attack_config
        cfg_off = load_attack_config(run_config={"attack-enabled": "false"})
        assert cfg_off.enabled is False
        cfg_on = load_attack_config(run_config={"attack-enabled": "true"})
        assert cfg_on.enabled is True


# ---------------------------------------------------------------------------
# 5. Strategy class resolution (needs torch + flwr)
# ---------------------------------------------------------------------------


@needs_torch
class TestStrategyDispatch:
    """Verify each thesis strategy name maps to a non-FedAvg class."""

    @pytest.mark.parametrize(
        "name, expected_class_substr",
        [
            ("bulyan", "Bulyan"),
            ("multikrum", "MultiKrum"),
            ("fedtrimmedavg", "TrimmedAvg"),
            ("fedmedian", "Median"),
            ("fltrust", "FLTrust"),
            ("foolsgold", "FoolsGold"),
            ("flram", "FLRAM"),
            ("mab-rfl", "MABRFL"),
        ],
    )
    def test_strategy_class_name(self, name, expected_class_substr):
        from pytorchexample.server_app import (
            AttackBulyan,
            AttackFedMedian,
            AttackFedTrimmedAvg,
            AttackFLRAM,
            AttackFLTrust,
            AttackFoolsGold,
            AttackMABRFL,
            AttackMultiKrum,
        )
        class_map = {
            "bulyan": AttackBulyan,
            "multikrum": AttackMultiKrum,
            "fedtrimmedavg": AttackFedTrimmedAvg,
            "fedmedian": AttackFedMedian,
            "fltrust": AttackFLTrust,
            "foolsgold": AttackFoolsGold,
            "flram": AttackFLRAM,
            "mab-rfl": AttackMABRFL,
        }
        cls = class_map[name]
        assert expected_class_substr in cls.__name__
        assert hasattr(cls, "set_attack_engine")

    def test_all_thesis_strategies_have_mixin(self):
        from pytorchexample.server_app import AttackInjectedStrategyMixin
        from pytorchexample.server_app import (
            AttackBulyan,
            AttackFedMedian,
            AttackFedTrimmedAvg,
            AttackFLRAM,
            AttackFLTrust,
            AttackFoolsGold,
            AttackMABRFL,
            AttackMultiKrum,
        )
        for cls in [
            AttackBulyan, AttackMultiKrum, AttackFedTrimmedAvg, AttackFedMedian,
            AttackFLTrust, AttackFoolsGold, AttackFLRAM, AttackMABRFL,
        ]:
            assert issubclass(cls, AttackInjectedStrategyMixin), (
                f"{cls.__name__} does not inherit AttackInjectedStrategyMixin"
            )


# ---------------------------------------------------------------------------
# 6. AttackEngine instantiation (needs torch)
# ---------------------------------------------------------------------------


@needs_torch
class TestAttackEngineInstantiation:
    def test_creates_with_minimal_config(self):
        from pytorchexample.task import AttackEngine
        engine = AttackEngine(run_config={}, num_rounds=10)
        assert engine.num_rounds == 10

    def test_creates_with_adaptive_mode(self):
        from pytorchexample.task import AttackEngine
        engine = AttackEngine(
            run_config={"attack-mode": "adaptive", "attack-malicious-fraction": 0.3},
            num_rounds=20,
        )
        assert engine.attack_config.mode == "adaptive"

    def test_creates_with_layered_mode(self):
        from pytorchexample.task import AttackEngine
        engine = AttackEngine(
            run_config={
                "attack-layering-mode": "sample_k",
                "attack-layered-k": 3,
            },
            num_rounds=15,
        )
        assert engine.attack_config.layering_mode == "sample_k"
        assert engine.attack_config.layered_k == 3
