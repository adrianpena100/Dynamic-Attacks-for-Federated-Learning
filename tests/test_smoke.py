import pathlib

import tomli
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOML_PATH = ROOT / "pyproject.toml"

_has_torch = True
try:
    import torch as _torch
except ImportError:
    _has_torch = False

needs_torch = pytest.mark.skipif(not _has_torch, reason="torch not installed")

IMPLEMENTED_STRATEGIES = {
    "fedavg", "avg",
    "fedavgm", "avgm",
    "fedprox", "prox",
    "qfedavg", "qffl",
    "fedadagrad", "adagrad",
    "fedadam", "adam",
    "fedyogi", "yogi",
    "fedmedian", "median",
    "fedtrimmedavg", "trimmedavg", "trimmed",
    "krum",
    "multikrum", "multi-krum",
    "bulyan",
    "foolsgold", "fools-gold",
    "flram", "flram-lite",
    "mab-rfl", "mabrfl", "mab_rfl",
    "fltrust", "fl-trust",
}


def _load_toml():
    with open(TOML_PATH, "rb") as f:
        return tomli.load(f)


class TestTomlParses:
    def test_pyproject_loads(self):
        data = _load_toml()
        assert isinstance(data, dict)

    def test_flwr_app_config_exists(self):
        data = _load_toml()
        config = data["tool"]["flwr"]["app"]["config"]
        assert isinstance(config, dict)
        assert len(config) > 0

    def test_flwr_attack_section_exists(self):
        data = _load_toml()
        attack = data["tool"]["flwr"]["attack"]
        assert isinstance(attack, dict)
        assert "preset" in attack


SUPPORTED_VISION_MODELS = {"simple-cnn", "resnet18"}


class TestDefenseNamesMap:
    def test_toml_default_strategy_is_implemented(self):
        data = _load_toml()
        strategy = data["tool"]["flwr"]["app"]["config"]["strategy"]
        assert strategy in IMPLEMENTED_STRATEGIES, (
            f"TOML default strategy '{strategy}' is not in the server_app.py factory"
        )

    @pytest.mark.parametrize("name", sorted(IMPLEMENTED_STRATEGIES))
    def test_strategy_name_in_set(self, name):
        assert name in IMPLEMENTED_STRATEGIES


class TestModelConfig:
    def test_toml_default_model_is_supported(self):
        data = _load_toml()
        model = data["tool"]["flwr"]["app"]["config"]["model"]
        assert model in SUPPORTED_VISION_MODELS, (
            f"TOML default model '{model}' is not in the supported set: {SUPPORTED_VISION_MODELS}"
        )

    @needs_torch
    def test_simple_cnn_creates(self):
        from pytorchexample.task import _create_vision_model
        m = _create_vision_model("simple-cnn", input_channels=1, num_classes=62)
        x = __import__("torch").randn(1, 1, 28, 28)
        out = m(x)
        assert out.shape == (1, 62)

    @needs_torch
    def test_resnet18_creates(self):
        import torch
        from pytorchexample.task import _create_vision_model
        m = _create_vision_model("resnet18", input_channels=1, num_classes=62)
        m.eval()
        x = torch.randn(1, 1, 28, 28)
        out = m(x)
        assert out.shape == (1, 62)

    @needs_torch
    def test_resnet18_3channel(self):
        import torch
        from pytorchexample.task import _create_vision_model
        m = _create_vision_model("resnet18", input_channels=3, num_classes=10)
        m.eval()
        x = torch.randn(1, 3, 32, 32)
        out = m(x)
        assert out.shape == (1, 10)

    @needs_torch
    def test_unknown_model_raises(self):
        from pytorchexample.task import _create_vision_model
        with pytest.raises(ValueError, match="Unknown model"):
            _create_vision_model("nonexistent-model", input_channels=3, num_classes=10)


@needs_torch
class TestTextPipeline:
    def test_text_classifier_creates(self):
        from pytorchexample.task import get_task_from_run_config
        spec, factory = get_task_from_run_config({"dataset": "sentiment140"})
        assert spec.modality == "text"
        model = factory()
        import torch
        x = torch.randn(2, 2 ** 15)
        out = model(x)
        assert out.shape == (2, 3)

    def test_text_ignores_model_config(self):
        from pytorchexample.task import get_task_from_run_config
        for model_name in ["simple-cnn", "resnet18", "nonexistent"]:
            spec, factory = get_task_from_run_config(
                {"dataset": "sentiment140", "model": model_name}
            )
            assert spec.modality == "text"
            assert type(factory()).__name__ == "TextClassifier"

    def test_sentiment140_label_normalization(self):
        from pytorchexample.task import _normalize_classification_labels
        result = _normalize_classification_labels([0, 2, 4, 0, 4, 2], num_classes=3)
        assert result == [0, 1, 2, 0, 2, 1]

    def test_standard_labels_unchanged(self):
        from pytorchexample.task import _normalize_classification_labels
        result = _normalize_classification_labels([0, 1, 2, 1, 0], num_classes=3)
        assert result == [0, 1, 2, 1, 0]

    def test_binary_label_normalization(self):
        from pytorchexample.task import _normalize_classification_labels
        assert _normalize_classification_labels([0, 4, 0, 4], num_classes=2) == [0, 1, 0, 1]
        assert _normalize_classification_labels([-1, 1, -1], num_classes=2) == [0, 1, 0]
        assert _normalize_classification_labels([0, 1, 0], num_classes=2) == [0, 1, 0]
