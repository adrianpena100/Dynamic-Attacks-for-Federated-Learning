import pathlib

import tomli
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOML_PATH = ROOT / "pyproject.toml"

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
