"""Guardrail tests for automatic dataset -> modality -> model resolution.

These lock in the "change only `dataset` and the model follows" contract so future
refactors cannot silently break it. Everything here runs offline: the 5 registry
vision datasets resolve from DatasetSpec metadata (no Hugging Face download), and
model I/O is exercised with synthetic tensors.

Run with the venv Python + torch:
    ../myenv/bin/python -m pytest tests/test_dataset_resolution.py -v
"""

import pytest

torch = pytest.importorskip("torch")

from pytorchexample.task import (  # noqa: E402
    ConfigurationError,
    describe_resolution,
    get_dataset_spec,
    get_task_from_run_config,
)

# (dataset, input_channels, input_size, num_classes) for the registry vision datasets.
VISION_DATASETS = [
    ("uoft-cs/cifar10", 3, 32, 10),
    ("uoft-cs/cifar100", 3, 32, 100),
    ("ylecun/mnist", 1, 28, 10),
    ("zalando-datasets/fashion_mnist", 1, 28, 10),
    ("flwrlabs/femnist", 1, 28, 62),
]

VISION_IDS = [d[0] for d in VISION_DATASETS]


@pytest.mark.parametrize("dataset,channels,size,num_classes", VISION_DATASETS, ids=VISION_IDS)
def test_dataset_resolves(dataset, channels, size, num_classes):
    """Dataset resolves to correct modality/metadata from the registry (no download)."""
    spec, _ = get_task_from_run_config({"dataset": dataset, "model": "auto"})
    assert spec.modality == "vision"
    assert spec.num_classes == num_classes
    assert spec.input_channels == channels
    assert spec.image_key
    assert spec.label_key


@pytest.mark.parametrize("dataset,channels,size,num_classes", VISION_DATASETS, ids=VISION_IDS)
def test_auto_model_forward_backward(dataset, channels, size, num_classes):
    """model='auto' builds a compatible model; a synthetic batch trains one step."""
    spec, model_factory = get_task_from_run_config({"dataset": dataset, "model": "auto"})
    model = model_factory()

    x = torch.randn(4, channels, size, size)
    y = torch.randint(0, num_classes, (4,))
    out = model(x)

    # Output dimension must follow the dataset, not a hard-coded 10.
    assert out.shape == (4, num_classes)
    assert 0 <= int(y.min()) and int(y.max()) < num_classes

    loss = torch.nn.functional.cross_entropy(out, y)
    loss.backward()  # backward must succeed
    assert torch.isfinite(loss)


@pytest.mark.parametrize("dataset,channels,size,num_classes", VISION_DATASETS, ids=VISION_IDS)
def test_client_and_server_build_identical_architecture(dataset, channels, size, num_classes):
    """The single shared factory guarantees client/server param shapes match."""
    # Two independent resolutions == what client_app and server_app each do.
    _, client_factory = get_task_from_run_config({"dataset": dataset, "model": "auto"})
    _, server_factory = get_task_from_run_config({"dataset": dataset, "model": "auto"})

    client_shapes = [tuple(p.shape) for p in client_factory().state_dict().values()]
    server_shapes = [tuple(p.shape) for p in server_factory().state_dict().values()]
    assert client_shapes == server_shapes
    assert len(client_shapes) > 0


def test_auto_is_the_default_and_does_not_crash():
    """A bare `dataset` (no model key) must resolve without error."""
    spec, model_factory = get_task_from_run_config({"dataset": "ylecun/mnist"})
    model = model_factory()
    assert model(torch.randn(2, 1, 28, 28)).shape == (2, 10)


def test_explicit_resnet18_override_tracks_classes():
    """Explicit resnet18 override still honors the dataset's class count."""
    _, model_factory = get_task_from_run_config(
        {"dataset": "uoft-cs/cifar100", "model": "resnet18"}
    )
    model = model_factory()
    assert model.fc.out_features == 100
    assert model(torch.randn(2, 3, 32, 32)).shape == (2, 100)


def test_grayscale_default_is_simple_cnn():
    """Registry default_model policy: grayscale/RGB currently both default to simple-cnn."""
    for ds in VISION_IDS:
        assert get_dataset_spec(ds).default_model == "simple-cnn"


def test_femnist_exposes_natural_partition_key():
    """FEMNIST advertises its real client identity for opt-in natural partitioning."""
    assert get_dataset_spec("flwrlabs/femnist").natural_partition_key == "writer_id"
    # Non-federated datasets must not claim a natural key.
    assert get_dataset_spec("uoft-cs/cifar10").natural_partition_key is None


def test_incompatible_vision_model_on_text_fails_fast():
    """A vision model on a text dataset must raise BEFORE any training starts."""
    with pytest.raises(ConfigurationError):
        get_task_from_run_config({"dataset": "sentiment140", "model": "resnet18"})


def test_text_auto_still_works_offline():
    """Non-vision auto path builds its own model with the right output dim."""
    spec, model_factory = get_task_from_run_config({"dataset": "sentiment140", "model": "auto"})
    assert spec.modality == "text"
    model = model_factory()
    out = model(torch.randn(4, 2 ** 15))
    assert out.shape == (4, spec.num_classes)


def test_natural_partition_count_validator():
    """The count guard passes on a match and fails fast on a mismatch."""
    from pytorchexample.task import _validate_natural_partition_count

    # Match: 3 requested supernodes, 3 unique clients in the data -> no error.
    _validate_natural_partition_count(
        3, 3, partition_by="writer_id", dataset="flwrlabs/femnist"
    )
    # Mismatch: 100 requested, 3 available -> ConfigurationError with a fix hint.
    with pytest.raises(ConfigurationError, match="unique 'writer_id' clients"):
        _validate_natural_partition_count(
            100, 3, partition_by="writer_id", dataset="flwrlabs/femnist"
        )


def test_natural_id_partitioner_derives_count_from_data():
    """NaturalIdPartitioner groups by the FEMNIST natural key (synthetic, no download).

    Guards the assumption the count validator relies on: partition count == number of
    unique natural ids in the data.
    """
    datasets = pytest.importorskip("datasets")
    from flwr_datasets.partitioner import NaturalIdPartitioner

    key = get_dataset_spec("flwrlabs/femnist").natural_partition_key
    assert key == "writer_id"

    # 3 writers, 6 rows -> partitioner must expose exactly 3 partitions.
    ds = datasets.Dataset.from_dict(
        {"image": list(range(6)), key: ["w0", "w0", "w1", "w1", "w2", "w2"]}
    )
    part = NaturalIdPartitioner(partition_by=key)
    part.dataset = ds
    assert part.num_partitions == 3
    assert len(part.load_partition(0)) == 2


@pytest.mark.parametrize("dataset", VISION_IDS)
def test_describe_resolution_reports_resolved_values(dataset):
    """The reproducibility log reports resolved (not requested) values."""
    info = describe_resolution({"dataset": dataset, "model": "auto", "partitioner": "dirichlet"})
    assert info["resolved_modality"] == "vision"
    assert info["resolved_num_classes"] > 0
    assert info["resolved_model"] in {"simple-cnn", "resnet18"}
    assert info["resolved_partitioner"] == "dirichlet"
    assert info["resolved_input_channels"] in {1, 3}
