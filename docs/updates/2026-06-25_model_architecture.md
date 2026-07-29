# Update: Configurable Model Architecture — June 25, 2026

## What Changed

Added a `model` config field to `pyproject.toml` that lets you switch between vision model architectures without touching any code.

### Supported Models

| Model | Config value | Parameters (FEMNIST) | Parameters (CIFAR-10) | Best for |
|-------|-------------|---------------------|----------------------|----------|
| LeNet-style CNN | `simple-cnn` | 66K | 62K | Fast iteration, debugging, FEMNIST/MNIST |
| ResNet-18 (small-image variant) | `resnet18` | 11.2M | 11.2M | Stronger baseline, CIFAR-10, cross-architecture validation |

### How to Use

**In pyproject.toml** (default for all runs):
```toml
model = "simple-cnn"   # or "resnet18"
```

**Per-run override** (from CLI):
```bash
flwr run . --run-config 'model="resnet18"'
```

**In sweep script** (via extra config):
```bash
./run_thesis_sweep.sh --extra-config 'model="resnet18"' ...
```

### ResNet-18 Adaptation for Small Images

Standard ResNet-18 uses a 7x7 stride-2 conv + maxpool, which collapses 28x28 or 32x32 images to 1x1 feature maps too aggressively. The implementation replaces these with a 3x3 stride-1 conv and removes maxpool, following the standard approach for CIFAR-scale ResNet variants.

## Files Modified

| File | Change |
|------|--------|
| `pyproject.toml` | Added `model = "simple-cnn"` config field with documentation |
| `pytorchexample/task.py` | Added `_create_resnet18()`, `_create_vision_model()` dispatch, updated `get_task_from_run_config()` to read model config |
| `tests/test_smoke.py` | Added 5 new tests: config validation, both models with 1ch/3ch inputs, unknown model error |

## Files NOT Modified

- `client_app.py` — uses `model_factory()`, already model-agnostic
- `server_app.py` — uses `model_factory()`, already model-agnostic (including FLTrust)
- `run_thesis_sweep.sh` — model set via TOML, no script changes needed
- Attack logic — operates on parameter tensors, architecture-independent

## Validation

- **45/45 tests pass** (all existing + 5 new model tests)
- Both models verified for FEMNIST (1ch, 62 classes), CIFAR-10 (3ch, 10 classes), MNIST (1ch, 10 classes)
- Default behavior (no model key) falls back to `simple-cnn` — backward compatible
- Trust strategy tests unaffected (use their own TinyModel)

## End-to-End Experiment Results (MNIST, 3 rounds, 2 non-IID clients, no attack)

| Model | Round 1 | Round 2 | Round 3 | Notes |
|-------|---------|---------|---------|-------|
| ResNet-18 | 87.6% | 96.7% | 98.2% | ~45 min on CPU (11.2M params) |
| simple-CNN | 10.3% | 8.9% | 8.9% | ~30 sec on CPU (66K params) |

ResNet-18 converges much faster but is ~170x slower to train per round on CPU.
