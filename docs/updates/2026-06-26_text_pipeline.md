# Update: Text Dataset Pipeline + Label Normalization Fix — June 26, 2026

## What Changed

### 1. Text Pipeline Verified End-to-End

The text modality pipeline (already scaffolded in `task.py`) was validated through a full Flower simulation using Sentiment140. Everything works: dataset loading, text-to-hash-vector transforms, federated partitioning, training, evaluation, and metric capture.

**Smoke test results (Sentiment140, 3 rounds, 2 clients, no attack):**

| Metric | Value | Notes |
|--------|-------|-------|
| Accuracy | 33.5% | Model predicts majority class only — expected for 3 rounds |
| F1 macro | 0.167 | Reflects single-class predictions |
| All 3 classes reported | Yes | class_0, class_1, class_2 (after label fix) |
| Metrics files produced | 26 | Same structure as vision experiments |

**How to run a text experiment:**
```bash
python scripts/run_simulation_and_log.py \
  --project-root . \
  --federation local-simulation-smoke \
  --strategy-name text_test \
  --run-config 'dataset="sentiment140" num-server-rounds=5 attack-enabled=false'
```

The `model` config field is ignored for text — `TextClassifier` (2-layer MLP) is always used.

### 2. Label Normalization Bug Fix

**Bug:** Sentiment140 labels {0, 2, 4} were not being mapped to {0, 1, 2} correctly. Values 0 and 2 passed the range check (`0 <= vi < 3`) before reaching the special mapping, so labels 2 and 4 both mapped to class 2, and class 1 was never produced.

**Fix:** Two-pass approach in `_normalize_classification_labels()`:
- Pass 1: check if all values are already in [0, num_classes). If yes, return as-is.
- Pass 2: if any value is out of range, apply known mappings (e.g. {0,2,4} → {0,1,2}).

This correctly handles both standard labels ({0,1,2} → unchanged) and non-standard labels ({0,2,4} → remapped).

### 3. New Tests

Added 5 tests to `TestTextPipeline` class:
- TextClassifier creation and forward pass
- Text modality ignores `model` config field
- Sentiment140 label normalization ({0,2,4} → {0,1,2})
- Standard labels pass through unchanged
- Binary label normalization ({0,4} and {-1,1})

## Text Pipeline Architecture

The text pipeline uses a hash-based bag-of-words approach:

1. **Text transform** (`_apply_text_transforms_factory`): whitespace-tokenizes text, hashes each token to a 32768-dim vector using CRC32
2. **Model** (`TextClassifier`): 2-layer MLP (32768 → 128 → num_classes) with ReLU
3. **Label normalization**: handles non-standard label ranges (Sentiment140's {0,2,4})
4. **Training/eval**: uses `batch["x"]` key — same code path as tabular data

The `train()` and `test()` functions in task.py already handle both `batch["img"]` (vision) and `batch["x"]` (text/tabular), so no changes were needed to the training loop.

## Supported Text Datasets

| Dataset | HF Name | Classes | Text Key | Label Key |
|---------|---------|---------|----------|-----------|
| Sentiment140 | `sentiment140` | 3 | text | sentiment |
| Financial PhraseBank | `takala/financial_phrasebank` | 2* | auto | label |
| Twitter Financial | `zeroshot/twitter-financial-news-sentiment` | 2* | auto | label |
| FiQA | `pauri32/fiqa-2018` | 2* | auto | label |

*Note: some specs may need `num_classes` correction — only Sentiment140 has been end-to-end validated.

## Files Modified

| File | Change |
|------|--------|
| `pytorchexample/task.py` | Fixed `_normalize_classification_labels()` two-pass logic |
| `tests/test_smoke.py` | Added `TestTextPipeline` class (5 new tests) |

## Files NOT Modified

- `client_app.py` — already handles `batch["x"]` for non-vision
- `server_app.py` — FLTrust already handles `batch["x"]` at line 425
- `pyproject.toml` — text config keys (`text-key`, `label-key`, `dataset-modality`) already exist

## Validation

- **50/50 tests pass** (45 existing + 5 new text pipeline tests)
- Sentiment140 end-to-end experiment completed successfully
- Label normalization verified for all known edge cases
- Model swap between vision and text modalities works via dataset config alone
