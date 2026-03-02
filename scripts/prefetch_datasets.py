#!/usr/bin/env python3
"""Prefetch HF image datasets used by this project.

This script downloads full splits into the local HF cache so switching datasets in
pyproject.toml is fast and offline-friendly.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Iterable, List

from datasets import get_dataset_config_names, load_dataset


DEFAULT_IMAGE_DATASETS: List[str] = [
    "ylecun/mnist",
    "uoft-cs/cifar10",
    "uoft-cs/cifar100",
    "zalando-datasets/fashion_mnist",
    "flwrlabs/femnist",
    "zh-plus/tiny-imagenet",
    "flwrlabs/usps",
    "flwrlabs/pacs",
    "flwrlabs/cinic10",
    "flwrlabs/caltech101",
    "flwrlabs/office-home",
    "flwrlabs/fed-isic2019",
    "ufldl-stanford/svhn",
    "sasha/dog-food",
    "Mike0307/MNIST-M",
]


def _set_cache_dir(cache_dir: str | None) -> None:
    if not cache_dir:
        return
    base = Path(cache_dir).expanduser().resolve()
    datasets_cache = base / "datasets"
    hub_cache = base / "hub"
    os.environ["HF_HOME"] = str(base)
    os.environ["HF_DATASETS_CACHE"] = str(datasets_cache)
    os.environ["HF_HUB_CACHE"] = str(hub_cache)
    datasets_cache.mkdir(parents=True, exist_ok=True)
    hub_cache.mkdir(parents=True, exist_ok=True)


def _iter_splits() -> List[str]:
    return ["train", "test"]


def _try_load(dataset: str, split: str, config: str | None) -> bool:
    kwargs = {}
    if config:
        kwargs["name"] = config
    try:
        load_dataset(dataset, split=split, **kwargs)
        return True
    except Exception:
        return False


def _prefetch_dataset(dataset: str) -> None:
    print(f"\n==> {dataset}")
    config = None

    # Try default config first; fall back to the first named config if required.
    try:
        load_dataset(dataset, split="train")
    except Exception as exc:
        msg = str(exc)
        if "Config name" in msg or "Config names" in msg:
            try:
                configs = get_dataset_config_names(dataset)
                if configs:
                    config = configs[0]
                    print(f"Using config: {config}")
            except Exception as inner_exc:
                print(f"  Could not list configs: {inner_exc}")
        else:
            print(f"  Failed to load train split: {exc}")
            return

    # Fetch train and test/validation splits.
    for split in _iter_splits():
        if _try_load(dataset, split, config):
            print(f"  Downloaded split: {split}")
            continue
        if split == "test" and _try_load(dataset, "validation", config):
            print("  Downloaded split: validation (no test split)")
            continue
        print(f"  Skipped split: {split} (not available)")


def _parse_dataset_list(value: str | None) -> List[str]:
    if not value:
        return list(DEFAULT_IMAGE_DATASETS)
    items = [v.strip() for v in value.split(",") if v.strip()]
    return items or list(DEFAULT_IMAGE_DATASETS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prefetch HF image datasets.")
    parser.add_argument(
        "--datasets",
        help="Comma-separated dataset list (overrides defaults)",
        default=None,
    )
    parser.add_argument(
        "--cache-dir",
        help="HF cache directory (default: ~/.cache/huggingface)",
        default=None,
    )
    args = parser.parse_args()

    _set_cache_dir(args.cache_dir)
    datasets = _parse_dataset_list(args.datasets)

    print("Prefetching datasets:")
    for ds in datasets:
        print(f"  - {ds}")

    for ds in datasets:
        _prefetch_dataset(ds)

    print("\nDone.")


if __name__ == "__main__":
    main()
