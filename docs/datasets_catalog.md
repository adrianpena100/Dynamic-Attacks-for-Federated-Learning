# Dataset catalog (Flower Datasets)

This file mirrors the dataset lists you pasted from the Flower Datasets “Recommended FL Datasets” page.

Important: the code in this repo is wired for a **small set of vision datasets** and a simple IID/non-IID toggle. Everything else in this catalog is for reference (future wiring) so you can enable switching via config without hunting for names.

Currently supported by the example code:

- Datasets: `uoft-cs/cifar10` (default), `uoft-cs/cifar100`, `ylecun/mnist`, `zalando-datasets/fashion_mnist`
- Partitioner toggle: `iid` or `dirichlet` (controlled by `dirichlet-alpha`)

## IID vs non-IID (how to think about it)

- **Most datasets** can be either IID or non-IID depending on the **partitioner** you choose (IIDPartitioner vs DirichletPartitioner vs PathologicalPartitioner vs NaturalIdPartitioner, etc.).
- **Some datasets are naturally non-IID** because they have a meaningful “client/user ID” (e.g., FEMNIST by writer). Those are typically non-IID-by-design.

## Image datasets

| Dataset ID | Size | Image shape | IID / non-IID notes |
|---|---:|---|---|
| ylecun/mnist | train 60k; test 10k | 28x28 | Depends on partitioner |
| uoft-cs/cifar10 | train 50k; test 10k | 32x32x3 | Depends on partitioner (current code path is IID) |
| uoft-cs/cifar100 | train 50k; test 10k | 32x32x3 | Depends on partitioner |
| zalando-datasets/fashion_mnist | train 60k; test 10k | 28x28 | Depends on partitioner |
| flwrlabs/femnist | train 814k | 28x28 | Typically natural non-IID (by writer/user id) |
| zh-plus/tiny-imagenet | train 100k; valid 10k | 64x64x3 | Depends on partitioner |
| flwrlabs/usps | train 7.3k; test 2k | 16x16 | Depends on partitioner |
| flwrlabs/pacs | train 10k | 227x227 | Often treated as non-IID by domain shift (if partitioned by domain); otherwise depends |
| flwrlabs/cinic10 | train 90k; valid 90k; test 90k | 32x32x3 | Depends on partitioner |
| flwrlabs/caltech101 | train 8.7k | varies | Depends on partitioner |
| flwrlabs/office-home | train 15.6k | varies | Often treated as non-IID by domain shift (if partitioned by domain); otherwise depends |
| flwrlabs/fed-isic2019 | train 18.6k; test 4.7k | varies | Typically non-IID (medical/site/patient heterogeneity) depending on IDs |
| ufldl-stanford/svhn | train 73.3k; test 26k; extra 531k | 32x32x3 | Depends on partitioner |
| sasha/dog-food | train 2.1k; test 0.9k | varies | Depends on partitioner |
| Mike0307/MNIST-M | train 59k; test 9k | 32x32 | Depends on partitioner |

## Audio datasets

Note: audio requires different preprocessing/modeling than the current image CNN.

| Dataset ID | Size | Subset | IID / non-IID notes |
|---|---:|---|---|
| google/speech_commands | train 64.7k | v0.01 | Depends on partitioner; can also be natural by speaker id if present |
| google/speech_commands | train 105.8k | v0.02 | Depends on partitioner |
| flwrlabs/ambient-acoustic-context | train 70.3k | - | Depends on partitioner |
| fixie-ai/common_voice_17_0 | varies | 14 versions | Often natural non-IID (speaker/device/locale) if partitioned by speaker/locale |
| fixie-ai/librispeech_asr | varies | clean/other | Can be natural non-IID by speaker/book; depends on partitioning |

## Tabular datasets

Note: tabular requires a different model than the current image CNN.

| Dataset ID | Size | IID / non-IID notes |
|---|---:|---|
| scikit-learn/adult-census-income | train 32.6k | Depends on partitioner |
| jlh/uci-mushrooms | train 8.1k | Depends on partitioner |
| scikit-learn/iris | train 150 | Depends on partitioner |
| jiahborcn/chembl_aqsol | train 12.9k; test 3.2k | Depends on partitioner |
| jiahborcn/chembl_multiassay_activity | train 350k; test 87.5k | Depends on partitioner |

## Text datasets

Note: text requires tokenization + a different model than the current image CNN.

| Dataset ID | Size | Category | IID / non-IID notes |
|---|---:|---|---|
| sentiment140 | train 1.6M; test 0.5k | Sentiment | Can be natural non-IID by user/time if IDs exist; otherwise depends |
| google-research-datasets/mbpp | full 974; sanitized 427 | General | Depends on partitioner |
| openai/openai_humaneval | test 164 | General | Not typical for FL training; more like evaluation |
| lukaemon/mmlu | varies | General | Depends on partitioner |
| takala/financial_phrasebank | train 4.8k | Financial | Depends on partitioner |
| pauri32/fiqa-2018 | train 0.9k; validation 0.1k; test 0.2k | Financial | Depends on partitioner |
| zeroshot/twitter-financial-news-sentiment | train 9.5k; validation 2.4k | Financial | Depends on partitioner |
| bigbio/pubmed_qa | train 2M; validation 11k | Medical | Depends on partitioner |
| openlifescienceai/medmcqa | train 183k; validation 4.3k; test 6.2k | Medical | Depends on partitioner |
| bigbio/med_qa | train 10.1k; test 1.3k; validation 1.3k | Medical | Depends on partitioner |
