# Novelty Map: Prior Art Coverage Matrix for FL Attack-Defense Evaluation

> **Purpose:** Systematic comparison of our framework's capabilities against published FL robustness literature.  
> Map each finding to: (a) prior work that covers it, (b) what is genuinely new.  
> **Last updated:** 2026-08-16  
> **Papers cataloged:** 205 (96 in-scope Byzantine FL robustness + 109 broader FL security)  
> **Known vulnerability pairs:** 99  
> **Coverage:** NeurIPS, ICML, ICLR, USENIX Security, NDSS, IEEE S&P, ACM CCS, RAID, AISTATS, UAI, IJCAI, KDD, CVPR, WACV, MLSys, IEEE TSP, IEEE TBD, WWW, INFOCOM, arXiv

---

## 1. Prior Art Coverage Matrix

Rows = attack types. Columns = defenses. Cells = papers that tested that specific combination.  
`--` = no prior work found testing this combination.

### 1.1 Standard Attack Primitives

| Attack | Krum/MultiKrum | Bulyan | TrimmedMean | Median | FLTrust | FoolsGold | FLRAM | MAB-RFL |
|--------|---------------|--------|-------------|--------|---------|-----------|-------|---------|
| **Gaussian noise** | Blanchard17, FLPoison25, BLADES24, ByzFL25, FedSec24, LASA25 | FLPoison25, BLADES24 | Yin18, FLPoison25, BLADES24, ByzFL25, FedSec24, LASA25 | Yin18, FLPoison25, BLADES24, ByzFL25, FedSec24, LASA25 | Cao21, FLPoison25, BLADES24, ByzFL25 | FLPoison25 | Chen23 (own) | -- |
| **Sign flip** | Fang20, FLPoison25, BLADES24, ByzFL25, Karimireddy21, Farhadkhani22, LASA25, SignGuard22 | FLPoison25, Karimireddy22 | FLPoison25, BLADES24, ByzFL25, Karimireddy21, Farhadkhani22, LASA25, SignGuard22 | FLPoison25, BLADES24, ByzFL25, Karimireddy21, Farhadkhani22, SignGuard22 | Cao21, FLPoison25, BLADES24, ByzFL25 | FLPoison25 | Chen23 (own) | -- |
| **ALIE** | Baruch19, Fang20, FLPoison25, BLADES24, ByzFL25, Karimireddy21, Farhadkhani22, LASA25 | Baruch19, FLPoison25, Karimireddy22 | Baruch19, Fang20, FLPoison25, BLADES24, ByzFL25, Karimireddy21, Farhadkhani22, LASA25 | Baruch19, FLPoison25, BLADES24, ByzFL25 | PoisonedFL25, FLPoison25, BLADES24 | FLPoison25 | -- | -- |
| **Mean shift** | -- | -- | -- | -- | -- | -- | -- | -- |
| **Label flip** | FLPoison25, BLADES24, Zeno19, FedSec24 | FLPoison25 | Yin18, FLPoison25, BLADES24, Zeno19, FedSec24 | FLPoison25, BLADES24, Zeno19 | Cao21, FLPoison25 | Fung20 (own), FLPoison25 | Chen23 (own) | -- |
| **Backdoor** | Wang20, DBA20, FLDetector22, Sun19, FLPoison25, BackFed25, FedSec24, Neurotoxin22 | -- | PoisonedFL25, FLPoison25, BackFed25 | PoisonedFL25, FLPoison25, BackFed25 | PoisonedFL25, BadSampler24, FLPoison25, BackFed25 | FLAME22, DeepSight22, FLPoison25, BackFed25 | -- | -- |

### 1.2 Optimization-Based Attacks (Defense-Aware)

| Attack | Krum/MultiKrum | Bulyan | TrimmedMean | Median | FLTrust | FoolsGold | FLRAM | MAB-RFL |
|--------|---------------|--------|-------------|--------|---------|-----------|-------|---------|
| **Fang (optimized)** | Fang20, Shejwalkar21, PoisonedFL25, FLPoison25, Mozaffari23, FedRecover23 | Fang20, Shejwalkar21 | Fang20, Shejwalkar21, PoisonedFL25, FLPoison25, Mozaffari23 | Fang20, Shejwalkar21, PoisonedFL25, FLPoison25 | PoisonedFL25, FLPoison25, FoundationFL25 | FoundationFL25 | -- | -- |
| **Min-Max** | Shejwalkar21, PoisonedFL25, FLPoison25, Mozaffari23, SignGuard22, LASA25 | Shejwalkar21, LASA25 | Shejwalkar21, PoisonedFL25, FLPoison25, Mozaffari23, SignGuard22, LASA25 | Shejwalkar21, PoisonedFL25, FLPoison25, SignGuard22 | PoisonedFL25, FLPoison25 | -- | -- | -- |
| **Min-Sum** | Shejwalkar21, PoisonedFL25, FLPoison25, Mozaffari23, SignGuard22, LASA25 | Shejwalkar21, LASA25 | Shejwalkar21, PoisonedFL25, FLPoison25, Mozaffari23, SignGuard22, LASA25 | Shejwalkar21, PoisonedFL25, FLPoison25, SignGuard22 | PoisonedFL25, FLPoison25 | -- | -- | -- |
| **IPM** | Xie19(UAI), Karimireddy21, Karimireddy22, Farhadkhani22, FLPoison25, ByzFL25, SignGuard22, LASA25 | Karimireddy22 | Karimireddy21, Farhadkhani22, FLPoison25, ByzFL25, SignGuard22, LASA25 | Xie19(UAI), Karimireddy21, Farhadkhani22, FLPoison25, ByzFL25 | FLPoison25 | -- | -- | -- |
| **PoisonedFL** | PoisonedFL25 | -- | PoisonedFL25 | PoisonedFL25 | PoisonedFL25 | -- | -- | -- |

### 1.3 Our Framework-Specific Attack Dimensions (Novel Axes)

| Attack Dimension | Krum/MultiKrum | Bulyan | TrimmedMean | Median | FLTrust | FoolsGold | FLRAM | MAB-RFL |
|-----------------|---------------|--------|-------------|--------|---------|-----------|-------|---------|
| **Adaptive MAB (attacker-side)** | -- | -- | -- | -- | -- | -- | -- | -- |
| **Multi-layer composite** | -- | -- | -- | -- | -- | -- | -- | -- |
| **Dynamic scheduling (churn/sticky/random)** | -- | -- | -- | -- | -- | -- | -- | -- |
| **Delayed onset** | -- | -- | -- | -- | -- | -- | -- | -- |
| **Intensity ramping** | -- | -- | -- | -- | -- | -- | -- | -- |

### Reading the Matrix

- **Well-covered:** ALIE, Fang, Min-Max, sign flip vs {Krum, TrimmedMean, Median} — many papers
- **Moderately covered:** FLTrust — tested in 6+ papers but mostly against standard attacks
- **Sparsely covered:** FoolsGold — tested in its own paper + FLAME, DeepSight, MESAS, FLPoison
- **Barely covered:** FLRAM — only tested by its own authors (Chen 2023) with basic attacks
- **Barely covered:** MAB-RFL — only tested by its own authors (Wan 2022) with basic attacks
- **Completely empty:** All 5 novel attack dimensions (bottom section) — no prior work at all

---

## 2. Comprehensive Paper Catalog

### 2.1 Foundational Defense Papers

| # | Paper | Year | Venue | Defenses Proposed/Tested | Attacks Tested | Adaptive? | Non-IID? | Classes | Code |
|---|-------|------|-------|--------------------------|----------------|-----------|----------|---------|------|
| 1 | Blanchard et al. — Krum | 2017 | NeurIPS | **Krum, Multi-Krum** (proposed) | Omniscient, Gaussian | No | No | 10 | -- |
| 2 | Yin et al. — Coord. Median/TrimMean | 2018 | ICML | **TrimmedMean, Median** (proposed) | Label flip, random | No | No | 10 | -- |
| 3 | El Mhamdi et al. — Bulyan | 2018 | ICML | **Bulyan** (proposed), Krum | High-dim Byzantine | No | No | 10 | -- |
| 4 | Xie et al. — Zeno | 2019 | ICML | **Zeno** (proposed), Krum, TrimMean | Sign flip, Gaussian, label flip | No | No | 10 | -- |
| 5 | Cao et al. — FLTrust | 2021 | NDSS | **FLTrust** (proposed), Krum, TrimMean, Median | Fang, LIE, label flip, sign flip, scaling | Yes | Yes | 10-62 | -- |
| 6 | Fung et al. — FoolsGold | 2020 | RAID | **FoolsGold** (proposed) | Label flip, backdoor, Sybil | Limited | Yes | 10 | -- |
| 7 | Wan et al. — MAB-RFL | 2022 | IJCAI | **MAB-RFL** (proposed), Krum, TrimMean | Byzantine, Sybil | No | Yes | 10 | -- |
| 8 | Chen et al. — FLRAM | 2023 | MDPI Elec. | **FLRAM** (proposed), Krum, TrimMean, Median | Byzantine poisoning | No | Yes | 10 | -- |
| 9 | Pillutla et al. — RFA | 2022 | IEEE TSP | **RFA/GeoMedian** (proposed), TrimMean, Krum | Gaussian, sign flip, label flip | No | No | varied | -- |
| 10 | Karimireddy et al. — CenteredClipping | 2021 | ICML | **CenteredClipping** (proposed), Krum, TrimMean, Median, RFA | Time-coupled, ALIE, IPM, sign flip | Yes | Yes | 10 | -- |
| 11 | Nguyen et al. — FLAME | 2022 | USENIX Sec | **FLAME** (proposed), Krum, FoolsGold, AFA, norm-clip, RFA | Backdoor (scaling, DBA, constrain-and-scale) | No | Yes | 10 | -- |
| 12 | Karimireddy et al. — Bucketing | 2022 | ICLR | **Bucketing** (meta, proposed), Krum, Median, CClip, Bulyan | ALIE, IPM, Fang, sign flip, Gaussian | Yes | Yes | 10 | -- |
| 13 | Farhadkhani et al. — RESAM | 2022 | ICML | **RESAM** (proposed), Krum, TrimMean, Median, CClip | ALIE, IPM, sign flip, label flip | Yes | No | 10 | -- |
| 14 | Shejwalkar & Houmansadr — DnC | 2021 | NDSS | Krum, MultiKrum, Bulyan, TrimMean, Median, **DnC** (proposed) | **Min-Max, Min-Sum** (proposed), Fang, LIE | Yes | Limited | 10 | [code](https://github.com/vrt1shjwlkr/NDSS21-Model-Poisoning) |

### 2.2 Key Attack Papers

| # | Paper | Year | Venue | Defenses Tested | Attacks Proposed/Tested | Adaptive? | Non-IID? | Classes | Code |
|---|-------|------|-------|-----------------|--------------------------|-----------|----------|---------|------|
| 15 | Baruch et al. — ALIE | 2019 | NeurIPS | Krum, Bulyan, TrimMean, Median | **ALIE** (proposed) | Yes | No | 10-100 | -- |
| 16 | Fang et al. — Local Model Poisoning | 2020 | USENIX Sec | Krum, MultiKrum, Bulyan, TrimMean, Median | **Fang** (proposed, per-defense optimized) | Yes | No | 10 | [code](https://github.com/vrt1shjwlkr/Poisoning-Attacks-on-FLs) |
| 17 | Xie et al. — IPM | 2019 | UAI | Krum, Median | **IPM** (proposed) | Yes | No | 10 | -- |
| 18 | Bagdasaryan et al. — Backdoor | 2020 | AISTATS | FedAvg, norm-bound | **Constrain-and-scale** (proposed), scaling | Yes | Yes | 10 | -- |
| 19 | Xie et al. — DBA | 2020 | ICLR | FedAvg, Krum, norm-bound, RFA | **DBA** (proposed, distributed trigger) | Partial | Yes | 10 | -- |
| 20 | Wang et al. — Edge-case | 2020 | NeurIPS | Krum, MultiKrum, norm-bound, RFA | **Edge-case backdoor** (proposed) | Partial | Yes | 10 | -- |
| 21 | Zhang et al. — Neurotoxin | 2022 | ICML | FedAvg, Krum, MultiKrum, TrimMean, RFA, FoolsGold | **Neurotoxin** (proposed, durable backdoor) | Partial | Yes | 10 | -- |
| 22 | Xie et al. — PoisonedFL | 2025 | CVPR | MultiKrum, Median, TrimMean, FLTrust, FLAME, FLCert, FLDetector | **PoisonedFL** (proposed, multi-round consistency) | Yes | Yes | 10 | [code](https://github.com/xyq7/PoisonedFL) |
| 23 | Shejwalkar et al. — Back to Drawing Board | 2022 | IEEE S&P | Krum, MultiKrum, TrimMean, Median, DnC, norm-bound | Min-Max, Min-Sum, Fang, LIE | Yes | Yes | 10-62 | -- |
| 24 | Sun et al. — Can You Really Backdoor FL? | 2019 | NeurIPS wksp | Krum, TrimMean, Bulyan, norm-bound, weak DP | Backdoor (scaling) | No | No | 10 | -- |

### 2.3 Security Conference Papers (Defense + Attack Evaluations)

| # | Paper | Year | Venue | Defenses Tested | Attacks Tested | Adaptive? | Non-IID? | Classes | Code |
|---|-------|------|-------|-----------------|----------------|-----------|----------|---------|------|
| 25 | Mozaffari et al. — FRL | 2023 | USENIX Sec | **FRL** (proposed), MultiKrum, TrimMean | Min-Max, Min-Sum, Fang, LIE | Yes | Yes | **62** (FEMNIST) | -- |
| 26 | Krauss & Dmitrienko — MESAS | 2023 | ACM CCS | **MESAS** (proposed), FoolsGold, MultiKrum, norm-clip, FLAME, DeepSight, FLTrust | 9 backdoor attacks (DBA, constrain-and-scale, edge-case) | Yes | Yes | **62** (FEMNIST) | -- |
| 27 | Rieger et al. — DeepSight | 2022 | NDSS | **DeepSight** (proposed), FedAvg, norm-clip, FoolsGold, Krum, AFA | Backdoor (scaling, DBA, constrain-and-scale) | Partial | Yes | 10 | -- |
| 28 | Fereidooni et al. — FreqFed | 2024 | NDSS | **FreqFed** (proposed), Krum, AFA, Median, DP, FoolsGold, BayBFed, FLAME, DeepSight, Auror | Label flip, random, PGD, constrain-and-scale, DBA | Partial | Yes | 10 | -- |
| 29 | Fang et al. — FoundationFL | 2025 | NDSS | **FoundationFL** (proposed), Krum, FoolsGold, FLAME, TrimMean, Median | Fang, Min-Max, Min-Sum, LIE | Yes | Yes | 10 | -- |
| 30 | Lycklama et al. — RoFL | 2023 | IEEE S&P | Norm-bound + SecAgg (proposed), FedAvg | Scaling, constrain-and-scale, backdoor | Yes | Yes | 10 | -- |
| 31 | Cao et al. — FedRecover | 2023 | IEEE S&P | **FedRecover** (proposed), TrimMean, Median | Fang, LIE, DBA, scaling backdoor | Yes | No | 10-62 | -- |
| 32 | Choudhary et al. — HIDRA | 2024 | IEEE S&P | Tests dimension-chunked defenses | **HIDRA** (proposed, breaks chunking-based robustness) | Yes | Yes | 10 | -- |
| 33 | Pasquini et al. — Model Inconsistency | 2022 | ACM CCS | Secure aggregation protocols | Gradient suppression + inversion | Yes (server) | Yes | 10 | -- |
| 34 | Fang et al. — BRDFL | 2024 | ACM CCS | **BRDFL** (proposed), CClip, DnC | Fang, Min-Max, LIE, IPM | Yes | Yes | 10 | -- |
| 35 | Zhang et al. — FLDetector | 2022 | KDD | **FLDetector** (proposed), TrimMean, Median, Krum | Fang, LIE, DBA, scaling, adaptive-to-FLDetector | Yes | No | **62** (FEMNIST) | -- |

### 2.4 Additional ML Conference Papers (Byzantine Focus)

| # | Paper | Year | Venue | Defenses Tested | Attacks Tested | Adaptive? | Non-IID? | Classes | Code |
|---|-------|------|-------|-----------------|----------------|-----------|----------|---------|------|
| 36 | Alistarh et al. — Byzantine SGD | 2018 | NeurIPS | Filtering-based SGD (proposed) | Arbitrary Byzantine | No | No | -- | -- |
| 37 | Bernstein et al. — signSGD majority | 2019 | ICLR | **signSGD** (proposed) | Arbitrary sign vectors | No | No | 10 | -- |
| 38 | Allen-Zhu et al. — SafeguardSGD | 2021 | ICLR | **SafeguardSGD** (proposed) | Custom Byzantine attacks | Yes | No | varied | -- |
| 39 | El Mhamdi et al. — Distributed Momentum | 2021 | ICLR | 6 defenses + momentum (Krum, Bulyan, Median, TrimMean) | 2 SOTA attacks (ALIE, IPM) | Yes | No | varied | -- |
| 40 | Allouah et al. — Breakdown Points | 2023 | NeurIPS | Krum, TrimMean, Median, CClip, Bucketing (theoretical) | Theoretical Byzantine | N/A | Yes | -- | -- |
| 41 | Allouah et al. — Byzantine + Partial Participation | 2024 | NeurIPS | Partial participation + Byzantine robustness | Byzantine under partial participation | Yes | Yes | 10-62 | -- |
| 42 | Farhadkhani et al. — Data↔Byzantine Equivalence | 2022 | ICML | Krum, TrimMean, Median | Data poisoning ≡ Byzantine (theoretical) | -- | Yes | -- | -- |
| 43 | Liu et al. — Gradient Splitting | 2023 | ICML | **GradSplit** (proposed), Krum, TrimMean, Median, CClip, Bucketing | ALIE, IPM, sign flip | Yes | Yes | 10 | -- |
| 44 | Allouah et al. — Privacy-Robustness-Utility Trilemma | 2023 | ICML | Robust aggregation + DP | Byzantine | No | Yes | -- | -- |
| 45 | RFLPA | 2024 | NeurIPS | **RFLPA** (proposed), Krum, TrimMean, Bulyan, FLTrust | Fang, Min-Max, Min-Sum, LIE, IPM | Yes | Yes | 10 | -- |
| 46 | Xu & Huang — SignGuard | 2022 | IEEE ICDCS | **SignGuard** (proposed), TrimMean, Median, GeoMed, MultiKrum, Bulyan, DnC | Fang, LIE, Min-Max, Min-Sum, sign flip, IPM | Yes | Yes | 10 | -- |
| 47 | Liu et al. — BadSampler | 2024 | KDD | FLTrust, FedAvg | **BadSampler** (proposed, clean-label backdoor) | Yes | Yes | 10 | -- |
| 48 | Data & Diggavi — Byzantine SGD Heterogeneous | 2021 | ICML | Robust mean estimation (proposed) | Byzantine (arbitrary) | No | Yes | -- | -- |
| 49 | Xu et al. — LASA | 2025 | WACV | TrimMean, GeoMed, MultiKrum, Bulyan, DnC, SignGuard, SparseFed, **LASA** (proposed) | 8 attacks (Random, Noise, SignFlip, MinMax, MinSum, TrmAtk, ByzMean, LIE) | No | Yes | 10-100 | [code](https://github.com/JiiahaoXU/LASA) |

### 2.5 Benchmark and Survey Papers

| # | Paper | Year | Venue | # Attacks | # Defenses | Total Configs | Datasets | Composite? | Scheduling? | Code |
|---|-------|------|-------|-----------|------------|---------------|----------|------------|-------------|------|
| 50 | Zhang et al. — **FLPoison/SoK** | 2025 | arXiv | **15** | **17+** | **2,040** | MNIST, CIFAR-10, FEMNIST, EMNIST, CIFAR-100, TinyImageNet | No | No | [code](https://github.com/vio1etus/FLPoison) |
| 51 | Li et al. — **BLADES** | 2024 | IoTDI | 7 | 7 | ~1,500 | F-MNIST, CIFAR-10, UCI-HAR | No | No | [code](https://github.com/lishenghui/blades) |
| 52 | Xie et al. — **PoisonedFL** | 2025 | CVPR | 8 | 9 | ~360+ | CIFAR-10, F-MNIST, MNIST, Purchase, FEMNIST | No | Yes (multi-round) | [code](https://github.com/xyq7/PoisonedFL) |
| 53 | Dao et al. — **BackFed** | 2025 | arXiv | 11 | **20** | many | CIFAR-10, FEMNIST, TinyImageNet | No | No | [code](https://github.com/thinh-dao/BackFed) |
| 54 | Han et al. — **FedSecurity** | 2024 | KDD | 9 | 16 | ~50+ | CIFAR-10/100, FEMNIST, Shakespeare, 20News | No | No | FedML |
| 55 | Garcia et al. — **ByzFL** | 2025 | arXiv | 6 | 10+ | configurable | configurable | No | No | [code](https://github.com/LPD-EPFL/byzfl) |
| 56 | Li et al. — Exp. Study of Byzantine AGRs | 2024 | IEEE TBD | 5 | 8 | moderate | F-MNIST, CIFAR-10 | No | No | -- |

### 2.6 Recent AAAI/IJCAI Attack-Defense Papers (2025-2026)

| # | Paper | Year | Venue | Focus | Relevant to Our Matrix? |
|---|-------|------|-------|-------|------------------------|
| 57 | Good Gradients Poison Your Model (boundary-adaptive perturbation) | 2026 | AAAI | Evasion of existing defenses | Partially — new attack, tests against Byzantine defenses |
| 58 | Poisoning with a Pill | 2026 | AAAI | Circumventing detection | Partially — tests detection-based defenses |
| 59 | SADBA: Self-Adaptive Distributed Backdoor | 2025 | AAAI | Adaptive distributed backdoor | Partially — distributed backdoor evasion |
| 60 | Exploit Gradient Skewness to Circumvent Byzantine Defenses | 2025 | AAAI | Circumventing Byzantine defenses | Yes — tests gradient skewness attack vs robust AGRs |
| 61 | Defending Against Sophisticated Poisoning with RL-based Aggregation | 2025 | AAAI | RL-based aggregation defense | Partially — defense-side RL, not attack-side MAB |
| 62 | LiD-FL: List-Decodable FL | 2025 | AAAI | New robust aggregation | Partially — new defense paradigm |
| 63 | EBS-CFL: Byzantine-robust Secure Clustered FL | 2025 | AAAI | Clustering + Byzantine robustness | Partially — defense, not attack evaluation |
| 64 | FedHAN: Defending Against Poisoning in Heterogeneous Clients | 2025 | IJCAI | Cache-based defense | Partially — heterogeneous defense |
| 65 | Performance Guaranteed Poisoning: Sliding Mode | 2025 | IJCAI | New attack technique | Partially — theory-focused attack |
| 66 | BOBA: Byzantine-Robust FL with Label Skewness | 2024 | AISTATS | **BOBA** defense | Partially — addresses label skew |
| 67 | Invariant Aggregator for Backdoor | 2024 | AISTATS | Invariant aggregation defense | Partially — backdoor defense |

---

## 3. Defense Coverage Summary

How many papers test each defense (approximate count from catalog):

| Defense | Papers Testing It | First Proposed | Tested by Others? |
|---------|-------------------|----------------|-------------------|
| **Krum / Multi-Krum** | ~28 | Blanchard 2017 (NeurIPS) | Extensively |
| **Trimmed Mean** | ~26 | Yin 2018 (ICML) | Extensively |
| **Median** | ~18 | Yin 2018 (ICML) | Extensively |
| **Bulyan** | ~12 | El Mhamdi 2018 (ICML) | Moderately |
| **FLTrust** | ~8 | Cao 2021 (NDSS) | Moderately |
| **DnC** | ~7 | Shejwalkar 2021 (NDSS) | Moderately |
| **FoolsGold** | ~8 | Fung 2020 (RAID) | Moderately |
| **FLAME** | ~6 | Nguyen 2022 (USENIX Sec) | Moderately |
| **Norm bounding/clipping** | ~8 | Various | Used as baseline |
| **RFA / Geometric Median** | ~6 | Pillutla 2022 (IEEE TSP) | Moderately |
| **CenteredClipping** | ~5 | Karimireddy 2021 (ICML) | Partially |
| **SignGuard** | ~2 | Xu 2022 (ICDCS) | Barely |
| **FLRAM** | **1** | Chen 2023 (MDPI Elec.) | **Only by own authors** |
| **MAB-RFL** | **1** | Wan 2022 (IJCAI) | **Only by own authors** |

---

## 4. Attack Coverage Summary

| Attack | Papers Testing It | First Proposed |
|--------|-------------------|----------------|
| **ALIE / LIE** | ~14 | Baruch 2019 (NeurIPS) |
| **Fang (optimized)** | ~13 | Fang 2020 (USENIX Sec) |
| **Backdoor (scaling/model replacement)** | ~12 | Bagdasaryan 2020 (AISTATS) |
| **IPM** | ~10 | Xie 2019 (UAI) |
| **Sign flip** | ~8 | Classic |
| **Min-Max** | ~7 | Shejwalkar 2021 (NDSS) |
| **Label flip** | ~7 | Classic |
| **Min-Sum** | ~6 | Shejwalkar 2021 (NDSS) |
| **DBA (distributed backdoor)** | ~6 | Xie 2020 (ICLR) |
| **Gaussian noise** | ~6 | Classic |
| **Constrain-and-scale** | ~6 | Bagdasaryan 2020 |
| **Edge-case backdoor** | ~3 | Wang 2020 (NeurIPS) |
| **Neurotoxin** | ~1 | Zhang 2022 (ICML) |
| **PoisonedFL (multi-round)** | ~1 | Xie 2025 (CVPR) |
| **Mean shift** | **0** | -- |
| **Adaptive MAB (attack-side)** | **0** | -- |
| **Composite/layered** | **0** | -- |

---

## 5. Benchmark Comparison Table

| Benchmark | Year | Venue | # Attacks | # Defenses | # Configs | Composite? | Adaptive MAB? | Scheduling? | Onset/Ramp? | Per-class? | Trust Defenses Tested |
|-----------|------|-------|-----------|------------|-----------|------------|---------------|-------------|-------------|------------|----------------------|
| **FLPoison/SoK** | 2025 | arXiv | **15** | **17** | 2,040 | No | No | No | No | No | FoolsGold only |
| **BackFed** | 2025 | arXiv | 11 | **20** | many | No | No | No | No | No | FoolsGold, FLTrust |
| **FedSecurity** | 2024 | KDD | 9 | 16 | ~50 | No | No | No | No | No | FoolsGold, Krum, Bulyan |
| **PoisonedFL** | 2025 | CVPR | 8 | 9 | ~360 | No | No | multi-round | No | No | FLTrust |
| **BLADES** | 2024 | IoTDI | 7 | 7 | ~1,500 | No | No | No | No | No | FLTrust |
| **ByzFL** | 2025 | arXiv | 6 | 10+ | config | No | No | No | No | No | None |
| **LASA** | 2025 | WACV | 8 | 9 | mod | No | No | No | No | No | None |
| **Our Framework** | 2026 | Thesis | **6** | **8** | **600+** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **FLTrust, FoolsGold, FLRAM, MAB-RFL** |

### Key Differentiation

Our framework tests FEWER individual attack primitives (6 vs 15 in FLPoison), but covers **5 orthogonal dimensions that no benchmark touches**:

1. **Adaptive attack-side MAB** — no benchmark has this
2. **Composite/layered attacks** — no benchmark has this
3. **Dynamic scheduling** (churn/sticky/random) — no benchmark has this
4. **Delayed onset** — no benchmark has this
5. **Intensity ramping** — no benchmark has this

Additionally, no benchmark tests **4 trust/reputation defenses** (FLTrust + FoolsGold + FLRAM + MAB-RFL) under a shared abstraction.

---

## 6. Gap Analysis: What Is Genuinely New

### Gap 1: Attack-side MAB (epsilon-greedy bandit for the attacker) — Automated Assumption Fuzzer

**Status: NO prior work found** (60+ papers surveyed).

Prior MAB in FL is exclusively **defensive**: MAB-RFL (Wan 2022) uses bandit for client reputation, SARA (Hu 2025) uses bandit for defense selection, FedAA (AAAI 2025) uses RL for aggregation. Wang 2023 uses bandit for data poisoning in autonomous driving, but only for a single attack type against a single defense. RL-based aggregation defense (AAAI 2025) is defense-side, not attack-side.

No paper places an epsilon-greedy bandit in the hands of the attacker to select among 6 different poisoning primitives round-by-round based on observed model degradation.

**The MAB as an automated assumption fuzzer:** Beyond attack selection, the MAB functions as an empirical assumption prober. Each defense rests on stated assumptions (e.g., "honest majority," "Sybil similarity," "IID data"). The MAB does not know these assumptions — it simply tries all available attacks and gravitates toward whichever causes the most damage. When the MAB converges to an attack that happens to violate a specific defense assumption, it has **discovered** that assumption's weakness empirically, without any prior knowledge of the defense's internals. This makes the MAB a genuine vulnerability discovery mechanism, not just an optimization tool (see Section 6.5).

**Novelty claim:** "To the best of our knowledge, this is the first framework to employ attacker-side multi-armed bandit selection among diverse poisoning primitives in federated learning. The MAB's convergence patterns serve as an automated assumption fuzzer that can empirically discover defense-specific vulnerabilities."

**Confidence:** High — surveyed 60+ papers across all top venues (2017-2026).

### Gap 2: Multi-layer attack composition

**Status: NO prior work found** for stacking multiple model-poisoning primitives in a single round.

DBA (Xie 2020, ICLR) distributes *trigger patterns* for backdoor attacks, but does not stack heterogeneous attack primitives (e.g., gaussian_noise + sign_flip + ALIE). No benchmark (FLPoison, BLADES, BackFed, FedSecurity, ByzFL) evaluates composite attacks.

**Novelty claim:** "We introduce multi-layer attack composition, where multiple model poisoning primitives are simultaneously applied to a single client update, and evaluate three layering modes (single, fixed, sample-k) against eight defenses."

**Confidence:** High.

### Gap 3: Malicious client scheduling as a configurable attack dimension

**Status: NO prior work found** systematically comparing churn, sticky, and per-round-random scheduling.

Bagdasaryan 2020 briefly compares one-shot vs repeated injection. Sun 2019 tests fixed-frequency vs random sampling. Neurotoxin (Zhang 2022, ICML) uses intermittent attacker participation for durability. But NO paper treats malicious client scheduling mode as an explicit, swept attack parameter comparing churn vs sticky vs per-round-random across defenses.

**Novelty claim:** "We systematically evaluate the impact of malicious client scheduling — churn, sticky, and per-round-random — as an attacker-controlled dimension, showing scheduling mode changes the dominant attack per defense."

**Confidence:** High.

### Gap 4: Delayed onset + intensity ramping

**Status: NO prior work found** combining both as configurable sweep parameters.

PoisonedFL (Xie 2025) uses multi-round consistency and dynamic magnitude adjustment, but this is an attack algorithm property, not a configurable sweep parameter. No paper provides onset time and ramp rate as independently tunable dimensions tested across multiple defenses.

**Novelty claim:** "We evaluate delayed-onset attacks with configurable intensity ramping, showing that onset timing shifts the dominant attack for some defenses."

**Confidence:** High.

### Gap 5: Cross-defense vulnerability profiling (8 defenses, same framework, same conditions)

**Status: Partial coverage in FLPoison and BLADES, but neither includes all 8 of our defenses.**

- FLPoison tests 17 defenses but no FLRAM, no MAB-RFL, no composite attacks, no scheduling
- BLADES tests 7 defenses but no FoolsGold, no FLRAM, no MAB-RFL
- BackFed tests 20 defenses but no FLRAM, no MAB-RFL, no model-poisoning-focused primitives
- None test under adaptive + composite + scheduling dimensions simultaneously

**Novelty claim:** "We provide the first unified evaluation spanning Krum, Bulyan, TrimmedMean, Median, FLTrust, FoolsGold, FLRAM, and MAB-RFL under identical experimental conditions with adaptive, composite, and scheduled attacks."

**Confidence:** Moderate — the defense count (8) is lower than FLPoison's 17, but the attack dimension coverage is wider.

### Gap 6: 62-class FEMNIST under Dirichlet non-IID with Byzantine attacks

**Status: Rare but not unique.**

Papers using FEMNIST with 62 classes in Byzantine settings:
- Mozaffari 2023 (USENIX Sec, FRL) — tested FEMNIST(62) but only 4 defenses, no composites
- Krauss 2023 (CCS, MESAS) — tested FEMNIST(62) but backdoor-focused
- Shejwalkar 2022 (S&P) — used EMNIST(62) in production setting
- FLDetector 2022 (KDD) — tested FEMNIST(62) but only 4 defenses

These papers use FEMNIST but none combine it with: 8 defenses + adaptive MAB + composite attacks + scheduling.

**Revised novelty claim:** "While FEMNIST(62) appears in a handful of prior evaluations (Mozaffari 2023, Krauss 2023, FLDetector 2022), no prior work evaluates it under our full attack dimension space (adaptive MAB, composites, scheduling, onset, ramping)."

**Confidence:** Moderate — FEMNIST alone is not novel, but the combination is.

### Gap 7: Trust-weight shared abstraction

**Status: NO prior work found.**

No prior paper implements FLTrust, FoolsGold, FLRAM, and MAB-RFL under a shared trust-weighting framework with matched parameters and the same blending equation.

**Novelty claim:** "We formalize FLTrust, FoolsGold, FLRAM, and MAB-RFL under a shared trust-weight abstraction, enabling controlled comparison by varying only the raw trust score computation."

**Confidence:** High.

### Gap 8: Per-class accuracy degradation under Byzantine attacks

**Status: NO prior work found.**

All surveyed papers report aggregate accuracy, loss, attack success rate, or F1. None report per-class accuracy degradation showing which classes are disproportionately damaged by attacks.

**Novelty claim:** "We report per-class accuracy under attack, revealing that Byzantine attacks disproportionately affect under-represented classes in non-IID settings."

**Confidence:** Moderate — need multi-seed confirmation.

---

## 6.5 Automated Vulnerability Discovery: How the MAB Finds New Things

### The Core Insight

Every robust aggregation defense rests on **stated assumptions** — mathematical or behavioral conditions that must hold for the defense to work. These assumptions are documented in the original papers but rarely tested systematically. Our MAB-based adaptive attack engine functions as an **automated assumption fuzzer**: it probes each defense empirically, without knowing its assumptions, and gravitates toward whichever attack primitive causes the most damage.

When the MAB converges to an attack that violates a specific defense assumption, it has **discovered** that assumption's weakness — not through analysis, but through empirical trial and error. This is genuinely different from manual attack design, where the researcher must first understand the defense to craft an exploit.

### Discovery Classification Types

The analysis pipeline (`db/atlas_mapping.py`) automatically classifies findings into four discovery types:

| Discovery Type | Definition | Example |
|----------------|------------|---------|
| **assumption_violation** | Finding directly contradicts a defense's stated mathematical or behavioral assumption | FoolsGold collapsed under adaptive MAB because diverse attack switching decorrelates the Sybil similarity signal it relies on |
| **synergistic_composite** | Composite attack is significantly more effective than any individual component | `sample_k` layering causes Bulyan collapse at 89% rate vs 8% for `fixed` — the multi-primitive composition overwhelms the two-stage filtering |
| **scheduling_sensitivity** | Client scheduling mode significantly changes attack outcome for a defense | `per_round_random` scheduling causes more damage than `sticky` to history-dependent defenses (FoolsGold, MAB-RFL) |
| **unexpected_convergence** | MAB converged to an attack the knowledge base says should NOT work against this defense | MAB selects an attack the literature marks as ineffective, suggesting the defense is weaker than published |

### Discoveries Already in the Data (600 Runs)

From automated analysis of the 600-run database (252 FEMNIST + 320 MNIST + 22 pilot + 6 dummy):

| # | Defense | Discovery Type | Assumption Violated | Evidence |
|---|---------|---------------|---------------------|----------|
| 1 | FoolsGold | assumption_violation | "Sybil similarity: colluding clients produce similar gradient histories" | Collapsed to 3.3% accuracy under adaptive MAB — diverse attack switching each round decorrelates gradient histories |
| 2 | MAB-RFL | assumption_violation | "Stationarity: client behavior is consistent enough for bandit arms to converge" | Churn scheduling disrupts reputation tracking, exploit via behavioral instability |
| 3 | Bulyan | assumption_violation | "Strong honest majority: requires n > 4f + 3 honest clients" | 52 collapses across sweep — overrepresentation at 24% malicious violates the stricter majority requirement |
| 4 | MultiKrum | assumption_violation | "Honest majority: fewer than half the clients are malicious" | 13 collapses — zero Byzantine filtering when malicious fraction triggers overrepresentation |
| 5 | FedMedian | assumption_violation | "Honest majority: median is robust when fewer than half the values are corrupted" | 64 collapses — most frequent assumption violation in the dataset |
| 6 | FedTrimmedAvg | assumption_violation | "IID data: non-IID makes honest updates span a wide range" | 28 collapses — trimming honest updates under non-IID data is the primary failure mode |
| 7 | Bulyan | synergistic_composite | — | Composite `sample_k` causes collapse at rates far exceeding single-attack components |
| 8 | FedMedian | synergistic_composite | — | Composite attacks collapse median defense despite 100% malicious client rejection ("denial-of-learning") |

**Total automated discoveries: 166 out of 592 findings (28%)**

### How the Pipeline Works

1. **Defense assumptions** are stored in `db/known_vulnerabilities.json` under `defenses.*.assumptions` (4-5 per defense, 15 defenses)
2. For each finding, `classify_discovery()` checks whether the attack/pattern/scheduling combination contradicts a specific assumption
3. Discoveries are persisted in the `agent_recommendations` table with `discovery_type` and `assumption_violated` columns
4. The vulnerability report (`docs/reports/vulnerability_report_atlas.md`) includes an "Automated Discoveries" section

### What Makes This Different From Manual Analysis

| Aspect | Manual vulnerability research | Our automated fuzzer |
|--------|-------------------------------|---------------------|
| **Prior knowledge** | Must understand defense internals to craft exploit | Needs zero defense knowledge — explores blindly |
| **Coverage** | Tests researcher's hypotheses | Explores all combinations (6 attacks × 3 scheduling × 3 layering × 8 defenses) |
| **Discovery mechanism** | Deductive: analyze → predict weakness → test | Inductive: test everything → observe which assumptions break |
| **Scalability** | One defense at a time | All defenses simultaneously under identical conditions |
| **Reproducibility** | Researcher-dependent | Deterministic given same seed and config |

### Conditions That Maximize Discovery Likelihood

The MAB is most likely to discover new vulnerabilities when:
- **Non-IID data** — widens the honest update distribution, making it harder for defenses to distinguish honest from malicious
- **Composite attacks** — multi-primitive compositions can overwhelm defenses that assume single attack vectors
- **Diverse scheduling** — churn and per_round_random break history-dependent defenses that assume persistent client identity
- **Sufficient rounds** — the MAB needs exploration time before its convergence reveals the defense's weakest assumption (30 rounds may be marginal; 100+ preferred)

---

## 7. Known vs Novel Findings Classification

### Known weaknesses (confirmed by prior literature)

| Finding | Prior Evidence | Our Contribution |
|---------|---------------|------------------|
| Krum/MultiKrum fails against ALIE | Baruch19, Fang20, FLPoison25, BLADES24 | **Confirmed** under 62-class non-IID. Added: zero filtering at 24% malicious (overrepresentation). |
| TrimmedMean fails against ALIE | Baruch19, Fang20, FLPoison25, BLADES24 | **Confirmed** under 62-class non-IID. Added: scheduling mode changes dominant attack. |
| Bulyan fails under non-IID | El Mhamdi18, Karimireddy22, LASA25 | **Confirmed** with quantification: 57pp accuracy range across clean baselines. |
| FLTrust is more robust than coordinate-wise defenses | Cao21, PoisonedFL25, FLPoison25 | **Confirmed** — only defense that never collapsed. Added: root dataset must scale with class count. |
| FoolsGold has false positives under non-IID | Fung20, FLAME22 | **Confirmed** with mechanism: MAB attack-type switching decorrelates Sybil signal. |
| All robust AGRs degrade under non-IID | Karimireddy22, LASA25, Li24(TBD) | **Confirmed** across 8 defenses. |

### Candidate novel findings (not found in 60+ papers)

| Finding | Why novel | Discovery Type | Evidence strength |
|---------|-----------|---------------|-------------------|
| **Different dominant attack per defense under adaptive MAB** | No prior work tests attacker-side MAB across defenses | — | Moderate (single-seed, full sweep for 4 defenses, pilot for 4) |
| **Scheduling mode changes dominant attack** | No prior work sweeps scheduling as attack parameter | scheduling_sensitivity | Moderate (single-seed, 252-run FEMNIST) |
| **Multi-layer composition causes universal collapse** | No benchmark tests stacked model poisoning | synergistic_composite | Moderate (sample_k with k=3 collapsed all 4 swept defenses) |
| **FoolsGold evasion via MAB switching + churn** | No prior work tests FoolsGold against adaptive + scheduled attacks | assumption_violation | Weak (pilot, 1 attacked run) |
| **FLRAM bypassed by ALIE (all 3 sub-scores high)** | FLRAM only tested with basic attacks by own authors | — | Weak (pilot, 1 attacked run) |
| **MAB-RFL reputation exploit via delayed onset** | MAB-RFL only tested with basic attacks by own authors | assumption_violation | Weak (pilot, 1 attacked run) |
| **FLTrust root dataset must scale with class count** | Cao21 tested only 10-class datasets | — | Moderate (3 root dataset sizes on 62-class) |
| **Bulyan clean baseline 57pp sensitivity range** | Parameterization sensitivity known but not quantified this extremely | assumption_violation | Moderate (3 clean baselines) |
| **Trust-weight paradox (conservative params = weak discrimination)** | Not formalized in prior work | — | Moderate (all 4 trust defenses) |
| **Per-class accuracy reveals disproportionate class damage** | No prior work reports per-class under Byzantine | — | Moderate (62-class FEMNIST) |
| **FedMedian denial-of-learning (collapses despite 100% rejection)** | Defense filters all malicious but model still collapses | assumption_violation | Moderate (multiple runs across sweep) |

---

## 8. MITRE ATLAS Deep Mapping

### Layer 1: ATLAS technique (general category)

| ATLAS ID | Technique | Our instantiation |
|----------|-----------|-------------------|
| AML.T0020 | Poison Training Data | label_flip, backdoor, scheduling variants |
| AML.T0018.000 | Poison ML Model | sign_flip, noise, ALIE, mean_shift, composites |
| AML.T0031 | Erode ML Model Integrity | All untargeted attacks |
| AML.T0042 | Verify Attack | MAB reward computation (attack-side) |
| AML.T0015 | Evade ML Model | ALIE (distribution-aware), stealth norm-capping |
| AML.T0007 | Discover ML Artifacts | Vulnerability profiling via convergence patterns |

### Layer 2: Our sub-techniques (framework-specific)

| Parent ATLAS | Sub-technique ID | Description | Novel? |
|-------------|-----------------|-------------|--------|
| AML.T0018.000 | DFL.T001 | Multi-layer model poisoning (stacking primitives) | YES — 0/60+ papers |
| AML.T0018.000 | DFL.T002 | Intensity ramping with escalation on failure | YES — 0/60+ papers |
| AML.T0018.000 | DFL.T003 | Delayed-onset model poisoning | YES — as parameterized sweep dimension |
| AML.T0020 | DFL.T004 | Churn-based malicious client scheduling | YES — 0/60+ papers |
| AML.T0020 | DFL.T005 | Sticky malicious client scheduling | YES — as explicit comparison axis |
| AML.T0042 | DFL.T006 | Attacker-side MAB for attack selection | YES — 0/60+ papers |
| AML.T0042 | DFL.T007 | Patience-based forced strategy switching | YES — 0/60+ papers |
| AML.T0042 | DFL.T008 | Intensity escalation before strategy switch | YES — 0/60+ papers |
| AML.T0007 | DFL.T009 | Defense vulnerability profiling via bandit convergence | YES — 0/60+ papers |
| AML.T0015 | DFL.T010 | Cross-axis evasion (attack switching + scheduling erodes Sybil detection) | YES — 0/60+ papers |
| AML.T0007 | DFL.T011 | Automated defense assumption probing via MAB convergence analysis | YES — 0/60+ papers |

### Layer 3: Defense-specific vulnerability findings

| Defense | Vulnerability ID | Description | Prior coverage | Our evidence |
|---------|-----------------|-------------|----------------|--------------|
| MultiKrum | DFL.V001 | Zero Byzantine filtering at 24% (overrepresentation) | Partially known (ALIE bypasses scoring) | 252-run sweep, 1 seed |
| Bulyan | DFL.V002 | Clean baseline 57pp accuracy range from parameterization | Partially known (El Mhamdi's constraints) | 3 clean baselines, 1 seed |
| Bulyan | DFL.V003 | Composite attacks survive two-stage pipeline | NOT in 60+ papers | 252-run sweep, 1 seed |
| FedTrimmedAvg | DFL.V004 | Scheduling-dependent dominant attack | NOT in 60+ papers | 252-run sweep, 1 seed |
| FedMedian | DFL.V005 | Most scheduling-sensitive defense | NOT in 60+ papers | 252-run sweep, 1 seed |
| FoolsGold | DFL.V006 | MAB switching decorrelates Sybil signal | NOT in 60+ papers | 1 pilot run (weak) |
| FLRAM | DFL.V007 | ALIE bypasses all 3 sub-scores | Only Chen23 basic tests | 1 pilot run (weak) |
| MAB-RFL | DFL.V008 | Reputation exploit via delayed onset | NOT in 60+ papers | 1 pilot run (weak) |
| FLTrust | DFL.V009 | Root dataset must scale with class count | NOT in Cao21 (10-class only) | 3 root sizes tested |
| All trust | DFL.V010 | Trust-weight paradox (conservative = weak) | NOT formalized | All 4 trust defenses |

---

## 9. What Must Be Done to Strengthen Claims

### To upgrade from "candidate" to "confirmed vulnerability":

| Vulnerability | Current evidence | What's needed |
|---------------|-----------------|---------------|
| DFL.V001 (MultiKrum zero filtering) | 252-run single-seed | 3+ seeds, verify Krum-score distributions |
| DFL.V002 (Bulyan param sensitivity) | 3 clean baselines | 3+ seeds, IID control |
| DFL.V003 (Bulyan composite survival) | 252-run single-seed | 3+ seeds, per-stage survival counts |
| DFL.V004 (TrimmedAvg scheduling) | 252-run single-seed | 3+ seeds |
| DFL.V005 (FedMedian scheduling) | 252-run single-seed | 3+ seeds |
| DFL.V006 (FoolsGold adaptive evasion) | 1 pilot run | Full 63-config sweep, 3+ seeds |
| DFL.V007 (FLRAM ALIE bypass) | 1 pilot run | Full sweep, 3+ seeds |
| DFL.V008 (MAB-RFL delayed onset) | 1 pilot run | Full sweep, 3+ seeds |
| DFL.V009 (FLTrust root scaling) | 3 root sizes | Multiple class counts, 3+ seeds |
| DFL.V010 (Trust paradox) | All trust defenses | Varied trust params (alpha=0.5, 0.8, 1.0) |

### The single most important missing experiment:

**Adaptive (MAB) vs non-adaptive (weighted random, best fixed, uniform random) comparison.**

Without this, the central contribution (attack-side MAB) cannot be validated as producing worse outcomes for the defense than simpler strategies. This comparison should hold everything else constant and measure:
- Final accuracy
- Cumulative degradation (area under curve)
- Rounds to collapse
- Attack-selection efficiency

---

## 10. Reference Links

### Foundational Defense Papers

| Paper | Link |
|-------|------|
| Blanchard 2017 (Krum) | https://proceedings.neurips.cc/paper_files/paper/2017/file/f4b9ec30ad9f68f89b29639786cb62ef-Paper.pdf |
| Yin 2018 (TrimMean/Median) | https://proceedings.mlr.press/v80/yin18a.html |
| El Mhamdi 2018 (Bulyan) | https://proceedings.mlr.press/v80/mhamdi18a.html |
| Cao 2021 (FLTrust) | https://arxiv.org/abs/2012.06337 |
| Fung 2020 (FoolsGold) | https://www.usenix.org/conference/raid2020/presentation/fung |
| Wan 2022 (MAB-RFL) | https://www.ijcai.org/proceedings/2022/106 |
| Chen 2023 (FLRAM) | https://www.mdpi.com/2079-9292/12/21/4463 |
| Pillutla 2022 (RFA) | IEEE TSP |
| Karimireddy 2021 (CenteredClipping) | ICML 2021 |
| Nguyen 2022 (FLAME) | https://www.usenix.org/conference/usenixsecurity22/presentation/nguyen |
| Karimireddy 2022 (Bucketing) | ICLR 2022 |
| Farhadkhani 2022 (RESAM) | ICML 2022 |
| Shejwalkar 2021 (DnC) | https://github.com/vrt1shjwlkr/NDSS21-Model-Poisoning |

### Key Attack Papers

| Paper | Link |
|-------|------|
| Baruch 2019 (ALIE) | https://arxiv.org/abs/1902.06156 |
| Fang 2020 (Local Model Poisoning) | https://www.usenix.org/conference/usenixsecurity20/presentation/fang |
| Xie 2019 (IPM) | UAI 2019 |
| Bagdasaryan 2020 (Backdoor) | https://proceedings.mlr.press/v108/bagdasaryan20a.html |
| Xie 2020 (DBA) | ICLR 2020 |
| Wang 2020 (Edge-case) | NeurIPS 2020 |
| Zhang 2022 (Neurotoxin) | ICML 2022 |
| Xie 2025 (PoisonedFL) | https://arxiv.org/abs/2404.15611 |
| Shejwalkar 2022 (Back to Drawing Board) | IEEE S&P 2022 |

### Security Conference Papers

| Paper | Link |
|-------|------|
| Mozaffari 2023 (FRL) | USENIX Security 2023 |
| Krauss 2023 (MESAS) | ACM CCS 2023 |
| Rieger 2022 (DeepSight) | NDSS 2022 |
| Fereidooni 2024 (FreqFed) | NDSS 2024 |
| Fang 2025 (FoundationFL) | NDSS 2025 |
| Lycklama 2023 (RoFL) | IEEE S&P 2023 |
| Cao 2023 (FedRecover) | IEEE S&P 2023 |
| Choudhary 2024 (HIDRA) | IEEE S&P 2024 |
| Fang 2024 (BRDFL) | ACM CCS 2024 |
| Zhang 2022 (FLDetector) | KDD 2022 |
| Liu 2024 (BadSampler) | KDD 2024 |

### Benchmark Papers

| Paper | Link |
|-------|------|
| Zhang 2025 (FLPoison/SoK) | https://github.com/vio1etus/FLPoison |
| Li 2024 (BLADES) | https://github.com/lishenghui/blades |
| Dao 2025 (BackFed) | https://github.com/thinh-dao/BackFed |
| Han 2024 (FedSecurity) | KDD 2024 / FedML |
| Garcia 2025 (ByzFL) | https://github.com/LPD-EPFL/byzfl |
| Xu 2025 (LASA) | https://github.com/JiiahaoXU/LASA |

### Additional ML Conference Papers

| Paper | Link |
|-------|------|
| Alistarh 2018 (Byzantine SGD) | NeurIPS 2018 |
| Bernstein 2019 (signSGD majority) | ICLR 2019 |
| Allen-Zhu 2021 (SafeguardSGD) | ICLR 2021 |
| El Mhamdi 2021 (Distributed Momentum) | ICLR 2021 |
| Allouah 2023 (Breakdown Points) | NeurIPS 2023 |
| Liu 2023 (Gradient Splitting) | ICML 2023 |
| Xu 2022 (SignGuard) | IEEE ICDCS 2022 |
| Sun 2019 (Can You Really Backdoor FL?) | NeurIPS Workshop 2019 |

### Awesome-FL Source

| Resource | Link |
|----------|------|
| Awesome-FL paper list | https://youngfish42.github.io/Awesome-FL/ |
| Awesome-FL GitHub | https://github.com/youngfish42/Awesome-FL |


---

## 8. Complete Knowledge Base Reference (205 Papers)

> Auto-generated from `db/known_vulnerabilities.json` — the knowledge base the framework uses to classify findings as [KNOWN], [REPRODUCED], or [NOVEL].
> 
> **96 in-scope** (Byzantine FL robustness: attacks, defenses, robust aggregation)
> **109 out-of-scope** (privacy, inference, gradient inversion — included for completeness)

### 8.1 In-Scope Papers: Byzantine FL Robustness (96 papers)

These are the papers the framework's novelty classifier directly compares against.

#### 2017 (1 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 1 | `blanchard2017` | Blanchard et al. | Machine Learning with Adversaries: Byzantine Tolerant Gradient Descent | NeurIPS | gaussian_noise | krum | Proposed Krum; tolerates up to f < n/2 - 1 Byzantine workers. Convergence proven under IID; accuracy degrades under non-IID. |

#### 2018 (2 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 2 | `elmhamdi2018` | El Mhamdi et al. | The Hidden Vulnerability of Distributed Learning in Byzantium | ICML | byzantine | bulyan, krum | Proposed Bulyan; showed Krum alone is vulnerable to dimension-coupled attacks. Bulyan adds coordinate-wise trimming on top of Krum selection. |
| 3 | `yin2018` | Yin et al. | Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates | ICML | label_flip, gaussian_noise | fedtrimmedavg, fedmedian | Proposed coordinate-wise trimmed mean and median; achieves near-optimal statistical rates under Byzantine faults with IID data. |

#### 2019 (4 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 4 | `zeno2019` | Xie et al. | Zeno: Distributed SGD with Suspicion-Based Fault-Tolerance | ICML | sign_flip, gaussian_noise, label_flip | zeno, krum, fedtrimmedavg | Zeno uses a small validation set to score updates by loss reduction. Outperforms Krum and trimmed mean under sign-flip and label-flip attacks. |
| 5 | `baruch2019` | Baruch et al. | A Little Is Enough: Circumventing Defenses For Distributed Learning | NeurIPS | alie | krum, bulyan, fedtrimmedavg (+1) | ALIE crafts updates at mu - z*sigma to stay within honest distribution. Bypasses Krum, Bulyan, trimmed mean, and median with as few as 20% maliciou... |
| 6 | `sun2019` | Sun et al. | Can You Really Backdoor Federated Learning? | NeurIPS Workshop | backdoor | krum, fedtrimmedavg, bulyan (+1) | Backdoor attacks in FL succeed even with defenses; Krum and trimmed mean reduce but do not eliminate backdoor ASR. |
| 7 | `xie2019ipm` | Xie et al. | Fall of Empires: Breaking Byzantine-tolerant SGD by Inner Product Manipulation | UAI | ipm | krum, fedmedian | Inner Product Manipulation (IPM) breaks Krum and median by aligning poisoned updates with negative of true gradient. Converges to arbitrary target. |

#### 2020 (5 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 8 | `bagdasaryan2020` | Bagdasaryan et al. | How To Backdoor Federated Learning | AISTATS | backdoor, constrain_and_scale | norm_bounding | -- |
| 9 | `dba2020` | Xie et al. | DBA: Distributed Backdoor Attacks against Federated Learning | ICLR | dba | krum, norm_bounding, rfa | -- |
| 10 | `wang2020` | Wang et al. | Attack of the Tails: Yes, You Really Can Backdoor Federated Learning | NeurIPS | edge_case | krum, norm_bounding, rfa | -- |
| 11 | `fung2020` | Fung et al. | The Limitations of Federated Learning in Sybil Settings (FoolsGold) | RAID | label_flip, backdoor | foolsgold | FoolsGold detects Sybil attacks via cosine similarity of historical gradients. Effective against coordinated label-flip but vulnerable to diverse a... |
| 12 | `fang2020` | Fang et al. | Local Model Poisoning Attacks to Byzantine-Robust Federated Learning | USENIX Security | fang, alie | krum, bulyan, fedtrimmedavg (+1) | USENIX paper reports substantial error increases against four Byzantine-robust methods and finds generalized defenses insufficient in many evaluate... |

#### 2021 (3 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 13 | `karimireddy2021` | Karimireddy et al. | Learning from History for Byzantine Robust Optimization | ICML | alie, ipm, sign_flip | centered_clipping, krum, fedtrimmedavg (+2) | CenteredClipping uses coordinate-wise clipping around geometric median. Provably robust under heterogeneous data; outperforms Krum and trimmed mean... |
| 14 | `cao2021` | Cao et al. | FLTrust: Byzantine-robust Federated Learning via Trust Bootstrapping | NDSS | fang, alie, label_flip (+3) | fltrust, krum, fedtrimmedavg (+1) | FLTrust uses a small server root dataset to compute trust scores via cosine similarity. |
| 15 | `shejwalkar2021` | Shejwalkar & Houmansadr | Manipulating the Byzantine: Optimizing Model Poisoning Attacks and Defenses f... | NDSS | min_max, min_sum, fang (+2) | krum, bulyan, fedtrimmedavg (+2) | NDSS paper reports 1.5×–60× larger accuracy reductions than prior attacks and demonstrates substantial susceptibility of existing Byzantine-robust ... |

#### 2022 (14 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 16 | `more2022` | *(unverified)* | More is Better (Mostly): On the Backdoor Attacks in Federated Graph Neural Ne... | ACSAC | -- | -- | -- |
| 17 | `eluding2022` | *(unverified)* | Eluding Secure Aggregation in Federated Learning via Model Inconsistency | CCS | -- | -- | Primary paper states the server can elude secure aggregation as if it were not in place, regardless of the underlying SA protocol. |
| 18 | `mpaf2022` | Cao et al. | MPAF: Model Poisoning Attacks to Federated Learning Based on Fake Clients | CVPR Workshop | mpaf | krum, fedtrimmedavg, norm_bounding | -- |
| 19 | `backdoor2022` | *(unverified)* | Backdoor Attacks in Federated Learning by Rare Embeddings and Gradient Ensemb... | EMNLP | -- | -- | -- |
| 20 | `karimireddy2022` | Karimireddy et al. | Byzantine-Robust Learning on Heterogeneous Datasets via Bucketing | ICLR | alie, ipm, fang (+2) | krum, fedmedian, centered_clipping (+1) | Bucketing randomly groups clients before aggregation to reduce Byzantine influence under heterogeneous data. |
| 21 | `farhadkhani2022` | Farhadkhani et al. | Byzantine Machine Learning Made Easy By Resilient Averaging of Momentums | ICML | alie, ipm, sign_flip (+1) | krum, fedtrimmedavg, fedmedian (+1) | Resilient Averaging of Momentums (RAM) combines momentum with robust aggregation. Achieves SOTA convergence under ALIE and IPM on heterogeneous data. |
| 22 | `neurotoxin2022` | Zhang et al. | Neurotoxin: Durable Backdoors in Federated Learning | ICML | neurotoxin | krum, fedtrimmedavg, rfa (+2) | -- |
| 23 | `signguard2022` | Xu & Huang | SignGuard: Byzantine-robust FL through Collaborative Malicious Gradient Filte... | IEEE ICDCS | fang, alie, min_max (+3) | signguard, fedtrimmedavg, fedmedian (+3) | SignGuard filters by gradient sign agreement and direction. Defends against ALIE, IPM, and min-max attacks that bypass Krum and Bulyan. |
| 24 | `shejwalkar2022` | Shejwalkar et al. | Back to the Drawing Board: A Critical Evaluation of Poisoning Attacks on Prod... | IEEE S&P | min_max, min_sum, fang (+1) | krum, fedtrimmedavg, fedmedian (+2) | -- |
| 25 | `pillutla2022` | Pillutla et al. | Robust Aggregation for Federated Learning | IEEE TSP | gaussian_noise, sign_flip, label_flip | rfa, fedtrimmedavg, krum | RFA (Robust Federated Averaging) uses approximate geometric median. Tolerates up to 50% Byzantine with convergence guarantees; tested on sign-flip ... |
| 26 | `wan2022` | Wan et al. | Shielding FL: Robust Aggregation with Adaptive Client Selection (MAB-RFL) | IJCAI | byzantine | mab-rfl, krum, fedtrimmedavg | MAB-RFL uses multi-armed bandit to adaptively assign client reputation scores. Outperforms Krum and trimmed mean under Byzantine attacks with varyi... |
| 27 | `fldetector2022` | Zhang et al. | FLDetector: Defending FL Against Model Poisoning via Detecting Malicious Clients | KDD | fang, alie, dba (+1) | fldetector, fedtrimmedavg, fedmedian (+1) | FLDetector predicts expected updates and flags deviations. Detects Fang, ALIE, and DBA attacks; outperforms trimmed mean and Krum on model poisoning. |
| 28 | `deepsight2022` | Rieger et al. | DeepSight: Mitigating Backdoor Attacks in FL Through Deep Model Inspection | NDSS | backdoor, constrain_and_scale, dba | deepsight, foolsgold, krum (+1) | DeepSight inspects model weight distributions to detect backdoored updates. Detects constrain-and-scale and DBA attacks that bypass Krum and FoolsG... |
| 29 | `flame2022` | Nguyen et al. | FLAME: Taming Backdoors in Federated Learning | USENIX Security | backdoor, constrain_and_scale, dba | flame, krum, foolsgold (+2) | FLAME combines cosine-similarity clustering with adaptive noise injection. Eliminates DBA backdoor while maintaining accuracy; outperforms Krum and... |

#### 2023 (19 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 30 | `poisoning2023` | *(unverified)* | Poisoning with Cerberus: Stealthy and Colluded Backdoor Attack against Federa... | AAAI | -- | -- | -- |
| 31 | `untargeted2023` | *(unverified)* | Untargeted Attack against Federated Recommendation Systems via Poisonous Item... | AAAI | -- | -- | -- |
| 32 | `vuln_backdoor_defenses2023` | various | On the Vulnerability of Backdoor Defenses for Federated Learning | AAAI | backdoor | krum, foolsgold, flame (+1) | AAAI abstract explicitly frames the work as circumventing existing backdoor defenses. |
| 33 | `mesas2023` | Krauss & Dmitrienko | MESAS: Poisoning Defense for FL Resilient against Adaptive Attackers | ACM CCS | backdoor, constrain_and_scale, dba (+1) | mesas, foolsgold, krum (+4) | MESAS specifically targets adaptive attackers. Shows existing defenses fail against attackers that adapt; proposes moving-target defense strategy. |
| 34 | `characterizing2023` | *(unverified)* | Characterizing Internal Evasion Attacks in Federated Learning | AISTATS | -- | -- | PMLR abstract reports only limited improvement from federated adversarial training against internal evasion; personalization + adversarial training... |
| 35 | `unraveling2023` | *(unverified)* | Unraveling the Connections between Privacy and Certified Robustness in Federa... | CCS | -- | -- | -- |
| 36 | `chameleon2023` | Dai et al. | Chameleon: Adapting to Peer Images for Planting Durable Backdoors in Federate... | ICML | backdoor | krum, foolsgold, norm_bounding (+1) | -- |
| 37 | `liu2023gradsplit` | Liu et al. | Byzantine-Robust Learning on Heterogeneous Data via Gradient Splitting | ICML | alie, ipm, sign_flip | krum, fedtrimmedavg, fedmedian (+1) | Gradient splitting separates updates into magnitude and direction components. Provably robust under heterogeneous data; breaks ALIE and IPM assumpt... |
| 38 | `3dfed2023` | Lyu et al. | 3DFed: Adaptive and Extensible Framework for Covert Backdoor Attack in Federa... | IEEE S&P | 3dfed | deepsight, foolsgold, flame (+1) | Primary publication description reports evasion of multiple named defenses. |
| 39 | `fedrecover2023` | Cao et al. | FedRecover: Recovering from Poisoning Attacks in FL | IEEE S&P | fang, alie, dba (+1) | fedrecover, fedtrimmedavg, fedmedian | FedRecover identifies and removes poisoned model updates post-hoc. Recovers model accuracy after training-time poisoning without retraining from sc... |
| 40 | `denialofservice2023` | *(unverified)* | Denial-of-Service or Fine-Grained Control: Towards Flexible Model Poisoning A... | IJCAI | -- | -- | -- |
| 41 | `oblivion2023` | various | OBLIVION: Poisoning Federated Learning by Inducing Catastrophic Forgetting | INFOCOM | oblivion | krum, fedtrimmedavg | -- |
| 42 | `jmlr_attacks2023` | Moshawrab et al. | Attacks against Federated Learning Defense Systems and their Mitigation | JMLR | on_off_attack, label_flip | foolsgold, krum, fedtrimmedavg | JMLR abstract reports the attacks effectively deceive well-known FL defense systems; the paper then proposes Viceroy as mitigation. |
| 43 | `chen2023` | Chen et al. | FLRAM: Robust Aggregation for Defense against Byzantine Poisoning in FL | MDPI Electronics | gaussian_noise, sign_flip, label_flip | flram, krum, fedtrimmedavg (+1) | FLRAM scores clients on norm, direction, and sign agreement. Outperforms Krum and trimmed mean under Gaussian noise, sign-flip, and label-flip atta... |
| 44 | `a3fl2023` | Zhang et al. | A3FL: Adversarially Adaptive Backdoor Attacks to Federated Learning | NeurIPS | a3fl | krum, foolsgold, flame (+3) | NeurIPS abstract states evaluation against 12 existing defenses and stronger/persistent attack behavior. |
| 45 | `iba2023` | various | IBA: Towards Irreversible Backdoor Attacks in Federated Learning | NeurIPS | backdoor | krum, fedtrimmedavg, norm_bounding (+1) | -- |
| 46 | `backdoor2023` | *(unverified)* | Backdoor Threats from Compromised Foundation Models to Federated Learning | NeurIPS workshop | -- | -- | -- |
| 47 | `gradient2023` | *(unverified)* | Gradient Obfuscation Gives a False Sense of Security in Federated Learning | USENIX Security | -- | -- | USENIX abstract concludes common gradient post-processing defenses can provide a false sense of security against reconstruction. |
| 48 | `mozaffari2023` | Mozaffari et al. | Every Vote Counts: Ranking-Based Training of FL (FRL) | USENIX Security | min_max, min_sum, fang (+1) | krum, fedtrimmedavg | FRL ranks clients by loss improvement on validation set. Outperforms Krum and trimmed mean under min-max and ALIE attacks with up to 40% malicious. |

#### 2024 (24 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 49 | `beyond2024` | *(unverified)* | Beyond Traditional Threats: A Persistent Backdoor Attack on Federated Learning | AAAI | -- | -- | -- |
| 50 | `brdfl2024` | Fang et al. | Byzantine-Robust Decentralized FL | ACM CCS | fang, min_max, alie (+1) | brdfl, centered_clipping, dnc | Byzantine-robust decentralized FL without server. Achieves convergence under 1/3 Byzantine with gossip-based robust aggregation. |
| 51 | `boba2024` | various | BOBA: Byzantine-Robust FL with Label Skewness | AISTATS | byzantine | boba | BOBA addresses label-skewed non-IID settings where honest clients look Byzantine. Outperforms Krum and trimmed mean under severe label imbalance. |
| 52 | `distributed2024` | *(unverified)* | Distributed Backdoor Attacks on Federated Graph Learning and Certified Defenses | CCS | backdoor | -- | -- |
| 53 | `fake2024` | *(unverified)* | Fake Node-Based Perception Poisoning Attacks against Federated Object Detecti... | DAC | -- | -- | -- |
| 54 | `backdoor2024` | *(unverified)* | Backdoor Federated Learning by Poisoning Backdoor-Critical Layers | ICLR | backdoor | -- | -- |
| 55 | `like2024` | *(unverified)* | Like Oil and Water: Group Robustness Methods and Poisoning Defenses Don't Mix | ICLR | -- | -- | ICLR abstract reports poison ASR increasing from 0% to >97% in some group-robust settings and defense-induced harm to legitimate minority samples. |
| 56 | `hidra2024` | Choudhary et al. | Attacking Byzantine Robust Aggregation in High Dimensions | IEEE S&P | hidra | chunked_defenses | HIDRA shows high-dimensional robust aggregation fails when dimension >> clients. Proposes dimensionality-aware robust aggregation. |
| 57 | `layerdba2024` | Dai et al. | LayerDBA: Circumventing Similarity-Based Defenses in Federated Learning | IEEE S&P | layerdba | foolsgold | Primary research page reports circumvention of FoolsGold and Contra, including high ASR with only 5% malicious clients. |
| 58 | `blades2024` | Li et al. | Blades: A Unified Benchmark Suite for Byzantine Attacks and Defenses in FL | IEEE/ACM IoTDI | gaussian_noise, label_flip, sign_flip (+4) | krum, fedtrimmedavg, fedmedian (+2) | Unified benchmark of 6 attacks × 8 defenses across CIFAR-10/MNIST. Confirms ALIE and min-max bypass Krum; FLTrust most robust overall. |
| 59 | `badfss2024` | *(unverified)* | BADFSS: Backdoor Attacks on Federated Self-Supervised Learning | IJCAI | -- | -- | -- |
| 60 | `darkfed2024` | *(unverified)* | DarkFed: A Data-Free Backdoor Attack in Federated Learning | IJCAI | -- | -- | IJCAI abstract motivates DarkFed by showing prior attacks become stoppable under realistic settings and develops a data-free covert alternative tha... |
| 61 | `eabfl2024` | *(unverified)* | EAB-FL: Exacerbating Algorithmic Bias through Model Poisoning Attacks in Fede... | IJCAI | -- | -- | -- |
| 62 | `badsampler2024` | Liu et al. | BadSampler: Clean-Label Backdoor Attacks against FLTrust | KDD | backdoor | fltrust | BadSampler attacks FLTrust by manipulating the root dataset sampling. Achieves high backdoor ASR even with FLTrust by exploiting root data distribu... |
| 63 | `badsampler2024_2` | *(unverified)* | *BadSampler:* Harnessing the Power of Catastrophic Forgetting to Poison Byzan... | KDD | -- | -- | Primary preprint presents BadSampler specifically as poisoning Byzantine-robust FL while avoiding classic malicious-update signatures. |
| 64 | `fedsecurity2024` | Han et al. | FedSecurity: Benchmarking Attacks and Defenses in FL and Federated LLMs | KDD | byzantine, label_flip, backdoor (+1) | foolsgold, krum, bulyan (+5) | Benchmarks attacks and defenses in both FL and federated LLM fine-tuning. Shows LLM FL is more vulnerable to backdoor attacks than vision FL. |
| 65 | `navigation2024` | *(unverified)* | Navigation as Attackers Wish? Towards Building Robust Embodied Agents under F... | NAACL | -- | -- | -- |
| 66 | `autoadapt2024` | various | Automatic Adversarial Adaption for Stealthy Poisoning Attacks in Federated Le... | NDSS | autoadapt | krum, fedtrimmedavg, fedmedian (+1) | NDSS abstract frames a unified strong adaptive attacker specifically designed to challenge multiple defense metrics simultaneously. |
| 67 | `freqfed2024` | Fereidooni et al. | FreqFed: Frequency Analysis-Based Approach for Mitigating Poisoning | NDSS | label_flip, backdoor, constrain_and_scale (+1) | freqfed, krum, fedmedian (+3) | FreqFed analyzes model updates in the frequency domain. Detects backdoor patterns invisible in weight space; outperforms FLAME and DeepSight. |
| 68 | `rflpa2024` | various | RFLPA: A Robust FL Framework against Poisoning Attacks | NeurIPS | fang, min_max, min_sum (+2) | rflpa, krum, fedtrimmedavg (+2) | RFLPA combines reputation scoring with adaptive penalty. Outperforms FLTrust and MAB-RFL under multi-round persistent attacks. |
| 69 | `badvfl2024` | *(unverified)* | BadVFL: Backdoor Attacks in Vertical Federated Learning | S&P | -- | -- | -- |
| 70 | `revisit2024` | *(unverified)* | Revisit Targeted Model Poisoning on Federated Recommendation: Optimize via Mu... | SIGIR | -- | -- | -- |
| 71 | `ace2024` | *(unverified)* | ACE: A Model Poisoning Attack on Contribution Evaluation Methods in Federated... | USENIX Security | -- | -- | USENIX abstract reports deception of five SOTA contribution-evaluation methods and finds six explored countermeasures inadequate. |
| 72 | `lurking2024` | *(unverified)* | Lurking in the shadows: Unveiling Stealthy Backdoor Attacks against Personali... | USENIX Security | -- | -- | -- |

#### 2025 (20 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 73 | `labelfree2025` | Wei Shen; Wenke Huang; Guancheng Wan; Mang Ye | Label-Free Backdoor Attacks in Vertical Federated Learning | AAAI | -- | -- | -- |
| 74 | `rethinking2025` | *(unverified)* | Rethinking Byzantine Robustness in Federated Recommendation from Sparse Aggre... | AAAI | -- | -- | AAAI abstract reports the attack family can break down defenses with a small number of malicious clients. |
| 75 | `sadba2025` | Jun Feng; Yuzhe Lai; Hong Sun; Bocheng Ren | SADBA: Self-Adaptive Distributed Backdoor Attack Against Federated Learning | AAAI | backdoor, fang | -- | Primary AAAI abstract reports SADBA achieves higher or comparable backdoor performance and main-task accuracy across various datasets with limited ... |
| 76 | `strike2025` | various | Exploit Gradient Skewness to Circumvent Byzantine Defenses for Federated Lear... | AAAI | strike | krum, fedtrimmedavg, fedmedian (+1) | AAAI/Sony primary descriptions state that STRIKE deceives existing Byzantine defenses by exploiting gradient skewness. |
| 77 | `hyperparameters2025` | Simon Lachnit; Ghassan Karame | On Hyperparameters and Backdoor-Resistance in Horizontal Federated Learning | CCS | -- | -- | Reports that proper benign hyperparameter tuning can reduce the 50%-lifespan of A3FL by 98.6% without a defense, with a 2.9 percentage-point clean-... |
| 78 | `infighting2025` | Ye Li; Yanchao Zhao; Chengcheng Zhu; Jiale Zhang | Infighting in the Dark: Multi-Label Backdoor Attack in Federated Learning | CVPR | backdoor | -- | Primary CVPR abstract reports average ASR >97% and >90% ASR after 900 rounds while bypassing existing defenses. |
| 79 | `model2025` | Yueqi Xie; Minghong Fang; Neil Zhenqiang Gong | Model Poisoning Attacks to Federated Learning via Multi-Round Consistency | CVPR | poisonedfl | -- | Primary CVPR paper reports PoisonedFL breaks 8 SOTA defenses and outperforms 7 existing model-poisoning attacks on 5 benchmark datasets. |
| 80 | `poisonedfl2025` | Xie et al. | Model Poisoning Attacks to FL via Multi-Round Consistency | CVPR | poisonedfl, fang, alie (+2) | krum, fedmedian, fedtrimmedavg (+3) | PoisonedFL exploits multi-round consistency to bypass FLTrust and FoolsGold. Gradually shifts model over multiple rounds to evade per-round detection. |
| 81 | `badpfl2025` | Mingyuan Fan; Zhanyi Hu; Fuyi Wang; Cen Chen | Bad-PFL: Exploiting Backdoor Attacks against Personalized Federated Learning | ICLR | backdoor | -- | Primary ICLR abstract reports superior attack performance across 3 benchmark datasets and multiple PFL methods, including methods equipped with SOT... |
| 82 | `backdoor2025` | Jirui Yang; Peng Chen; Zhihui Lu; Jianping Zeng; Qiang Duan; Xin Du; Ruijun Deng | Backdoor Attack on Vertical Federated Graph Neural Network Learning | IJCAI | backdoor | -- | Primary IJCAI abstract reports nearly 100% ASR across 3 datasets and 3 GNN models with minimal main-task impact, remaining effective under evaluate... |
| 83 | `performance2025` | *(unverified)* | Performance Guaranteed Poisoning Attacks in Federated Learning: A Sliding Mod... | IJCAI | -- | -- | -- |
| 84 | `foundationfl2025` | Fang et al. | Do We Really Need to Design New Byzantine-robust Aggregation Rules? | NDSS | fang, min_max, min_sum (+1) | foundationfl, krum, foolsgold (+3) | Questions necessity of complex aggregation rules; shows simple defenses with proper hyperparameters match or exceed Krum, Bulyan, and FLTrust. |
| 85 | `practical2025` | *(unverified)* | Practical Poisoning Attacks with Limited Byzantine Clients in Clustered Feder... | S&P | -- | -- | -- |
| 86 | `poisafl2025` | various | PoiSAFL: Scalable Poisoning Attack Framework to Byzantine-resilient Semi-asyn... | USENIX Security | poisafl | krum, fedtrimmedavg, fedmedian | USENIX abstract states PoiSAFL bypasses three typical categories of Byzantine-resilient defenses. |
| 87 | `lasa2025` | Xu et al. | Achieving Byzantine-Resilient FL via Layer-Adaptive Sparsified Model Aggregation | WACV | gaussian_noise, sign_flip, min_max (+2) | lasa, fedtrimmedavg, rfa (+4) | Layer-adaptive sparsification aggregates only important parameters per layer. Robust to model poisoning while preserving accuracy under non-IID. |
| 88 | `nigdba2025` | *(unverified)* | NI-GDBA: Non-Intrusive Distributed Backdoor Attack Based on Adaptive Perturba... | WWW | -- | -- | -- |
| 89 | `backfed2025` | Dao et al. | BackFed: An Efficient & Standardized Benchmark Suite for Backdoor Attacks in FL | arXiv | neurotoxin, backdoor, dba (+1) | fedtrimmedavg, krum, rfa (+5) | Standardized backdoor benchmark for FL. Shows constrain-and-scale and DBA bypass most defenses; only FLAME and frequency-based methods partially su... |
| 90 | `byzfl2025` | Garcia et al. | ByzFL: Research Framework for Robust Federated Learning | arXiv | sign_flip, label_flip, ipm (+1) | krum, fedtrimmedavg, fedmedian (+2) | ByzFL framework for systematic evaluation of Byzantine-robust FL. Reproduces and compares 8 defenses under standardized conditions. |
| 91 | `flpoison2025` | Zhang et al. | SoK: Benchmarking Poisoning Attacks and Defenses in Federated Learning | arXiv | gaussian_noise, sign_flip, alie (+11) | krum, bulyan, fedtrimmedavg (+10) | SoK benchmarking 12 attacks × 10 defenses on 4 datasets. Finds no single defense robust to all attacks; ALIE and adaptive attacks most effective ov... |
| 92 | `stealthy2025` | Qingqian Yang; Peishen Yan; Xiaoyu Wu; Jiaru Zhang; Tao Song; Yang Hua; Hao Wang; Liangliang Wang; Haibing Guan | Stealthy Backdoor Attack in Federated Learning via Adaptive Layer-Wise Gradie... | iccv | backdoor | -- | Primary ICCV abstract reports bypass of 8 SOTA defenses and improvement over existing attacks by up to 54.76%. |

#### 2026 (4 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 93 | `breaking2026` | Jarin Tasneem | Breaking Cross-View Associations: Byzantine Model Poisoning Attack against Ve... | AAAI | -- | -- | -- |
| 94 | `goodgradients2026` | various | Good Gradients Poison Your Model: Evading Defenses in Federated Learning via ... | AAAI | good_gradients | fltrust, krum, fedtrimmedavg (+1) | Primary abstract describes evasion across mainstream defensive mechanisms by crafting seemingly benign malicious gradients. |
| 95 | `pill2026` | various | Poisoning with a Pill: Circumventing Detection in Federated Learning | AAAI | pill | krum, fedtrimmedavg, fedmedian (+5) | AAAI abstract reports bypassing 8 SOTA defenses, up to 7× error-rate increase and >2× average increase, across IID/non-IID and cross-silo/cross-dev... |
| 96 | `dynamic2026` | *(unverified)* | Dynamic Min-Max Multi-Dimensional Reinforcement Backdoor Attacks and Orchestr... | WWW | -- | -- | -- |

### 8.2 Out-of-Scope Papers: Privacy, Inference, Other FL Security (109 papers)

These papers cover FL security topics outside Byzantine robustness (gradient inversion, membership inference, free-riding, etc.). Included in the KB for completeness — the framework does not compare findings against these.

#### 2017 (1 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 97 | `deep2017` | *(unverified)* | Deep Models Under the GAN: Information Leakage from Collaborative Deep Learning | CCS | -- |

#### 2019 (3 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 98 | `beyond2019` | *(unverified)* | Beyond Inferring Class Representatives: User-Level Privacy Leakage From Feder... | INFOCOM | -- |
| 99 | `comprehensive2019` | *(unverified)* | Comprehensive Privacy Analysis of Deep Learning: Passive and Active White-box... | S&P | -- |
| 100 | `exploiting2019` | *(unverified)* | Exploiting Unintended Feature Leakage in Collaborative Learning | S&P | -- |

#### 2020 (1 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 101 | `inverting2020` | *(unverified)* | Inverting Gradients - How easy is it to break privacy in federated learning? | NeurIPS | -- |

#### 2021 (6 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 102 | `freerider2021` | *(unverified)* | Free-rider Attacks on Model Aggregation in Federated Learning | AISTATS | -- |
| 103 | `feature2021` | *(unverified)* | Feature Inference Attack on Model Predictions in Vertical Federated Learning | ICDE | -- |
| 104 | `gradient2021` | *(unverified)* | Gradient Disaggregation: Breaking Privacy in Federated Learning by Reconstruc... | ICML | -- |
| 105 | `cafe2021` | *(unverified)* | CAFE: Catastrophic Data Leakage in Vertical Federated Learning | NeurIPS | -- |
| 106 | `evaluating2021` | *(unverified)* | Evaluating Gradient Inversion Attacks and Defenses in Federated Learning | NeurIPS | -- |
| 107 | `gradient2021_2` | *(unverified)* | Gradient Inversion with Generative Image Prior | NeurIPS | -- |

#### 2022 (11 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 108 | `auditing2022` | *(unverified)* | Auditing Privacy Defenses in Federated Learning via Generative Gradient Leakage | CVPR | CVPR abstract reports leakage despite commonly used additive-noise and compression defenses. |
| 109 | `gradvit2022` | *(unverified)* | GradViT: Gradient Inversion of Vision Transformers | CVPR | -- |
| 110 | `fedrecattack2022` | *(unverified)* | FedRecAttack: Model Poisoning Attack to Federated Recommendation | ICDE | -- |
| 111 | `bayesian2022` | *(unverified)* | Bayesian Framework for Gradient Leakage | ICLR | -- |
| 112 | `robbing2022` | *(unverified)* | Robbing the Fed: Directly Obtaining Private Data in Federated Learning with M... | ICLR | -- |
| 113 | `poisoning2022` | *(unverified)* | Poisoning Deep Learning Based Recommender Model in Federated Learning Scenarios | IJCAI | -- |
| 114 | `survey2022` | *(unverified)* | A Survey on Gradient Inversion: Attacks, Defenses and Future Directions | IJCAI | -- |
| 115 | `fedattack2022` | *(unverified)* | FedAttack: Effective and Covert Poisoning Attack on Federated Recommendation ... | KDD | -- |
| 116 | `learning2022` | *(unverified)* | Learning to Attack Federated Learning: A Model-based Reinforcement Learning A... | NeurIPS | -- |
| 117 | `label2022` | *(unverified)* | Label Inference Attacks Against Vertical Federated Learning | USENIX Security | -- |
| 118 | `pipattack2022` | *(unverified)* | PipAttack: Poisoning Federated Recommender Systems for Manipulating Item Prom... | WSDM | -- |

#### 2023 (27 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 119 | `mgia2023` | *(unverified)* | MGIA: Mutual Gradient Inversion Attack in Multi-Modal Federated Learning (Stu... | AAAI | -- |
| 120 | `active2023` | *(unverified)* | Active Membership Inference Attack under Local Differential Privacy in Federa... | AISTATS | PMLR abstract reports very high attack success under rigorous LDP; noise sufficient to suppress the attack significantly degrades utility. |
| 121 | `explaining2023` | *(unverified)* | Explaining predictions and attacks in federated learning via random forests | Appl. Intell. | -- |
| 122 | `turning2023` | *(unverified)* | Turning Privacy-preserving Mechanisms against Federated Learning | CCS | Primary TU Delft description reports deception of SOTA defenses, ~60% performance detriment in adversarial mode, and effective backdoors in 93% of ... |
| 123 | `resource2023` | *(unverified)* | The Resource Problem of Using Linear Layer Leakage Attack in Federated Learning | CVPR | -- |
| 124 | `generative2023` | *(unverified)* | Generative Gradient Inversion via Over-Parameterized Networks in Federated Le... | ICCV | -- |
| 125 | `gifd2023` | *(unverified)* | GIFD: A Generative Gradient Inversion Method with Feature Domain Optimization | ICCV | -- |
| 126 | `federated2023` | *(unverified)* | Federated IoT Interaction Vulnerability Analysis | ICDE | -- |
| 127 | `decepticons2023` | *(unverified)* | Decepticons: Corrupted Transformers Breach Privacy in Federated Learning for ... | ICLR | -- |
| 128 | `effective2023` | *(unverified)* | Effective passive membership inference attacks in federated learning against ... | ICLR | -- |
| 129 | `instancewise2023` | *(unverified)* | Instance-wise Batch Label Restoration via Gradients in Federated Learning | ICLR | -- |
| 130 | `cocktail2023` | *(unverified)* | Cocktail Party Attack: Breaking Aggregation-Based Privacy in Federated Learni... | ICML | PMLR abstract reports recovery from aggregated gradients at large batch sizes, including up to 1024. |
| 131 | `sratta2023` | *(unverified)* | SRATTA: Sample Re-ATTribution Attack of Secure Aggregation in Federated Learning | ICML | PMLR abstract states the attack effectively breaks the privacy offered by secure aggregation through sample re-attribution. |
| 132 | `surrogate2023` | *(unverified)* | Surrogate Model Extension (SME): A Fast and Accurate Weight Update Attack on ... | ICML | -- |
| 133 | `tableak2023` | *(unverified)* | TabLeak: Tabular Data Leakage in Federated Learning | ICML | -- |
| 134 | `graphfraudster2023` | *(unverified)* | Graph-Fraudster: Adversarial Attacks on Graph Neural Network Based Vertical F... | IEEE Trans. Comput. Soc. Syst. | -- |
| 135 | `uafedrec2023` | *(unverified)* | UA-FedRec: Untargeted Attack on Federated News Recommendation | KDD | -- |
| 136 | `ppa2023` | *(unverified)* | PPA: Preference Profiling Attack Against Federated Learning | NDSS | -- |
| 137 | `understanding2023` | *(unverified)* | Understanding Deep Gradient Leakage via Inversion Influence Functions | NeurIPS | -- |
| 138 | `absolute2023` | *(unverified)* | Absolute Variation Distance: an Inversion Attack Evaluation Metric for Federa... | NeurIPS workshop | -- |
| 139 | `beyond2023` | *(unverified)* | Beyond Gradient and Priors in Privacy Attacks: Leveraging Pooler Layer Inputs... | NeurIPS workshop | -- |
| 140 | `exploring2023` | *(unverified)* | Exploring User-level Gradient Inversion with a Diffusion Prior | NeurIPS workshop | -- |
| 141 | `user2023` | *(unverified)* | User Inference Attacks on Large Language Models | NeurIPS workshop | -- |
| 142 | `manipulating2023` | *(unverified)* | Manipulating Federated Recommender Systems: Poisoning with Synthetic Users an... | SIGIR | -- |
| 143 | `learning2023` | *(unverified)* | Learning To Invert: Simple Adaptive Attacks for Gradient Inversion in Federat... | UAI | -- |
| 144 | `agrevader2023` | *(unverified)* | AgrEvader: Poisoning Membership Inference against Byzantine-robust Federated ... | WWW | Primary institutional abstract reports coordinate-wise averaging defenses fail against PMIA and AgrEvader circumvents detection; reported attack ac... |
| 145 | `interactionlevel2023` | *(unverified)* | Interaction-level Membership Inference Attack Against Federated Recommender S... | WWW | -- |

#### 2024 (25 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 146 | `adversarial2024` | *(unverified)* | Adversarial Attacks on Federated-Learned Adaptive Bitrate Algorithms | AAAI | -- |
| 147 | `foreseeing2024` | *(unverified)* | Foreseeing Reconstruction Quality of Gradient Inversion: An Optimization Pers... | AAAI | -- |
| 148 | `highfidelity2024` | *(unverified)* | High-Fidelity Gradient Inversion in Distributed Learning | AAAI | -- |
| 149 | `analysis2024` | *(unverified)* | Analysis of Privacy Leakage in Federated Large Language Models | AISTATS | -- |
| 150 | `not2024` | *(unverified)* | Not One Less: Exploring Interplay between User Profiles and Items in Untarget... | CCS | -- |
| 151 | `uncovering2024` | *(unverified)* | Uncovering Gradient Inversion Risks in Practical Language Model Training | CCS | -- |
| 152 | `leak2024` | *(unverified)* | Leak and Learn: An Attacker's Cookbook to Train Using Leaked Data from Federa... | CVPR | -- |
| 153 | `the2024` | *(unverified)* | On the Efficiency of Privacy Attacks in Federated Learning | CVPR workshop | -- |
| 154 | `fedinverse2024` | *(unverified)* | FedInverse: Evaluating Privacy Leakage in Federated Learning | ICLR | -- |
| 155 | `hiding2024` | *(unverified)* | Hiding in Plain Sight: Disguising Data Stealing Attacks in Federated Learning | ICLR | ICLR abstract reports data stealing for batch sizes up to 512 and under secure aggregation while meeting stated detectability requirements. |
| 156 | `towards2024` | *(unverified)* | Towards Eliminating Hard Label Constraints in Gradient Inversion Attacks | ICLR | -- |
| 157 | `breaking2024` | *(unverified)* | Breaking Secure Aggregation: Label Leakage from Aggregated Gradients in Feder... | INFOCOM | Primary preprint abstract reports bypassing secure aggregation and 100% label recovery across evaluated datasets/architectures. |
| 158 | `data2024` | *(unverified)* | A Data Reconstruction Attack Against Vertical Federated Learning Based on Kno... | INFOCOM | -- |
| 159 | `ganbased2024` | *(unverified)* | GAN-Based Privacy Abuse Attack on Federated Learning in IoT Networks | INFOCOM | -- |
| 160 | `fedsecurity2024_2` | *(unverified)* | FedSecurity: A Benchmark for Attacks and Defenses in Federated Learning and F... | KDD | -- |
| 161 | `dager2024` | *(unverified)* | DAGER: Exact Gradient Inversion for Large Language Models | NeurIPS | -- |
| 162 | `datastealing2024` | *(unverified)* | DataStealing: Steal Data from Diffusion Models in Federated Learning with Mul... | NeurIPS | -- |
| 163 | `freerider2024` | *(unverified)* | Free-Rider and Conflict Aware Collaboration Formation for Cross-Silo Federate... | NeurIPS | -- |
| 164 | `spear2024` | *(unverified)* | SPEAR: Exact Gradient Inversion of Batches in Federated Learning | NeurIPS | -- |
| 165 | `loki2024` | *(unverified)* | Loki: Large-scale Data Reconstruction Attack against Federated Learning throu... | S&P | -- |
| 166 | `gradient2024` | *(unverified)* | Gradient Inversion Attacks: Impact Factors Analyses and Privacy Enhancement | TPAMI | -- |
| 167 | `impact2024` | *(unverified)* | The Impact of Adversarial Attacks on Federated Learning: A Survey | TPAMI | -- |
| 168 | `federated2024` | *(unverified)* | Federated Learning Vulnerabilities: Privacy Attacks with Denoising Diffusion ... | WWW | -- |
| 169 | `poisoning2024` | *(unverified)* | Poisoning Attack on Federated Knowledge Graph Embedding | WWW | -- |
| 170 | `poisoning2024_2` | *(unverified)* | Poisoning Federated Recommender Systems with Fake Users | WWW | -- |

#### 2025 (26 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 171 | `attribute2025` | Francesco Diana; Othmane Marfoq; Chuan Xu; Giovanni Neglia; Frédéric Giroire; Eoin Thomas | Attribute Inference Attacks for Federated Regression Tasks | AAAI | -- |
| 172 | `personalized2025` | Hanyu Zhao; Zijie Pan; Yajie Wang; Zuobin Ying; Lei Xu; Yu-an Tan | Personalized Label Inference Attack in Federated Transfer Learning via Contra... | AAAI | -- |
| 173 | `gradient2025` | Ying Gao; Yuxin Xie; Huanghao Deng; Zukun Zhu | Gradient Inversion Attack in Federated Learning: Exposing Text Data through D... | COLING | Across three datasets, exact-match rate improves on average by 39% for TinyBERT-6, 20% for BERT-base, and 15% for BERT-large over the compared sett... |
| 174 | `fedmia2025` | Gongxi Zhu; Donghao Li; Hanlin Gu; Yuan Yao; Lixin Fan; Yuxing Han | FedMIA: An Effective Membership Inference Attack Exploiting "All for One" Pri... | CVPR | Primary CVPR abstract reports FedMIA outperforms existing MIAs in classification and generative tasks and remains robust across defense strategies,... |
| 175 | `gradient2025_3` | *(unverified)* | Gradient Inversion Attacks on Parameter-Efficient Fine-Tuning | CVPR | -- |
| 176 | `can2025` | Wenkai Guo; Xuefeng Liu; Haolin Wang; Jianwei Niu; Shaojie Tang; Jing Yuan | Can Federated Learning Safeguard Private Data in LLM Training? Vulnerabilitie... | EMNLP | ACL paper evaluates multiple privacy defenses and documents persistent FL-LLM privacy vulnerabilities. |
| 177 | `emerging2025` | Rui Ye; Jingyi Chai; Xiangrui Liu; Yaodong Yang; Yanfeng Wang; Siheng Chen | Emerging Safety Attack and Defense in Federated Instruction Tuning of Large L... | ICLR | Primary ICLR abstract reports up to a 70% safety-rate reduction; existing defenses improve safety by at most 4 percentage points, while the propose... |
| 178 | `grain2025` | *(unverified)* | GRAIN: Exact Graph Reconstruction from Gradients | ICLR | -- |
| 179 | `gradient2025_2` | Omri Ben Hemo; Alon Zolfi; Oryan Yehezkel; Omer Hofman; Roman Vainshtein; Hisashi Kojima; Yuval Elovici; Asaf Shabtai | Gradient Inversion of Multimodal Models | ICML | -- |
| 180 | `theoretically2025` | Quan Minh Nguyen; Minh N. Vu; Truc Nguyen; My T. Thai | Theoretically Unmasking Inference Attacks Against LDP-Protected Clients in Fe... | ICML | Primary ICML page reports persistent privacy risk under LDP; noise sufficient to mitigate the attacks significantly degrades model utility. |
| 181 | `generic2025` | *(unverified)* | Generic Adversarial Attack Framework Against Vertical Federated Learning | IJCAI | -- |
| 182 | `mmgia2025` | *(unverified)* | MMGIA: Gradient Inversion Attack Against Multimodal Federated Learning via In... | IJCAI | -- |
| 183 | `where2025` | *(unverified)* | Where Does This Data Come From? Enhanced Source Inference Attacks in Federate... | IJCAI | -- |
| 184 | `preference2025` | *(unverified)* | Preference Profiling Attacks Against Vertical Federated Learning Over Graph Data | INFOCOM | -- |
| 185 | `vanikg2025` | *(unverified)* | VaniKG: Vanishing Key Gradient Attack and Defense for Robust Federated Aggreg... | INFOCOM | -- |
| 186 | `raifle2025` | *(unverified)* | RAIFLE: Reconstruction Attacks on Interaction-based Federated Learning with A... | NDSS | -- |
| 187 | `scalemia2025` | *(unverified)* | Scale-MIA: A Scalable Model Inversion Attack against Secure Federated Learnin... | NDSS | Primary research description reports reconstruction of local samples despite robust secure aggregation. |
| 188 | `urvfl2025` | *(unverified)* | URVFL: Undetectable Data Reconstruction Attack on Vertical Federated Learning | NDSS | -- |
| 189 | `cutting2025` | *(unverified)* | Cutting Through Privacy: A Hyperplane-Based Data Reconstruction Attack in Fed... | UAI | -- |
| 190 | `sok2025` | *(unverified)* | SoK: Gradient Inversion Attacks in Federated Learning | USENIX Security | -- |
| 191 | `sok2025_2` | *(unverified)* | SoK: On Gradient Leakage in Federated Learning | USENIX Security | -- |
| 192 | `poisoning2025` | *(unverified)* | Poisoning Attacks and Defenses to Federated Unlearning | WWW | ACM abstract reports BadUnlearn compromises existing federated-unlearning methods; the same paper proposes UnlearnGuard as a stronger defense. |
| 193 | `selfcomparison2025` | *(unverified)* | Self-Comparison for Dataset-Level Membership Inference in Large (Vision-)Lang... | WWW | -- |
| 194 | `find2025` | Wenjin Mo; Zhiyuan Li; Minghong Fang; Mingwei Fang | Find a Scapegoat: Poisoning Membership Inference Attack and Defense to Federa... | iccv | Primary ICCV abstract reports effectiveness across various datasets and that the proposed defense reduces the attack's impact to a degree. |
| 195 | `geminio2025` | Junjie Shan; Ziqi Zhao; Jialin Lu; Rui Zhang; Siu Ming Yiu; Ka-Ho Chow | Geminio: Language-Guided Gradient Inversion Attacks in Federated Learning | iccv | Primary ICCV abstract reports high-success targeted reconstruction across complex datasets and large batch sizes, with resilience against existing ... |
| 196 | `hfia2025` | *(unverified)* | HFIA: a parasitic feature inference attack and gradient-based defense strateg... | machine learning | -- |

#### 2026 (9 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 197 | `generic2026` | Yimin Liu; Peng Jiang; Qi Liu; Liehuang Zhu | Generic Adversarial Attack Framework Against Graph-based Vertical Federated L... | AAAI | -- |
| 198 | `retaliatory2026` | Xinyi Sheng; Wei Bao; Hequn Wang; Yuqin Liu; Sen Fu | Retaliatory Attacks Against Federated Unlearning via Data Leakage | AAAI | AAAI abstract reports attacks across varied federated-unlearning methods and demonstrates leakage/manipulation caused by the unlearning process. |
| 199 | `shadeedit2026` | Xu Zhang; Hangcheng Liu; Shangwei Guo; Shudong Zhang; Tianwei Zhang; Tao Xiang | ShadeEdit: A Utility-Preserving and Defense-Evasive Knowledge Manipulation At... | AAAI | AAAI abstract reports average 99.5% attack success across eight robust aggregation algorithms while maintaining instruction-following accuracy. |
| 200 | `venom2026` | B. Hu; J. Yuan; J. Jiang; C. Hu | Venom: Liquid Diffusion-Guided Gradient Inversion for Breaking Differential P... | AAAI | AAAI abstract reports high-fidelity recovery under strong DP and up to 38,343× speedup over prior approaches. |
| 201 | `exploring2026` | Pengxin Guo; Runxi Wang; Shuang Zeng; Jinjing Zhu; Haoning Jiang; Yanran Wang; Yuyin Zhou; Feifei Wang; Hui Xiong; Liangqiong Qu | Exploring the Vulnerabilities of Federated Learning: A Deep Dive Into Gradien... | TPAMI | -- |
| 202 | `beyond2026` | Zhihao Chen; Zirui Gong; Jianting Ning; Yanjun Zhang; Leo Yu Zhang | Beyond Denial-of-Service: The Puppeteer's Attack for Fine-Grained Control in ... | WWW | -- |
| 203 | `reconstructing2026` | *(unverified)* | Reconstructing Training Data from Adapter-based Federated Large Language Models | WWW | -- |
| 204 | `spattack2026` | Bo Yan; Yurong Hao; Dingqi Liu; Huabin Sun; Pengpeng Qiao; Wei Yang Bryan Lim; Yang Cao; Chuan Shi | Spattack: Subgroup Poisoning Attacks on Federated Recommender Systems | WWW | -- |
| 205 | `unveiling2026` | *(unverified)* | Unveiling and Mitigating Untargeted Poisoning Attacks on Federated Knowledge ... | WWW | -- |

**Total: 205 papers — 96 in-scope (Byzantine FL robustness) + 109 out-of-scope (broader FL security)**

### 8.3 Known Vulnerability Pairs (99 entries)

Pre-cataloged attack-defense combinations from the literature. The framework uses these to classify a finding as [KNOWN] when the same attack-defense pair has been tested before.

| # | Attack | Defense | Source Paper | Notes |
|---|--------|---------|-------------|-------|
| 1 | alie | krum | `--` |  |
| 2 | alie | bulyan | `--` |  |
| 3 | alie | fedtrimmedavg | `--` |  |
| 4 | alie | fedmedian | `--` |  |
| 5 | alie | fltrust | `--` |  |
| 6 | fang | krum | `--` |  |
| 7 | fang | bulyan | `--` |  |
| 8 | fang | fedtrimmedavg | `--` |  |
| 9 | fang | fedmedian | `--` |  |
| 10 | fang | fltrust | `--` |  |
| 11 | min_max | krum | `--` |  |
| 12 | min_max | bulyan | `--` |  |
| 13 | min_max | fedtrimmedavg | `--` |  |
| 14 | min_max | fedmedian | `--` |  |
| 15 | min_max | fltrust | `--` |  |
| 16 | min_sum | krum | `--` |  |
| 17 | min_sum | bulyan | `--` |  |
| 18 | min_sum | fedtrimmedavg | `--` |  |
| 19 | min_sum | fedmedian | `--` |  |
| 20 | ipm | krum | `--` |  |
| 21 | ipm | fedtrimmedavg | `--` |  |
| 22 | ipm | fedmedian | `--` |  |
| 23 | ipm | bulyan | `--` |  |
| 24 | sign_flip | krum | `--` |  |
| 25 | sign_flip | fedtrimmedavg | `--` |  |
| 26 | sign_flip | fedmedian | `--` |  |
| 27 | sign_flip | fltrust | `--` |  |
| 28 | gaussian_noise | krum | `--` |  |
| 29 | gaussian_noise | fedtrimmedavg | `--` |  |
| 30 | gaussian_noise | fedmedian | `--` |  |
| 31 | gaussian_noise | fltrust | `--` |  |
| 32 | label_flip | krum | `--` |  |
| 33 | label_flip | fedtrimmedavg | `--` |  |
| 34 | label_flip | fedmedian | `--` |  |
| 35 | label_flip | fltrust | `--` |  |
| 36 | label_flip | foolsgold | `--` |  |
| 37 | backdoor | krum | `--` |  |
| 38 | backdoor | fedtrimmedavg | `--` |  |
| 39 | backdoor | fedmedian | `--` |  |
| 40 | backdoor | fltrust | `--` |  |
| 41 | backdoor | foolsgold | `--` |  |
| 42 | poisonedfl | krum | `--` |  |
| 43 | poisonedfl | fedtrimmedavg | `--` |  |
| 44 | poisonedfl | fedmedian | `--` |  |
| 45 | poisonedfl | fltrust | `--` |  |
| 46 | dba | krum | `--` |  |
| 47 | constrain_and_scale | flame | `--` |  |
| 48 | constrain_and_scale | foolsgold | `--` |  |
| 49 | neurotoxin | krum | `--` |  |
| 50 | neurotoxin | foolsgold | `--` |  |
| 51 | edge_case | krum | `--` |  |
| 52 | gaussian_noise | bulyan | `--` |  |
| 53 | sign_flip | bulyan | `--` |  |
| 54 | label_flip | bulyan | `--` |  |
| 55 | gaussian_noise | foolsgold | `--` |  |
| 56 | sign_flip | foolsgold | `--` |  |
| 57 | alie | foolsgold | `--` |  |
| 58 | gaussian_noise | dnc | `--` |  |
| 59 | alie | dnc | `--` |  |
| 60 | alie | centered_clipping | `--` |  |
| 61 | ipm | centered_clipping | `--` |  |
| 62 | gaussian_noise | rfa | `--` |  |
| 63 | sign_flip | rfa | `--` |  |
| 64 | fang | dnc | `--` |  |
| 65 | min_max | dnc | `--` |  |
| 66 | fang | foolsgold | `--` |  |
| 67 | alie | signguard | `--` |  |
| 68 | fang | signguard | `--` |  |
| 69 | gaussian_noise | flram | `--` |  |
| 70 | sign_flip | flram | `--` |  |
| 71 | label_flip | flram | `--` |  |
| 72 | backdoor | flame | `--` |  |
| 73 | dba | flame | `--` |  |
| 74 | backdoor | deepsight | `--` |  |
| 75 | backdoor | norm_bounding | `--` |  |
| 76 | gaussian_noise | norm_bounding | `--` |  |
| 77 | label_flip | krum | `--` |  |
| 78 | gaussian_noise | fltrust | `--` |  |
| 79 | sign_flip | fltrust | `--` |  |
| 80 | label_flip | fltrust | `--` |  |
| 81 | fang | fltrust | `--` |  |
| 82 | 3dfed | foolsgold | `--` |  |
| 83 | 3dfed | deepsight | `--` |  |
| 84 | 3dfed | flame | `--` |  |
| 85 | 3dfed | fldetector | `--` |  |
| 86 | layerdba | foolsgold | `--` |  |
| 87 | a3fl | krum | `--` |  |
| 88 | a3fl | foolsgold | `--` |  |
| 89 | a3fl | flame | `--` |  |
| 90 | on_off_attack | foolsgold | `--` |  |
| 91 | strike | krum | `--` |  |
| 92 | strike | fedtrimmedavg | `--` |  |
| 93 | strike | fedmedian | `--` |  |
| 94 | autoadapt | krum | `--` |  |
| 95 | autoadapt | fedtrimmedavg | `--` |  |
| 96 | pill | krum | `--` |  |
| 97 | pill | fedtrimmedavg | `--` |  |
| 98 | good_gradients | fltrust | `--` |  |
| 99 | poisafl | krum | `--` |  |

**Total: 99 known vulnerability pairs**
