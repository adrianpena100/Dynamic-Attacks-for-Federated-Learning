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
| Pillutla 2022 (RFA) | https://arxiv.org/abs/1912.13445 |
| Karimireddy 2021 (CenteredClipping) | https://arxiv.org/abs/2012.10333 |
| Nguyen 2022 (FLAME) | https://www.usenix.org/conference/usenixsecurity22/presentation/nguyen |
| Karimireddy 2022 (Bucketing) | https://arxiv.org/abs/2006.09365 |
| Farhadkhani 2022 (RESAM) | https://arxiv.org/abs/2205.12173 |
| Shejwalkar 2021 (DnC) | https://github.com/vrt1shjwlkr/NDSS21-Model-Poisoning |

### Key Attack Papers

| Paper | Link |
|-------|------|
| Baruch 2019 (ALIE) | https://arxiv.org/abs/1902.06156 |
| Fang 2020 (Local Model Poisoning) | https://www.usenix.org/conference/usenixsecurity20/presentation/fang |
| Xie 2019 (IPM) | https://arxiv.org/abs/1903.03936 |
| Bagdasaryan 2020 (Backdoor) | https://proceedings.mlr.press/v108/bagdasaryan20a.html |
| Xie 2020 (DBA) | https://openreview.net/forum?id=rkgyS0VFvr |
| Wang 2020 (Edge-case) | https://arxiv.org/abs/2007.05084 |
| Zhang 2022 (Neurotoxin) | https://arxiv.org/abs/2206.10341 |
| Xie 2025 (PoisonedFL) | https://arxiv.org/abs/2404.15611 |
| Shejwalkar 2022 (Back to Drawing Board) | https://arxiv.org/abs/2108.10241 |

### Security Conference Papers

| Paper | Link |
|-------|------|
| Mozaffari 2023 (FRL) | https://www.usenix.org/conference/usenixsecurity23/presentation/mozaffari |
| Krauss 2023 (MESAS) | https://dl.acm.org/doi/10.1145/3576915.3623212 |
| Rieger 2022 (DeepSight) | https://arxiv.org/abs/2201.00763 |
| Fereidooni 2024 (FreqFed) | https://arxiv.org/abs/2312.04432 |
| Fang 2025 (FoundationFL) | https://arxiv.org/abs/2501.17381 |
| Lycklama 2023 (RoFL) | https://arxiv.org/abs/2107.03311 |
| Cao 2023 (FedRecover) | https://arxiv.org/abs/2210.10936 |
| Choudhary 2024 (HIDRA) | https://arxiv.org/abs/2312.14461 |
| Fang 2024 (BRDFL) | https://arxiv.org/abs/2406.10416 |
| Zhang 2022 (FLDetector) | https://arxiv.org/abs/2207.09209 |
| Liu 2024 (BadSampler) | https://arxiv.org/abs/2406.12222 |

### Benchmark Papers

| Paper | Link |
|-------|------|
| Zhang 2025 (FLPoison/SoK) | https://github.com/vio1etus/FLPoison |
| Li 2024 (BLADES) | https://github.com/lishenghui/blades |
| Dao 2025 (BackFed) | https://github.com/thinh-dao/BackFed |
| Han 2024 (FedSecurity) | https://arxiv.org/abs/2306.04959 |
| Garcia 2025 (ByzFL) | https://github.com/LPD-EPFL/byzfl |
| Xu 2025 (LASA) | https://github.com/JiiahaoXU/LASA |

### Additional ML Conference Papers

| Paper | Link |
|-------|------|
| Alistarh 2018 (Byzantine SGD) | https://arxiv.org/abs/1803.08917 |
| Bernstein 2019 (signSGD majority) | https://arxiv.org/abs/1810.05291 |
| Allen-Zhu 2021 (SafeguardSGD) | ICLR 2021 |
| El Mhamdi 2021 (Distributed Momentum) | ICLR 2021 |
| Allouah 2023 (Breakdown Points) | NeurIPS 2023 |
| Liu 2023 (Gradient Splitting) | https://arxiv.org/abs/2302.06079 |
| Xu 2022 (SignGuard) | https://arxiv.org/abs/2109.05872 |
| Sun 2019 (Can You Really Backdoor FL?) | https://arxiv.org/abs/1911.07963 |

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
| 1 | `blanchard2017` | Blanchard et al. | [Machine Learning with Adversaries: Byzantine Tolerant Gradient Descent](https://arxiv.org/abs/1703.02757) | NeurIPS | gaussian_noise | krum | Proposed Krum; tolerates up to f < n/2 - 1 Byzantine workers. Convergence proven under IID; accuracy degrades under non-IID. |

#### 2018 (2 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 2 | `elmhamdi2018` | El Mhamdi et al. | [The Hidden Vulnerability of Distributed Learning in Byzantium](https://arxiv.org/abs/1802.07927) | ICML | byzantine | bulyan, krum | Proposed Bulyan; showed Krum alone is vulnerable to dimension-coupled attacks. Bulyan adds coordinate-wise trimming on top of Krum selection. |
| 3 | `yin2018` | Yin et al. | [Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates](https://arxiv.org/abs/1803.01498) | ICML | label_flip, gaussian_noise | fedtrimmedavg, fedmedian | Proposed coordinate-wise trimmed mean and median; achieves near-optimal statistical rates under Byzantine faults with IID data. |

#### 2019 (4 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 4 | `zeno2019` | Xie et al. | [Zeno: Distributed SGD with Suspicion-Based Fault-Tolerance](https://arxiv.org/abs/1805.10032) | ICML | sign_flip, gaussian_noise, label_flip | zeno, krum, fedtrimmedavg | Zeno uses a small validation set to score updates by loss reduction. Outperforms Krum and trimmed mean under sign-flip and label-flip attacks. |
| 5 | `baruch2019` | Baruch et al. | [A Little Is Enough: Circumventing Defenses For Distributed Learning](https://arxiv.org/abs/1902.06156) | NeurIPS | alie | krum, bulyan, fedtrimmedavg, fedmedian | ALIE crafts updates at mu - z*sigma to stay within honest distribution. Bypasses Krum, Bulyan, trimmed mean, and median with as few as 20% malicious clients. |
| 6 | `sun2019` | Sun et al. | [Can You Really Backdoor Federated Learning?](https://arxiv.org/abs/1911.07963) | NeurIPS Workshop | backdoor | krum, fedtrimmedavg, bulyan, norm_bounding | Backdoor attacks in FL succeed even with defenses; Krum and trimmed mean reduce but do not eliminate backdoor ASR. Constrain-and-scale evades norm-based defenses. |
| 7 | `xie2019ipm` | Xie et al. | [Fall of Empires: Breaking Byzantine-tolerant SGD by Inner Product Manipulation](https://arxiv.org/abs/1903.03936) | UAI | ipm | krum, fedmedian | Inner Product Manipulation (IPM) breaks Krum and median by aligning poisoned updates with negative of true gradient. Converges to arbitrary target. |

#### 2020 (5 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 8 | `bagdasaryan2020` | Bagdasaryan et al. | [How To Backdoor Federated Learning](https://arxiv.org/abs/1807.00459) | AISTATS | backdoor, constrain_and_scale | norm_bounding | Demonstrated that a single attacker in one round of FL can achieve 100% backdoor task accuracy via model replacement, greatly outperforming data poisoning. The constrain-and-scale technique evades ano... |
| 9 | `dba2020` | Xie et al. | [DBA: Distributed Backdoor Attacks against Federated Learning](https://openreview.net/forum?id=rkgyS0VFvr) | ICLR | backdoor, dba | krum, norm_bounding, rfa | DBA decomposes a global backdoor trigger into separate local patterns assigned to different adversarial parties. Achieved significantly higher ASR than centralized backdoor attacks and evaded two robu... |
| 10 | `wang2020` | Wang et al. | [Attack of the Tails: Yes, You Really Can Backdoor Federated Learning](https://arxiv.org/abs/2007.05084) | NeurIPS | backdoor, edge_case | krum, norm_bounding, rfa | Introduced edge-case backdoors that target inputs on the tail of the data distribution, which are unlikely to appear in training or test data. Proved theoretically that robustness to backdoors implies... |
| 11 | `fung2020` | Fung et al. | [The Limitations of Federated Learning in Sybil Settings (FoolsGold)](https://www.usenix.org/conference/raid2020/presentation/fung) | RAID | label_flip, backdoor | foolsgold | FoolsGold detects Sybil attacks via cosine similarity of historical gradients. Effective against coordinated label-flip but vulnerable to diverse attack patterns. |
| 12 | `fang2020` | Fang et al. | [Local Model Poisoning Attacks to Byzantine-Robust Federated Learning](https://arxiv.org/abs/1911.11815) | USENIX Security | fang, alie | krum, bulyan, fedtrimmedavg, fedmedian | USENIX paper reports substantial error increases against four Byzantine-robust methods and finds generalized defenses insufficient in many evaluated cases. |

#### 2021 (3 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 13 | `karimireddy2021` | Karimireddy et al. | [Learning from History for Byzantine Robust Optimization](https://arxiv.org/abs/2012.10333) | ICML | alie, ipm, sign_flip | centered_clipping, krum, fedtrimmedavg, fedmedian, rfa | CenteredClipping uses coordinate-wise clipping around geometric median. Provably robust under heterogeneous data; outperforms Krum and trimmed mean on non-IID. |
| 14 | `cao2021` | Cao et al. | [FLTrust: Byzantine-robust Federated Learning via Trust Bootstrapping](https://arxiv.org/abs/2012.13995) | NDSS | fang, alie, label_flip, sign_flip, gaussian_noise, backdoor | fltrust, krum, fedtrimmedavg, fedmedian | FLTrust uses a small server root dataset to compute trust scores via cosine similarity. Outperforms Krum, trimmed mean, and median across 6 attack types. |
| 15 | `shejwalkar2021` | Shejwalkar & Houmansadr | [Manipulating the Byzantine: Optimizing Model Poisoning Attacks and Defenses f...](https://www.ndss-symposium.org/ndss-paper/manipulating-the-byzantine-optimizing-model-poisoning-attacks-and-defenses-for-federated-learning/) | NDSS | min_max, min_sum, fang, alie, label_flip | krum, bulyan, fedtrimmedavg, fedmedian, dnc | NDSS paper reports 1.5×–60× larger accuracy reductions than prior attacks and demonstrates substantial susceptibility of existing Byzantine-robust FL algorithms. |

#### 2022 (14 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 16 | `more2022` | *(unverified)* | [More is Better (Mostly): On the Backdoor Attacks in Federated Graph Neural Ne...](https://arxiv.org/abs/2202.03195) | ACSAC | backdoor, dba | foolsgold | First study of backdoor attacks in Federated Graph Neural Networks (GNNs). Evaluates centralized backdoor attacks (CBA) and distributed backdoor attacks (DBA) on graph classification tasks (NCI1, PROT... |
| 17 | `eluding2022` | *(unverified)* | [Eluding Secure Aggregation in Federated Learning via Model Inconsistency](https://arxiv.org/abs/2111.07380) | CCS | -- | -- | Primary paper states the server can elude secure aggregation as if it were not in place, regardless of the underlying SA protocol. |
| 18 | `mpaf2022` | Cao et al. | [MPAF: Model Poisoning Attacks to Federated Learning Based on Fake Clients](https://arxiv.org/abs/2203.08669) | CVPR Workshop | mpaf | fedmedian, fedtrimmedavg, krum, norm_bounding | First model poisoning attack based on fake (injected) clients rather than compromised genuine clients. Drags the global model toward an attacker-chosen low-accuracy base model. On MNIST, Fashion-MNIST... |
| 19 | `backdoor2022` | *(unverified)* | [Backdoor Attacks in Federated Learning by Rare Embeddings and Gradient Ensemb...](https://arxiv.org/abs/2204.14017) | EMNLP | backdoor, dba | fedmedian, krum, norm_bounding | Proposes rare-embedding backdoor poisoning with gradient ensembling for NLP federated learning. Less than 1% adversary clients suffice to inject backdoors on text classification with no drop in clean ... |
| 20 | `karimireddy2022` | Karimireddy et al. | [Byzantine-Robust Learning on Heterogeneous Datasets via Bucketing](https://arxiv.org/abs/2006.09365) | ICLR | alie, ipm, fang, sign_flip, gaussian_noise | krum, fedmedian, centered_clipping, bulyan | Bucketing randomly groups clients before aggregation to reduce Byzantine influence under heterogeneous data. Achieves optimal rates with Krum/median + bucketing. |
| 21 | `farhadkhani2022` | Farhadkhani et al. | [Byzantine Machine Learning Made Easy By Resilient Averaging of Momentums](https://arxiv.org/abs/2205.12173) | ICML | alie, ipm, sign_flip, label_flip | krum, fedtrimmedavg, fedmedian, centered_clipping | Resilient Averaging of Momentums (RAM) combines momentum with robust aggregation. Achieves SOTA convergence under ALIE and IPM on heterogeneous data. |
| 22 | `neurotoxin2022` | Zhang et al. | [Neurotoxin: Durable Backdoors in Federated Learning](https://arxiv.org/abs/2206.10341) | ICML | backdoor, neurotoxin | krum, fedtrimmedavg, rfa, foolsgold, norm_bounding | Neurotoxin is a one-line modification to existing backdoor attacks that targets parameters changed less in magnitude during training. Doubled the durability (lifespan) of state-of-the-art backdoors ac... |
| 23 | `signguard2022` | Xu & Huang | [SignGuard: Byzantine-robust FL through Collaborative Malicious Gradient Filte...](https://arxiv.org/abs/2109.05872) | IEEE ICDCS | fang, alie, min_max, min_sum, sign_flip, ipm | signguard, fedtrimmedavg, fedmedian, krum, bulyan, dnc | SignGuard filters by gradient sign agreement and direction. Defends against ALIE, IPM, and min-max attacks that bypass Krum and Bulyan. |
| 24 | `shejwalkar2022` | Shejwalkar et al. | [Back to the Drawing Board: A Critical Evaluation of Poisoning Attacks on Prod...](https://arxiv.org/abs/2108.10241) | IEEE S&P | alie, fang, label_flip, min_max, min_sum | bulyan, dnc, fedmedian, fedtrimmedavg, krum, norm_bounding, rfa | Critical finding: contrary to established belief, FL is highly robust in practice even with simple low-cost defenses like norm bounding. Evaluated on FEMNIST, CIFAR-10, and Purchase datasets with up t... |
| 25 | `pillutla2022` | Pillutla et al. | [Robust Aggregation for Federated Learning](https://arxiv.org/abs/1912.13445) | IEEE TSP | gaussian_noise, sign_flip, label_flip | rfa, fedtrimmedavg, krum | RFA (Robust Federated Averaging) uses approximate geometric median. Tolerates up to 50% Byzantine with convergence guarantees; tested on sign-flip and label-flip. |
| 26 | `wan2022` | Wan et al. | [Shielding FL: Robust Aggregation with Adaptive Client Selection (MAB-RFL)](https://arxiv.org/abs/2204.13256) | IJCAI | byzantine | mab-rfl, krum, fedtrimmedavg | MAB-RFL uses multi-armed bandit to adaptively assign client reputation scores. Outperforms Krum and trimmed mean under Byzantine attacks with varying fractions. |
| 27 | `fldetector2022` | Zhang et al. | [FLDetector: Defending FL Against Model Poisoning via Detecting Malicious Clients](https://arxiv.org/abs/2207.09209) | KDD | fang, alie, dba, backdoor | fldetector, fedtrimmedavg, fedmedian, krum | FLDetector predicts expected updates and flags deviations. Detects Fang, ALIE, and DBA attacks; outperforms trimmed mean and Krum on model poisoning. |
| 28 | `deepsight2022` | Rieger et al. | [DeepSight: Mitigating Backdoor Attacks in FL Through Deep Model Inspection](https://arxiv.org/abs/2201.00763) | NDSS | backdoor, constrain_and_scale, dba | deepsight, foolsgold, krum, norm_bounding | DeepSight inspects model weight distributions to detect backdoored updates. Detects constrain-and-scale and DBA attacks that bypass Krum and FoolsGold. |
| 29 | `flame2022` | Nguyen et al. | [FLAME: Taming Backdoors in Federated Learning](https://arxiv.org/abs/2101.02281) | USENIX Security | backdoor, constrain_and_scale, dba | flame, krum, foolsgold, rfa, norm_bounding | FLAME combines cosine-similarity clustering with adaptive noise injection. Eliminates DBA backdoor while maintaining accuracy; outperforms Krum and FoolsGold. |

#### 2023 (19 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 30 | `poisoning2023` | *(unverified)* | [Poisoning with Cerberus: Stealthy and Colluded Backdoor Attack against Federa...](https://ojs.aaai.org/index.php/AAAI/article/view/26083) | AAAI | alie, backdoor, dba | bulyan, dnc, fedmedian, fedtrimmedavg, fltrust, foolsgold, krum, rfa | CerP (Cerberus Poisoning) is a colluded distributed backdoor attack that jointly tunes triggers and controls poisoned model changes across malicious participants. Evaluated against 13 defense methods:... |
| 31 | `untargeted2023` | *(unverified)* | [Untargeted Attack against Federated Recommendation Systems via Poisonous Item...](https://arxiv.org/abs/2212.05399) | AAAI | alie, fang, gaussian_noise, label_flip | fedtrimmedavg, krum, norm_bounding | Proposes ClusterAttack (untargeted poisoning that converges item embeddings into dense clusters disrupting ranking) and UNION defense (uniformity-based contrastive learning + malicious gradient filter... |
| 32 | `vuln_backdoor_defenses2023` | various | [On the Vulnerability of Backdoor Defenses for Federated Learning](https://arxiv.org/abs/2301.08170) | AAAI | backdoor | krum, foolsgold, flame, deepsight | AAAI abstract explicitly frames the work as circumventing existing backdoor defenses. |
| 33 | `mesas2023` | Krauss & Dmitrienko | [MESAS: Poisoning Defense for FL Resilient against Adaptive Attackers](https://dl.acm.org/doi/10.1145/3576915.3623212) | ACM CCS | backdoor, constrain_and_scale, dba, edge_case | mesas, foolsgold, krum, norm_bounding, flame, deepsight, fltrust | MESAS specifically targets adaptive attackers. Shows existing defenses fail against attackers that adapt; proposes moving-target defense strategy. |
| 34 | `characterizing2023` | *(unverified)* | [Characterizing Internal Evasion Attacks in Federated Learning](https://arxiv.org/abs/2209.08412) | AISTATS | -- | -- | PMLR abstract reports only limited improvement from federated adversarial training against internal evasion; personalization + adversarial training improves relative robustness. |
| 35 | `unraveling2023` | *(unverified)* | [Unraveling the Connections between Privacy and Certified Robustness in Federa...](https://arxiv.org/abs/2209.04030) | CCS | backdoor, dba, label_flip, min_max, min_sum | bulyan, fedmedian, fedtrimmedavg, krum, norm_bounding, rfa | Establishes theoretical connections between differential privacy and certified robustness in FL against poisoning attacks. Proposes UserDP-FedAvg and InsDP-FedAvg with two certification criteria (cert... |
| 36 | `chameleon2023` | Dai et al. | [Chameleon: Adapting to Peer Images for Planting Durable Backdoors in Federate...](https://arxiv.org/abs/2304.12961) | ICML | backdoor, neurotoxin | krum, foolsgold, norm_bounding, flame | Chameleon uses contrastive learning to amplify relationships between poisoned images and peer images (interferers and facilitators) for more durable backdoors. Extends backdoor lifespan by 1.2x-4x ove... |
| 37 | `liu2023gradsplit` | Liu et al. | [Byzantine-Robust Learning on Heterogeneous Data via Gradient Splitting](https://arxiv.org/abs/2302.06079) | ICML | alie, ipm, sign_flip | krum, fedtrimmedavg, fedmedian, centered_clipping | Gradient splitting separates updates into magnitude and direction components. Provably robust under heterogeneous data; breaks ALIE and IPM assumptions. |
| 38 | `3dfed2023` | Lyu et al. | [3DFed: Adaptive and Extensible Framework for Covert Backdoor Attack in Federa...](https://arxiv.org/abs/2308.04466) | IEEE S&P | 3dfed | deepsight, foolsgold, flame, fldetector | Primary publication description reports evasion of multiple named defenses. |
| 39 | `fedrecover2023` | Cao et al. | [FedRecover: Recovering from Poisoning Attacks in FL](https://arxiv.org/abs/2210.10936) | IEEE S&P | fang, alie, dba, backdoor | fedrecover, fedtrimmedavg, fedmedian | FedRecover identifies and removes poisoned model updates post-hoc. Recovers model accuracy after training-time poisoning without retraining from scratch. |
| 40 | `denialofservice2023` | *(unverified)* | [Denial-of-Service or Fine-Grained Control: Towards Flexible Model Poisoning A...](https://arxiv.org/abs/2304.10783) | IJCAI | alie, fang, ipm, min_max, min_sum, mpaf | bulyan, centered_clipping, dnc, fedmedian, fedtrimmedavg, krum, norm_bounding | FMPA (Flexible Model Poisoning Attack) supports both denial-of-service and fine-grained accuracy control goals without knowing the defense or benign clients' updates. Compared against 6 attacks (AGRT/... |
| 41 | `oblivion2023` | various | [OBLIVION: Poisoning Federated Learning by Inducing Catastrophic Forgetting](https://ieeexplore.ieee.org/document/10228981) | INFOCOM | oblivion | krum, fedtrimmedavg | Proposed OBLIVION, a model poisoning attack exploiting catastrophic forgetting to destroy the global model's memory. Uses weight prioritization (targeting weights with most influence on accuracy) and ... |
| 42 | `jmlr_attacks2023` | Moshawrab et al. | [Attacks against Federated Learning Defense Systems and their Mitigation](https://www.jmlr.org/papers/v24/22-0014.html) | JMLR | on_off_attack, label_flip | foolsgold, krum, fedtrimmedavg | JMLR abstract reports the attacks effectively deceive well-known FL defense systems; the paper then proposes Viceroy as mitigation. |
| 43 | `chen2023` | Chen et al. | [FLRAM: Robust Aggregation for Defense against Byzantine Poisoning in FL](https://www.mdpi.com/2079-9292/12/21/4463) | MDPI Electronics | gaussian_noise, sign_flip, label_flip | flram, krum, fedtrimmedavg, fedmedian | FLRAM scores clients on norm, direction, and sign agreement. Outperforms Krum and trimmed mean under Gaussian noise, sign-flip, and label-flip attacks. |
| 44 | `a3fl2023` | Zhang et al. | [A3FL: Adversarially Adaptive Backdoor Attacks to Federated Learning](https://proceedings.neurips.cc/paper_files/paper/2023/hash/c07d71ff0bc042e4b9acd626a79597fa-Abstract-Conference.html) | NeurIPS | a3fl | krum, foolsgold, flame, deepsight, fldetector, norm_bounding | NeurIPS abstract states evaluation against 12 existing defenses and stronger/persistent attack behavior. |
| 45 | `iba2023` | various | [IBA: Towards Irreversible Backdoor Attacks in Federated Learning](https://proceedings.neurips.cc/paper_files/paper/2023/hash/d0c6bc641a56bebee9d985b937307367-Abstract-Conference.html) | NeurIPS | backdoor, dba | fedtrimmedavg, flame, foolsgold, krum, norm_bounding, rfa | IBA jointly learns optimal visually stealthy triggers and gradually implants backdoors using selective parameter poisoning and constrained updates. On CIFAR-10 with FedAvg: 87.13% BA while maintaining... |
| 46 | `backdoor2023` | *(unverified)* | [Backdoor Threats from Compromised Foundation Models to Federated Learning](https://arxiv.org/abs/2311.00144) | NeurIPS workshop | backdoor | -- | Proposes BD-FMFL, a backdoor attack exploiting compromised foundation models (FMs) as initialization for FL, requiring no attacker participation during FL training. Compared against attack-free FL (AF... |
| 47 | `gradient2023` | *(unverified)* | [Gradient Obfuscation Gives a False Sense of Security in Federated Learning](https://arxiv.org/abs/2206.04055) | USENIX Security | -- | -- | USENIX abstract concludes common gradient post-processing defenses can provide a false sense of security against reconstruction. |
| 48 | `mozaffari2023` | Mozaffari et al. | [Every Vote Counts: Ranking-Based Training of FL (FRL)](https://www.usenix.org/conference/usenixsecurity23/presentation/mozaffari) | USENIX Security | min_max, min_sum, fang, alie | krum, fedtrimmedavg | FRL ranks clients by loss improvement on validation set. Outperforms Krum and trimmed mean under min-max and ALIE attacks with up to 40% malicious. |

#### 2024 (24 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 49 | `beyond2024` | *(unverified)* | [Beyond Traditional Threats: A Persistent Backdoor Attack on Federated Learning](https://arxiv.org/abs/2404.17617) | AAAI | backdoor, dba | -- | Proposes FCBA (Full Combination Backdoor Attack) for persistent backdoors in FL. On GTSRB post-attack 120 rounds: FCBA achieves 57.78% ASR vs DBA's 0.95% (+56.83pp). On MNIST: FCBA 99.52% vs DBA 64.64... |
| 50 | `brdfl2024` | Fang et al. | [Byzantine-Robust Decentralized FL](https://arxiv.org/abs/2406.10416) | ACM CCS | fang, min_max, alie, ipm | brdfl, centered_clipping, dnc | Byzantine-robust decentralized FL without server. Achieves convergence under 1/3 Byzantine with gossip-based robust aggregation. |
| 51 | `boba2024` | various | [BOBA: Byzantine-Robust FL with Label Skewness](https://arxiv.org/abs/2208.12932) | AISTATS | byzantine | boba | BOBA addresses label-skewed non-IID settings where honest clients look Byzantine. Outperforms Krum and trimmed mean under severe label imbalance. |
| 52 | `distributed2024` | *(unverified)* | [Distributed Backdoor Attacks on Federated Graph Learning and Certified Defenses](https://arxiv.org/abs/2407.08935) | CCS | backdoor, dba | -- | Proposes Opt-GDBA for distributed backdoor attacks on federated graph learning with adaptive trigger generation. Achieves >90% backdoor accuracy across 6 graph datasets (BITCOIN 0.99, MUTAG 0.95, PROT... |
| 53 | `fake2024` | *(unverified)* | [Fake Node-Based Perception Poisoning Attacks against Federated Object Detecti...](https://dl.acm.org/doi/10.1145/3649329.3655934) | DAC | -- | -- | Proposes FNPPA, a fake-node-based perception poisoning attack against federated object detection in mobile computing that poisons local data and injects fake nodes to overwrite clean updates, achievin... |
| 54 | `backdoor2024` | *(unverified)* | [Backdoor Federated Learning by Poisoning Backdoor-Critical Layers](https://arxiv.org/abs/2308.04466) | ICLR | 3dfed, backdoor, constrain_and_scale, dba | flame, fldetector, fltrust, krum | Proposes BC (Backdoor-Critical) layer-aware backdoor attacks that identify and target only the small subset of layers dominating model vulnerabilities. Successfully backdoors FL under seven defenses (... |
| 55 | `like2024` | *(unverified)* | [Like Oil and Water: Group Robustness Methods and Poisoning Defenses Don't Mix](https://arxiv.org/abs/2504.02142) | ICLR | backdoor, label_flip | fedmedian, fedtrimmedavg | ICLR abstract reports poison ASR increasing from 0% to >97% in some group-robust settings and defense-induced harm to legitimate minority samples. |
| 56 | `hidra2024` | Choudhary et al. | [Attacking Byzantine Robust Aggregation in High Dimensions](https://arxiv.org/abs/2312.14461) | IEEE S&P | hidra | chunked_defenses | HIDRA shows high-dimensional robust aggregation fails when dimension >> clients. Proposes dimensionality-aware robust aggregation. |
| 57 | `layerdba2024` | Dai et al. | [LayerDBA: Circumventing Similarity-Based Defenses in Federated Learning](https://ieeexplore.ieee.org/document/10795458) | IEEE S&P | layerdba | foolsgold | Primary research page reports circumvention of FoolsGold and Contra, including high ASR with only 5% malicious clients. |
| 58 | `blades2024` | Li et al. | [Blades: A Unified Benchmark Suite for Byzantine Attacks and Defenses in FL](https://arxiv.org/abs/2206.05359) | IEEE/ACM IoTDI | gaussian_noise, label_flip, sign_flip, alie, ipm, fang, min_max | krum, fedtrimmedavg, fedmedian, dnc, fltrust | Unified benchmark of 6 attacks × 8 defenses across CIFAR-10/MNIST. Confirms ALIE and min-max bypass Krum; FLTrust most robust overall. |
| 59 | `badfss2024` | *(unverified)* | [BADFSS: Backdoor Attacks on Federated Self-Supervised Learning](https://www.ijcai.org/proceedings/2024/61) | IJCAI | backdoor | -- | BADFSS proposes a backdoor attack against federated self-supervised learning (FSSL) using supervised contrastive learning and attention alignment. Compared against 4 centralized SSL backdoor baselines... |
| 60 | `darkfed2024` | *(unverified)* | [DarkFed: A Data-Free Backdoor Attack in Federated Learning](https://arxiv.org/abs/2405.03299) | IJCAI | 3dfed, backdoor | flame, foolsgold, norm_bounding | IJCAI abstract motivates DarkFed by showing prior attacks become stoppable under realistic settings and develops a data-free covert alternative that evades defenses. |
| 61 | `eabfl2024` | *(unverified)* | [EAB-FL: Exacerbating Algorithmic Bias through Model Poisoning Attacks in Fede...](https://arxiv.org/abs/2410.02042) | IJCAI | -- | krum | EAB-FL is a model poisoning attack targeting group fairness (not accuracy) in FL. Tested on CelebA, Adult Income, and UTK Faces. Under FedAvg, EAB-FL achieves EOD up to 0.45 and DPD up to 0.50 while m... |
| 62 | `badsampler2024` | Liu et al. | [BadSampler: Clean-Label Backdoor Attacks against FLTrust](https://arxiv.org/abs/2406.12222) | KDD | backdoor | fltrust | BadSampler attacks FLTrust by manipulating the root dataset sampling. Achieves high backdoor ASR even with FLTrust by exploiting root data distribution. |
| 63 | `badsampler2024_2` | *(unverified)* | [*BadSampler:* Harnessing the Power of Catastrophic Forgetting to Poison Byzan...](https://arxiv.org/abs/2406.12222) | KDD | label_flip | fedtrimmedavg, fldetector, fltrust, foolsgold, krum | Primary preprint presents BadSampler specifically as poisoning Byzantine-robust FL while avoiding classic malicious-update signatures. |
| 64 | `fedsecurity2024` | Han et al. | [FedSecurity: Benchmarking Attacks and Defenses in FL and Federated LLMs](https://arxiv.org/abs/2306.04959) | KDD | byzantine, label_flip, backdoor, edge_case | foolsgold, krum, bulyan, fedtrimmedavg, fedmedian, rfa, norm_bounding, centered_clipping | Benchmarks attacks and defenses in both FL and federated LLM fine-tuning. Shows LLM FL is more vulnerable to backdoor attacks than vision FL. |
| 65 | `navigation2024` | *(unverified)* | [Navigation as Attackers Wish? Towards Building Robust Embodied Agents under F...](https://arxiv.org/abs/2211.14769) | NAACL | backdoor, dba | bulyan, fedmedian, fedtrimmedavg, fltrust, krum | Proposes NAW (Navigation As Wish) backdoor attack on federated vision-and-language navigation agents, and PBA (Prompt-Based Aggregation) defense. On R2R dataset, NAW achieves 0.68-0.85 ASR under FedAv... |
| 66 | `autoadapt2024` | various | [Automatic Adversarial Adaption for Stealthy Poisoning Attacks in Federated Le...](https://www.ndss-symposium.org/ndss-paper/automatic-adversarial-adaption-for-stealthy-poisoning-attacks-in-federated-learning/) | NDSS | autoadapt | krum, fedtrimmedavg, fedmedian, norm_bounding | NDSS abstract frames a unified strong adaptive attacker specifically designed to challenge multiple defense metrics simultaneously. |
| 67 | `freqfed2024` | Fereidooni et al. | [FreqFed: Frequency Analysis-Based Approach for Mitigating Poisoning](https://arxiv.org/abs/2312.04432) | NDSS | label_flip, backdoor, constrain_and_scale, dba | freqfed, krum, fedmedian, foolsgold, flame, deepsight | FreqFed analyzes model updates in the frequency domain. Detects backdoor patterns invisible in weight space; outperforms FLAME and DeepSight. |
| 68 | `rflpa2024` | various | [RFLPA: A Robust FL Framework against Poisoning Attacks](https://arxiv.org/abs/2405.15182) | NeurIPS | fang, min_max, min_sum, alie, ipm | rflpa, krum, fedtrimmedavg, bulyan, fltrust | RFLPA combines reputation scoring with adaptive penalty. Outperforms FLTrust and MAB-RFL under multi-round persistent attacks. |
| 69 | `badvfl2024` | *(unverified)* | [BadVFL: Backdoor Attacks in Vertical Federated Learning](https://arxiv.org/abs/2304.08847) | S&P | backdoor | -- | Proposes BadVFL, first clean-label backdoor attack in Vertical FL exploiting feature embeddings. On CIFAR-10 (2-party): ASR 0.85, MTA 0.77. On CIFAR-100: ASR 0.78, MTA 0.70. Tested countermeasures: Ne... |
| 70 | `revisit2024` | *(unverified)* | [Revisit Targeted Model Poisoning on Federated Recommendation: Optimize via Mu...](https://dl.acm.org/doi/10.1145/3626772.3657764) | SIGIR | -- | -- | Proposes HMTA (Heterogeneous Multi-target Transfer Attack), a two-stage targeted model poisoning framework for federated recommendation that uses collaboration-aware manifold learning and optimal mult... |
| 71 | `ace2024` | *(unverified)* | [ACE: A Model Poisoning Attack on Contribution Evaluation Methods in Federated...](https://arxiv.org/abs/2405.20975) | USENIX Security | -- | fedtrimmedavg, foolsgold, krum | USENIX abstract reports deception of five SOTA contribution-evaluation methods and finds six explored countermeasures inadequate. |
| 72 | `lurking2024` | *(unverified)* | [Lurking in the shadows: Unveiling Stealthy Backdoor Attacks against Personali...](https://arxiv.org/abs/2406.06207) | USENIX Security | backdoor, neurotoxin | dnc, fedtrimmedavg, flame, fltrust, krum | PFedBA is a backdoor attack against personalized FL that aligns backdoor and main learning tasks via trigger optimization with gradient and loss alignment. Tested across 10 PFL algorithms (FedAvg-FT, ... |

#### 2025 (20 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 73 | `labelfree2025` | Wei Shen; Wenke Huang; Guancheng Wan; Mang Ye | [Label-Free Backdoor Attacks in Vertical Federated Learning](https://ojs.aaai.org/index.php/AAAI/article/view/34246) | AAAI | backdoor | -- | Proposes Label-Free Backdoor Attacks (LFBA) for vertical federated learning, removing the assumption that attackers need task label information. Key insight: gradients of local embeddings reflect sema... |
| 74 | `rethinking2025` | *(unverified)* | [Rethinking Byzantine Robustness in Federated Recommendation from Sparse Aggre...](https://arxiv.org/abs/2501.03301) | AAAI | alie, fang, gaussian_noise, label_flip | fedmedian, fedtrimmedavg, krum, norm_bounding | AAAI abstract reports the attack family can break down defenses with a small number of malicious clients. |
| 75 | `sadba2025` | Jun Feng; Yuzhe Lai; Hong Sun; Bocheng Ren | [SADBA: Self-Adaptive Distributed Backdoor Attack Against Federated Learning](https://ojs.aaai.org/index.php/AAAI/article/view/33820) | AAAI | backdoor, dba, fang | -- | Primary AAAI abstract reports SADBA achieves higher or comparable backdoor performance and main-task accuracy across various datasets with limited malicious-client percentage. |
| 76 | `strike2025` | various | [Exploit Gradient Skewness to Circumvent Byzantine Defenses for Federated Lear...](https://arxiv.org/abs/2502.04890) | AAAI | strike | krum, fedtrimmedavg, fedmedian, bulyan | AAAI/Sony primary descriptions state that STRIKE deceives existing Byzantine defenses by exploiting gradient skewness. |
| 77 | `hyperparameters2025` | Simon Lachnit; Ghassan Karame | [On Hyperparameters and Backdoor-Resistance in Horizontal Federated Learning](https://dl.acm.org/doi/10.1145/3719027.3765211) | CCS | a3fl, backdoor | -- | Reports that proper benign hyperparameter tuning can reduce the 50%-lifespan of A3FL by 98.6% without a defense, with a 2.9 percentage-point clean-accuracy drop. |
| 78 | `infighting2025` | Ye Li; Yanchao Zhao; Chengcheng Zhu; Jiale Zhang | [Infighting in the Dark: Multi-Label Backdoor Attack in Federated Learning](https://arxiv.org/abs/2409.19601) | CVPR | a3fl, backdoor, neurotoxin | deepsight, flame, foolsgold, krum | Primary CVPR abstract reports average ASR >97% and >90% ASR after 900 rounds while bypassing existing defenses. |
| 79 | `model2025` | Yueqi Xie; Minghong Fang; Neil Zhenqiang Gong | [Model Poisoning Attacks to Federated Learning via Multi-Round Consistency](https://arxiv.org/abs/2404.15611) | CVPR | alie, fang, min_max, min_sum, mpaf, poisonedfl | fedmedian, fedtrimmedavg, flame, fldetector, fltrust, krum, norm_bounding | Primary CVPR paper reports PoisonedFL breaks 8 SOTA defenses and outperforms 7 existing model-poisoning attacks on 5 benchmark datasets. |
| 80 | `poisonedfl2025` | Xie et al. | [Model Poisoning Attacks to FL via Multi-Round Consistency](https://arxiv.org/abs/2404.15611) | CVPR | poisonedfl, fang, alie, min_max, min_sum | krum, fedmedian, fedtrimmedavg, fltrust, flame, fldetector | PoisonedFL exploits multi-round consistency to bypass FLTrust and FoolsGold. Gradually shifts model over multiple rounds to evade per-round detection. |
| 81 | `badpfl2025` | Mingyuan Fan; Zhanyi Hu; Fuyi Wang; Cen Chen | [Bad-PFL: Exploiting Backdoor Attacks against Personalized Federated Learning](https://arxiv.org/abs/2501.12736) | ICLR | backdoor, dba, neurotoxin | fedmedian, krum, norm_bounding | Primary ICLR abstract reports superior attack performance across 3 benchmark datasets and multiple PFL methods, including methods equipped with SOTA defenses. |
| 82 | `backdoor2025` | Jirui Yang; Peng Chen; Zhihui Lu; Jianping Zeng; Qiang Duan; Xin Du; Ruijun Deng | [Backdoor Attack on Vertical Federated Graph Neural Network Learning](https://arxiv.org/abs/2410.11290) | IJCAI | backdoor | -- | Primary IJCAI abstract reports nearly 100% ASR across 3 datasets and 3 GNN models with minimal main-task impact, remaining effective under evaluated defenses. |
| 83 | `performance2025` | *(unverified)* | [Performance Guaranteed Poisoning Attacks in Federated Learning: A Sliding Mod...](https://arxiv.org/abs/2505.16403) | IJCAI | alie, min_max, min_sum | bulyan, centered_clipping, dnc, fedmedian, fedtrimmedavg, fltrust, krum, norm_bounding | Proposes FedSA using sliding mode control theory for precise model poisoning. Can degrade global accuracy to any predefined target level with average deviation of 1.62-2.64%. Tested against 9 defenses... |
| 84 | `foundationfl2025` | Fang et al. | [Do We Really Need to Design New Byzantine-robust Aggregation Rules?](https://arxiv.org/abs/2501.17381) | NDSS | fang, min_max, min_sum, alie | foundationfl, krum, foolsgold, flame, fedtrimmedavg, fedmedian | Questions necessity of complex aggregation rules; shows simple defenses with proper hyperparameters match or exceed Krum, Bulyan, and FLTrust. |
| 85 | `practical2025` | *(unverified)* | [Practical Poisoning Attacks with Limited Byzantine Clients in Clustered Feder...](https://ieeexplore.ieee.org/document/11023464/) | S&P | -- | -- | Proposes Cluster-U-M and Cluster-U-D attacks targeting Clustered Federated Learning (CFL). Attacks work via cluster poisoning and client-drift exploitation within clusters. Can compromise up to 54% of... |
| 86 | `poisafl2025` | various | [PoiSAFL: Scalable Poisoning Attack Framework to Byzantine-resilient Semi-asyn...](https://www.usenix.org/conference/usenixsecurity25/presentation/pang-xiaoyi) | USENIX Security | poisafl | krum, fedtrimmedavg, fedmedian | USENIX abstract states PoiSAFL bypasses three typical categories of Byzantine-resilient defenses. |
| 87 | `lasa2025` | Xu et al. | [Achieving Byzantine-Resilient FL via Layer-Adaptive Sparsified Model Aggregation](https://arxiv.org/abs/2409.01435) | WACV | gaussian_noise, sign_flip, min_max, min_sum, alie | lasa, fedtrimmedavg, rfa, krum, bulyan, dnc, signguard | Layer-adaptive sparsification aggregates only important parameters per layer. Robust to model poisoning while preserving accuracy under non-IID. |
| 88 | `nigdba2025` | *(unverified)* | [NI-GDBA: Non-Intrusive Distributed Backdoor Attack Based on Adaptive Perturba...](https://dl.acm.org/doi/10.1145/3696410.3714630) | WWW | backdoor, dba | -- | Proposes NI-GDBA, a non-intrusive distributed backdoor attack on federated graph learning using adaptive perturbation trigger generators for each malicious client. Does not require intrusive trigger e... |
| 89 | `backfed2025` | Dao et al. | [BackFed: An Efficient & Standardized Benchmark Suite for Backdoor Attacks in FL](https://arxiv.org/abs/2507.04903) | arXiv | neurotoxin, backdoor, dba, edge_case | fedtrimmedavg, krum, rfa, fltrust, foolsgold, deepsight, flame, fldetector | Standardized backdoor benchmark for FL. Shows constrain-and-scale and DBA bypass most defenses; only FLAME and frequency-based methods partially succeed. |
| 90 | `byzfl2025` | Garcia et al. | [ByzFL: Research Framework for Robust Federated Learning](https://arxiv.org/abs/2505.24802) | arXiv | sign_flip, label_flip, ipm, alie | krum, fedtrimmedavg, fedmedian, rfa, centered_clipping | ByzFL framework for systematic evaluation of Byzantine-robust FL. Reproduces and compares 8 defenses under standardized conditions. |
| 91 | `flpoison2025` | Zhang et al. | [SoK: Benchmarking Poisoning Attacks and Defenses in Federated Learning](https://arxiv.org/abs/2502.03801) | arXiv | gaussian_noise, sign_flip, alie, ipm, fang, min_max, min_sum, mimic, label_flip, backdoor, dba, edge_case, neurotoxin, constrain_and_scale | krum, bulyan, fedtrimmedavg, fedmedian, rfa, fltrust, centered_clipping, dnc, signguard, foolsgold, norm_bounding, deepsight, flame | SoK benchmarking 12 attacks × 10 defenses on 4 datasets. Finds no single defense robust to all attacks; ALIE and adaptive attacks most effective overall. |
| 92 | `stealthy2025` | Qingqian Yang; Peishen Yan; Xiaoyu Wu; Jiaru Zhang; Tao Song; Yang Hua; Hao Wang; Liangliang Wang; Haibing Guan | [Stealthy Backdoor Attack in Federated Learning via Adaptive Layer-Wise Gradie...](https://ieeexplore.ieee.org/document/11444883) | iccv | backdoor, dba | deepsight, dnc, flame, fltrust, krum | Primary ICCV abstract reports bypass of 8 SOTA defenses and improvement over existing attacks by up to 54.76%. |

#### 2026 (4 papers)

| # | Key | Authors | Title | Venue | Attacks Tested | Defenses Tested | Key Findings |
|---|-----|---------|-------|-------|----------------|-----------------|--------------|
| 93 | `breaking2026` | Jarin Tasneem | [Breaking Cross-View Associations: Byzantine Model Poisoning Attack against Ve...](https://ojs.aaai.org/index.php/AAAI/article/view/42327) | AAAI | -- | -- | A 3-page AAAI-26 Undergraduate Consortium position paper on Byzantine model poisoning in vertical federated learning (VFL). Demonstrates that a single malicious participant can significantly reduce in... |
| 94 | `goodgradients2026` | various | [Good Gradients Poison Your Model: Evading Defenses in Federated Learning via ...](https://ojs.aaai.org/index.php/AAAI/article/view/38328) | AAAI | good_gradients | fltrust, krum, fedtrimmedavg, norm_bounding | Primary abstract describes evasion across mainstream defensive mechanisms by crafting seemingly benign malicious gradients. |
| 95 | `pill2026` | various | [Poisoning with a Pill: Circumventing Detection in Federated Learning](https://arxiv.org/abs/2407.15389) | AAAI | pill | krum, fedtrimmedavg, fedmedian, bulyan, fltrust, foolsgold, norm_bounding, dnc | AAAI abstract reports bypassing 8 SOTA defenses, up to 7× error-rate increase and >2× average increase, across IID/non-IID and cross-silo/cross-device settings. |
| 96 | `dynamic2026` | *(unverified)* | [Dynamic Min-Max Multi-Dimensional Reinforcement Backdoor Attacks and Orchestr...](https://dl.acm.org/doi/10.1145/3774904.3792994) | WWW | backdoor | -- | Proposes CLARF for fairness-aware federated fraud detection with a dynamic Min-Max adversarial game framework. Attackers use hybrid multi-stage reinforcement learning with multi-dimensional rewards to... |

### 8.2 Out-of-Scope Papers: Privacy, Inference, Other FL Security (109 papers)

These papers cover FL security topics outside Byzantine robustness (gradient inversion, membership inference, free-riding, etc.). Included in the KB for completeness — the framework does not compare findings against these.

#### 2017 (1 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 97 | `deep2017` | *(unverified)* | [Deep Models Under the GAN: Information Leakage from Collaborative Deep Learning](https://arxiv.org/abs/1702.07464) | CCS | -- |

#### 2019 (3 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 98 | `beyond2019` | *(unverified)* | [Beyond Inferring Class Representatives: User-Level Privacy Leakage From Feder...](https://dl.acm.org/doi/10.1109/INFOCOM.2019.8737416) | INFOCOM | -- |
| 99 | `comprehensive2019` | *(unverified)* | [Comprehensive Privacy Analysis of Deep Learning: Passive and Active White-box...](https://arxiv.org/abs/1812.00910) | S&P | -- |
| 100 | `exploiting2019` | *(unverified)* | [Exploiting Unintended Feature Leakage in Collaborative Learning](https://arxiv.org/abs/1805.04049) | S&P | -- |

#### 2020 (1 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 101 | `inverting2020` | *(unverified)* | [Inverting Gradients - How easy is it to break privacy in federated learning?](https://arxiv.org/abs/2003.14053) | NeurIPS | -- |

#### 2021 (6 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 102 | `freerider2021` | *(unverified)* | [Free-rider Attacks on Model Aggregation in Federated Learning](https://proceedings.mlr.press/v130/fraboni21a.html) | AISTATS | -- |
| 103 | `feature2021` | *(unverified)* | [Feature Inference Attack on Model Predictions in Vertical Federated Learning](https://arxiv.org/abs/2010.10152) | ICDE | -- |
| 104 | `gradient2021` | *(unverified)* | [Gradient Disaggregation: Breaking Privacy in Federated Learning by Reconstruc...](https://arxiv.org/abs/2106.06089) | ICML | -- |
| 105 | `cafe2021` | *(unverified)* | [CAFE: Catastrophic Data Leakage in Vertical Federated Learning](https://arxiv.org/abs/2110.15122) | NeurIPS | -- |
| 106 | `evaluating2021` | *(unverified)* | [Evaluating Gradient Inversion Attacks and Defenses in Federated Learning](https://arxiv.org/abs/2112.00059) | NeurIPS | -- |
| 107 | `gradient2021_2` | *(unverified)* | [Gradient Inversion with Generative Image Prior](https://arxiv.org/abs/2110.14962) | NeurIPS | -- |

#### 2022 (11 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 108 | `auditing2022` | *(unverified)* | [Auditing Privacy Defenses in Federated Learning via Generative Gradient Leakage](https://arxiv.org/abs/2203.15696) | CVPR | CVPR abstract reports leakage despite commonly used additive-noise and compression defenses. |
| 109 | `gradvit2022` | *(unverified)* | [GradViT: Gradient Inversion of Vision Transformers](https://arxiv.org/abs/2203.11894) | CVPR | -- |
| 110 | `fedrecattack2022` | *(unverified)* | [FedRecAttack: Model Poisoning Attack to Federated Recommendation](https://arxiv.org/abs/2204.01499) | ICDE | -- |
| 111 | `bayesian2022` | *(unverified)* | [Bayesian Framework for Gradient Leakage](https://arxiv.org/abs/2111.04706) | ICLR | -- |
| 112 | `robbing2022` | *(unverified)* | [Robbing the Fed: Directly Obtaining Private Data in Federated Learning with M...](https://arxiv.org/abs/2110.13057) | ICLR | -- |
| 113 | `poisoning2022` | *(unverified)* | [Poisoning Deep Learning Based Recommender Model in Federated Learning Scenarios](https://arxiv.org/abs/2204.13594) | IJCAI | -- |
| 114 | `survey2022` | *(unverified)* | [A Survey on Gradient Inversion: Attacks, Defenses and Future Directions](https://arxiv.org/abs/2206.07284) | IJCAI | -- |
| 115 | `fedattack2022` | *(unverified)* | [FedAttack: Effective and Covert Poisoning Attack on Federated Recommendation ...](https://arxiv.org/abs/2202.04975) | KDD | -- |
| 116 | `learning2022` | *(unverified)* | [Learning to Attack Federated Learning: A Model-based Reinforcement Learning A...](https://proceedings.neurips.cc/paper_files/paper/2022/hash/e2ef0cae667dbe9bfdbcaed1bd91807b-Abstract-Conference.html) | NeurIPS | -- |
| 117 | `label2022` | *(unverified)* | [Label Inference Attacks Against Vertical Federated Learning](https://www.usenix.org/conference/usenixsecurity22/presentation/fu-chong) | USENIX Security | -- |
| 118 | `pipattack2022` | *(unverified)* | [PipAttack: Poisoning Federated Recommender Systems for Manipulating Item Prom...](https://arxiv.org/abs/2110.10926) | WSDM | -- |

#### 2023 (27 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 119 | `mgia2023` | *(unverified)* | [MGIA: Mutual Gradient Inversion Attack in Multi-Modal Federated Learning (Stu...](https://ojs.aaai.org/index.php/AAAI/article/view/26995) | AAAI | -- |
| 120 | `active2023` | *(unverified)* | [Active Membership Inference Attack under Local Differential Privacy in Federa...](https://arxiv.org/abs/2302.12685) | AISTATS | PMLR abstract reports very high attack success under rigorous LDP; noise sufficient to suppress the attack significantly degrades utility. |
| 121 | `explaining2023` | *(unverified)* | [Explaining predictions and attacks in federated learning via random forests](https://doi.org/10.1007/s10489-022-03435-1) | Appl. Intell. | -- |
| 122 | `turning2023` | *(unverified)* | [Turning Privacy-preserving Mechanisms against Federated Learning](https://arxiv.org/abs/2305.05355) | CCS | Primary TU Delft description reports deception of SOTA defenses, ~60% performance detriment in adversarial mode, and effective backdoors in 93% of ... |
| 123 | `resource2023` | *(unverified)* | [The Resource Problem of Using Linear Layer Leakage Attack in Federated Learning](https://arxiv.org/abs/2303.14868) | CVPR | -- |
| 124 | `generative2023` | *(unverified)* | [Generative Gradient Inversion via Over-Parameterized Networks in Federated Le...](https://openaccess.thecvf.com/content/ICCV2023/html/Zhang_Generative_Gradient_Inversion_via_Over-Parameterized_Networks_in_Federated_Learning_ICCV_2023_paper.html) | ICCV | -- |
| 125 | `gifd2023` | *(unverified)* | [GIFD: A Generative Gradient Inversion Method with Feature Domain Optimization](https://arxiv.org/abs/2308.04699) | ICCV | -- |
| 126 | `federated2023` | *(unverified)* | [Federated IoT Interaction Vulnerability Analysis](https://ieeexplore.ieee.org/document/10184681) | ICDE | -- |
| 127 | `decepticons2023` | *(unverified)* | [Decepticons: Corrupted Transformers Breach Privacy in Federated Learning for ...](https://arxiv.org/abs/2201.12675) | ICLR | -- |
| 128 | `effective2023` | *(unverified)* | [Effective passive membership inference attacks in federated learning against ...](https://openreview.net/forum?id=QsCSLPP55Ku) | ICLR | -- |
| 129 | `instancewise2023` | *(unverified)* | [Instance-wise Batch Label Restoration via Gradients in Federated Learning](https://openreview.net/forum?id=FIrQfNSOoTr) | ICLR | -- |
| 130 | `cocktail2023` | *(unverified)* | [Cocktail Party Attack: Breaking Aggregation-Based Privacy in Federated Learni...](https://proceedings.mlr.press/v202/kariyappa23a.html) | ICML | PMLR abstract reports recovery from aggregated gradients at large batch sizes, including up to 1024. |
| 131 | `sratta2023` | *(unverified)* | [SRATTA: Sample Re-ATTribution Attack of Secure Aggregation in Federated Learning](https://arxiv.org/abs/2306.07644) | ICML | PMLR abstract states the attack effectively breaks the privacy offered by secure aggregation through sample re-attribution. |
| 132 | `surrogate2023` | *(unverified)* | [Surrogate Model Extension (SME): A Fast and Accurate Weight Update Attack on ...](https://arxiv.org/abs/2306.00127) | ICML | -- |
| 133 | `tableak2023` | *(unverified)* | [TabLeak: Tabular Data Leakage in Federated Learning](https://arxiv.org/abs/2210.01785) | ICML | -- |
| 134 | `graphfraudster2023` | *(unverified)* | [Graph-Fraudster: Adversarial Attacks on Graph Neural Network Based Vertical F...](https://arxiv.org/abs/2110.06468) | IEEE Trans. Comput. Soc. Syst. | -- |
| 135 | `uafedrec2023` | *(unverified)* | [UA-FedRec: Untargeted Attack on Federated News Recommendation](https://arxiv.org/abs/2202.06701) | KDD | -- |
| 136 | `ppa2023` | *(unverified)* | [PPA: Preference Profiling Attack Against Federated Learning](https://arxiv.org/abs/2202.04856) | NDSS | -- |
| 137 | `understanding2023` | *(unverified)* | [Understanding Deep Gradient Leakage via Inversion Influence Functions](https://arxiv.org/abs/2309.13016) | NeurIPS | -- |
| 138 | `absolute2023` | *(unverified)* | [Absolute Variation Distance: an Inversion Attack Evaluation Metric for Federa...](https://openreview.net/pdf?id=OoEIUohfcp) | NeurIPS workshop | -- |
| 139 | `beyond2023` | *(unverified)* | [Beyond Gradient and Priors in Privacy Attacks: Leveraging Pooler Layer Inputs...](https://arxiv.org/abs/2312.05720) | NeurIPS workshop | -- |
| 140 | `exploring2023` | *(unverified)* | [Exploring User-level Gradient Inversion with a Diffusion Prior](https://arxiv.org/abs/2409.07291) | NeurIPS workshop | -- |
| 141 | `user2023` | *(unverified)* | [User Inference Attacks on Large Language Models](https://arxiv.org/abs/2310.09266) | NeurIPS workshop | -- |
| 142 | `manipulating2023` | *(unverified)* | [Manipulating Federated Recommender Systems: Poisoning with Synthetic Users an...](https://arxiv.org/abs/2304.03054) | SIGIR | -- |
| 143 | `learning2023` | *(unverified)* | [Learning To Invert: Simple Adaptive Attacks for Gradient Inversion in Federat...](https://arxiv.org/abs/2210.10880) | UAI | -- |
| 144 | `agrevader2023` | *(unverified)* | [AgrEvader: Poisoning Membership Inference against Byzantine-robust Federated ...](https://dl.acm.org/doi/10.1145/3543507.3583542) | WWW | Primary institutional abstract reports coordinate-wise averaging defenses fail against PMIA and AgrEvader circumvents detection; reported attack ac... |
| 145 | `interactionlevel2023` | *(unverified)* | [Interaction-level Membership Inference Attack Against Federated Recommender S...](https://arxiv.org/abs/2301.10964) | WWW | -- |

#### 2024 (25 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 146 | `adversarial2024` | *(unverified)* | [Adversarial Attacks on Federated-Learned Adaptive Bitrate Algorithms](https://ojs.aaai.org/index.php/AAAI/article/view/27796) | AAAI | -- |
| 147 | `foreseeing2024` | *(unverified)* | [Foreseeing Reconstruction Quality of Gradient Inversion: An Optimization Pers...](https://arxiv.org/abs/2312.12488) | AAAI | -- |
| 148 | `highfidelity2024` | *(unverified)* | [High-Fidelity Gradient Inversion in Distributed Learning](https://ojs.aaai.org/index.php/AAAI/article/view/29975) | AAAI | -- |
| 149 | `analysis2024` | *(unverified)* | [Analysis of Privacy Leakage in Federated Large Language Models](https://arxiv.org/abs/2403.04784) | AISTATS | -- |
| 150 | `not2024` | *(unverified)* | [Not One Less: Exploring Interplay between User Profiles and Items in Untarget...](https://dl.acm.org/doi/10.1145/3658644.3670365) | CCS | -- |
| 151 | `uncovering2024` | *(unverified)* | [Uncovering Gradient Inversion Risks in Practical Language Model Training](https://arxiv.org/abs/2507.21198) | CCS | -- |
| 152 | `leak2024` | *(unverified)* | [Leak and Learn: An Attacker's Cookbook to Train Using Leaked Data from Federa...](https://arxiv.org/abs/2403.18144) | CVPR | -- |
| 153 | `the2024` | *(unverified)* | [On the Efficiency of Privacy Attacks in Federated Learning](https://arxiv.org/abs/2404.09430) | CVPR workshop | -- |
| 154 | `fedinverse2024` | *(unverified)* | [FedInverse: Evaluating Privacy Leakage in Federated Learning](https://openreview.net/forum?id=nTNgkEIfeb) | ICLR | -- |
| 155 | `hiding2024` | *(unverified)* | [Hiding in Plain Sight: Disguising Data Stealing Attacks in Federated Learning](https://arxiv.org/abs/2306.03013) | ICLR | ICLR abstract reports data stealing for batch sizes up to 512 and under secure aggregation while meeting stated detectability requirements. |
| 156 | `towards2024` | *(unverified)* | [Towards Eliminating Hard Label Constraints in Gradient Inversion Attacks](https://arxiv.org/abs/2402.03124) | ICLR | -- |
| 157 | `breaking2024` | *(unverified)* | [Breaking Secure Aggregation: Label Leakage from Aggregated Gradients in Feder...](https://arxiv.org/abs/2406.15731) | INFOCOM | Primary preprint abstract reports bypassing secure aggregation and 100% label recovery across evaluated datasets/architectures. |
| 158 | `data2024` | *(unverified)* | [A Data Reconstruction Attack Against Vertical Federated Learning Based on Kno...](https://ieeexplore.ieee.org/document/10620788/) | INFOCOM | -- |
| 159 | `ganbased2024` | *(unverified)* | [GAN-Based Privacy Abuse Attack on Federated Learning in IoT Networks](https://ieeexplore.ieee.org/document/10620772/) | INFOCOM | -- |
| 160 | `fedsecurity2024_2` | *(unverified)* | [FedSecurity: A Benchmark for Attacks and Defenses in Federated Learning and F...](https://arxiv.org/abs/2306.04959) | KDD | -- |
| 161 | `dager2024` | *(unverified)* | [DAGER: Exact Gradient Inversion for Large Language Models](https://arxiv.org/abs/2405.15586) | NeurIPS | -- |
| 162 | `datastealing2024` | *(unverified)* | [DataStealing: Steal Data from Diffusion Models in Federated Learning with Mul...](https://proceedings.neurips.cc/paper_files/paper/2024/hash/ef63b00ad8475605b2eaf520747f61d4-Abstract-Conference.html) | NeurIPS | -- |
| 163 | `freerider2024` | *(unverified)* | [Free-Rider and Conflict Aware Collaboration Formation for Cross-Silo Federate...](https://arxiv.org/abs/2410.19321) | NeurIPS | -- |
| 164 | `spear2024` | *(unverified)* | [SPEAR: Exact Gradient Inversion of Batches in Federated Learning](https://arxiv.org/abs/2403.03945) | NeurIPS | -- |
| 165 | `loki2024` | *(unverified)* | [Loki: Large-scale Data Reconstruction Attack against Federated Learning throu...](https://arxiv.org/abs/2303.12233) | S&P | -- |
| 166 | `gradient2024` | *(unverified)* | [Gradient Inversion Attacks: Impact Factors Analyses and Privacy Enhancement](https://arxiv.org/abs/2208.04767) | TPAMI | -- |
| 167 | `impact2024` | *(unverified)* | [The Impact of Adversarial Attacks on Federated Learning: A Survey](https://ieeexplore.ieee.org/document/10274102/) | TPAMI | -- |
| 168 | `federated2024` | *(unverified)* | [Federated Learning Vulnerabilities: Privacy Attacks with Denoising Diffusion ...](https://dl.acm.org/doi/10.1145/3589334.3645514) | WWW | -- |
| 169 | `poisoning2024` | *(unverified)* | [Poisoning Attack on Federated Knowledge Graph Embedding](https://dl.acm.org/doi/10.1145/3589334.3645422) | WWW | -- |
| 170 | `poisoning2024_2` | *(unverified)* | [Poisoning Federated Recommender Systems with Fake Users](https://arxiv.org/abs/2402.11637) | WWW | -- |

#### 2025 (26 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 171 | `attribute2025` | Francesco Diana; Othmane Marfoq; Chuan Xu; Giovanni Neglia; Frédéric Giroire; Eoin Thomas | [Attribute Inference Attacks for Federated Regression Tasks](https://arxiv.org/abs/2411.12697) | AAAI | -- |
| 172 | `personalized2025` | Hanyu Zhao; Zijie Pan; Yajie Wang; Zuobin Ying; Lei Xu; Yu-an Tan | [Personalized Label Inference Attack in Federated Transfer Learning via Contra...](https://ojs.aaai.org/index.php/AAAI/article/view/34438) | AAAI | -- |
| 173 | `gradient2025` | Ying Gao; Yuxin Xie; Huanghao Deng; Zukun Zhu | [Gradient Inversion Attack in Federated Learning: Exposing Text Data through D...](https://aclanthology.org/2025.coling-main.176/) | COLING | Across three datasets, exact-match rate improves on average by 39% for TinyBERT-6, 20% for BERT-base, and 15% for BERT-large over the compared sett... |
| 174 | `fedmia2025` | Gongxi Zhu; Donghao Li; Hanlin Gu; Yuan Yao; Lixin Fan; Yuxing Han | [FedMIA: An Effective Membership Inference Attack Exploiting "All for One" Pri...](https://arxiv.org/abs/2402.06289) | CVPR | Primary CVPR abstract reports FedMIA outperforms existing MIAs in classification and generative tasks and remains robust across defense strategies,... |
| 175 | `gradient2025_3` | *(unverified)* | [Gradient Inversion Attacks on Parameter-Efficient Fine-Tuning](https://arxiv.org/abs/2506.04453) | CVPR | -- |
| 176 | `can2025` | Wenkai Guo; Xuefeng Liu; Haolin Wang; Jianwei Niu; Shaojie Tang; Jing Yuan | [Can Federated Learning Safeguard Private Data in LLM Training? Vulnerabilitie...](https://arxiv.org/abs/2509.20680) | EMNLP | ACL paper evaluates multiple privacy defenses and documents persistent FL-LLM privacy vulnerabilities. |
| 177 | `emerging2025` | Rui Ye; Jingyi Chai; Xiangrui Liu; Yaodong Yang; Yanfeng Wang; Siheng Chen | [Emerging Safety Attack and Defense in Federated Instruction Tuning of Large L...](https://arxiv.org/abs/2406.10630) | ICLR | Primary ICLR abstract reports up to a 70% safety-rate reduction; existing defenses improve safety by at most 4 percentage points, while the propose... |
| 178 | `grain2025` | *(unverified)* | [GRAIN: Exact Graph Reconstruction from Gradients](https://arxiv.org/abs/2503.01838) | ICLR | -- |
| 179 | `gradient2025_2` | Omri Ben Hemo; Alon Zolfi; Oryan Yehezkel; Omer Hofman; Roman Vainshtein; Hisashi Kojima; Yuval Elovici; Asaf Shabtai | [Gradient Inversion of Multimodal Models](https://proceedings.mlr.press/v267/hemo25a.html) | ICML | -- |
| 180 | `theoretically2025` | Quan Minh Nguyen; Minh N. Vu; Truc Nguyen; My T. Thai | [Theoretically Unmasking Inference Attacks Against LDP-Protected Clients in Fe...](https://arxiv.org/abs/2506.17292) | ICML | Primary ICML page reports persistent privacy risk under LDP; noise sufficient to mitigate the attacks significantly degrades model utility. |
| 181 | `generic2025` | *(unverified)* | [Generic Adversarial Attack Framework Against Vertical Federated Learning](https://www.ijcai.org/proceedings/2025/646) | IJCAI | -- |
| 182 | `mmgia2025` | *(unverified)* | [MMGIA: Gradient Inversion Attack Against Multimodal Federated Learning via In...](https://www.ijcai.org/proceedings/2025/886) | IJCAI | -- |
| 183 | `where2025` | *(unverified)* | [Where Does This Data Come From? Enhanced Source Inference Attacks in Federate...](https://www.ijcai.org/proceedings/2025/536) | IJCAI | -- |
| 184 | `preference2025` | *(unverified)* | [Preference Profiling Attacks Against Vertical Federated Learning Over Graph Data](https://ieeexplore.ieee.org/document/11044459/) | INFOCOM | -- |
| 185 | `vanikg2025` | *(unverified)* | VaniKG: Vanishing Key Gradient Attack and Defense for Robust Federated Aggreg... | INFOCOM | -- |
| 186 | `raifle2025` | *(unverified)* | [RAIFLE: Reconstruction Attacks on Interaction-based Federated Learning with A...](https://arxiv.org/abs/2310.19163) | NDSS | -- |
| 187 | `scalemia2025` | *(unverified)* | [Scale-MIA: A Scalable Model Inversion Attack against Secure Federated Learnin...](https://arxiv.org/abs/2311.05808) | NDSS | Primary research description reports reconstruction of local samples despite robust secure aggregation. |
| 188 | `urvfl2025` | *(unverified)* | [URVFL: Undetectable Data Reconstruction Attack on Vertical Federated Learning](https://arxiv.org/abs/2404.19582) | NDSS | -- |
| 189 | `cutting2025` | *(unverified)* | [Cutting Through Privacy: A Hyperplane-Based Data Reconstruction Attack in Fed...](https://arxiv.org/abs/2505.10264) | UAI | -- |
| 190 | `sok2025` | *(unverified)* | [SoK: Gradient Inversion Attacks in Federated Learning](https://www.usenix.org/conference/usenixsecurity25/presentation/carletti) | USENIX Security | -- |
| 191 | `sok2025_2` | *(unverified)* | [SoK: On Gradient Leakage in Federated Learning](https://arxiv.org/abs/2404.05403) | USENIX Security | -- |
| 192 | `poisoning2025` | *(unverified)* | [Poisoning Attacks and Defenses to Federated Unlearning](https://arxiv.org/abs/2501.17396) | WWW | ACM abstract reports BadUnlearn compromises existing federated-unlearning methods; the same paper proposes UnlearnGuard as a stronger defense. |
| 193 | `selfcomparison2025` | *(unverified)* | [Self-Comparison for Dataset-Level Membership Inference in Large (Vision-)Lang...](https://arxiv.org/abs/2410.13088) | WWW | -- |
| 194 | `find2025` | Wenjin Mo; Zhiyuan Li; Minghong Fang; Mingwei Fang | [Find a Scapegoat: Poisoning Membership Inference Attack and Defense to Federa...](https://arxiv.org/abs/2507.00423) | iccv | Primary ICCV abstract reports effectiveness across various datasets and that the proposed defense reduces the attack's impact to a degree. |
| 195 | `geminio2025` | Junjie Shan; Ziqi Zhao; Jialin Lu; Rui Zhang; Siu Ming Yiu; Ka-Ho Chow | [Geminio: Language-Guided Gradient Inversion Attacks in Federated Learning](https://arxiv.org/abs/2411.14937) | iccv | Primary ICCV abstract reports high-success targeted reconstruction across complex datasets and large batch sizes, with resilience against existing ... |
| 196 | `hfia2025` | *(unverified)* | [HFIA: a parasitic feature inference attack and gradient-based defense strateg...](https://link.springer.com/article/10.1007/s10994-025-06804-2) | machine learning | -- |

#### 2026 (9 papers)

| # | Key | Authors | Title | Venue | Key Findings |
|---|-----|---------|-------|-------|--------------|
| 197 | `generic2026` | Yimin Liu; Peng Jiang; Qi Liu; Liehuang Zhu | [Generic Adversarial Attack Framework Against Graph-based Vertical Federated L...](https://ojs.aaai.org/index.php/AAAI/article/view/40878) | AAAI | -- |
| 198 | `retaliatory2026` | Xinyi Sheng; Wei Bao; Hequn Wang; Yuqin Liu; Sen Fu | [Retaliatory Attacks Against Federated Unlearning via Data Leakage](https://ojs.aaai.org/index.php/AAAI/article/view/39725) | AAAI | AAAI abstract reports attacks across varied federated-unlearning methods and demonstrates leakage/manipulation caused by the unlearning process. |
| 199 | `shadeedit2026` | Xu Zhang; Hangcheng Liu; Shangwei Guo; Shudong Zhang; Tianwei Zhang; Tao Xiang | [ShadeEdit: A Utility-Preserving and Defense-Evasive Knowledge Manipulation At...](https://ojs.aaai.org/index.php/AAAI/article/view/40787) | AAAI | AAAI abstract reports average 99.5% attack success across eight robust aggregation algorithms while maintaining instruction-following accuracy. |
| 200 | `venom2026` | B. Hu; J. Yuan; J. Jiang; C. Hu | [Venom: Liquid Diffusion-Guided Gradient Inversion for Breaking Differential P...](https://ojs.aaai.org/index.php/AAAI/article/view/39333) | AAAI | AAAI abstract reports high-fidelity recovery under strong DP and up to 38,343× speedup over prior approaches. |
| 201 | `exploring2026` | Pengxin Guo; Runxi Wang; Shuang Zeng; Jinjing Zhu; Haoning Jiang; Yanran Wang; Yuyin Zhou; Feifei Wang; Hui Xiong; Liangqiong Qu | [Exploring the Vulnerabilities of Federated Learning: A Deep Dive Into Gradien...](https://arxiv.org/abs/2503.11514) | TPAMI | -- |
| 202 | `beyond2026` | Zhihao Chen; Zirui Gong; Jianting Ning; Yanjun Zhang; Leo Yu Zhang | [Beyond Denial-of-Service: The Puppeteer's Attack for Fine-Grained Control in ...](https://arxiv.org/abs/2601.14687) | WWW | -- |
| 203 | `reconstructing2026` | *(unverified)* | [Reconstructing Training Data from Adapter-based Federated Large Language Models](https://arxiv.org/abs/2601.17533) | WWW | -- |
| 204 | `spattack2026` | Bo Yan; Yurong Hao; Dingqi Liu; Huabin Sun; Pengpeng Qiao; Wei Yang Bryan Lim; Yang Cao; Chuan Shi | [Spattack: Subgroup Poisoning Attacks on Federated Recommender Systems](https://arxiv.org/abs/2507.06258) | WWW | -- |
| 205 | `unveiling2026` | *(unverified)* | [Unveiling and Mitigating Untargeted Poisoning Attacks on Federated Knowledge ...](https://dl.acm.org/doi/10.1145/3774904.3792117) | WWW | -- |

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
