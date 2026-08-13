# Novelty Map: Prior Art Coverage Matrix for FL Attack-Defense Evaluation

> **Purpose:** Systematic comparison of our framework's capabilities against published FL robustness literature.  
> Map each finding to: (a) prior work that covers it, (b) what is genuinely new.  
> **Last updated:** 2026-08-10  
> **Papers cataloged:** 60+  
> **Coverage:** NeurIPS, ICML, ICLR, USENIX Security, NDSS, IEEE S&P, ACM CCS, RAID, AISTATS, UAI, IJCAI, KDD, CVPR, WACV, MLSys, IEEE TSP, IEEE TBD, arXiv

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

### Gap 1: Attack-side MAB (epsilon-greedy bandit for the attacker)

**Status: NO prior work found** (60+ papers surveyed).

Prior MAB in FL is exclusively **defensive**: MAB-RFL (Wan 2022) uses bandit for client reputation, SARA (Hu 2025) uses bandit for defense selection, FedAA (AAAI 2025) uses RL for aggregation. Wang 2023 uses bandit for data poisoning in autonomous driving, but only for a single attack type against a single defense. RL-based aggregation defense (AAAI 2025) is defense-side, not attack-side.

No paper places an epsilon-greedy bandit in the hands of the attacker to select among 6 different poisoning primitives round-by-round based on observed model degradation.

**Novelty claim:** "To the best of our knowledge, this is the first framework to employ attacker-side multi-armed bandit selection among diverse poisoning primitives in federated learning."

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

| Finding | Why novel | Evidence strength |
|---------|-----------|-------------------|
| **Different dominant attack per defense under adaptive MAB** | No prior work tests attacker-side MAB across defenses | Moderate (single-seed, full sweep for 4 defenses, pilot for 4) |
| **Scheduling mode changes dominant attack** | No prior work sweeps scheduling as attack parameter | Moderate (single-seed, 252-run FEMNIST) |
| **Multi-layer composition causes universal collapse** | No benchmark tests stacked model poisoning | Moderate (sample_k with k=3 collapsed all 4 swept defenses) |
| **FoolsGold evasion via MAB switching + churn** | No prior work tests FoolsGold against adaptive + scheduled attacks | Weak (pilot, 1 attacked run) |
| **FLRAM bypassed by ALIE (all 3 sub-scores high)** | FLRAM only tested with basic attacks by own authors | Weak (pilot, 1 attacked run) |
| **MAB-RFL reputation exploit via delayed onset** | MAB-RFL only tested with basic attacks by own authors | Weak (pilot, 1 attacked run) |
| **FLTrust root dataset must scale with class count** | Cao21 tested only 10-class datasets | Moderate (3 root dataset sizes on 62-class) |
| **Bulyan clean baseline 57pp sensitivity range** | Parameterization sensitivity known but not quantified this extremely | Moderate (3 clean baselines) |
| **Trust-weight paradox (conservative params = weak discrimination)** | Not formalized in prior work | Moderate (all 4 trust defenses) |
| **Per-class accuracy reveals disproportionate class damage** | No prior work reports per-class under Byzantine | Moderate (62-class FEMNIST) |

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
