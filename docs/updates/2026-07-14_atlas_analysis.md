# Update: MITRE ATLAS Vulnerability Analysis Pipeline — July 14, 2026

## What Changed

Built the automated MITRE ATLAS vulnerability analysis pipeline. The system now queries the database, maps findings to real ATLAS technique IDs (AML.T####), classifies novelty against published literature, scores severity, populates the `agent_recommendations` table, and generates a structured vulnerability report. This closes the loop between experiment results and research claims.

Also ingested all remaining pilot sweeps — the database now contains **22 runs across all 8 defense strategies** with baseline comparisons.

### 1. New File: `db/atlas_mapping.py` (~300 lines)

MITRE ATLAS technique registry and finding classifier.

**ATLAS Techniques Mapped:**

| ATLAS ID | Name | Our Framework Mapping |
|---|---|---|
| AML.T0020 | Poison Training Data | label_flip, backdoor (data poisoning) |
| AML.T0018 | Backdoor ML Model | backdoor trigger injection |
| AML.T0018.000 | Poison ML Model | sign_flip, gaussian_noise, mean_shift, ALIE (model update poisoning) |
| AML.T0043 | Craft Adversarial Data | All crafted malicious model updates |
| AML.T0043.004 | Insert Backdoor Trigger | Backdoor pattern injection |
| AML.T0015 | Evade ML Model | Stealth norm-capping, ALIE distribution-aware evasion |
| AML.T0031 | Erode ML Model Integrity | Accuracy degradation, model collapse |
| AML.T0044 | Full ML Model Access | FL clients receive full global model each round |
| AML.T0007 | Discover ML Artifacts | Adaptive MAB engine probing defense behavior |

**Literature Cross-Reference (7 papers):**

| Paper | Year | Key Finding |
|---|---|---|
| Fang et al., "Local Model Poisoning Attacks" | USENIX Sec 2020 | Model poisoning against Krum/Bulyan |
| Shejwalkar & Houmansadr, "Manipulating the Byzantine" | NDSS 2021 | Adaptive attacks against robust aggregation |
| Baruch et al., "A Little Is Enough" | NeurIPS 2019 | ALIE evades coordinate-wise defenses |
| Cao et al., "FLTrust" | NDSS 2021 | Trust bootstrapping for Byzantine robustness |
| Fung et al., "FoolsGold" | DLS 2020 | Sybil resistance via similarity detection |
| Wan et al., "MAB-RFL" | IEEE 2022 | MAB for defense-side client selection |
| Li et al. | arXiv 2024 | MAB for attack optimization in VFL |

**Novelty Classification System:**
- `known_weakness` — well-documented in published literature
- `reproduced` — consistent with literature, reproduced in our framework
- `candidate_new` — potentially novel, not directly established by prior work
- `needs_testing` — insufficient evidence to classify

### 2. New File: `db/analyze.py` (~500 lines)

Automated analysis pipeline that:
1. Runs 8 analysis queries against the database (collapses, degradations, slipthrough, trust failures, stealth evasion, convergence, resilience)
2. Classifies each finding via the ATLAS mapper
3. Scores severity (defense_weakness, attack_effectiveness, evidence_strength, priority)
4. Writes results to `agent_recommendations` table (was previously empty)
5. Generates a full markdown vulnerability report at `docs/reports/vulnerability_report_atlas.md`

### 3. Schema Update: `db/schema.sql`

Added two columns to `agent_recommendations`:
- `atlas_technique_id TEXT` — comma-separated ATLAS IDs (e.g., "AML.T0018.000,AML.T0031")
- `novelty_status TEXT` — one of: known_weakness, reproduced, candidate_new, needs_testing

Updated `db/create_db.py` dummy data inserts and `db/validate.py` validation checks for the new columns.

### 4. Ingested All Remaining Pilot Sweeps

| Sweep | Strategy | Runs |
|-------|----------|------|
| bulyan_pilot_vuln v1 | bulyan | 2 (baseline + attacked) |
| fedmedian_pilot_vuln v1 | fedmedian | 2 |
| fedmedian_pilot_vuln v2 | fedmedian | 2 |
| fedtrimmedavg_pilot_vuln v1 | fedtrimmedavg | 2 |
| fedtrimmedavg_pilot_vuln v2 | fedtrimmedavg | 2 |
| flram_pilot_vuln v1 | flram | 2 |
| fltrust_pilot_vuln v1 | fltrust | 2 |
| fltrust_pilot_vuln v2 | fltrust | 2 |
| foolsgold_pilot_vuln v1 | foolsgold | 2 |
| mab-rfl_pilot_vuln v1 | mab-rfl | 2 |
| multikrum_pilot_vuln v1 | multikrum | 2 |
| **Total** | **8 strategies** | **22 runs** |

Empty/failed sweeps skipped: flram v2, foolsgold v2, mab-rfl v2.

## Analysis Results

### Findings Summary

| Category | Count | Examples |
|----------|-------|---------|
| **candidate_new** | 16 | FLRAM/FoolsGold/MAB-RFL collapse, trust failures, convergence patterns |
| **known_weakness** | 16 | Bulyan/MultiKrum/FedTrimmedAvg/FedMedian collapse, slipthrough, stealth evasion |
| **needs_testing** | 8 | Some stealth evasion patterns, resilient defense confirmations |

### Key Findings from Real Data

**Defense Collapses (accuracy < 5%):**

| Defense | Clean Accuracy | Attacked Accuracy | Drop | Dominant Attack |
|---------|---------------|-------------------|------|-----------------|
| MultiKrum | 36.1% | 1.6% | 34.5pp | backdoor |
| Bulyan | 35.7% | 1.6% | 34.0pp | sign_flip |
| FLRAM | 26.6% | 2.4% | 24.1pp | alie |
| FedTrimmedAvg | 26.1% | 2.9% | 23.2pp | alie |
| MAB-RFL | 20.7% | 2.7% | 18.0pp | mean_shift |
| FedMedian | 17.2% | 3.0% | 14.2pp | alie |
| FoolsGold | 17.0% | 3.3% | 13.8pp | alie |

**Only FLTrust survived** — 53.1% → 53.6% (no significant drop under adaptive attack).

**Adaptive Attack Convergence (Defense Fingerprinting, ATLAS: AML.T0007):**

| Defense | Dominant Attack | Rate | Known? |
|---------|----------------|------|--------|
| FedMedian | ALIE | 60% | Yes (Baruch et al. 2019) |
| FedTrimmedAvg | ALIE | 58% | Yes (Baruch et al. 2019) |
| FoolsGold | ALIE | 67% | Candidate new |
| MAB-RFL | ALIE | 60% | Candidate new |
| FLRAM | ALIE | 57% | Candidate new |
| MultiKrum | backdoor | 47% | Candidate new |
| Bulyan | sign_flip | 33% | Partial (Fang et al. 2020) |
| FLTrust | gaussian_noise | 25% | No convergence — no attack dominates |

**Trust Failures (malicious clients with trust > 0.5):**
- FoolsGold, MAB-RFL, and FLRAM all had malicious clients receiving high trust scores
- Classified as `candidate_new` — trust-based defense failures under adaptive attack are less studied

**Slipthrough Rates:**
- Bulyan: 100% of malicious clients passed aggregation (known weakness)
- MultiKrum: high slipthrough rate (known weakness)

### Novelty Assessment

**Candidate Novel Contributions (from literature cross-reference):**

1. **MAB on the ATTACK side for vulnerability discovery** — Most papers use MAB defensively (MAB-RFL for client selection, FedStrategist for defense selection). Using MAB to adaptively select the most effective attack per defense is distinct. Prior art: Wan et al. 2022 (defense-side), Li et al. 2024 (VFL, not HFL).

2. **Multi-axis attack staging as systematic red-teaming** — Combining attack type × scheduling × layering × timing as a structured search space. Prior work (Shejwalkar & Houmansadr 2021) optimizes along one axis.

3. **Defense fingerprinting via convergence** — The adaptive engine converges to different dominant attacks per defense, identifying defense type through output alone. No direct prior art.

4. **Cross-defense ATLAS-mapped vulnerability comparison** — Systematic ATLAS mapping across 8 FL defenses. ATLAS has not been applied as a systematic FL vulnerability framework.

**Well-Established (Not Novel):**
- ALIE evading coordinate-wise defenses (Baruch et al. 2019)
- Krum/MultiKrum failure under poisoning (Fang et al. 2020)
- FLTrust resilience via trust bootstrapping (Cao et al. 2021)
- Non-IID data degrading defenses (extensively studied)

### Caveats

- All findings from **single-seed pilot runs** — need 3+ seeds for statistical claims
- Only FEMNIST tested — cross-dataset validation needed
- Some defense baselines were already low (FedMedian: 17.2%, FoolsGold: 17.0%)
- ATLAS mappings are approximate — FL-specific patterns don't have exact 1:1 ATLAS equivalents
- Novelty claims are **candidate** status until comprehensive literature review

## Files Modified

| File | Change |
|------|--------|
| `db/atlas_mapping.py` | **New** — ATLAS technique registry, finding classifier, literature cross-reference |
| `db/analyze.py` | **New** — automated analysis pipeline and report generator |
| `db/schema.sql` | Added `atlas_technique_id` and `novelty_status` to `agent_recommendations` |
| `db/create_db.py` | Updated dummy data inserts for new columns |
| `db/validate.py` | Added validation checks for ATLAS columns |
| `db/ingest.py` | Added migration logic for new ATLAS columns |
| `docs/reports/vulnerability_report_atlas.md` | **New** — generated ATLAS-mapped vulnerability report |
| `docs/updates/2026-07-14_atlas_analysis.md` | **New** — this update |

## How to Use

```bash
# Full pipeline: ingest → analyze → report
python db/ingest.py logs/sweeps/*pilot*
python db/analyze.py

# View generated report
cat docs/reports/vulnerability_report_atlas.md

# Query recommendations table directly
sqlite3 db/dynamic_fl.sqlite "SELECT strategy, atlas_technique_id, novelty_status, priority_score FROM agent_recommendations ORDER BY priority_score DESC;"

# Run dummy validation (tests schema + all queries)
cd db && python validate.py
```

## What Remains

1. **Multi-seed replication** — Run 3+ seeds per configuration for statistical significance
2. **Cross-dataset validation** — Test on CIFAR-10 and MNIST to confirm findings generalize
3. **Stress test FLTrust** — Increase malicious fraction beyond 30% to find FLTrust's breaking point
4. **IID control experiments** — Separate non-IID effects from attack effects
5. **MAB bandit state logging** — `adaptive_attack_scores` table still placeholder (needs AttackEngine changes)
6. **Ingest full FEMNIST sweep** — 67 runs per strategy × 5 strategies from old sweep
7. **Comprehensive literature review** — Validate all candidate_new claims against broader literature
