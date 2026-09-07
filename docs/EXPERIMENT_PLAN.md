# Experimental Plan: Adaptive Attack Selection for FL Defense Evaluation

## Core Claim

**"Fixed single-attack evaluation overestimates FL defense robustness. Adaptive multi-strategy attackers reveal defense-specific failures that standard evaluation misses."**

Every experiment below either supports this claim or controls for confounds.

---

## Experiment 1: Clean Baselines (Required Foundation)

**What:** Every defense, no attack, matched hyperparameters.

| Config | Values |
|--------|--------|
| Defenses | All 8 (bulyan, multikrum, fedtrimmedavg, fedmedian, fltrust, foolsgold, flram, mab-rfl) |
| Datasets | FEMNIST (non-IID, alpha=0.5), CIFAR-10 (non-IID, alpha=0.5) |
| Seeds | 3 minimum (1337, 42, 7) |
| Rounds | 100 (current 30 is too few for convergence) |

**Why:** You can't claim an attack caused damage without knowing what the defense achieves clean. Every attacked run gets compared to its matched baseline.

**Validates:** Nothing on its own — this is the measuring stick for everything else.

**Runs:** 8 defenses x 2 datasets x 3 seeds = **48 runs**

---

## Experiment 2: Standard Single-Attack Evaluation (The Control)

**What:** Each attack primitive individually, fixed for all rounds, sticky attackers. This is how papers normally evaluate.

| Config | Values |
|--------|--------|
| Attacks | gaussian_noise, sign_flip, alie, mean_shift, label_flip, backdoor (6) |
| Attack mode | fixed (not adaptive) |
| Scheduling | sticky |
| Layering | single |
| Malicious fraction | 30% |
| Defenses | All 8 |
| Dataset | FEMNIST alpha=0.5 (primary), CIFAR-10 alpha=0.5 (validation) |
| Seeds | 3 |

**Why:** This is the standard evaluation methodology you're critiquing. You need to actually run it to show what it finds — and then show what it misses.

**Validates:** Establishes the "standard evaluation" baseline. For known (attack, defense) pairs, your results should roughly match the literature. If ALIE breaks FedMedian in the papers, it should break it here too. That confirms your framework reproduces known results.

**Runs:** 6 attacks x 8 defenses x 2 datasets x 3 seeds = **288 runs**

(Can trim to 1 dataset x 3 seeds = 144 runs for thesis, add second dataset for paper.)

---

## Experiment 3: Adaptive MAB Evaluation (The Contribution)

**What:** MAB selects from all attack primitives each round. Same conditions as Experiment 2 except attack selection is adaptive.

| Config | Values |
|--------|--------|
| Attack mode | adaptive (epsilon-greedy MAB) |
| Attack pool | all 6 primitives |
| Scheduling | sticky (to isolate the MAB effect) |
| Layering | single (to isolate the MAB effect) |
| Everything else | Same as Experiment 2 |

**Why:** This is the direct comparison. Same defenses, same malicious fraction, same data — only difference is the attacker can switch strategies. If the MAB finds worse outcomes than the best single attack from Experiment 2, that proves adaptive selection discovers failures fixed evaluation misses.

**Key metric:** For each defense, compare:
- Best single-attack accuracy drop (from Exp 2)
- MAB accuracy drop (from Exp 3)
- Which attack the MAB converged to
- Whether the MAB-selected attack matches the best single attack (if not, why?)

**Validates:** The central thesis claim. If the MAB always converges to the same attack that was already the best in Experiment 2, your contribution is weaker (the MAB is just automating a search you could do manually). If the MAB finds *worse outcomes* — especially through mid-training switching — that's the novel finding.

**Runs:** 8 defenses x 2 datasets x 3 seeds = **48 runs**

---

## Experiment 4: Ablation — What Makes Adaptive Attacks Stronger?

Isolate which dimensions contribute to the failures the MAB finds. Run each ablation against the 3-4 defenses that showed the biggest difference between Experiment 2 and Experiment 3.

### 4a: Composites

| Config | Values |
|--------|--------|
| Layering | fixed (2 attacks every round), sample_k (random k of N each round) |
| Attack pool | Top 3 composites from MAB convergence data |
| Everything else | Fixed attack mode (not adaptive), sticky |

**Asks:** Is the damage from composites, or from adaptation?

### 4b: Scheduling

| Config | Values |
|--------|--------|
| Scheduling | sticky, churn, per_round_random |
| Attack | The dominant attack from Experiment 3 for that defense |
| Everything else | Fixed attack mode, single layering |

**Asks:** Does scheduling alone break reputation-based defenses?

### 4c: Adaptive + Composites + Scheduling (Full Stack)

| Config | Values |
|--------|--------|
| Attack mode | adaptive |
| Layering | sample_k |
| Scheduling | per_round_random |
| Everything else | Same as Experiment 3 |

**Asks:** Does combining all three dimensions produce failures beyond any single dimension?

**Runs:** ~4 defenses x 3 ablations x 3 seeds x ~3 configs each = **~108 runs**

---

## Experiment 5: Malicious Fraction Sensitivity

**What:** Vary the attacker's power to find thresholds.

| Config | Values |
|--------|--------|
| Malicious fraction | 10%, 20%, 30%, 40%, 50% |
| Attack mode | adaptive MAB |
| Defenses | All 8 |
| Dataset | FEMNIST alpha=0.5 |
| Seeds | 3 |

**Why:** Defense papers state theoretical Byzantine tolerance (e.g., Bulyan tolerates < 25%). Your MAB might break them below or above that threshold. Finding the exact fraction where each defense fails under adaptive attack is a concrete, quantitative result.

**Runs:** 5 fractions x 8 defenses x 3 seeds = **120 runs**

---

## Experiment 6: Non-IID Stress Test

**What:** Vary Dirichlet alpha to test whether data heterogeneity interacts with adaptive attacks.

| Config | Values |
|--------|--------|
| Alpha | 0.1 (severe non-IID), 0.5 (moderate), 1.0 (mild), IID |
| Attack mode | adaptive MAB |
| Defenses | Top 4 most interesting from prior experiments |
| Dataset | FEMNIST |
| Seeds | 3 |

**Why:** Some defenses assume IID data. If a defense handles adaptive attacks under IID but fails under non-IID, that's a specific assumption violation you can point to.

**Runs:** 4 alphas x 4 defenses x 3 seeds = **48 runs**

---

## Total Run Budget

| Experiment | Runs |
|---|---|
| 1. Clean baselines | 48 |
| 2. Standard single-attack | 288 (or 144 with 1 dataset) |
| 3. Adaptive MAB | 48 |
| 4. Ablations | ~108 |
| 5. Malicious fraction | 120 |
| 6. Non-IID stress test | 48 |
| **Total** | **~660** (or ~516 trimmed) |

At 100 rounds each, this is significant compute time. For the thesis, you need all of it. For a paper, you can cut Experiments 5 and 6 and focus on 1-4.

---

## How to Validate Each Finding

### 1. Statistical Validity
- Every claim backed by 3+ seeds
- Report mean +/- std for accuracy drop, F1 drop
- Use paired t-tests or Wilcoxon signed-rank between Experiment 2 (fixed) and Experiment 3 (adaptive) for each defense

### 2. KB Cross-Reference
- Run every finding through `classify_finding()`
- KNOWN findings validate your framework (you reproduce published results)
- NOVEL findings are your contribution
- Report both — the KNOWN ones prove the framework works, the NOVEL ones prove it finds new things

### 3. Ablation Isolation
- If MAB beats best single attack, Experiment 4 tells you *why*
- "FoolsGold collapses under adaptive MAB" — is it the switching? The diversity? The composites? The ablation answers this

### 4. Convergence Analysis
- For each defense, report which attack the MAB converged to and at which round
- Compare to the best single-attack result from Experiment 2
- If they differ, explain why (the MAB found something the fixed evaluation missed)

### 5. Cross-Dataset
- If a finding holds on both FEMNIST and CIFAR-10, it's not dataset-specific
- If it only holds on one, say so explicitly

---

## Thesis Structure

| Chapter | Content |
|---|---|
| 1. Introduction | The evaluation gap — why fixed attacks aren't realistic |
| 2. Background | FL defenses, attack taxonomy, ATLAS threat model |
| 3. Framework | MAB mechanism, composite attacks, scheduling, KB-based classification |
| 4. Experimental Setup | Datasets, defenses, attack pool, hyperparameters, baselines |
| 5. Standard vs Adaptive Evaluation | Experiments 1-3: direct comparison showing the gap |
| 6. What Makes Adaptive Attacks Effective | Experiment 4: ablation results |
| 7. Sensitivity Analysis | Experiments 5-6: malicious fraction and non-IID |
| 8. Automated Novelty Classification | The KB, how classification works, which findings are new |
| 9. Discussion | Implications for defense evaluation methodology |
| 10. Conclusion | |

---

## Paper Structure (Condensed)

For a conference paper (8-10 pages):

| Section | Content |
|---|---|
| Intro | The gap + one motivating example (FoolsGold collapse) |
| Method | MAB mechanism + composite/scheduling (1.5 pages) |
| Experiments | Experiments 1-3 + top ablation results (3 pages) |
| Results | Defense-specific vulnerability profiles, convergence analysis (2 pages) |
| Discussion | Implications for evaluation methodology |

Drop Experiments 5-6 entirely. Focus on 4 defenses, not 8. One dataset primary, one validation.

---

## The "Generalized Framework" Sell

The framework pitch is: **"Give us any FL defense, we'll find its weaknesses."**

Validate this by showing:

1. **It reproduces known results** — run it against Krum with sign_flip, it finds the known weakness. Run it against FedMedian with ALIE, it finds the known weakness. The KB classifies these as KNOWN. This proves the framework works.

2. **It finds new things** — run it against FoolsGold with adaptive MAB, it finds a collapse nobody published. Run composites against Bulyan, it finds a failure mode nobody tested. The KB classifies these as NOVEL.

3. **It's plug-and-play** — to test a new defense, implement it in `server_app.py`, run the sweep, and get a vulnerability report automatically. No need to know what to attack it with — the MAB figures that out.

4. **The output is actionable** — the report doesn't just say "it broke." It says which assumption was violated, which attack the MAB converged to, and what the defense author should fix.

**Strongest demo:** Implement one defense NOT in the current 8 (e.g., Centered Clipping or DnC), run the full pipeline, and show it produces a complete vulnerability profile without any manual analysis. That's the "plug-and-play" proof.

---

## Novelty Detection Pipeline

How `run.sh` determines what's new:

```
run.sh runs an experiment
    |
post_run_analysis.py reads the CSVs from that run
    |
Detects patterns (accuracy drop, collapse, slipthrough, trust failure, etc.)
    |
For each finding, calls classify_finding() in atlas_mapping.py
    |
classify_finding() looks up the (attack, defense) pair in the KB
    |
KB has 99 known vulnerability pairs from 205 papers
    |
Output: [KNOWN], [REPRODUCED], [NOVEL], or [ROBUST]
```

### Lookup Logic (atlas_mapping.py)

1. Take the attack and defense from the run (e.g., "alie" + "fedmedian")
2. Search `known_vulnerabilities` in KB for that exact pair
3. Match exists AND paper says attack was effective -> **known_weakness** ("demonstrated by Paper X")
4. Match exists AND paper says defense withstood it -> **known_robust** ("literature says defense handles this")
5. Attack and defense both in KB but specific pair never tested -> **candidate_new** ("both exist but nobody tested this combo")
6. Either attack or defense not in KB at all -> **candidate_new**

### Honest Limitation

The KB covers 205 papers. If a paper tested a combination and we missed it, the classifier would wrongly call it novel. That's why the label is `candidate_new`, not `confirmed_novel` — it means "not in our KB," which is the best you can do without reading every paper ever written.

---

## What's Genuinely Unique (Confirmed by Literature Search)

Across all 205 papers in the KB (covering every top venue 2017-2026):

1. **MAB on the attack side** — 0 papers do this. Everyone uses bandits for defense (client selection, reputation). Nobody flipped it to the attacker.

2. **Multi-primitive selection per round** — 0 papers. The literature tests attacks one at a time. Nobody asks "what if the attacker has a toolkit and picks the best tool each round?"

3. **Composite + scheduling + adaptive together** — each axis exists in isolation. Nobody combines them.

4. **Automated novelty classification** — the KB + classifier pipeline that automatically determines if a finding is known or new. No other FL robustness paper does this.

### Closest Prior Work

| Paper | What it does | Why it's different |
|---|---|---|
| "Learning to Attack FL" (NeurIPS 2022) | RL learns a continuous poisoning policy | Produces attack vectors directly, doesn't select from a library |
| AutoAdapt (NDSS 2024) | Optimizes single attack's parameters | Tunes one attack, doesn't switch between attacks |
| MAB-RFL (IJCAI 2022) | MAB for client reputation scoring | Defense-side, not attack-side |
| A3FL, Chameleon, PoisonedFL | Adapt a single attack over time | Still one attack type, just refined over rounds |

---

## Project Explanation (Plain English)

### What is this project?

This project is a framework for stress-testing federated learning defenses. Federated learning is a way to train machine learning models across many devices or organizations without sharing raw data — each participant trains locally on their own data and sends model updates to a central server, which aggregates them into a single global model. The problem is that some of those participants can be malicious. They can send poisoned updates designed to make the global model worse, inject backdoors, or manipulate the training process. To counter this, researchers have built robust aggregation defenses — algorithms that try to detect and filter out malicious updates before they corrupt the model.

The core question this project asks: **how robust are these defenses, really?**

The current way the research community tests defenses is simple — take one attack, run it against one defense, report the results. Every defense paper does this. FedMedian is tested against ALIE. Krum is tested against sign flip. Bulyan is tested against a few known Byzantine attacks. And the papers report: "our defense is robust."

But that's not how a real attacker behaves. A real attacker doesn't pick one strategy and stick with it for the entire training process. A real attacker tries things. They probe. They see what works and do more of it. They combine multiple strategies. They rotate which clients are malicious. They wait before attacking. They escalate intensity.

This project builds the attacker that the defense papers never tested against.

### What does it do?

The framework puts an adaptive adversary — powered by a multi-armed bandit (MAB) — in charge of attack selection during federated learning training. Instead of using one fixed attack for all rounds, the MAB has a toolkit of attack primitives (noise injection, sign flipping, ALIE, mean shift, label flipping, backdoor) and chooses which one to deploy each round based on observed effectiveness. After each round, the MAB sees whether the global model's accuracy dropped or loss increased, and updates its selection strategy accordingly. Over time, it converges to the attack that causes the most damage to that specific defense.

On top of adaptive selection, the framework supports three additional dimensions that the literature almost never tests together:

**Composite attacks.** Instead of using one attack per round, malicious clients can layer multiple attacks simultaneously. A client might inject noise AND flip signs in the same update. The framework supports fixed composites (same combination every round) and sampled composites (randomly selecting k attacks from the toolkit each round).

**Scheduling variants.** The framework controls which clients are malicious and how that changes over time. "Sticky" means the same clients are always malicious (the standard assumption). "Churn" rotates malicious clients periodically. "Per-round random" selects a fresh random set of malicious clients every round. This matters because defenses that build reputation or trust scores over time — like FoolsGold, FLRAM, and MAB-RFL — rely on seeing the same clients repeatedly to build a behavioral profile. When malicious clients rotate, that history becomes useless.

**Delayed onset and intensity ramping.** Attacks can start at round 0 or wait until the model has partially converged. Attack intensity can be fixed or gradually increase. These dimensions test whether defenses that look robust early in training remain robust when the threat landscape changes mid-training.

The combination of all four dimensions — adaptive selection, composites, scheduling, and timing — creates a threat model that is far more realistic than what any defense paper tests against. And the MAB makes it computationally tractable: instead of exhaustively testing every possible combination, the bandit efficiently searches the space and converges to the most effective strategy.

### What does it expose?

The framework exposes a fundamental blind spot in FL defense evaluation: **defenses that look robust under standard single-attack testing can fail under adaptive multi-strategy attacks.**

Specific examples from existing data:

**FoolsGold collapse.** FoolsGold is a defense designed to detect Sybil attacks — groups of malicious clients sending similar updates. Its core assumption is that attackers produce correlated gradient histories. Under standard evaluation with a single fixed attack, FoolsGold works well because all malicious clients use the same attack, making their updates look similar. Under the MAB, different attacks get selected each round, so malicious clients' gradient histories become diverse. FoolsGold's similarity-based detection breaks down completely, and the model collapses to 3.3% accuracy. No paper in the literature tests this scenario.

**Bulyan composite failure.** Bulyan uses a two-stage filtering process — first Krum-style distance-based selection, then coordinate-wise trimming. Under fixed composite attacks, Bulyan collapses about 8% of the time. Under sampled composites (sample_k), the collapse rate jumps to 89%. The varying attack profiles each round create updates that individually pass the distance filter but collectively corrupt the trimmed aggregate. This specific failure mode is not documented in any of the 205 papers in the knowledge base.

**Reputation defense scheduling sensitivity.** Defenses that build trust or reputation scores over time (FoolsGold, FLRAM, MAB-RFL) assume clients have persistent identities and consistent behavior. When malicious clients rotate via per-round-random scheduling, the defense can't build accurate behavioral profiles. The trust scores become unreliable, and malicious updates pass the filter at higher rates. This is an assumption violation — the defense's stated design assumption (persistent client identity) is broken by the attacker's scheduling choice.

**FedMedian denial-of-learning.** FedMedian successfully rejects 100% of malicious updates in some configurations — and the model still collapses. This happens because triggering the defense mechanism itself reduces effective participation below the threshold needed for meaningful learning. The defense "works" in the sense that it filters correctly, but the act of filtering causes a denial-of-service effect. The attack wins not by evading the defense but by making the defense destroy the training process.

### Why is it new and novel?

We conducted a systematic literature search across 205 papers from every top venue in adversarial federated learning (IEEE S&P, NeurIPS, ICML, ICLR, USENIX, ACM CCS, NDSS, AAAI, CVPR, AISTATS, and more), covering the period from 2017 to 2026. Across all 205 papers:

**Zero papers use a multi-armed bandit or any bandit algorithm to select among multiple attack primitives on the attack side of federated learning.** Every prior use of MAB in FL is on the defense side — for client reputation scoring (MAB-RFL, IJCAI 2022), for client selection, or for resource allocation. Nobody has flipped the bandit to the attacker.

**Zero papers systematically switch between different attack types during FL training based on observed effectiveness.** A few papers adapt a single attack over time — PoisonedFL adapts consistency across rounds, AutoAdapt tunes hyperparameters of one attack, A3FL adapts a single backdoor strategy. But none of them choose between fundamentally different attack types (noise injection vs sign flipping vs ALIE vs backdoor) on a per-round basis.

**The closest prior work** is "Learning to Attack Federated Learning" (NeurIPS 2022), which uses reinforcement learning to learn an attack policy. But it learns a continuous policy that directly generates poisoned model updates. It does not select from a library of known attack implementations. The distinction matters: the MAB approach tests whether existing known attacks, when combined and selected adaptively, can break defenses that were shown to be robust against each attack individually. The RL approach asks a different question — whether a learned continuous policy can generate better attacks than hand-designed ones.

**No paper combines composite attacks, scheduling variants, and adaptive selection into a unified evaluation framework.** Each dimension exists in isolation in the literature. Composite/layered attacks exist (DBA, 3DFed). Scheduling/client selection is studied. Adaptive attacks exist. But nobody tests them together, and nobody studies the interactions between them.

**No paper automates novelty classification for FL vulnerability findings.** The knowledge base with 205 papers, 99 known (attack, defense) vulnerability pairs, defense assumption databases, and MITRE ATLAS mapping — with an automated classifier that determines whether a finding is known, reproduced, or potentially novel — does not exist anywhere else in the literature.

### How we will test it

The experimental validation has six phases designed to prove the central claim with statistical rigor:

**Phase 1** establishes clean baselines — every defense running without attacks, with matched hyperparameters, across multiple seeds and datasets. This is the ruler everything else is measured against.

**Phase 2** runs the standard single-attack evaluation that the literature uses. Each attack individually, fixed for all rounds, against every defense. This reproduces what defense papers normally report. If our framework finds the same known weaknesses the papers report, that proves the framework works correctly. These findings get classified as KNOWN by the KB, confirming calibration.

**Phase 3** is the core experiment. Same defenses, same conditions, but the attacker uses the MAB to select adaptively. We compare the damage from the best single attack (Phase 2) against the damage from adaptive selection (Phase 3). If adaptive selection causes more damage, that proves the central claim — fixed evaluation misses failures that adaptive evaluation catches. The MAB convergence data also reveals which attack each defense is most vulnerable to, producing defense-specific vulnerability profiles.

**Phase 4** runs ablations to isolate which dimensions matter. If the MAB beats the best single attack, is it because of the switching? The composites? The scheduling? We test each dimension independently against the 3-4 defenses that showed the biggest gap between Phase 2 and Phase 3. We also test the full stack (adaptive + composites + scheduling together) to see if the combination produces failures beyond any single dimension.

**Phase 5** varies the malicious fraction from 10% to 50% to find the threshold where each defense fails under adaptive attack. Defense papers claim theoretical Byzantine tolerance limits. We test whether those limits hold under adaptive adversaries.

**Phase 6** varies data heterogeneity (Dirichlet alpha from 0.1 to IID) to test whether non-IID data interacts with adaptive attacks. Some defenses assume IID data. If a defense handles adaptive attacks under IID but fails under non-IID, that's a specific, documentable assumption violation.

Every finding is validated through: multiple seeds (3+) for statistical significance, clean baseline comparison, KB cross-reference for novelty classification, ablation for causal isolation, and cross-dataset replication where feasible.

### How the system works end-to-end

The pipeline from experiment to finding to classification works as follows:

**Step 1: Run the experiment.** The researcher executes `run.sh` with a configuration specifying the defense, attack parameters, dataset, and seed. This launches a Flower federated learning simulation where the server uses the specified defense and malicious clients use the attack engine. The attack engine contains the MAB, composite attack logic, and scheduling logic.

**Step 2: Collect metrics.** During training, the framework logs everything: per-round accuracy, loss, F1, precision, recall, backdoor ASR (if applicable), per-class accuracy, which attack was selected each round, which clients were malicious, trust/reputation scores (for trust-based defenses), which clients were selected or rejected by the aggregation filter, and full attack configurations. All of this goes into structured CSVs and JSON files in the run's output directory.

**Step 3: Post-run analysis.** Immediately after the simulation finishes, `post_run_analysis.py` reads all the output files and detects vulnerability patterns. It checks for: model collapse (accuracy < 5%), severe accuracy degradation (> 20pp drop), high malicious client slipthrough (> 50% passing the filter), trust score failures (malicious clients getting high trust), adaptive convergence patterns (which attack the MAB selected most), denial-of-learning effects, and poor trust separation between honest and malicious clients. Each detected pattern becomes a "finding."

**Step 4: Novelty classification.** For each finding, the analysis calls `classify_finding()` in `atlas_mapping.py`. This function takes the attack, defense, and pattern, and looks them up against the knowledge base — a curated database of 205 papers with 99 known (attack, defense) vulnerability pairs. Each pair records which paper first demonstrated it, whether the attack was effective, and what mechanism was involved.

The classifier returns one of five labels:
- **KNOWN** — this exact (attack, defense) pair is documented as effective in the literature. Your finding reproduces published results.
- **REPRODUCED** — consistent with literature, confirming known behavior in your framework.
- **ROBUST** — the literature says this defense handles this attack. If your data disagrees, that's either a bug or a genuinely surprising result.
- **CANDIDATE NEW** — this (attack, defense) combination has not been tested in any of the 205 papers. Potentially novel, needs confirmation with more seeds and cross-dataset validation.
- **NEEDS TESTING** — insufficient evidence to classify.

The classifier also checks whether the finding violates a defense's stated assumptions (stored in the KB) and classifies the discovery type: assumption violation, synergistic composite, scheduling sensitivity, or unexpected convergence.

**Step 5: Map to MITRE ATLAS.** Each finding is mapped to the MITRE ATLAS adversarial ML threat framework, giving it a standardized taxonomy ID and placing it within a recognized threat classification system. This isn't about claiming new ATLAS categories — it's about using ATLAS as a common language to describe what the attack does and which threat category it falls under.

**Step 6: Generate the report.** The analysis produces a structured terminal output and a JSON file with all findings, their classifications, ATLAS mappings, evidence metrics, and suggested follow-up experiments. For a sweep (multiple runs), the database ingestion pipeline aggregates findings across all runs and the ATLAS analysis engine produces a comprehensive vulnerability report grouping findings by defense, by attack, by pattern, and by novelty status.

**Step 7: The researcher interprets.** The framework does the systematic work — running combinations, detecting patterns, classifying novelty — but the researcher makes the final judgment. A CANDIDATE NEW finding is a signal to investigate, not a confirmed discovery. The researcher checks: is this real or an artifact? Does it replicate across seeds? Does it hold on different datasets? Is the accuracy drop practically significant or just statistical noise? The framework accelerates the search; the researcher confirms the science.

### What this project is NOT

This project is not claiming to invent new attack algorithms. The attack primitives — Gaussian noise, sign flip, ALIE, mean shift, label flip, backdoor — are all from the existing literature. The novelty is in how they're combined, selected, and scheduled, and in the finding that adaptive selection reveals failures that static evaluation misses.

This project is not claiming that all FL defenses are broken. Most defenses work well against the specific attacks they were designed for. The claim is narrower: **the standard way defenses are evaluated doesn't test realistic adversarial behavior**, and when you do test realistically, some defenses fail in ways their original papers didn't anticipate.

This project is not a production attack tool. It's a research framework for stress-testing defenses. The goal is to help defense designers identify weaknesses before deployment, not to enable real-world attacks.

This project operates strictly in the training-time poisoning threat model. It does not address inference-time attacks, model extraction, privacy attacks, or attacks on deployed models. The MAB and all attack mechanisms operate during the FL aggregation rounds. If the model is already trained and deployed, this framework doesn't apply.
