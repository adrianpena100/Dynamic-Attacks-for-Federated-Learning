"""
MITRE ATLAS technique registry and finding classifier for Dynamic FL.

Maps federated learning attack types and vulnerability patterns to
MITRE ATLAS technique IDs (v5.x). Cross-references findings with
published literature to classify novelty.

Usage:
    from atlas_mapping import classify_finding, get_attack_techniques, ATLAS_TECHNIQUES
"""

# ---------------------------------------------------------------------------
# ATLAS Technique Registry
# ---------------------------------------------------------------------------

ATLAS_TECHNIQUES = {
    "AML.T0020": {
        "name": "Poison Training Data",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0020",
        "description": "Adversary contaminates training data to alter ML model behavior.",
        "our_attacks": ["label_flip", "backdoor"],
        "category": "data_poisoning",
    },
    "AML.T0018": {
        "name": "Backdoor ML Model",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0018",
        "description": "Adversary embeds hidden behavior triggered by specific inputs.",
        "our_attacks": ["backdoor"],
        "category": "backdoor",
    },
    "AML.T0018.000": {
        "name": "Poison ML Model",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0018.000",
        "description": "Adversary poisons the model itself via corrupted updates.",
        "our_attacks": ["sign_flip", "gaussian_noise", "mean_shift", "alie"],
        "category": "model_poisoning",
    },
    "AML.T0043": {
        "name": "Craft Adversarial Data",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0043",
        "description": "Adversary crafts data designed to mislead ML systems.",
        "our_attacks": ["gaussian_noise", "sign_flip", "alie", "mean_shift",
                        "label_flip", "backdoor"],
        "category": "adversarial_crafting",
    },
    "AML.T0043.004": {
        "name": "Insert Backdoor Trigger",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0043.004",
        "description": "Adversary inserts trigger patterns into training data.",
        "our_attacks": ["backdoor"],
        "category": "backdoor_trigger",
    },
    "AML.T0015": {
        "name": "Evade ML Model",
        "tactic": "ML Evasion",
        "url": "https://atlas.mitre.org/techniques/AML.T0015",
        "description": "Adversary crafts inputs to evade ML model detection.",
        "our_attacks": [],
        "category": "evasion",
        "our_mechanisms": ["stealth_norm_capping", "alie_distribution_aware"],
    },
    "AML.T0031": {
        "name": "Erode ML Model Integrity",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0031",
        "description": "Adversary degrades model performance over time.",
        "our_attacks": ["gaussian_noise", "sign_flip", "alie", "mean_shift"],
        "category": "integrity_erosion",
        "our_outcomes": ["accuracy_drop", "model_collapse", "f1_drop"],
    },
    "AML.T0040": {
        "name": "AI Model Inference API Access",
        "tactic": "AI Model Access",
        "url": "https://atlas.mitre.org/techniques/AML.T0040",
        "description": "Adversary gains access to a model through its inference API, "
                       "enabling information gathering, attack staging, or impact.",
        "our_attacks": [],
        "category": "model_access",
        "our_mechanisms": ["fl_client_evaluates_global_model",
                          "adaptive_mab_measures_attack_impact"],
    },
    "AML.T0042": {
        "name": "Verify Attack",
        "tactic": "AI Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0042",
        "description": "Adversary confirms attack works by testing against inference API "
                       "or offline model copy before full deployment.",
        "our_attacks": [],
        "category": "attack_verification",
        "our_mechanisms": ["adaptive_mab_evaluates_attack_success",
                          "attack_effectiveness_feedback_loop"],
    },
    "AML.T0044": {
        "name": "Full AI Model Access",
        "tactic": "AI Model Access",
        "url": "https://atlas.mitre.org/techniques/AML.T0044",
        "description": "Adversary has complete white-box access to the AI model "
                       "including architecture, parameters, and class ontology.",
        "our_attacks": [],
        "category": "model_access",
        "our_mechanisms": ["fl_client_receives_global_model"],
    },
    "AML.T0007": {
        "name": "Discover ML Artifacts",
        "tactic": "Reconnaissance",
        "url": "https://atlas.mitre.org/techniques/AML.T0007",
        "description": "Adversary discovers information about ML artifacts.",
        "our_attacks": [],
        "category": "discovery",
        "our_mechanisms": ["adaptive_mab_probing", "defense_fingerprinting"],
    },
}


# ---------------------------------------------------------------------------
# Attack → ATLAS Technique Mapping
# ---------------------------------------------------------------------------

ATTACK_TO_TECHNIQUES = {
    "gaussian_noise": ["AML.T0018.000", "AML.T0043", "AML.T0031"],
    "sign_flip":      ["AML.T0018.000", "AML.T0043", "AML.T0031"],
    "alie":           ["AML.T0018.000", "AML.T0043", "AML.T0015", "AML.T0031"],
    "mean_shift":     ["AML.T0018.000", "AML.T0043", "AML.T0031"],
    "label_flip":     ["AML.T0020", "AML.T0043"],
    "backdoor":       ["AML.T0018", "AML.T0020", "AML.T0043", "AML.T0043.004"],
}

# Mechanism → ATLAS (non-attack-specific patterns)
MECHANISM_TO_TECHNIQUES = {
    "stealth_norm_capping":     ["AML.T0015"],
    "adaptive_mab":             ["AML.T0007", "AML.T0042"],
    "defense_fingerprinting":   ["AML.T0007"],
    "model_collapse":           ["AML.T0031"],
    "accuracy_degradation":     ["AML.T0031"],
    "fl_model_access":          ["AML.T0044", "AML.T0040"],
    "attack_verification":     ["AML.T0042"],
    "adaptive_feedback":       ["AML.T0040", "AML.T0042"],
}


# ---------------------------------------------------------------------------
# Literature Cross-Reference
# ---------------------------------------------------------------------------

LITERATURE = [
    {
        "key": "fang2020local",
        "authors": "Fang et al.",
        "title": "Local Model Poisoning Attacks to Byzantine-Robust Federated Learning",
        "venue": "USENIX Security 2020",
        "year": 2020,
        "finding": "Designed optimization-based model poisoning attacks that defeat Krum, Bulyan, "
                   "and trimmed mean aggregation rules.",
        "attacks": ["model_poisoning"],
        "defenses": ["krum", "multikrum", "bulyan", "fedtrimmedavg"],
        "atlas_techniques": ["AML.T0018.000", "AML.T0031"],
        "establishes": [
            "model_poisoning_against_byzantine_robust",
            "krum_failure_under_optimization",
            "bulyan_failure_under_optimization",
        ],
    },
    {
        "key": "shejwalkar2021manipulating",
        "authors": "Shejwalkar & Houmansadr",
        "title": "Manipulating the Byzantine: Optimizing Model Poisoning Attacks and Defenses "
                 "for Federated Learning",
        "venue": "NDSS 2021",
        "year": 2021,
        "finding": "Systematically evaluated optimized model poisoning attacks and defenses, "
                   "showing adaptive attacks can overcome robust aggregation.",
        "attacks": ["adaptive_model_poisoning"],
        "defenses": ["krum", "multikrum", "bulyan", "fedtrimmedavg", "fedmedian"],
        "atlas_techniques": ["AML.T0018.000", "AML.T0031", "AML.T0015"],
        "establishes": [
            "adaptive_attacks_defeat_robust_aggregation",
            "coordinated_poisoning_with_optimization",
        ],
    },
    {
        "key": "baruch2019little",
        "authors": "Baruch et al.",
        "title": "A Little Is Enough: Circumventing Defenses For Distributed Learning",
        "venue": "NeurIPS 2019",
        "year": 2019,
        "finding": "ALIE attack stays within the honest update distribution to evade "
                   "coordinate-wise defenses like trimmed mean and median.",
        "attacks": ["alie"],
        "defenses": ["fedtrimmedavg", "fedmedian"],
        "atlas_techniques": ["AML.T0018.000", "AML.T0015"],
        "establishes": [
            "alie_evades_coordinatewise_defenses",
            "distribution_aware_evasion",
        ],
    },
    {
        "key": "cao2021fltrust",
        "authors": "Cao et al.",
        "title": "FLTrust: Byzantine-robust Federated Learning via Trust Bootstrapping",
        "venue": "NDSS 2021",
        "year": 2021,
        "finding": "Trust bootstrapping with server-side root dataset provides Byzantine "
                   "robustness even when majority of clients are malicious.",
        "attacks": ["model_poisoning", "sign_flip"],
        "defenses": ["fltrust"],
        "atlas_techniques": ["AML.T0018.000"],
        "establishes": [
            "fltrust_resilience_mechanism",
            "cosine_trust_weighting",
        ],
    },
    {
        "key": "fung2020foolsgold",
        "authors": "Fung et al.",
        "title": "The Limitations of Federated Learning in Sybil Settings (FoolsGold)",
        "venue": "DLS Workshop 2020",
        "year": 2020,
        "finding": "Detects Sybil attacks by measuring pairwise similarity of client "
                   "gradient histories; penalizes clients with similar contributions.",
        "attacks": ["sybil_poisoning"],
        "defenses": ["foolsgold"],
        "atlas_techniques": ["AML.T0018.000"],
        "establishes": [
            "foolsgold_similarity_detection",
            "sybil_resistance_via_history",
        ],
    },
    {
        "key": "wan2022mabrfl",
        "authors": "Wan et al.",
        "title": "Shielding Federated Learning: A New Attack Approach and Its Defense "
                 "(MAB-RFL)",
        "venue": "IEEE 2022",
        "year": 2022,
        "finding": "Uses multi-armed bandit on the DEFENSE side for robust client "
                   "selection based on reputation scores.",
        "attacks": ["model_poisoning"],
        "defenses": ["mab-rfl"],
        "atlas_techniques": ["AML.T0007"],
        "establishes": [
            "mab_for_defense_client_selection",
            "reputation_based_robustness",
        ],
    },
    {
        "key": "li2024mab_vfl",
        "authors": "Li et al.",
        "title": "Multi-Armed Bandit for Optimal Client Corruption in VFL",
        "venue": "arXiv 2408.04310, 2024",
        "year": 2024,
        "finding": "Uses MAB to optimize which clients to corrupt in vertical FL. "
                   "Attack-side bandit, but for VFL not HFL.",
        "attacks": ["mab_attack_optimization"],
        "defenses": [],
        "atlas_techniques": ["AML.T0007"],
        "establishes": [
            "mab_for_attack_optimization_vfl",
        ],
    },
]

# Pre-index what the literature establishes (for novelty checking)
ESTABLISHED_FINDINGS = set()
for paper in LITERATURE:
    ESTABLISHED_FINDINGS.update(paper["establishes"])


# ---------------------------------------------------------------------------
# Finding Classification
# ---------------------------------------------------------------------------

FINDING_PATTERNS = {
    "defense_collapse": {
        "description": "Defense accuracy drops below 5% under attack",
        "atlas_techniques": ["AML.T0031", "AML.T0018.000"],
        "severity": "critical",
    },
    "high_slipthrough": {
        "description": "Malicious clients pass aggregation filter at >50% rate",
        "atlas_techniques": ["AML.T0015", "AML.T0018.000"],
        "severity": "high",
    },
    "trust_failure": {
        "description": "Malicious client receives trust score > 0.5",
        "atlas_techniques": ["AML.T0015"],
        "severity": "high",
    },
    "stealth_evasion": {
        "description": "Post-stealth malicious norm within honest p90 distribution",
        "atlas_techniques": ["AML.T0015", "AML.T0018.000"],
        "severity": "medium",
    },
    "adaptive_convergence": {
        "description": "MAB converges to a specific dominant attack per defense",
        "atlas_techniques": ["AML.T0007", "AML.T0042", "AML.T0040"],
        "severity": "medium",
    },
    "accuracy_degradation": {
        "description": "Significant accuracy drop (>10pp) under attack",
        "atlas_techniques": ["AML.T0031"],
        "severity": "medium",
    },
    "poor_trust_separation": {
        "description": "Benign and malicious trust scores overlap significantly",
        "atlas_techniques": ["AML.T0015"],
        "severity": "medium",
    },
    "backdoor_success": {
        "description": "Backdoor ASR increased significantly under attack",
        "atlas_techniques": ["AML.T0018", "AML.T0043.004"],
        "severity": "high",
    },
}

# Mapping from observed finding patterns to literature-established status
NOVELTY_RULES = {
    # (pattern, defense, attack) → novelty status
    # Well-established: basic poisoning attacks against Byzantine-robust defenses
    ("defense_collapse", "bulyan", "alie"): "known_weakness",
    ("defense_collapse", "bulyan", "*"): "known_weakness",
    ("defense_collapse", "multikrum", "*"): "known_weakness",
    ("defense_collapse", "fedtrimmedavg", "alie"): "known_weakness",
    ("defense_collapse", "fedmedian", "alie"): "known_weakness",
    ("high_slipthrough", "bulyan", "*"): "known_weakness",
    ("high_slipthrough", "multikrum", "*"): "known_weakness",
    ("stealth_evasion", "*", "alie"): "known_weakness",

    # Reproduced: consistent with literature but with our specific framework
    ("accuracy_degradation", "bulyan", "*"): "reproduced",
    ("accuracy_degradation", "multikrum", "*"): "reproduced",
    ("accuracy_degradation", "fedtrimmedavg", "*"): "reproduced",
    ("accuracy_degradation", "fedmedian", "*"): "reproduced",

    # Candidate new: findings involving our MAB attack-side approach
    ("adaptive_convergence", "*", "*"): "candidate_new",
    ("defense_collapse", "fltrust", "*"): "candidate_new",
    ("defense_collapse", "foolsgold", "*"): "candidate_new",
    ("defense_collapse", "flram", "*"): "candidate_new",
    ("defense_collapse", "mab-rfl", "*"): "candidate_new",
    ("trust_failure", "*", "*"): "candidate_new",
    ("poor_trust_separation", "*", "*"): "candidate_new",
}


def get_attack_techniques(attack_name):
    """Get ATLAS technique IDs for a given attack name (handles composite +joined)."""
    techniques = set()
    components = attack_name.split("+") if "+" in attack_name else [attack_name]
    for comp in components:
        comp = comp.strip()
        if comp in ATTACK_TO_TECHNIQUES:
            techniques.update(ATTACK_TO_TECHNIQUES[comp])
    return sorted(techniques)


def classify_novelty(pattern, defense, attack):
    """
    Classify a finding's novelty status.

    Returns one of:
        known_weakness  — well-documented in published literature
        reproduced      — consistent with literature, reproduced in our framework
        candidate_new   — potentially novel, not directly established by prior work
        needs_testing   — insufficient evidence to classify
    """
    # Try exact match
    key = (pattern, defense, attack)
    if key in NOVELTY_RULES:
        return NOVELTY_RULES[key]

    # Try wildcard attack
    key = (pattern, defense, "*")
    if key in NOVELTY_RULES:
        return NOVELTY_RULES[key]

    # Try wildcard defense
    key = (pattern, "*", attack)
    if key in NOVELTY_RULES:
        return NOVELTY_RULES[key]

    # Try full wildcard
    key = (pattern, "*", "*")
    if key in NOVELTY_RULES:
        return NOVELTY_RULES[key]

    return "needs_testing"


def classify_finding(pattern, defense, attack, accuracy_drop=None,
                     slipthrough_rate=None, trust_score=None,
                     collapse_detected=False):
    """
    Classify a vulnerability finding with ATLAS mapping and novelty status.

    Returns a dict with:
        pattern, defense, attack, atlas_techniques, novelty_status,
        severity, description, literature_refs, rationale
    """
    pattern_info = FINDING_PATTERNS.get(pattern, {})
    atlas_ids = list(pattern_info.get("atlas_techniques", []))

    # Also add attack-specific techniques
    if attack and attack != "none":
        atlas_ids = sorted(set(atlas_ids) | set(get_attack_techniques(attack)))

    novelty = classify_novelty(pattern, defense, attack)
    severity = pattern_info.get("severity", "medium")

    # Find relevant literature
    refs = []
    for paper in LITERATURE:
        # Check if this paper's established findings relate to our pattern
        defense_match = (defense in paper.get("defenses", []) or
                         not paper.get("defenses"))
        attack_components = attack.split("+") if attack else []
        attack_match = any(
            a in paper.get("attacks", []) for a in attack_components
        ) or any(
            cat in paper.get("attacks", [])
            for cat in ["model_poisoning", "adaptive_model_poisoning",
                        "sybil_poisoning", "mab_attack_optimization"]
        )
        technique_match = bool(
            set(atlas_ids) & set(paper.get("atlas_techniques", []))
        )

        if defense_match or attack_match or technique_match:
            refs.append(paper["key"])

    # Build rationale
    rationale_parts = []
    if novelty == "known_weakness":
        rationale_parts.append(
            f"This finding ({pattern}) for {defense} under {attack} is "
            f"well-documented in published literature."
        )
    elif novelty == "reproduced":
        rationale_parts.append(
            f"This finding reproduces known behavior for {defense} under "
            f"attack in our framework."
        )
    elif novelty == "candidate_new":
        rationale_parts.append(
            f"This finding represents a candidate new observation: {pattern} "
            f"for {defense} under {attack}."
        )
        if pattern == "adaptive_convergence":
            rationale_parts.append(
                "MAB-based attack selection converging to defense-specific "
                "dominant attacks is a novel contribution of this framework. "
                "Prior work uses MAB defensively (MAB-RFL, FedStrategist), "
                "not for attack-side vulnerability discovery."
            )
    else:
        rationale_parts.append(
            f"Insufficient evidence to classify. Needs replication with "
            f"3+ seeds and cross-dataset validation."
        )

    if collapse_detected:
        rationale_parts.append("Model collapse detected (accuracy < 5%).")
    if accuracy_drop and accuracy_drop > 0.2:
        rationale_parts.append(
            f"Severe accuracy degradation: {accuracy_drop:.1%} drop."
        )
    if slipthrough_rate and slipthrough_rate > 0.5:
        rationale_parts.append(
            f"High slipthrough rate: {slipthrough_rate:.1%} of malicious "
            f"clients passed aggregation filter."
        )

    return {
        "pattern": pattern,
        "defense": defense,
        "attack": attack,
        "atlas_technique_ids": atlas_ids,
        "atlas_techniques": [
            {"id": tid, "name": ATLAS_TECHNIQUES[tid]["name"]}
            for tid in atlas_ids if tid in ATLAS_TECHNIQUES
        ],
        "novelty_status": novelty,
        "severity": severity,
        "description": pattern_info.get("description", ""),
        "literature_refs": refs,
        "rationale": " ".join(rationale_parts),
    }


def get_literature_for_defense(defense):
    """Get papers relevant to a specific defense strategy."""
    return [p for p in LITERATURE if defense in p.get("defenses", [])]


def get_novelty_summary():
    """
    Return a structured summary of what's novel vs known in this framework.
    """
    return {
        "candidate_novel": [
            {
                "claim": "MAB on the ATTACK side for automated vulnerability discovery",
                "detail": "Most published work uses MAB defensively (MAB-RFL for "
                          "client selection, FedStrategist for defense selection). "
                          "Using MAB to adaptively select the most effective attack "
                          "per defense is a distinct contribution.",
                "prior_art": ["wan2022mabrfl", "li2024mab_vfl"],
                "distinction": "Prior MAB work is defense-side (client selection) or "
                               "VFL-specific. Ours is attack-side, HFL, multi-strategy.",
            },
            {
                "claim": "Multi-axis attack staging as systematic red-teaming",
                "detail": "Combining attack type × scheduling × layering × timing "
                          "as a structured vulnerability search space.",
                "prior_art": ["shejwalkar2021manipulating"],
                "distinction": "Prior work optimizes along one axis (attack type or "
                               "intensity). Our framework searches across multiple "
                               "orthogonal axes simultaneously.",
            },
            {
                "claim": "Automated defense fingerprinting via convergence patterns",
                "detail": "The adaptive engine converges to different dominant attacks "
                          "per defense, effectively identifying defense type through "
                          "output observation alone.",
                "prior_art": [],
                "distinction": "No direct prior art on using attack convergence "
                               "patterns to fingerprint FL defense mechanisms.",
            },
            {
                "claim": "Cross-defense ATLAS-mapped vulnerability comparison",
                "detail": "Systematic mapping of FL defense vulnerabilities to MITRE "
                          "ATLAS categories enables standardized comparison across "
                          "8 defense strategies.",
                "prior_art": [],
                "distinction": "MITRE ATLAS has not been applied as a systematic "
                               "framework for FL defense vulnerability assessment.",
            },
        ],
        "well_established": [
            "ALIE evading coordinate-wise defenses (Baruch et al. 2019)",
            "Krum/MultiKrum failure at moderate malicious fractions (Fang et al. 2020)",
            "Non-IID data degrading defense effectiveness (extensively studied)",
            "Basic model/data poisoning attacks against FL (well-established literature)",
            "FLTrust resilience via trust bootstrapping (Cao et al. 2021)",
        ],
    }
