"""
MITRE ATLAS technique registry and finding classifier for Dynamic FL.

Maps federated learning attack types and vulnerability patterns to
MITRE ATLAS technique IDs (v5.x). Cross-references findings with a
unified knowledge base of known vulnerabilities and 200+ papers.

Usage:
    from atlas_mapping import classify_finding, get_attack_techniques, ATLAS_TECHNIQUES
    from atlas_mapping import build_finding_context  # rich context for reports
"""

import json
import os

# ---------------------------------------------------------------------------
# Knowledge Base Loader
# ---------------------------------------------------------------------------

_KB = None
_KB_PATH = os.path.join(os.path.dirname(__file__), "known_vulnerabilities.json")


def _load_kb():
    global _KB
    if _KB is not None:
        return _KB
    try:
        with open(_KB_PATH, "r") as f:
            _KB = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        _KB = {"attacks": {}, "defenses": {}, "known_vulnerabilities": [],
               "novel_dimensions": [], "papers": []}
    return _KB


def _normalize_name(name, registry):
    """Resolve an attack or defense name via KB aliases."""
    if not name:
        return name
    lower = name.lower().strip()
    if lower in registry:
        return lower
    for canonical, info in registry.items():
        if lower in [a.lower() for a in info.get("aliases", [])]:
            return canonical
    return lower


# ---------------------------------------------------------------------------
# Unified Paper Search (queries the merged KB)
# ---------------------------------------------------------------------------


def _search_papers(attack=None, defense=None, family=None, scope="in_scope"):
    """
    Search the unified KB papers list.

    Filters by attack (in attacks_tested), defense (in defenses_tested),
    attack_family, and scope. Uses the alias system for fuzzy matching.
    Only returns in-scope papers by default.
    """
    kb = _load_kb()
    papers = kb.get("papers", [])
    attack_n = _normalize_name(attack, kb.get("attacks", {})) if attack else None
    defense_n = _normalize_name(defense, kb.get("defenses", {})) if defense else None

    results = []
    for p in papers:
        if scope and p.get("scope", "in_scope") != scope:
            continue

        match = False
        if attack_n and attack_n in p.get("attacks_tested", []):
            match = True
        if defense_n and defense_n in p.get("defenses_tested", []):
            match = True
        if family and p.get("attack_family", "") == family:
            match = True

        if match:
            results.append(p)

    return results


# ---------------------------------------------------------------------------
# ATLAS Sub-Category Mapping
# ---------------------------------------------------------------------------

ATLAS_SUB_CATEGORIES = {
    "AML.T0020": {
        "name": "Poison Training Data",
        "xlsx_families": ["Model/data poisoning"],
        "sub_techniques": [
            {"id": "label_poisoning", "name": "Label Corruption",
             "attacks": ["label_flip"],
             "description": "Flips or corrupts training labels to degrade model accuracy"},
            {"id": "feature_poisoning", "name": "Feature-Space Manipulation",
             "attacks": ["backdoor"],
             "description": "Modifies training features or injects trigger patterns"},
        ],
    },
    "AML.T0018": {
        "name": "Backdoor ML Model",
        "xlsx_families": ["Backdoor"],
        "sub_techniques": [
            {"id": "centralized_backdoor", "name": "Single-Client Backdoor",
             "attacks": ["backdoor", "constrain_and_scale"],
             "description": "Single malicious client embeds a trigger pattern"},
            {"id": "distributed_backdoor", "name": "Distributed Backdoor",
             "attacks": ["dba"],
             "description": "Trigger pattern distributed across multiple malicious clients"},
            {"id": "durable_backdoor", "name": "Durable/Persistent Backdoor",
             "attacks": ["neurotoxin", "a3fl"],
             "description": "Backdoor survives aggregation and fine-tuning over many rounds"},
            {"id": "adaptive_backdoor", "name": "Defense-Adaptive Backdoor",
             "attacks": ["3dfed", "a3fl", "layerdba"],
             "description": "Backdoor that adapts its strategy to evade specific defenses"},
        ],
    },
    "AML.T0018.000": {
        "name": "Poison ML Model",
        "xlsx_families": ["Model/data poisoning"],
        "sub_techniques": [
            {"id": "untargeted_poisoning", "name": "Untargeted Model Poisoning",
             "attacks": ["gaussian_noise", "sign_flip", "mean_shift"],
             "description": "Degrades overall model accuracy without a specific target class"},
            {"id": "distribution_aware", "name": "Distribution-Aware Poisoning",
             "attacks": ["alie", "ipm"],
             "description": "Crafts updates within honest distribution bounds to evade statistical defenses"},
            {"id": "defense_optimized", "name": "Defense-Optimized Poisoning",
             "attacks": ["fang", "min_max", "min_sum", "autoadapt"],
             "description": "Optimizes malicious updates specifically against the target defense mechanism"},
            {"id": "structural_poisoning", "name": "Structural/Subnetwork Poisoning",
             "attacks": ["pill", "oblivion"],
             "description": "Targets model structure (subnetworks, specific layers) rather than full updates"},
        ],
    },
    "AML.T0015": {
        "name": "Evade ML Model",
        "xlsx_families": ["Adversarial / evasion"],
        "sub_techniques": [
            {"id": "norm_evasion", "name": "Norm-Based Defense Evasion",
             "attacks": ["constrain_and_scale"],
             "description": "Constrains update norm to pass norm-based filtering"},
            {"id": "similarity_evasion", "name": "Similarity-Based Defense Evasion",
             "attacks": ["alie", "mimic", "good_gradients"],
             "description": "Maintains high cosine similarity or statistical similarity to honest updates"},
            {"id": "boundary_evasion", "name": "Boundary-Adaptive Evasion",
             "attacks": ["good_gradients", "autoadapt"],
             "description": "Finds the exact boundary of defense acceptance regions and operates just inside"},
        ],
    },
    "AML.T0031": {
        "name": "Erode ML Model Integrity",
        "xlsx_families": ["Model/data poisoning"],
        "sub_techniques": [
            {"id": "accuracy_erosion", "name": "Accuracy Degradation",
             "attacks": ["gaussian_noise", "sign_flip", "alie", "mean_shift"],
             "description": "Gradually or suddenly degrades overall model accuracy"},
            {"id": "model_collapse", "name": "Model Collapse",
             "attacks": ["sign_flip", "fang"],
             "description": "Causes model to lose all discriminative ability (accuracy near random)"},
            {"id": "targeted_erosion", "name": "Targeted Class Degradation",
             "attacks": ["label_flip"],
             "description": "Degrades performance on specific classes while maintaining overall accuracy"},
        ],
    },
    "AML.T0007": {
        "name": "Discover ML Artifacts",
        "xlsx_families": [],
        "sub_techniques": [
            {"id": "defense_fingerprinting", "name": "Defense Fingerprinting via MAB",
             "attacks": [],
             "description": "Adaptive MAB attack selection reveals defense-specific weaknesses by converging to different dominant attacks per defense"},
        ],
    },
}


def lookup_known_vulnerability(attack, defense):
    """Return all KB entries matching (attack, defense). Normalizes via aliases."""
    kb = _load_kb()
    attack_n = _normalize_name(attack, kb.get("attacks", {}))
    defense_n = _normalize_name(defense, kb.get("defenses", {}))
    matches = []
    for v in kb.get("known_vulnerabilities", []):
        if v["attack"] == attack_n and v["defense"] == defense_n:
            matches.append(v)
    return matches


def is_novel_dimension(attack_mode=None, selection_mode=None,
                       layering_mode=None, onset_round=0,
                       intensity_ramp=1.0):
    """Check which novel dimensions (0 prior art) this run uses."""
    kb = _load_kb()
    active = []
    for nd in kb.get("novel_dimensions", []):
        dim = nd["dimension"]
        if dim == "adaptive_mab_attack" and attack_mode == "adaptive":
            active.append(nd)
        elif dim == "composite_layering" and layering_mode in ("fixed", "sample_k"):
            active.append(nd)
        elif dim == "churn_scheduling" and selection_mode == "churn":
            active.append(nd)
        elif dim == "sticky_scheduling" and selection_mode == "sticky":
            active.append(nd)
        elif dim == "delayed_onset" and onset_round and onset_round > 0:
            active.append(nd)
        elif dim == "intensity_ramping" and intensity_ramp and intensity_ramp > 1.0:
            active.append(nd)
    return active


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
# Literature Cross-Reference (loaded from KB)
# ---------------------------------------------------------------------------

def _get_kb_papers():
    """Return the papers list from the KB (for literature cross-reference)."""
    kb = _load_kb()
    return kb.get("papers", [])


LITERATURE = _get_kb_papers()
ESTABLISHED_FINDINGS = set()


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

PATTERN_TO_MECHANISMS = {
    "adaptive_convergence": ["adaptive_mab", "defense_fingerprinting"],
    "stealth_evasion": ["stealth_norm_capping"],
    "defense_collapse": ["model_collapse", "accuracy_degradation"],
    "accuracy_degradation": ["accuracy_degradation"],
    "trust_failure": ["fl_model_access"],
    "poor_trust_separation": ["fl_model_access"],
    "backdoor_success": ["attack_verification"],
}


def get_attack_techniques(attack_name):
    """Get ATLAS technique IDs for a given attack name (handles composite +joined)."""
    techniques = set()
    components = attack_name.split("+") if "+" in attack_name else [attack_name]
    kb = _load_kb()
    for comp in components:
        comp = comp.strip()
        if comp in ATTACK_TO_TECHNIQUES:
            techniques.update(ATTACK_TO_TECHNIQUES[comp])
        else:
            # KB fallback: collect atlas_ids from known_vulnerabilities
            comp_n = _normalize_name(comp, kb.get("attacks", {}))
            for v in kb.get("known_vulnerabilities", []):
                if v["attack"] == comp_n and v.get("atlas_ids"):
                    techniques.update(v["atlas_ids"])
    return sorted(techniques)


def classify_novelty(pattern, defense, attack):
    """
    Classify a finding's novelty status using the KB.

    Returns one of:
        known_weakness  — well-documented in published literature
        reproduced      — consistent with literature, reproduced in our framework
        known_robust    — literature documents the defense withstands this attack
        candidate_new   — potentially novel, not directly established by prior work
        needs_testing   — insufficient evidence to classify
    """
    kb = _load_kb()
    attack_n = _normalize_name(attack, kb.get("attacks", {}))
    defense_n = _normalize_name(defense, kb.get("defenses", {}))

    # Adaptive convergence is always candidate_new (our MAB contribution)
    if pattern == "adaptive_convergence":
        return "candidate_new"

    # Trust failure / poor trust separation for trust-based defenses
    if pattern in ("trust_failure", "poor_trust_separation"):
        trust_defenses = {"fltrust", "foolsgold", "flram", "mab-rfl"}
        if defense_n in trust_defenses:
            return "candidate_new"

    # Check KB for matching known vulnerabilities
    matches = lookup_known_vulnerability(attack_n, defense_n)

    if matches:
        effective_matches = [m for m in matches if m.get("effective", True)]
        if effective_matches:
            if pattern in ("defense_collapse", "high_slipthrough", "stealth_evasion"):
                return "known_weakness"
            return "reproduced"
        else:
            return "known_robust"

    # Check if attack is in KB at all (even against other defenses)
    any_attack_match = any(
        v["attack"] == attack_n for v in kb.get("known_vulnerabilities", [])
    )
    any_defense_match = any(
        v["defense"] == defense_n for v in kb.get("known_vulnerabilities", [])
    )

    if any_attack_match and any_defense_match and not matches:
        return "candidate_new"

    if not any_attack_match or not any_defense_match:
        return "candidate_new"

    return "needs_testing"


def classify_finding(pattern, defense, attack, accuracy_drop=None,
                     slipthrough_rate=None, trust_score=None,
                     collapse_detected=False):
    """
    Classify a vulnerability finding with ATLAS mapping and novelty status.

    Returns a dict with:
        pattern, defense, attack, atlas_techniques, novelty_status,
        severity, description, literature_refs, rationale,
        kb_matches, kb_novel_dimensions
    """
    kb = _load_kb()
    pattern_info = FINDING_PATTERNS.get(pattern, {})
    atlas_ids = list(pattern_info.get("atlas_techniques", []))

    if attack and attack != "none":
        atlas_ids = sorted(set(atlas_ids) | set(get_attack_techniques(attack)))

    # Mechanism-based ATLAS enrichment
    mechanism_keys = PATTERN_TO_MECHANISMS.get(pattern, [])
    for mk in mechanism_keys:
        if mk in MECHANISM_TO_TECHNIQUES:
            atlas_ids = sorted(set(atlas_ids) | set(MECHANISM_TO_TECHNIQUES[mk]))

    novelty = classify_novelty(pattern, defense, attack)
    severity = pattern_info.get("severity", "medium")

    # KB vulnerability matches
    kb_matches = lookup_known_vulnerability(attack, defense)

    # Find relevant literature from KB papers
    refs = []
    attack_n = _normalize_name(attack, kb.get("attacks", {}))
    defense_n = _normalize_name(defense, kb.get("defenses", {}))
    for paper in kb.get("papers", []):
        defense_match = defense_n in paper.get("defenses_tested", [])
        attack_components = attack.split("+") if attack else []
        attack_match = any(
            _normalize_name(a, kb.get("attacks", {}))
            in paper.get("attacks_tested", [])
            for a in attack_components
        )
        if defense_match or attack_match:
            refs.append(paper["key"])

    # Deduplicate refs from KB matches
    for m in kb_matches:
        if m.get("first_demonstrated") and m["first_demonstrated"] not in refs:
            refs.append(m["first_demonstrated"])
        for c in m.get("confirmed_by", []):
            if c not in refs:
                refs.append(c)

    # Build rationale
    rationale_parts = []
    if novelty == "known_weakness":
        match_count = len(kb_matches)
        rationale_parts.append(
            f"KNOWN ({match_count} KB entries). "
            f"{pattern} for {defense} under {attack} is documented "
            f"in {len(refs)} papers."
        )
    elif novelty == "reproduced":
        rationale_parts.append(
            f"REPRODUCED. This finding confirms known behavior for "
            f"{defense} under attack in our framework."
        )
    elif novelty == "known_robust":
        match_count = len(kb_matches)
        rationale_parts.append(
            f"ROBUST ({match_count} KB entries). "
            f"Defense {defense} is documented to withstand {attack}."
        )
    elif novelty == "candidate_new":
        rationale_parts.append(
            f"NOVEL (0 matches in {len(kb.get('known_vulnerabilities', []))}-entry KB). "
            f"{pattern} for {defense} under {attack}."
        )
        if pattern == "adaptive_convergence":
            rationale_parts.append(
                "MAB-based attack selection converging to defense-specific "
                "dominant attacks is a novel contribution of this framework."
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
        "kb_matches": [
            {"id": m["id"], "effective": m.get("effective", True),
             "first_demonstrated": m.get("first_demonstrated", ""),
             "mechanism": m.get("mechanism", "")}
            for m in kb_matches
        ],
    }


def get_literature_for_defense(defense):
    """Get papers relevant to a specific defense strategy."""
    kb = _load_kb()
    defense_n = _normalize_name(defense, kb.get("defenses", {}))
    return [p for p in kb.get("papers", [])
            if defense_n in p.get("defenses_tested", [])]


def get_novelty_summary():
    """
    Return a structured summary of what's novel vs known in this framework,
    driven by the knowledge base.
    """
    kb = _load_kb()
    novel_dims = kb.get("novel_dimensions", [])
    total_kvs = len(kb.get("known_vulnerabilities", []))
    total_papers = len(kb.get("papers", []))

    _novel_distinctions = {
        "adaptive_mab_attack": (
            "Existing adaptive attacks (Fang, AutoAdapt) optimize a single attack against "
            "a known defense. Our MAB selects among 6 primitives with no prior knowledge "
            "of the defense, converging to defense-specific weaknesses autonomously."
        ),
        "composite_layering": (
            "DBA distributes a single backdoor trigger. Our layering stacks multiple "
            "model-poisoning primitives (e.g. ALIE + sign_flip) on the same update, "
            "testing whether combined attacks breach defenses that withstand each primitive alone."
        ),
        "churn_scheduling": (
            "On-off attacks (Moshawrab 2023) alternate a fixed client between honest and "
            "malicious. Our churn rotates which clients are malicious each round, testing "
            "defenses that track client identity for reputation scoring."
        ),
        "sticky_scheduling": (
            "Most FL attack papers use random per-round malicious assignment. Sticky scheduling "
            "keeps the same clients malicious across all rounds, testing whether persistent "
            "identity helps or hurts the attacker against reputation-based defenses."
        ),
        "delayed_onset": (
            "No prior work systematically tests delayed-onset attacks where N honest rounds "
            "build legitimate reputation before the attack begins. This directly tests whether "
            "trust/reputation defenses can detect behavioral shifts."
        ),
        "intensity_ramping": (
            "Prior attacks use constant intensity. Gradual ramping tests whether defenses "
            "with adaptive thresholds can detect slowly increasing attack strength."
        ),
    }

    _novel_prior_art = {
        "adaptive_mab_attack": ["fang2020", "autoadapt2024"],
        "composite_layering": ["dba2020"],
        "churn_scheduling": ["jmlr_attacks2023"],
        "sticky_scheduling": [],
        "delayed_onset": [],
        "intensity_ramping": [],
    }

    candidate_novel = []
    for nd in novel_dims:
        dim = nd["dimension"]
        candidate_novel.append({
            "claim": dim.replace("_", " ").title(),
            "detail": nd["description"],
            "papers_searched": nd.get("papers_searched", 0),
            "papers_found": nd.get("papers_found", 0),
            "prior_art": _novel_prior_art.get(dim, []),
            "distinction": _novel_distinctions.get(dim, "No direct prior art found."),
        })

    well_established = []
    for kv in kb.get("known_vulnerabilities", []):
        if kv.get("effective", True) and kv.get("first_demonstrated"):
            paper = next(
                (p for p in kb.get("papers", [])
                 if p["key"] == kv["first_demonstrated"]), None)
            if paper:
                label = (f"{kv['attack']} vs {kv['defense']}: "
                         f"{kv.get('mechanism', 'see paper')} "
                         f"({paper.get('authors', [''])[0].split(',')[0]} "
                         f"et al. {paper.get('year', '?')})")
                well_established.append(label)

    return {
        "kb_stats": {
            "total_known_vulnerabilities": total_kvs,
            "total_papers": total_papers,
        },
        "candidate_novel": candidate_novel,
        "well_established": well_established[:20],
    }


# ---------------------------------------------------------------------------
# Rich Finding Context Builder
# ---------------------------------------------------------------------------

def build_finding_context(attack, defense, pattern, accuracy_drop=None,
                          slipthrough_rate=None, trust_score=None,
                          dominant_attack_fraction=None):
    """
    Build a rich knowledge-base context for a single finding.

    Queries the unified KB (known_vulnerabilities.json) which contains
    all papers from both the original structured KB and the XLSX survey.

    Returns a dict with defense_profile, attack_profile, atlas_mapping,
    literature (unified), mab_insight, and plain-English summaries.
    """
    kb = _load_kb()

    attack_n = _normalize_name(attack, kb.get("attacks", {}))
    defense_n = _normalize_name(defense, kb.get("defenses", {}))

    # --- Defense profile ---
    defense_info = kb.get("defenses", {}).get(defense_n, {})
    defense_profile = {
        "name": defense_n,
        "category": defense_info.get("category", "unknown"),
        "description": defense_info.get("description", ""),
        "assumptions": defense_info.get("assumptions", []),
        "first_paper": defense_info.get("first_paper", ""),
    }

    # --- Attack profile ---
    attack_info = kb.get("attacks", {}).get(attack_n, {})
    attack_components = attack.split("+") if attack and "+" in attack else [attack_n]
    attack_profile = {
        "name": attack_n,
        "original_name": attack,
        "category": attack_info.get("category", "unknown"),
        "description": attack_info.get("description", ""),
        "is_composite": "+" in (attack or ""),
        "components": attack_components,
    }

    # --- ATLAS mapping with sub-categories ---
    atlas_ids = get_attack_techniques(attack) if attack else []
    mechanism_keys = PATTERN_TO_MECHANISMS.get(pattern, [])
    for mk in mechanism_keys:
        if mk in MECHANISM_TO_TECHNIQUES:
            atlas_ids = sorted(set(atlas_ids) | set(MECHANISM_TO_TECHNIQUES[mk]))

    sub_cats = []
    for tid in atlas_ids:
        if tid in ATLAS_SUB_CATEGORIES:
            sc = ATLAS_SUB_CATEGORIES[tid]
            matching_subs = []
            for st in sc.get("sub_techniques", []):
                if any(a in st.get("attacks", []) for a in attack_components):
                    matching_subs.append(st)
            if matching_subs:
                sub_cats.append({
                    "atlas_id": tid,
                    "atlas_name": sc["name"],
                    "matched_sub_techniques": matching_subs,
                })

    atlas_mapping = {
        "main_techniques": [
            {"id": tid, "name": ATLAS_TECHNIQUES[tid]["name"],
             "tactic": ATLAS_TECHNIQUES[tid].get("tactic", "")}
            for tid in atlas_ids if tid in ATLAS_TECHNIQUES
        ],
        "sub_categories": sub_cats,
    }

    # --- Unified literature search ---
    kb_matches = lookup_known_vulnerability(attack_n, defense_n)
    novelty = classify_novelty(pattern, defense_n, attack_n)

    # Papers that tested this exact attack+defense combo
    confirming_papers = []
    for m in kb_matches:
        if m.get("first_demonstrated"):
            paper = next((p for p in kb.get("papers", [])
                          if p["key"] == m["first_demonstrated"]), None)
            if paper and paper["key"] not in [c["key"] for c in confirming_papers]:
                confirming_papers.append(paper)
        for ckey in m.get("confirmed_by", []):
            paper = next((p for p in kb.get("papers", [])
                          if p["key"] == ckey), None)
            if paper and paper["key"] not in [c["key"] for c in confirming_papers]:
                confirming_papers.append(paper)

    # Papers that tested this attack OR this defense (broader context)
    attack_papers = _search_papers(attack=attack_n)
    defense_papers = _search_papers(defense=defense_n)
    confirming_keys = {p["key"] for p in confirming_papers}
    related_papers = []
    seen_keys = set(confirming_keys)
    for p in attack_papers + defense_papers:
        if p["key"] not in seen_keys:
            related_papers.append(p)
            seen_keys.add(p["key"])

    # Papers that broke this defense
    defense_breaking_papers = [
        p for p in kb.get("papers", [])
        if p.get("defense_breaking") and p.get("scope") == "in_scope"
        and defense_n in p.get("defenses_tested", [])
    ]

    # Attack family context
    attack_cat = attack_info.get("category", "")
    family_map = {
        "model_poisoning": "Model/data poisoning",
        "data_poisoning": "Model/data poisoning",
    }
    attack_family = family_map.get(attack_cat, "")
    family_papers = _search_papers(family=attack_family) if attack_family else []

    total_in_scope = sum(
        1 for p in kb.get("papers", []) if p.get("scope") == "in_scope"
    )

    def _paper_summary(p):
        return {
            "key": p.get("key", ""),
            "title": p.get("title", ""),
            "year": p.get("year", ""),
            "venue": p.get("venue", ""),
            "authors": p.get("authors", ""),
            "mechanism": (p.get("mechanism", "") or "")[:200],
            "experimental_results": (p.get("experimental_results", "") or "")[:200],
            "defense_breaking": p.get("defense_breaking", False),
        }

    literature = {
        "status": novelty,
        "matching_papers": [_paper_summary(p) for p in confirming_papers],
        "related_papers": [_paper_summary(p) for p in related_papers[:15]],
        "defense_breaking_papers": [_paper_summary(p) for p in defense_breaking_papers[:5]],
        "attack_family": attack_family,
        "attack_family_paper_count": len(family_papers),
        "total_papers_searched": total_in_scope,
        "kb_entries": [
            {"id": m["id"], "effective": m.get("effective", True),
             "mechanism": m.get("mechanism", "")}
            for m in kb_matches
        ],
    }

    # --- MAB insight ---
    mab_insight = None
    if pattern == "adaptive_convergence":
        mab_insight = _get_mab_insight(defense_n, attack_n, kb_matches, novelty)

    # --- Plain-English summaries ---
    what_was_known = _build_known_summary(
        defense_n, attack_n, kb_matches, confirming_papers, novelty)
    what_might_be_new = _build_novelty_summary(
        defense_n, attack_n, pattern, novelty, kb_matches)
    what_to_test_next = _build_next_steps(
        defense_n, attack_n, pattern, novelty, accuracy_drop,
        slipthrough_rate, defense_profile)

    # --- Assumptions exploited ---
    assumptions_exploited = _identify_exploited_assumptions(
        defense_profile, attack_n, pattern, attack_info)

    return {
        "defense_profile": defense_profile,
        "attack_profile": attack_profile,
        "atlas_mapping": atlas_mapping,
        "literature": literature,
        "mab_insight": mab_insight,
        "assumptions_exploited": assumptions_exploited,
        "what_was_known": what_was_known,
        "what_might_be_new": what_might_be_new,
        "what_to_test_next": what_to_test_next,
    }


def _get_mab_insight(defense, attack, kb_matches, novelty):
    """Explain what MAB convergence to a specific attack means for this defense."""
    kb = _load_kb()
    defense_info = kb.get("defenses", {}).get(defense, {})
    category = defense_info.get("category", "unknown")

    if kb_matches:
        effective = [m for m in kb_matches if m.get("effective", True)]
        if effective:
            mechanism = effective[0].get("mechanism", "")
            return (
                f"The MAB converged to {attack} against {defense}, confirming "
                f"a known vulnerability: {mechanism}. This is consistent with "
                f"published findings and validates the MAB's ability to "
                f"autonomously rediscover known defense weaknesses."
            )

    if category == "distance_based":
        return (
            f"The MAB converged to {attack} against {defense} (distance-based). "
            f"This suggests {attack} produces updates that remain close to honest "
            f"updates in distance metrics while still causing damage — a potential "
            f"evasion of the distance-based filtering mechanism."
        )
    elif category == "coordinate_wise":
        return (
            f"The MAB converged to {attack} against {defense} (coordinate-wise). "
            f"This suggests {attack} manipulates individual coordinates in a way "
            f"that survives trimming or median operations — possibly by staying "
            f"within per-coordinate bounds."
        )
    elif category == "trust_based":
        return (
            f"The MAB converged to {attack} against {defense} (trust-based). "
            f"This is a candidate novel finding: the MAB identified an attack "
            f"that can maintain high trust scores while injecting poison, "
            f"potentially exposing a gap in the trust scoring mechanism."
        )
    return (
        f"The MAB converged to {attack} against {defense}. The autonomous "
        f"selection of this attack suggests it is the most effective primitive "
        f"against this defense under the tested conditions."
    )


def _build_known_summary(defense, attack, kb_matches, papers, novelty):
    """Plain-English summary of what was already known."""
    if novelty == "known_weakness":
        refs = []
        for p in papers[:3]:
            authors = p.get("authors", "Unknown")
            first = authors.split(",")[0].split(" et")[0] if authors else "Unknown"
            refs.append(f"{first} et al. ({p.get('year', '?')})")
        ref_str = ", ".join(refs) if refs else "published literature"
        mechanism = kb_matches[0].get("mechanism", "") if kb_matches else ""
        return (
            f"This is a well-documented vulnerability. {mechanism} "
            f"First demonstrated by {ref_str}. Our framework reproduces "
            f"this known weakness, validating the experimental setup."
        )
    elif novelty == "reproduced":
        return (
            f"This behavior is consistent with published results for {attack} "
            f"against {defense}. Our framework successfully reproduces the "
            f"expected interaction, providing additional confirmation."
        )
    elif novelty == "known_robust":
        return (
            f"Published literature documents {defense} as robust against {attack}. "
            f"If our results show vulnerability here, it may indicate a "
            f"configuration-specific weakness or a genuinely novel finding."
        )
    elif novelty == "candidate_new":
        return (
            f"No prior work in our {len(kb_matches)}-entry knowledge base "
            f"directly tests this specific {attack} vs {defense} interaction. "
            f"This is a candidate novel finding that needs confirmation."
        )
    return f"Insufficient evidence to determine prior knowledge status."


def _build_novelty_summary(defense, attack, pattern, novelty, kb_matches):
    """Plain-English summary of what might be new."""
    if novelty != "candidate_new":
        return None

    if pattern == "adaptive_convergence":
        return (
            f"The MAB's autonomous convergence to {attack} against {defense} "
            f"is a novel contribution. No prior work uses an attacker-side "
            f"multi-armed bandit to discover defense-specific weaknesses "
            f"without prior knowledge of the defense mechanism."
        )
    if pattern in ("trust_failure", "poor_trust_separation"):
        return (
            f"Trust-based defense {defense} failing to separate malicious "
            f"from honest clients under {attack} may indicate a gap in the "
            f"trust scoring mechanism. This needs multi-seed validation "
            f"before claiming novelty."
        )
    return (
        f"The {pattern.replace('_', ' ')} of {defense} under {attack} has "
        f"no direct match in our knowledge base. This could represent a "
        f"previously untested attack-defense combination. Needs 3+ seeds "
        f"and cross-dataset validation before claiming novelty."
    )


def _build_next_steps(defense, attack, pattern, novelty, accuracy_drop,
                      slipthrough_rate, defense_profile):
    """Recommend specific next experiments."""
    steps = []

    if novelty == "candidate_new":
        steps.append(
            f"Run 3+ seeds with different random seeds to confirm this "
            f"{pattern.replace('_', ' ')} is reproducible, not a single-seed artifact."
        )
        steps.append(
            f"Test on CIFAR-10 and MNIST to check if the finding transfers "
            f"across datasets or is FEMNIST-specific."
        )

    if pattern == "defense_collapse":
        steps.append(
            f"Run an IID control experiment to separate non-IID effects "
            f"from attack effects on {defense}."
        )
        steps.append(
            f"Increase total rounds to 100-200 to check if {defense} "
            f"recovers with more training time."
        )

    if pattern == "adaptive_convergence":
        steps.append(
            f"Compare the MAB-selected attack ({attack}) against each "
            f"primitive individually to quantify the MAB's advantage."
        )

    if pattern in ("trust_failure", "poor_trust_separation"):
        category = defense_profile.get("category", "")
        if category == "trust_based":
            steps.append(
                f"Increase the malicious fraction beyond 30% to find "
                f"the trust-scoring breakpoint for {defense}."
            )

    if slipthrough_rate and slipthrough_rate > 0.5:
        steps.append(
            f"Tune {defense}'s filtering parameters (if configurable) "
            f"to test whether tighter thresholds reduce slipthrough."
        )

    if accuracy_drop and accuracy_drop > 0.3:
        steps.append(
            f"Test with delayed onset (attack starts after round 10) to "
            f"see if {defense} detects the behavioral shift."
        )

    if not steps:
        steps.append(
            f"Replicate with 3+ seeds to confirm statistical significance."
        )

    return steps


def _identify_exploited_assumptions(defense_profile, attack, pattern, attack_info):
    """Identify which defense assumptions this attack/pattern exploits."""
    assumptions = defense_profile.get("assumptions", [])
    if not assumptions:
        return []

    exploited = []
    attack_cat = attack_info.get("category", "")
    category = defense_profile.get("category", "")

    for assumption in assumptions:
        a_lower = assumption.lower()
        if "iid" in a_lower and pattern in ("defense_collapse", "accuracy_degradation"):
            exploited.append(assumption)
        elif "honest majority" in a_lower and pattern == "defense_collapse":
            exploited.append(assumption)
        elif "distance" in a_lower and attack in ("alie", "mimic", "good_gradients"):
            exploited.append(assumption)
        elif "extreme" in a_lower and attack == "alie":
            exploited.append(assumption)
        elif ("cosine" in a_lower or "direction" in a_lower) and attack == "sign_flip":
            exploited.append(assumption)
        elif "root dataset" in a_lower and category == "trust_based":
            exploited.append(assumption)
        elif "sybil" in a_lower and pattern in ("trust_failure", "poor_trust_separation"):
            exploited.append(assumption)
        elif "reputation" in a_lower and pattern in ("trust_failure", "adaptive_convergence"):
            exploited.append(assumption)
        elif "norm" in a_lower and attack in ("constrain_and_scale", "pill"):
            exploited.append(assumption)
        elif "sign" in a_lower and attack == "sign_flip":
            exploited.append(assumption)
        elif "median" in a_lower and attack == "alie":
            exploited.append(assumption)
        elif "trimm" in a_lower and attack == "alie":
            exploited.append(assumption)

    return exploited
