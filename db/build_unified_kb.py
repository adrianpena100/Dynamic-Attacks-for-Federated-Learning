"""
Build a unified knowledge base by merging XLSX literature survey into known_vulnerabilities.json.

Run once after updating XLSX CSVs:
    python db/build_unified_kb.py

The XLSX CSVs (xlsx_extracted/) become archive source data — at runtime,
only known_vulnerabilities.json is loaded.
"""

import csv
import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KB_PATH = PROJECT_ROOT / "db" / "known_vulnerabilities.json"
XLSX_DIR = PROJECT_ROOT / "xlsx_extracted"
ATTACK_MAP_CSV = XLSX_DIR / "Attack_Vulnerability_Map.csv"
DEFENSE_BREAKING_CSV = XLSX_DIR / "Defense-Breaking_Core.csv"

IN_SCOPE_FAMILIES = {
    "Model/data poisoning",
    "Model/data poisoning / Byzantine attack",
    "Backdoor / targeted poisoning",
    "Backdoor / targeted poisoning (graph)",
    "Byzantine / defense-evasion",
    "Attack / vulnerability analysis",
    "Security analysis",
}


def load_kb():
    with open(KB_PATH) as f:
        return json.load(f)


def load_xlsx():
    rows = []
    if ATTACK_MAP_CSV.exists():
        with open(ATTACK_MAP_CSV) as f:
            rows = list(csv.DictReader(f))
    return rows


def load_defense_breaking():
    titles = set()
    if DEFENSE_BREAKING_CSV.exists():
        with open(DEFENSE_BREAKING_CSV) as f:
            for r in csv.DictReader(f):
                titles.add(r["Paper"].strip())
    return titles


def _make_key(title, year):
    """Generate a paper key from title and year."""
    words = re.sub(r"[^a-zA-Z0-9\s]", "", title).lower().split()
    if not words:
        return f"unknown{year}"
    first_meaningful = words[0]
    if first_meaningful in ("a", "an", "the", "on", "in", "for", "to", "of"):
        first_meaningful = words[1] if len(words) > 1 else words[0]
    return f"{first_meaningful}{year}"


def _normalize_title(title):
    """Normalize title for fuzzy matching."""
    return re.sub(r"\s+", " ", title.strip().lower())[:60]


def _parse_attacks_from_xlsx(row, attack_registry):
    """Extract attack names from XLSX free text using the alias system."""
    attacks = []
    attack_name = row.get("Proposed attack name", "").strip()
    mechanism = row.get("Mechanism", "").strip().lower()

    for canon_name, info in attack_registry.items():
        aliases = [canon_name] + [a.lower() for a in info.get("aliases", [])]
        if attack_name.lower() in aliases:
            attacks.append(canon_name)
            continue
        for alias in aliases:
            if len(alias) > 3 and alias in mechanism:
                attacks.append(canon_name)
                break

    return list(set(attacks))


def _parse_defenses_from_xlsx(row, defense_registry):
    """Extract defense names from XLSX 'Defenses evaluated against' using aliases."""
    defenses = []
    field = row.get("Defenses evaluated against", "").lower()
    if not field:
        return defenses

    for canon_name, info in defense_registry.items():
        aliases = [canon_name] + [a.lower() for a in info.get("aliases", [])]
        for alias in aliases:
            if len(alias) > 2 and alias in field:
                defenses.append(canon_name)
                break

    return list(set(defenses))


def _xlsx_to_paper(row, attack_registry, defense_registry, is_defense_breaking):
    """Convert an XLSX row to a KB paper entry."""
    title = row.get("Paper", "").strip()
    year = row.get("Year", "").strip()
    family = row.get("Attack family", "").strip()
    scope = "in_scope" if family in IN_SCOPE_FAMILIES else "out_of_scope"

    try:
        year_int = int(year)
    except ValueError:
        year_int = 0

    return {
        "key": _make_key(title, year),
        "title": title,
        "year": year_int,
        "venue": row.get("Venue", "").strip(),
        "authors": row.get("Authors", "").strip(),
        "attacks_tested": _parse_attacks_from_xlsx(row, attack_registry),
        "defenses_tested": _parse_defenses_from_xlsx(row, defense_registry),
        "adaptive": False,
        "non_iid": False,
        "classes": 0,
        "composite": False,
        "scheduling": False,
        "attack_family": family,
        "attack_name": row.get("Proposed attack name", "").strip(),
        "mechanism": row.get("Mechanism", "").strip(),
        "attack_objective": row.get("Attack objective", "").strip(),
        "datasets": row.get("Datasets", "").strip(),
        "models": row.get("Models", "").strip(),
        "strengths": row.get("Strengths", "").strip(),
        "weaknesses": row.get("Weaknesses", "").strip(),
        "experimental_results": row.get("Important experimental results", "").strip(),
        "limitations": row.get("Limitations stated by authors", "").strip(),
        "link": row.get("Direct paper link", "").strip(),
        "code_link": row.get("Code link", "").strip() or None,
        "defense_breaking": is_defense_breaking,
        "scope": scope,
        "source": "xlsx",
    }


def _enrich_kb_paper(kb_paper, xlsx_row, is_defense_breaking):
    """Add XLSX rich fields to an existing KB paper entry."""
    kb_paper["attack_family"] = xlsx_row.get("Attack family", "").strip()
    kb_paper["attack_name"] = xlsx_row.get("Proposed attack name", "").strip()
    kb_paper["mechanism"] = xlsx_row.get("Mechanism", "").strip()
    kb_paper["attack_objective"] = xlsx_row.get("Attack objective", "").strip()
    kb_paper["datasets"] = xlsx_row.get("Datasets", "").strip()
    kb_paper["models"] = xlsx_row.get("Models", "").strip()
    kb_paper["strengths"] = xlsx_row.get("Strengths", "").strip()
    kb_paper["weaknesses"] = xlsx_row.get("Weaknesses", "").strip()
    kb_paper["experimental_results"] = xlsx_row.get(
        "Important experimental results", ""
    ).strip()
    kb_paper["limitations"] = xlsx_row.get(
        "Limitations stated by authors", ""
    ).strip()
    kb_paper["link"] = xlsx_row.get("Direct paper link", "").strip()
    kb_paper["code_link"] = xlsx_row.get("Code link", "").strip() or None
    kb_paper["defense_breaking"] = is_defense_breaking
    family = xlsx_row.get("Attack family", "").strip()
    kb_paper["scope"] = "in_scope" if family in IN_SCOPE_FAMILIES else "out_of_scope"
    kb_paper["source"] = "kb+xlsx"
    return kb_paper


def merge():
    kb = load_kb()
    xlsx_rows = load_xlsx()
    dbc_titles = load_defense_breaking()

    attack_registry = kb["attacks"]
    defense_registry = kb["defenses"]

    kb_papers = kb["papers"]
    kb_by_title = {}
    for p in kb_papers:
        norm = _normalize_title(p["title"])
        kb_by_title[norm] = p

    kb_keys_used = {p["key"] for p in kb_papers}

    matched = 0
    added_in_scope = 0
    added_out_scope = 0

    for row in xlsx_rows:
        title = row.get("Paper", "").strip()
        norm_title = _normalize_title(title)
        is_dbc = title in dbc_titles

        if norm_title in kb_by_title:
            _enrich_kb_paper(kb_by_title[norm_title], row, is_dbc)
            matched += 1
        else:
            new_paper = _xlsx_to_paper(row, attack_registry, defense_registry, is_dbc)
            # Deduplicate keys
            base_key = new_paper["key"]
            if base_key in kb_keys_used:
                suffix = 2
                while f"{base_key}_{suffix}" in kb_keys_used:
                    suffix += 1
                new_paper["key"] = f"{base_key}_{suffix}"
            kb_keys_used.add(new_paper["key"])
            kb_papers.append(new_paper)

            if new_paper["scope"] == "in_scope":
                added_in_scope += 1
            else:
                added_out_scope += 1

    # Mark KB-only papers that weren't enriched
    for p in kb_papers:
        if "source" not in p:
            p["source"] = "kb_only"
            p["scope"] = "in_scope"
            p["defense_breaking"] = False

    kb["papers"] = kb_papers
    kb["sources_count"] = len(kb_papers)
    kb["description"] = (
        "Unified FL attack-defense knowledge base. "
        f"Contains {len(kb_papers)} papers "
        f"({matched} merged from KB+XLSX, {added_in_scope} in-scope from XLSX, "
        f"{added_out_scope} out-of-scope from XLSX, "
        f"{len(kb_papers) - matched - added_in_scope - added_out_scope} KB-only). "
        "Sources: 60+ venues including NeurIPS, ICML, ICLR, USENIX Security, NDSS, "
        "IEEE S&P, ACM CCS, RAID, AISTATS, UAI, IJCAI, KDD, CVPR, AAAI."
    )

    with open(KB_PATH, "w") as f:
        json.dump(kb, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Merged {matched} overlapping papers")
    print(f"Added {added_in_scope} in-scope XLSX papers")
    print(f"Added {added_out_scope} out-of-scope XLSX papers")
    print(f"Total papers: {len(kb_papers)}")
    print(f"Written to {KB_PATH}")

    # Summary stats
    in_scope = sum(1 for p in kb_papers if p.get("scope") == "in_scope")
    out_scope = sum(1 for p in kb_papers if p.get("scope") == "out_of_scope")
    dbc_count = sum(1 for p in kb_papers if p.get("defense_breaking"))
    print(f"  In-scope: {in_scope}")
    print(f"  Out-of-scope: {out_scope}")
    print(f"  Defense-breaking: {dbc_count}")


if __name__ == "__main__":
    merge()
