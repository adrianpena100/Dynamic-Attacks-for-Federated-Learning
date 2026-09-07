"""Integrity and behavior checks for the literature knowledge base."""

from __future__ import annotations

import json
import re
from pathlib import Path

from db.atlas_mapping import (
    build_finding_context,
    classify_finding,
    classify_novelty,
    lookup_known_vulnerability,
)


ROOT = Path(__file__).resolve().parents[1]
KB_PATH = ROOT / "db" / "known_vulnerabilities.json"
NOVELTY_MAP_PATH = ROOT / "docs" / "NOVELTY_MAP.md"


def _load_kb() -> dict:
    return json.loads(KB_PATH.read_text(encoding="utf-8"))


def test_knowledge_base_counts_and_paper_result_coverage():
    kb = _load_kb()
    papers = kb["papers"]

    assert kb["sources_count"] == 205
    assert len(papers) == 205
    assert sum(p.get("scope") == "in_scope" for p in papers) == 96
    assert sum(p.get("scope") == "out_of_scope" for p in papers) == 109
    assert len(kb["known_vulnerabilities"]) == 99
    assert all(p.get("experimental_results", "").strip() for p in papers)
    assert len({p["key"] for p in papers}) == len(papers)


def test_structured_vulnerability_references_are_resolvable():
    kb = _load_kb()
    paper_keys = {p["key"] for p in kb["papers"]}
    attack_keys = set(kb["attacks"])
    defense_keys = set(kb["defenses"])
    vulnerability_ids = set()

    for item in kb["known_vulnerabilities"]:
        assert item["id"] not in vulnerability_ids
        vulnerability_ids.add(item["id"])
        assert item["attack"] in attack_keys
        assert item["defense"] in defense_keys
        if item.get("first_demonstrated"):
            assert item["first_demonstrated"] in paper_keys
        assert set(item.get("confirmed_by", [])) <= paper_keys


def test_novelty_map_catalog_matches_json_papers():
    kb_keys = {p["key"] for p in _load_kb()["papers"]}
    markdown = NOVELTY_MAP_PATH.read_text(encoding="utf-8")
    catalog_keys = {
        match.group(1)
        for line in markdown.splitlines()
        if (match := re.match(r"^\|\s*\d+\s*\|\s*`([^`]+)`\s*\|", line))
    }

    assert catalog_keys == kb_keys


def test_exact_pair_lookup_drives_literature_context_and_status():
    matches = lookup_known_vulnerability("alie", "fedmedian")
    assert [item["id"] for item in matches] == ["KV-004"]
    assert classify_novelty("defense_bypass", "fedmedian", "alie") == "reproduced"

    context = build_finding_context("alie", "fedmedian", "defense_bypass")
    matching_keys = {p["key"] for p in context["literature"]["matching_papers"]}
    assert {"baruch2019", "flpoison2025", "blades2024"} <= matching_keys
    assert context["literature"]["status"] == "reproduced"


def test_known_robust_and_candidate_new_paths_are_conservative():
    assert classify_novelty("defense_bypass", "fltrust", "alie") == "known_robust"
    assert (
        classify_novelty("adaptive_convergence", "mab-rfl", "mean_shift")
        == "candidate_new"
    )

    finding = classify_finding("adaptive_convergence", "mab-rfl", "mean_shift")
    rationale = finding["rationale"]
    assert rationale.startswith("CANDIDATE NEW")
    assert "not proof of global novelty" in rationale
    assert "matched adaptive-versus-static comparison" in rationale

