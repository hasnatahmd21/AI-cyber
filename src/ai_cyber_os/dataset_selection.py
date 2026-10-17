"""Locked first-wave dataset selection for AI-CYBER."""
from __future__ import annotations

DATASET_SELECTION = {
    "core_now": [
        ("capec", "Attack-pattern taxonomy"),
        ("cisa_kev", "Known-exploited vulnerability overlay"),
        ("cpe", "Product/platform identity and applicability"),
        ("cwe", "Weakness taxonomy"),
        ("epss", "Exploitation-likelihood overlay"),
        ("mitre_attack", "Adversary behavior and relationships"),
        ("mitre_d3fend", "Defensive countermeasure ontology"),
        ("mitre_mbc", "Malware behavior taxonomy; no binaries"),
        ("sigma", "Vendor-neutral log/SIEM detection content"),
        ("suricata", "Network IDS detection content"),
        ("zeek_intel", "Network indicator enrichment"),
    ],
    "phase_two_optional": [
        ("attck_attack_flows", "Only for a demonstrated flow-analysis use case"),
        ("yara_rules", "Only from a vetted, clearly licensed source"),
        ("ocsf", "Only when telemetry normalization is implemented"),
    ],
    "do_not_add_now": [
        "raw_malware_samples",
        "generic_security_news",
        "random_github_security_repos",
        "duplicate_cve_mirrors",
        "massive_public_log_corpora",
        "unlicensed_vendor_rule_packs",
        "live_api_caches_as_versioned_datasets",
    ],
}

LOCKED_CORE = tuple(name for name, _ in DATASET_SELECTION["core_now"])
