"""Locked first-wave dataset selection for AI-CYBER."""
from __future__ import annotations

DATASET_SELECTION = {
    "core_now": [
        ("nvd_cve", "Primary vulnerability corpus"),
        ("cisa_kev", "Known-exploited vulnerability overlay"),
        ("epss", "CVSS-adjacent exploitation-likelihood overlay"),
        ("cwe", "Weakness taxonomy"),
        ("cpe", "Product/platform identity and applicability"),
        ("cvss", "Scoring reference and CVE score metadata, not duplicate CVEs"),
        ("mitre_attack", "Adversary behavior and relationships"),
        ("capec", "Attack-pattern taxonomy"),
        ("d3fend", "Defensive countermeasure ontology"),
        ("sigma", "Vendor-neutral log/SIEM detection content"),
        ("suricata_rules", "Network IDS detection content"),
        ("zeek_intel", "Network indicator enrichment"),
        ("mbc", "Malware behavior taxonomy; no binaries"),
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
