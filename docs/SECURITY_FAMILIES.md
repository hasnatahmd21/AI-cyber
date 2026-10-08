# 13-Family Security Knowledge Structure

The canonical security knowledge layer normalizes heterogeneous security records into exactly 13 controlled families.

| Family | Scope |
|---|---|
| vulnerability | Specific security flaws and affected components |
| weakness | General weakness classes such as CWE |
| threat | Threat actors, campaigns, objectives, and intelligence |
| attack | Attack techniques, tactics, procedures, and behaviors |
| exploit | Exploit artifacts and exploitability evidence |
| malware | Malware families, capabilities, and artifacts |
| identity_access | Identity, authentication, authorization, and access control |
| network_security | Network protocols, services, segmentation, and controls |
| application_security | Application and software security concepts |
| cloud_security | Cloud, container, orchestration, and hosted-service security |
| detection_monitoring | Detection logic, telemetry, indicators, and monitoring |
| incident_response | Investigation, containment, recovery, and incident handling |
| defense_remediation | Mitigations, patches, hardening, and defensive guidance |

## Canonical record contract

Every record has a stable `record_id`, exactly one controlled family, a non-empty title, optional description, optional CVE/CWE/CAPEC/ATT&CK identifiers, optional CVSS score/vector and severity, explicit evidence references, explicit related-record identifiers, source dataset/artifact/version provenance, and deterministic canonical JSON plus SHA-256 content hash.

CVE/CWE/CAPEC/ATT&CK are identifier dimensions, not additional families. CVSS is severity metadata, not a family.

## Boundary with #4

The `related_record_ids` field preserves declared relationships without claiming that those targets exist or that the relationship is semantically resolved. Cross-dataset resolution, relationship typing, graph traversal, orphan detection, and relationship integrity belong exclusively to **#4 Cross-Dataset Relationship Layer**.

## Integrity guarantees

`SecurityFamilyStore.verify_integrity()` checks the complete 13-family catalog, stored record identity, canonical payload validity, deterministic content hashes, schema version, and record count.

The store is local-first SQLite and deterministic. No external API, LLM, or generated assertion is required for correctness.
