# Real Dataset Runbook

Controlled path for loading actual security datasets.

## Order

1. Place downloaded/licensed datasets under a local dataset root.
2. Run tools/real_dataset_readiness.py and preserve its JSON output.
3. Generate manifests with the existing manifest tooling.
4. Verify SHA-256 and declared record counts.
5. Ingest only manifests that pass integrity checks.
6. Run intelligence evaluation and RAG evidence-contract evaluation.
7. Run extended HYDRA plus existing regression/hardening.
8. Only then expose the dataset through the UI.

## Required evidence

Every accepted dataset retains source/version where available, license/provenance, local SHA-256, declared and observed record counts, schema/validation status, ingestion status, and evaluation result.

## Safety

No live feed, API credential, freshness claim, or external execution is introduced by the harness. A real dataset is accepted only after local bytes and its manifest agree.

## Target families

NVD/CVE, CVSS, CWE, CPE, CISA KEV, MITRE ATT&CK, Suricata, Zeek, and malware feature/metadata datasets.
