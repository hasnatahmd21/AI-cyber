# Real Dataset Runbook

Controlled path for loading actual security datasets.

## Order

1. Place downloaded/licensed datasets under the project dataset root.
2. Restore any manifest-pinned Git LFS pointer with `python tools/restore_lfs_artifact.py datasets/manifests/<dataset>.json`. The utility only replaces a recognized pointer after HTTPS download, exact byte-size validation, and SHA-256 verification.
3. Run `python tools/real_dataset_readiness.py . --json-out /kaggle/working/real-dataset-readiness.json` and preserve the report outside the repository.
4. Resolve every eligible manifest reported as `BLOCKED`. A placeholder example manifest is reported as `TEMPLATE_EXCLUDED`; it is never ingested.
5. Verify source/version/license provenance, artifact SHA-256, declared versus observed logical-record counts, and any manifest-declared format statistics (such as STIX object types and active/disabled Suricata rules).
6. Ingest only after the entire intended scope passes the readiness gate; keep real ingestion separate from read-only parser verification.
7. Run persistent-store integrity/FTS checks, restart-persistence tests, exact identifier retrieval, evidence/citation evaluation, and existing regression/hardening tests.
8. Only then expose the dataset through the UI.

Do not treat a Git LFS pointer as payload, do not infer verified license status from a successful checksum, and do not mark the whole inventory green when an intended dataset is missing or blocked.

## Required evidence

Every accepted dataset retains source/version where available, license/provenance, local SHA-256, declared and observed record counts, schema/validation status, ingestion status, and evaluation result.

## Safety

No live feed, API credential, freshness claim, or external execution is introduced by the harness. A real dataset is accepted only after local bytes and its manifest agree.

## Target families

NVD/CVE, CVSS, CWE, CPE, CISA KEV, MITRE ATT&CK, Suricata, Zeek, and malware feature/metadata datasets.


## Dataset family metadata

Use `src/ai_cyber_os/dataset_profiles.py` for the supported families:
NVD/CVE, CVSS, CWE, CPE, CISA KEV, MITRE ATT&CK, Suricata, Zeek, and malware.

Profiles intentionally do not invent version, license, URI, or validation claims.
Populate those fields from the exact artifact's authoritative provenance before
generating a manifest.

For files whose names do not match the dataset family (for example a vendor export
with a generated filename), the batch factory accepts an exact relative-path
mapping through the metadata JSON's `_files` object. `_datasets` may hold
family/name keyed defaults.

Example metadata shape:

    {
      "_datasets": {
        "nvd_cve": {
          "dataset": "nvd_cve",
          "version": "<artifact version>",
          "source": "<authoritative source>",
          "source_uri": "<authoritative URI>",
          "license": "<artifact license/provenance>",
          "schema": {"type": "object"},
          "validation_status": "verified-local"
        }
      },
      "_files": {
        "datasets/nvd/nvdcve-export.jsonl": {
          "dataset": "nvd_cve",
          "version": "<artifact version>",
          "source": "<authoritative source>",
          "source_uri": "<authoritative URI>",
          "license": "<artifact license/provenance>",
          "schema": {"type": "object"},
          "validation_status": "verified-local"
        }
      }
    }

The factory computes local SHA-256 and observed record count itself; operators do
not supply those values manually.
