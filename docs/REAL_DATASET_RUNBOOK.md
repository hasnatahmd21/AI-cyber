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

CAPEC, CISA KEV, CPE, CWE, EPSS, MITRE ATT&CK, MITRE D3FEND, MITRE MBC, Sigma, Suricata, and Zeek.


## Dataset family metadata

Use `src/ai_cyber_os/dataset_profiles.py` for the supported families:
CAPEC, CISA KEV, CPE, CWE, EPSS, MITRE ATT&CK, MITRE D3FEND, MITRE MBC, Sigma, Suricata, and Zeek.

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
        "cisa_kev": {
          "dataset": "cisa_kev",
          "version": "<artifact version>",
          "source": "<authoritative source>",
          "source_uri": "<authoritative URI>",
          "license": "<artifact license/provenance>",
          "schema": {"type": "object"},
          "validation_status": "verified-local"
        }
      },
      "_files": {
        "datasets/cisa_kev/known_exploited_vulnerabilities.json": {
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


## Parser/readiness-only gate (before Knowledge DB creation)

Run the committed parser regressions first:

    python -m compileall -q src/ai_cyber_os tests scripts
    python -m pytest -q tests/test_dataset_specific_parsers.py tests/test_dataset_pipeline.py tests/test_threat_intel.py tests/test_knowledge.py tests/test_rag.py

The approved build scope is the eleven existing manifests: CAPEC, CISA KEV, CPE, CWE, EPSS, MITRE ATT&CK, MITRE D3FEND, MITRE MBC, Sigma, Suricata, and Zeek Intel. NVD's full CVE feed and the CVSS derivation dependent on it are intentionally excluded. Do not download NVD feeds or wait for an NVD manifest.

Run the consolidated gate against the existing source artifacts only:

    python scripts/kaggle_dataset_parser_readiness_gate.py --raw-root datasets/raw --report datasets/acquisition_reports/dataset_parser_readiness_report.json

The gate verifies each in-scope manifest, raw-artifact integrity/counts and the source-specific ATT&CK, D3FEND, MBC and Suricata parser/count checks. A passing parser test is not a substitute for real-source PASS.

## Permanent Knowledge DB and RAG build (only after real-source PASS)

The approved first-wave builder is scripts/kaggle_build_knowledge_db.py. It reruns the real-artifact gate before opening the target DB, preflights all eleven required raw-source manifests, then ingests through the verified format-specific parser for each source. A missing source, Git LFS pointer, SHA-256/byte-size mismatch, or record-count mismatch blocks ingestion before a new DB is created.

From a fresh Kaggle session, first ensure existing Git LFS files have real bytes (not pointer text):

    git lfs install
    git lfs pull

The eleven checked-in dataset families are the entire required input set. NVD CVE bulk feeds and NVD-derived CVSS are excluded and are neither downloaded nor required by the gate or builder. Proceed only after the eleven-source report says overall: PASS.

For the first DB build, use a dedicated path under Kaggle working storage, and request a private Kaggle Dataset to make the result durable:

    python scripts/kaggle_build_knowledge_db.py \
      --db-path /kaggle/working/ai_cyber_knowledge_v1.sqlite3 \
      --persist-kaggle-dataset-id YOUR_KAGGLE_USERNAME/ai-cyber-knowledge-db \
      --kaggle-dataset-action create

Configure a Kaggle API token as an attached notebook secret named KAGGLE_API_TOKEN (or provide KAGGLE_API_TOKEN, ~/.kaggle/access_token, or legacy ~/.kaggle/kaggle.json). The separate GitHub secret cyber repo is not a Kaggle API token. Replace YOUR_KAGGLE_USERNAME with the actual owner. The publish flow validates credentials before beginning the lengthy ingestion. It never passes Kaggle's public flag; the dataset remains private by default.

For a retry interrupted during ingestion, keep the same manifests and the same DB path; its artifact/page checkpoints allow safe resume. The builder pins all source-manifest digests, so a changed source snapshot is blocked from being mixed into an existing DB.

For an intentional rebuild after any source manifest/version changes, use a new versioned DB path (for example v2) and then publish it as a new Kaggle Dataset version under the same OWNER/SLUG:

    python scripts/kaggle_build_knowledge_db.py \
      --db-path /kaggle/working/ai_cyber_knowledge_v2.sqlite3 \
      --persist-kaggle-dataset-id YOUR_KAGGLE_USERNAME/ai-cyber-knowledge-db \
      --kaggle-dataset-action version

The builder stores the database version, source manifest hash, artifact hashes, record counts and build report, then checks SQLite integrity before publication. The Knowledge DB retains deterministic IDs, source URI/version/license, content SHA-256, validation status, relationships, FTS/chunk indexes, and per-artifact ingestion checkpoints. The selected scope intentionally excludes NVD CVE bulk feeds and dependent CVSS derivation.

Before reporting overall PASS, the builder verifies a CISA KEV CVE query, CWE and ATT&CK retrieval, evidence-only RAG output, source/hash/validation citation fields, the shared AI_CYBER_KNOWLEDGE_DB setting, and a separate Python-process restart query. It also records DB file SHA-256 and byte size. A local build without successful durable publication is reported as persistence-pending and exits non-zero by default.

The Kaggle Dataset metadata uses the "other" label because the DB combines sources with separate licenses. This label is not a blanket relicense: per-record source/license metadata remains in the DB, and the published dataset stays private. Do not make it public unless each upstream source's redistribution terms are independently reviewed. Kaggle documents support dataset metadata licenses and private datasets; see the Kaggle dataset metadata reference at https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets_metadata.md and dataset publishing CLI at https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets.md.

The raw-source gate still must pass separately. Green fixture tests, a locally populated SQLite file, or a successful upload command by itself is not proof that the full system works: keep the JSON readiness/build reports and repeat the fresh-process retrieval check against the persisted dataset after restoring it in a new runtime.
