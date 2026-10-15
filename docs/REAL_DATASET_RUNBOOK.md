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


## Parser/readiness-only gate (before Knowledge DB creation)

Run the committed parser regressions first:

    python -m compileall -q src/ai_cyber_os tests scripts
    python -m pytest -q tests/test_dataset_specific_parsers.py tests/test_dataset_pipeline.py tests/test_threat_intel.py tests/test_knowledge.py tests/test_rag.py

Then acquire and validate the missing NVD source from official NVD JSON 2.0 feeds. This command does not create a Knowledge DB or ingest records:

    python scripts/kaggle_nvd_feed_readiness.py

The runner reads each feed's official `.meta` file, verifies compressed size plus uncompressed SHA-256 and size, parses actual CVE IDs, creates `datasets/manifests/nvd_cve.json`, and executes the consolidated raw-source readiness gate. Yearly feeds are full snapshots; recent/modified feeds overlap them, so the report separates feed-record occurrences from distinct CVE IDs.

To persist the verified NVD feed snapshot into the current Git branch with Git LFS, explicitly request:

    python scripts/kaggle_nvd_feed_readiness.py --push --branch fix/dataset-parser-readiness

The push requires Git LFS and the Kaggle Secret `cyber repo` (or `GITHUB_TOKEN`/ `GH_TOKEN` environment variable). The script refuses to push from a different active branch. Do not use `--push` unless the checkout is the intended repository/branch.

Only proceed to Knowledge DB construction after `OVERALL_READINESS=PASS` and the persisted JSON report shows every required source as `PASS`. A parser-test pass by itself is not a real-source readiness pass.


## Permanent Knowledge DB and RAG build (only after real-source PASS)

The approved first-wave builder is scripts/kaggle_build_knowledge_db.py. It reruns the real-artifact gate before opening the target DB, preflights all twelve required raw-source manifests, then ingests through the verified format-specific parser for each source. A missing source, Git LFS pointer, SHA-256/byte-size mismatch, or record-count mismatch blocks ingestion before a new DB is created.

From a fresh Kaggle session, first ensure existing Git LFS files have real bytes (not pointer text):

    git lfs install
    git lfs pull

Then acquire NVD's official JSON 2.0 feeds and create the NVD manifest:

    python scripts/kaggle_nvd_feed_readiness.py

This verifies the compressed feed size plus upstream .meta uncompressed SHA-256 and size, parses actual CVE IDs, and runs the consolidated source-readiness gate. Proceed only when its full report says overall: PASS; NVD's source acquisition pass alone does not imply all datasets passed.

For the first DB build, use a dedicated path under Kaggle working storage, and request a private Kaggle Dataset to make the result durable:

    python scripts/kaggle_build_knowledge_db.py \
      --db-path /kaggle/working/ai_cyber_knowledge_v1.sqlite3 \
      --persist-kaggle-dataset-id YOUR_KAGGLE_USERNAME/ai-cyber-knowledge-db \
      --kaggle-dataset-action create

Configure a Kaggle API token as an attached notebook secret named KAGGLE_API_TOKEN (or provide KAGGLE_API_TOKEN, ~/.kaggle/access_token, or legacy ~/.kaggle/kaggle.json). The separate GitHub secret cyber repo is not a Kaggle API token. Replace YOUR_KAGGLE_USERNAME with the actual owner. The publish flow validates credentials before beginning the lengthy ingestion. It never passes Kaggle's public flag; the dataset remains private by default.

For future rebuilds, change the action to version while keeping the same OWNER/SLUG:

    python scripts/kaggle_build_knowledge_db.py \
      --db-path /kaggle/working/ai_cyber_knowledge_v1.sqlite3 \
      --persist-kaggle-dataset-id YOUR_KAGGLE_USERNAME/ai-cyber-knowledge-db \
      --kaggle-dataset-action version

The builder stores the database version, source manifest hash, artifact hashes, record counts and build report, then checks SQLite integrity before publication. The Knowledge DB retains deterministic IDs, source URI/version/license, content SHA-256, validation status, relationships, FTS/chunk indexes, and per-artifact ingestion checkpoints. CVSS is derived from NVD's indexed metric payload with deterministic IDs and page checkpoints; it is not counted as a thirteenth independent raw source and does not fetch a duplicate CVE corpus.

Before reporting overall PASS, the builder verifies a real CVE query, derived CVSS retrieval, evidence-only RAG output, source/hash/validation citation fields, the shared AI_CYBER_KNOWLEDGE_DB setting, and a separate Python-process restart query. It also records DB file SHA-256 and byte size. A local build without successful durable publication is reported as persistence-pending and exits non-zero by default.

The Kaggle Dataset metadata uses the "other" label because the DB combines sources with separate licenses. This label is not a blanket relicense: per-record source/license metadata remains in the DB, and the published dataset stays private. Do not make it public unless each upstream source's redistribution terms are independently reviewed. Kaggle documents support dataset metadata licenses and private datasets; see the Kaggle dataset metadata reference at https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets_metadata.md and dataset publishing CLI at https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets.md.

The raw-source gate still must pass separately. Green fixture tests, a locally populated SQLite file, or a successful upload command by itself is not proof that the full system works: keep the JSON readiness/build reports and repeat the fresh-process retrieval check against the persisted dataset after restoring it in a new runtime.
