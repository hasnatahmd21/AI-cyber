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

The committed \`scripts/kaggle_build_knowledge_db.py\` is the approved first-wave builder. It reruns the raw-artifact readiness gate before opening the target DB, then preflights every required manifest. A missing source, Git LFS pointer, checksum/size mismatch, or count mismatch blocks ingestion without creating a new database.

After \`scripts/kaggle_nvd_feed_readiness.py\` reports real NVD artifacts restored and the full readiness report has \`overall: PASS\`, run from the checkout on the intended branch:

    python scripts/kaggle_build_knowledge_db.py \\
      --db-path datasets/knowledge/ai_cyber_knowledge_v1.sqlite3 \\
      --persist-lfs \\
      --branch fix/dataset-parser-readiness

This creates the versioned \`ai-cyber-knowledge-v1\` SQLite store, stores source provenance and deterministic record IDs, ingests through the same format-specific parsers used by readiness, and resumes completed artifacts from checkpoints on restart. CVSS records are derived from the final ingested NVD CVE evidence with separate deterministic IDs and page checkpoints; it does not download or duplicate a second CVE corpus.

The builder verifies a real CVE query, CVSS retrieval, provenance/citation fields, evidence-only RAG output, database status, and retrieval from a new Python process using the same \`AI_CYBER_KNOWLEDGE_DB\` path. It writes a JSON report alongside the dataset reports.

**Durability:** \`/kaggle/working\` is ephemeral. \`--persist-lfs\` is mandatory for the builder to return an overall \`PASS\`; it requires Git LFS, a checkout of the exact branch, and the Kaggle Secret \`cyber repo\` (or a valid \`GITHUB_TOKEN\`/\`GH_TOKEN\`). The report records the persistence result and commit. If the repository's Git LFS quota or permissions reject the upload, the build must not be declared complete. In that case retain the DB and reports as a saved Kaggle Notebook Output/Version or on an explicitly configured durable store, then verify it can be reopened in a fresh runtime.

The no-ingestion readiness gate must still pass separately. A green fixture test or successful local SQLite build is not proof that all real source artifacts are ready or that the DB is durably saved.
