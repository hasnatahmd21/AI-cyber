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
          "dataset": "cisa_kev",
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


## GitHub Actions private persistence path

The repository workflow `.github/workflows/permanent-knowledge-db-build.yml` uses the existing 11-dataset builder and is intentionally blocked before ingestion until a durable private destination and credentials are configured. This avoids spending hours building a temporary database that cannot be retained.

1. In the repository's **Settings → Secrets and variables → Actions → Secrets**, add `KAGGLE_API_TOKEN` (recommended), or both `KAGGLE_USERNAME` and `KAGGLE_KEY`. Never place token values in source files, workflow inputs, issues, or chat.
2. In **Settings → Secrets and variables → Actions → Variables**, set `AI_CYBER_KNOWLEDGE_DATASET_ID` to the exact Kaggle dataset owner/slug, such as `your-kaggle-name/ai-cyber-knowledge-db` (replace the example with the actual owner). Set `AI_CYBER_KNOWLEDGE_DATASET_ACTION` to `create` for a new private dataset or `version` for a dataset that already exists.
3. Open **Actions → Permanent Knowledge DB Build (11 approved datasets) → Run workflow**. Optional workflow inputs override the matching repository variables. Use `create` only if that private dataset does not already exist; choose `version` for updates.
4. The workflow runs compile and focused regressions, restores existing LFS source bytes, reruns all 11-source integrity gates, ingests with resumable checkpoints, runs SQLite/FTS and fresh-process verification, checks ten random real-record retrievals and the live localhost evidence-only RAG API, then publishes to the private Kaggle dataset. The builder downloads the published DB again and verifies its SHA-256 and restart/retrieval before confirming durability.
5. Confirm completion only when the workflow and JSON build report say `overall=PASS` and `permanent_persistence=CONFIRMED_KAGGLE_DATASET_PRIVATE`. A workflow artifact containing reports is diagnostic evidence only; it is **not** a permanent database.

The RAG surface in this branch retrieves cited evidence; it does not generate a natural-language answer. The ten-record gate therefore evaluates retrieval fidelity and exact source/hash/validation provenance, not generative-answer correctness.

The repository is public, so do not use the GitHub Release/Git LFS persistence option for these records until redistribution permissions for every source are explicitly reviewed and approved.


## Stage 3 — persistent DB to live RAG/API runtime

Stage 3 consumes an already-built/published DB; it does not rebuild datasets. Run the verifier before starting the UI/API:

    export AI_CYBER_KNOWLEDGE_DB=/path/to/restored/knowledge-v1.sqlite3
    export AI_CYBER_REQUIRE_VERIFIED_DB=1
    ai-cyber-knowledge-verify --db "$AI_CYBER_KNOWLEDGE_DB"

The DB path must refer to a real, writable restored copy of the private artifact (for example under `/kaggle/working`), not the read-only `/kaggle/input` mount. The verification CLI opens the file read-only and never creates, migrates, or fills in a missing DB. A full check validates SQLite integrity, exact approved 11-source scope, schema/database versions, pinned source-manifest SHA-256 ledger, FTS row parity, chunk-FTS parity, foreign keys, and failed/incomplete ingestion checkpoints. Exit code `0` means PASS; `2` means the runtime must remain blocked.

When `AI_CYBER_REQUIRE_VERIFIED_DB=1`, the localhost runtime re-resolves `AI_CYBER_KNOWLEDGE_DB` at request time, rejects missing/unpopulated/wrong-scope stores before retrieval, blocks UI/API ingestion mutations, and exposes `GET /api/knowledge/health` for the full read-only gate. `GET /api/knowledge/status` reports readiness without creating an empty fallback database. Keep this strict flag enabled when serving the persistent Knowledge DB.

The live API verifier `scripts/verify_live_rag_api.py` performs the full DB gate before starting the localhost server, then selects one random cited record from each of the 11 datasets and checks that `/api/knowledge` returns the exact record ID and matching source URI, content hash, title, and validation state. It also checks fixed CISA KEV/CVE, CWE, and ATT&CK retrieval probes. These are retrieval/provenance checks, not generated-answer accuracy tests: `ai_cyber_os.rag` returns evidence only. Actual generated outputs must be separately supplied to `ai-cyber-evaluate` and pass `validate_security_output` before being treated as grounded answers.

Stage 3 runtime verification is not complete until `ai-cyber-knowledge-verify` passes against the actual restored private artifact, the live API report passes, and the restored DB SHA-256 matches the private publication manifest. A fixture database passing unit tests is not evidence that a permanent production DB has been published.


## Stage 4 — end-to-end evidence-grounded security evaluation

Stage 4 is the evaluation gate between RAG retrieval and durable publication. The implementation lives in `src/ai_cyber_os/security_evaluation_runtime.py` and is called by the existing `scripts/kaggle_build_knowledge_db.py` builder before the live API check and private dataset publication. It verifies the supplied DB using the Stage 3 read-only runtime verifier, picks one real source-backed record randomly from each of the eleven approved families, then randomly selects exactly ten distinct families for the release gate.

For each of the ten samples it creates a query from that record's own content, verifies RAG actually returns the exact saved record, compares title/source/source URI/license/version/validation status/content hash against the selected DB row, recalculates evidence integrity, and validates an extractive output that contains only the cited content. It also runs the existing `evaluate_end_to_end` gate with strict top-1 retrieval and grounding thresholds and a negative control that adds an unsupported CVE-like identifier; the evaluator must reject that control. Published build reports keep source text/query terms/record identifiers out of the sample summary.

After restoring the private DB in a new runtime, Stage 4 can be run directly with:

    export AI_CYBER_KNOWLEDGE_DB=/path/to/restored/knowledge-v1.sqlite3
    export AI_CYBER_REQUIRE_VERIFIED_DB=1
    ai-cyber-evaluate-live --db "$AI_CYBER_KNOWLEDGE_DB" --report stage4-evaluation.json

The guarded localhost API also supports `POST /api/security-evaluation` with exactly `{"mode":"live-sampled"}`. The endpoint runs through the existing layered-defence operation guard and fails closed with HTTP 503 if strict mode cannot verify the permanent DB. `scripts/verify_live_rag_api.py` remains an additional separate-process API/provenance gate; passing only one of these checks is not enough to publish.

Interpretation boundary: this RAG engine is evidence-only. Stage 4 verifies exact extractive answers, source/hash provenance, and that unsupported identifiers are rejected. It does not claim LLM semantic-answer correctness because no LLM answer generation is wired into the current RAG API. For generated outputs, provide the actual generated JSON to `ai-cyber-evaluate` and require its claim/citation grounding gate to pass.
