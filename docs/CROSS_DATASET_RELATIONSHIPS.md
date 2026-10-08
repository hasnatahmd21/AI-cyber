# Cross-Dataset Relationship Layer

The relationship layer turns the canonical #3 security-family records into a deterministic, queryable knowledge graph. It is the bridge between isolated records and connected security knowledge.

## Design principles

1. **No fabricated relationships.** Edges are created only from explicit CVE/CWE/CAPEC/ATT&CK identifiers, explicit evidence references, explicit severity, or an explicit related_record_ids declaration that resolves uniquely.
2. **Dataset-aware record identity.** A record node is identified by (dataset_id, artifact_path, record_id), preventing collisions when independent datasets reuse the same record identifier.
3. **Shared knowledge anchors.** CVE, CWE, CAPEC and ATT&CK identifiers are shared first-class nodes. Evidence references and severity labels are also first-class nodes, allowing cross-dataset convergence without copying claims between records.
4. **Typed direct links.** Unique identifier matches can materialize direct maps_to_weakness, maps_to_attack, maps_to_attack_pattern, references_vulnerability, and same_vulnerability edges. High fan-out matches remain represented through the shared identifier node rather than being guessed.
5. **Explicit ambiguity.** Plain related_record_ids resolve only when the target is globally unique. A scoped reference uses dataset_id/artifact_path#record_id. Missing targets are marked orphan; duplicate targets are marked ambiguous.
6. **Deterministic traversal.** Breadth-first traversal is bounded by depth, node count, and stable edge ordering.
7. **Integrity-first storage.** Nodes, edges and relationship declarations use canonical JSON plus SHA-256 hashes. SQLite foreign keys prevent dangling stored edge endpoints.

## Canonical graph model

### Node types

| Type | Purpose |
|---|---|
| record | A #3 canonical SecurityKnowledgeRecord from a specific dataset/artifact |
| identifier | Shared CVE/CWE/CAPEC/ATT&CK anchor |
| evidence | A declared evidence reference; the layer does not fetch or authenticate it |
| severity | Shared severity label such as HIGH; CVSS score/vector remain record metadata |

### Relationship types

| Relation | Meaning |
|---|---|
| identified_as | Record explicitly declares an identifier |
| maps_to_weakness | Record's declared CWE uniquely resolves to a weakness record |
| maps_to_attack | Record's declared ATT&CK identifier uniquely resolves to an attack record |
| maps_to_attack_pattern | Record's CAPEC identifier resolves to an attack record |
| references_vulnerability | Non-vulnerability record uniquely resolves to a vulnerability carrying the same CVE |
| same_vulnerability | Distinct vulnerability records carry the same CVE |
| same_entity | Reserved for explicit future entity linkage |
| has_severity | Record declares a severity label |
| supported_by | Record declares an evidence reference |
| related_to | Explicit related_record_ids declaration resolved to a unique target |

## Resolution boundary

The graph resolver distinguishes three states:

- **Resolved:** exactly one safe target exists and a typed edge is materialized.
- **Ambiguous:** multiple safe targets exist; the system records all candidates and deliberately creates no guessed direct edge.
- **Orphan:** no target exists; the declaration is retained for later reconciliation.

A pending declaration can become resolved after the target dataset is ingested.

## Cross-dataset security path

A typical chain can now be represented as:

NVD vulnerability record
→ CVE identifier
→ vendor vulnerability record
→ CWE identifier
→ CWE weakness record
→ severity node
→ evidence node

The direct typed edges add shorter paths where the target is uniquely resolvable. This makes connected retrieval possible without claiming that two independent records are identical merely because they share an identifier.

## Integrity and operational checks

CrossDatasetRelationshipStore.verify_integrity() checks:

- graph and #3 schema versions
- canonical node payloads and node identity
- SHA-256 node and edge hashes
- canonical #3 security records stored inside record nodes
- edge endpoint existence
- valid relationship declarations and their hashes
- resolved declaration → matching edge consistency
- orphan / ambiguous / pending counts
- cross-dataset direct record-to-record edge count

health() exposes the same information as a compact operational snapshot.

## Scope boundary with later stages

This layer does not:

- run commands or exploits
- fetch external evidence
- perform LLM inference
- expose a backend API
- replace the #1 RAG retrieval engine
- decide that an unverified relationship is true

Backend integration and connected retrieval endpoints are #5.
