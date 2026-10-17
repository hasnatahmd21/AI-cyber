# AI-CYBER — Locked Dataset Selection

This freezes the first production dataset scope before real data is loaded.

## Core — eleven selected datasets

1. CAPEC — attack-pattern taxonomy.
2. CISA KEV — exploited-in-the-wild prioritization overlay.
3. CPE — product/platform identity and applicability.
4. CWE — weakness taxonomy.
5. EPSS — exploitation-likelihood overlay.
6. MITRE ATT&CK STIX 2.1 — adversary behavior and relationships.
7. MITRE D3FEND — defensive countermeasure ontology.
8. MITRE MBC — malware behavior taxonomy; **no malware binaries**.
9. SigmaHQ rules — vendor-neutral log/SIEM detection content.
10. Suricata rules — network IDS detection content.
11. Zeek Intel content/schema — network indicator enrichment.

The separate NVD CVE bulk corpus and the CVSS derivation that depends on it are out of scope. Do not download or wait for that source during this build.

NVD publishes CPE 2.0 source data, which may support the selected CPE family; the separate NVD CVE corpus is excluded from this build. citeturn0search0  
CISA describes KEV as the authoritative catalog of vulnerabilities exploited in the wild and provides JSON/CSV forms. citeturn1search4  
FIRST EPSS is an enrichment layer for CVEs with current and historical scores. citeturn2search15  
MITRE ATT&CK provides versioned STIX 2.1 collections. citeturn2search8  
CWE and CAPEC provide structured downloadable taxonomies. citeturn0search2turn2search6  
D3FEND provides ontology files and ATT&CK-to-D3FEND mappings. citeturn3search1turn3search4  
Sigma provides a maintained generic detection specification and rule repository. citeturn2search0turn2search5  
Zeek's Intelligence Framework is designed around atomic indicators plus source/metadata. citeturn0search7  
MBC is a malware behavior taxonomy that complements ATT&CK rather than duplicating it. citeturn2search12

## Do NOT add now

- Raw malware binaries/samples.
- Generic security-news datasets.
- Random GitHub security repositories.
- Duplicate CVE mirrors.
- Huge public log corpora before telemetry normalization exists.
- Vendor rule packs without clear license/provenance.
- Live API caches treated as versioned datasets.

## Phase 2 only

- ATT&CK Attack Flow content — only if flow analysis becomes a demonstrated runtime/UI requirement.
- YARA rules — only after selecting a vetted, clearly licensed source.
- OCSF — only when the telemetry normalization layer is implemented.

## Why this split matters

These are different evidence classes:

- **Vulnerability intelligence:** KEV and EPSS
- **Reference/ontology:** CWE, CPE, ATT&CK, CAPEC, D3FEND, MBC
- **Detection content:** Sigma, Suricata
- **Telemetry/enrichment:** Zeek Intel

We should not turn every public security dataset into one giant corpus. Each source must have a distinct role.

## Loading order

**Wave A:** CAPEC → CWE → CPE  
**Wave B:** CISA KEV → EPSS  
**Wave C:** ATT&CK → D3FEND → MBC  
**Wave D:** Sigma → Suricata → Zeek Intel

After every wave:

**Readiness → Manifest → SHA-256/count verification → Ingestion → Relations → RAG evidence evaluation**

Only after all four waves pass should the selected eleven-dataset corpus be exposed to the UI.

## Selection lock

No new dataset gets added merely because it is large or popular. A new source must provide a distinct information role, authoritative provenance, acceptable licensing, deterministic versioning, and a concrete runtime/retrieval use case.
