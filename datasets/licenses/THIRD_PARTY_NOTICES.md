# AI-CYBER third-party cybersecurity dataset notices

This file summarizes public-source notices for the pinned data snapshots. It is not legal advice and does not grant a new licence. The terms attached to each source control that source's content. Some datasets contain third-party references, descriptions or embedded rule authorship that may have separate rights. Preserve record identifiers, source URIs, author names, copyright notices and upstream licence files in user-visible evidence and exports.

## Source notices

- **MITRE CAPEC** — Official terms: https://capec.mitre.org/about/termsofuse.html. Preserve MITRE's copyright designation and terms notice when copying or distributing CAPEC material.
- **MITRE CWE** — Official terms: https://cwe.mitre.org/about/termsofuse.html. Preserve MITRE's copyright designation and terms; CWE is a MITRE trademark.
- **MITRE ATT&CK** — Official terms: https://attack.mitre.org/resources/terms-of-use/. The upstream release includes a LICENSE.txt; the durable DB bundle includes that file. Required designation: © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
- **MITRE D3FEND** — Official terms: https://d3fend.mitre.org/tou/. The pinned ontology carries an MIT licence, which is bundled. Terms for any third-party material included by the source remain applicable.
- **MITRE Malware Behavior Catalog (MBC)** — The pinned upstream repository identifies Apache-2.0; its upstream licence file is bundled.
- **NIST/NVD CPE Dictionary** — Official source: https://nvd.nist.gov/products/cpe. The public dictionary requests attribution to NIST. Do not imply NIST endorsement; individual third-party metadata may have separate terms.
- **NIST National Vulnerability Database (NVD)** — Official feeds: https://nvd.nist.gov/vuln/data-feeds. General data information: https://www.nist.gov/copyrights-disclaimers. Credit NIST/NVD and preserve per-record references. This is not a blanket re-licence of third-party text or referenced resources in individual CVE records.
- **CISA Known Exploited Vulnerabilities (KEV)** — Official feed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog. Preserve the pinned upstream licence file and identify CISA KEV as the source.
- **FIRST Exploit Prediction Scoring System (EPSS)** — Official FAQ: https://www.first.org/epss/faq. EPSS scores are freely published; FIRST/EPSS requests attribution when used in products, reports or publications.
- **SigmaHQ rules** — Official rule licence: https://github.com/SigmaHQ/Detection-Rule-License. Rules use DRL 1.1; preserve each supplied rule author, source/licence reference and author attribution in output showing matches. The DRL 1.1 text is bundled.
- **Emerging Threats Open Suricata rules** — Upstream notice: https://rules.emergingthreats.net/open/. The pinned notice identifies multiple SID-scoped terms, including GPLv2 and BSD-style ranges and a separate ETPRO-only range. This project bundles the upstream notice plus GPL-2.0 text and blocks public DB releases containing SIDs 2800000–2900000. Do not describe the whole ruleset as BSD-only.
- **Zeek Intel scripts** — Upstream source: https://github.com/zeek/zeek. The pinned BSD-style notice is bundled; some upstream files may carry additional notices.

## Release checks

The release packager requires all twelve source manifests (excluding the placeholder example.json) to record license_verified: true and an HTTPS official terms URL. Before publishing, it verifies declared local licence-file hashes, bundles notices/manifests and rejects Suricata records with the upstream ETPRO-only SID range. This snapshot-level gate cannot guarantee that every embedded third-party passage has identical terms; the source provenance remains part of the stored record and must be respected.
