# 10 - License Audit of the 17 Research References
**Scope.** All 17 shallow clones under `D:\Github\Agent Bug Bounty\research\`, audited for
`LICENSE` / `NOTICE` / `EULA` / terms-of-use files and embedded license text.
**Audit date:** 2026-11-20. **Commit hashes** are the local `HEAD` of each clone.
**Status:** engineering due-diligence summary, **not legal advice**. When in doubt, obtain counsel
or a written clarification from the rights holder before shipping.

---

## 0. Classification key

| Class | Meaning for AgentBug |
| --- | --- |
| `SAFE_TO_LEARN_PATTERNS` | Read, internalise, re-derive independently. Facts/standards may be restated in our own words with source attribution. Do not bulk-copy text. |
| `CODE_COPY_WITH_ATTRIBUTION_OK` | May adapt/copy source if the license notice, copyright line, change notices and (where present) `NOTICE`/patent terms are preserved in our distribution. |
| `RESTRICTED/DO_NOT_COPY` | Do not copy code or substantive text into AgentBug. Study behaviour/architecture only, or obtain a separate licence. |

---

## 1. Summary matrix

| # | Repo (upstream) | Commit (HEAD) | License type | Primary source of truth (absolute path) | Copyleft / network | Patent | Research-only | Class |
|---|---|---|---|---|---|---|---|---|
| 1 | opencode (`anomalyco/opencode`) | `d643c875879feef6198d28307a5592a46c6fd56d` | MIT (c) 2025 opencode | `D:\Github\Agent Bug Bounty\research\opencode\LICENSE` | none | none explicit | none | **CODE_COPY_WITH_ATTRIBUTION_OK** |
| 2 | pentagi (`vxcontrol/pentagi`) | `cffed9485aa1cca70762cd08a57ac62a80406258` | MIT core **+ EULA + AGPL-3.0 SDK claim** | `...\pentagi\LICENSE`, `...\pentagi\NOTICE`, `...\pentagi\EULA.md`, `...\pentagi\README.md` | **AGPL-3.0 network copyleft** (VXControl Cloud SDK) | AGPL patent terms; MIT/EULA silent | **YES** (lawful pen-test/research only; no production) | **RESTRICTED/DO_NOT_COPY** |
| 3 | goose (`block/goose`) | `42055e73fda21edd8f3056a5eef682d08589aef0` | Apache-2.0 (c) 2024 Block, Inc. | `...\goose\LICENSE` | none | express grant + litigation termination | none | **CODE_COPY_WITH_ATTRIBUTION_OK** |
| 4 | rig (`0xPlaygrounds/rig`) | `da8d6a935bdbe3bc9b6a72a56859df0100d2e998` | MIT (c) 2024 Playgrounds Analytics Inc. | `...\rig\LICENSE` (+ per-crate `LICENSE`, `...\rig\plugins\rig-claude-cloak\THIRD_PARTY_NOTICES`) | none | none explicit | none | **CODE_COPY_WITH_ATTRIBUTION_OK** |
| 5 | strix (`usestrix/strix`) | `a1ccf777d80e812edf23fc8b82bdc17def6143ac` | Apache-2.0 (c) 2025 OmniSecure Inc. | `...\strix\LICENSE` | none | express grant + litigation termination | none | **CODE_COPY_WITH_ATTRIBUTION_OK** |
| 6 | cai (`aliasrobotics/cai`) | `6dc79257777f5f1c9500b4d2319935d34a47412e` | **Dual: MIT + proprietary research-only** | `...\cai\LICENSE`, `...\cai\LICENSE-MIT`, `...\cai\DISCLAIMER`, `...\cai\pyproject.toml` | none | none explicit | **YES** (non-commercial research/academic only) | **RESTRICTED/DO_NOT_COPY** |
| 7 | langgraph (`langchain-ai/langgraph`) | `58a6e1cc5b7dfc3619fc6e7e7573b040d554649b` | MIT (c) 2024 LangChain, Inc. | `...\langgraph\LICENSE` (+ 8 sub-package `LICENSE` files, all MIT) | none | none explicit | none | **CODE_COPY_WITH_ATTRIBUTION_OK** |
| 8 | temporal (`temporalio/temporal`) | `a8f8328b001bd3302e658cdd062e18a5e92cf50f` | MIT (c) 2025 Temporal Technologies Inc. + (c) 2020 Uber Technologies, Inc. | `...\temporal\LICENSE` (+ 5 sub-`LICENSE`, same text) | none | none explicit | none | **CODE_COPY_WITH_ATTRIBUTION_OK** |
| 9 | mcp (`modelcontextprotocol/modelcontextprotocol`) | `8a18b4b3292b9f9b3aee73f6325f9f62f19a89f9` | **MIT to Apache-2.0 transition + CC-BY-4.0 docs** | `...\mcp\LICENSE` (single file contains all three) | none | Apache grant + litigation termination | none | **CODE_COPY_WITH_ATTRIBUTION_OK** (per-file license awareness) |
| 10 | owasp-wstg (`OWASP/www-project-web-security-testing-guide`) | `4126c29f4f585cc2b19897f90f9f252a9e36f4c8` | CC BY-SA 4.0 | `...\owasp-wstg\info.md` line 27 (no root LICENSE) | doc ShareAlike | patent not licensed | none | **SAFE_TO_LEARN_PATTERNS** |
| 11 | owasp-asvs (`OWASP/ASVS`) | `82fb2f41cdb623e0b11e4d9a6b97c4306c1d119c` | CC BY-SA 4.0 | `...\owasp-asvs\LICENSE.md`, `...\owasp-asvs\README.md` lines 5-14 | doc ShareAlike | patent not licensed | none | **SAFE_TO_LEARN_PATTERNS** |
| 12 | owasp-api-security (`OWASP/API-Security`) | `33cea37b2ffde3e2e62f6b5d79a029a22a846633` | CC BY-SA 4.0 | `...\owasp-api-security\LICENSE` | doc ShareAlike | patent not licensed | none | **SAFE_TO_LEARN_PATTERNS** |
| 13 | cwe (`CWE-CAPEC/CWE-Content-Development-Repository`) | `ea5a2ea88febdf26d293e604ecd4b4dae183a93d` | MITRE CWE Terms of Use (custom permissive) | `...\cwe\LICENSE` | none | none | none (commercial explicitly allowed) | **SAFE_TO_LEARN_PATTERNS** |
| 14 | cvss (`FIRSTdotorg/cvss-resources`) | `d766d0c8ab4368b67bf27dd0e411eb481f05fdbb` | No LICENSE file; FIRST CVSS conditions embedded in spec | `...\cvss\spec-rev\specification-document.md` lines 26-37 | none | none stated | none | **SAFE_TO_LEARN_PATTERNS** |
| 15 | hackerone-docs (`jk715/docs.hackerone.com`, community mirror) | `ba9ef9b2b3ddd4465312f0c6b94bf6863dd9f5bb` | CC BY-NC-SA 4.0 (c) 2018 HackerOne, Inc. | `...\hackerone-docs\LICENSE` | doc ShareAlike + **NonCommercial** | patent/trademark not licensed | **YES** (non-commercial only) | **RESTRICTED/DO_NOT_COPY** |
| 16 | bugcrowd-docs (`bugcrowd/mintlify-docs`) | `558fda7d191d241514613afc92e8714db457e41a` | MIT (c) 2026 Mintlify (starter-kit template) | `...\bugcrowd-docs\LICENSE` | none | none explicit | none | **SAFE_TO_LEARN_PATTERNS** (template code: attribution OK) |
| 17 | portswigger-academy (`frank-leitner/portswigger-websecurity-academy`, community mirror) | `d01874157191b49bcba642771b0a9d3b2e3f69f4` | **No license** - all rights reserved by author | `...\portswigger-academy\README.md` (personal write-ups; no LICENSE anywhere) | n/a | n/a | de facto | **RESTRICTED/DO_NOT_COPY** |

---

## 2. Detailed findings - agent/harness references

### 2.1 opencode - MIT (clean baseline)

- **Repo:** `https://github.com/anomalyco/opencode` (old fork: `sst/opencode`).
- **Commit:** `d643c875879feef6198d28307a5592a46c6fd56d` (2026-11-20).
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\opencode\LICENSE` (plain MIT, 21 lines, "Copyright (c) 2025 opencode").
- **Key obligations:** include the copyright notice and permission notice in all copies or substantial portions; "AS IS" warranty disclaimer. That is the entire obligation set.
- **Copyleft / network-copyleft:** none. MIT is permissive; no source-disclosure or network-use trigger.
- **Patent:** no express patent grant and no patent-termination clause (MIT's traditional gap). No known patent pledge in the LICENSE.
- **Research-only restrictions:** none.
- **Notes:** some packages carry their own MIT `LICENSE` files (e.g. `...\opencode\packages\http-recorder\LICENSE`, `packages\process-daemon\LICENSE`, `packages\ui\LICENSE`) and the app ships third-party notices at `...\opencode\packages\app\src\settings\about\notices\`. If you copy a specific package, carry that package's notice too.
- **Classification:** `CODE_COPY_WITH_ATTRIBUTION_OK`.

### 2.2 pentagi - MIT core, but EULA + AGPL-3.0 cloud SDK (highest-risk agent repo)

- **Repo:** `https://github.com/vxcontrol/pentagi`.
- **Commit:** `cffed9485aa1cca70762cd08a57ac62a80406258` (2026-10-23).
- **Sources of truth (all must be read together):**
  - `D:\Github\Agent Bug Bounty\research\pentagi\LICENSE` - MIT, "Copyright (c) 2025 PentAGI Development Team".
  - `D:\Github\Agent Bug Bounty\research\pentagi\NOTICE` - states: "This software integrates VXControl Cloud SDK for enhanced intelligence services. VXControl Cloud SDK is licensed under **AGPL-3.0 with a special exception for this official PentAGI project**."
  - `D:\Github\Agent Bug Bounty\research\pentagi\EULA.md` - 93 lines, full end-user licence agreement.
  - `D:\Github\Agent Bug Bounty\research\pentagi\README.md` lines 4231-4247 - section License; body says "All third-party dependencies use MIT-compatible licenses" and "While the VXControl Cloud SDK code is **MIT licensed**" - **directly contradicts** the NOTICE's AGPL-3.0 claim.
  - `D:\Github\Agent Bug Bounty\research\pentagi\licenses\README.md` - third-party licence generation instructions; claims MIT-compatible set (MIT, Apache-2.0, BSD-2, BSD-3, ISC, MPL-2.0, 0BSD).
  - Duplicate EULA shipped into the product: `...\pentagi\backend\cmd\installer\files\links\EULA.md`.
- **Key obligations:**
  - MIT: preserve copyright + permission notice.
  - EULA: non-exclusive, **non-transferable, revocable** licence for **lawful penetration testing only**; accepts EULA by downloading source/Docker image or using the web UI; **research/testing purposes only, "should not be deployed in production environments without thorough security assessment"**; authorized-access-only; extensive warranty disclaimer, liability cap (amount paid), **indemnification** obligation, **UK governing law and binding arbitration**; unilateral right to modify the EULA. Clause 17 says MIT prevails over EULA "with respect to the source code" in a conflict - but the EULA still governs the software "as a whole, including pre-built Docker images and the web UI."
  - NOTICE: AGPL-3.0 obligations for the VXControl Cloud SDK, with an exception granted **only to the official PentAGI project** - that exception does **not** flow to AgentBug.
- **Copyleft / network-copyleft risk:** **HIGH.** AGPL-3.0 is network copyleft: if AgentBug incorporated the VXControl Cloud SDK and users interact with it over a network, the corresponding source of the combined work would have to be offered to those users. The README contradicts the NOTICE (calls the SDK MIT); **treat the stricter AGPL-3.0 statement as controlling until VXControl confirms in writing.** MPL-2.0 also appears in the dependency list (file-level copyleft).
- **Patent:** MIT and EULA contain no express patent grant; AGPL-3.0 carries its own patent/non-discrimination terms. The EULA adds an indemnity that could be triggered by patent claims arising from your use.
- **Research-only restrictions:** explicit - authorized pen-testing/research; no production, no critical infrastructure without validation; no illegal use.
- **Classification:** `RESTRICTED/DO_NOT_COPY`. The bare MIT source modules could in theory be copied with attribution, but the EULA-over-whole-product layer plus the unresolved AGPL/MIT SDK conflict make repo-wide copying unsafe. Study architecture only; do not vendor code.

### 2.3 goose - Apache-2.0

- **Repo:** `https://github.com/block/goose`. **Commit:** `42055e73fda21edd8f3056a5eef682d08589aef0` (2026-11-20).
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\goose\LICENSE` (Apache-2.0, "Copyright 2024 Block, Inc.").
- **Obligations:** (section 4a) give recipients a copy of the licence; (4b) mark modified files prominently; (4c) retain copyright/patent/trademark/attribution notices; (4d) propagate any `NOTICE` file if one exists (none at root); (6) no trademark use.
- **Copyleft:** none. **Patent:** express royalty-free patent grant from each contributor, **terminating if you bring patent litigation** alleging the work infringes. **Research-only:** none.
- **Classification:** `CODE_COPY_WITH_ATTRIBUTION_OK`.

### 2.4 rig - MIT

- **Repo:** `https://github.com/0xPlaygrounds/rig`. **Commit:** `da8d6a935bdbe3bc9b6a72a56859df0100d2e998` (2026-11-19).
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\rig\LICENSE` (MIT, "Copyright (c) 2024, Playgrounds Analytics Inc."). Per-crate MIT `LICENSE` files exist under `crates/rig-core`, `rig-lancedb`, `rig-mongodb`, `rig-neo4j`, `rig-postgres`, `rig-qdrant`, `rig-sqlite`, `rig-cassette`.
- **Obligations:** MIT notice; preserve per-crate notices when copying a crate. `D:\Github\Agent Bug Bounty\research\rig\plugins\rig-claude-cloak\THIRD_PARTY_NOTICES` records that "portions of the request shaping and schema normalization are adapted from Oh My Pi ... under MIT License, Copyright (c) 2025 Mario Zechner / 2025-2026 Can BAlAk / 2026 Stencil Labs, Inc." - copy that notice if you copy that plugin.
- **Copyleft:** none. **Patent:** none explicit. **Research-only:** none.
- **Classification:** `CODE_COPY_WITH_ATTRIBUTION_OK`.

### 2.5 strix - Apache-2.0

- **Repo:** `https://github.com/usestrix/strix`. **Commit:** `a1ccf777d80e812edf23fc8b82bdc17def6143ac` (2026-11-19).
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\strix\LICENSE` (Apache-2.0, boilerplate "Copyright 2025 OmniSecure Inc."); README badge confirms Apache 2.0.
- **Obligations:** standard Apache-2.0 section 4 (licence copy, change notices, retained notices, `NOTICE` propagation if present - no root `NOTICE` found); section 6 trademarks.
- **Copyleft:** none. **Patent:** express grant with litigation-termination clause (section 3). **Research-only:** none in the licence (the tool is documented for authorized security testing, a use-policy point, not a copyright restriction).
- **Classification:** `CODE_COPY_WITH_ATTRIBUTION_OK`.

### 2.6 cai - dual MIT + proprietary research-only (high restriction)

- **Repo:** `https://github.com/aliasrobotics/cai`. **Commit:** `6dc79257777f5f1c9500b4d2319935d34a47412e` (archival snapshot, 2026-08-22; repo described as archived/read-only research artifact).
- **Sources of truth:**
  - `D:\Github\Agent Bug Bounty\research\cai\LICENSE` - "combination of open-source components under the MIT License and proprietary additions licensed for research purposes only." Section 1: MIT-licensed portions are in **`src/cai/agents`**, derived from `openai/openai-agents-python`, full text in `LICENSE-MIT`. Section 2: "All additions, modifications, and new components authored by Alias Robotics S.L. - found in the `src/cai`" are under a **Research-Use License**: "Permission is granted to use, copy, and modify these components **solely for non-commercial research and academic purposes** ... **Commercial, professional, or production use ... is strictly prohibited without a commercial license.**" Copyright (c) 2025 Alias Robotics S.L.
  - `D:\Github\Agent Bug Bounty\research\cai\LICENSE-MIT` - MIT (c) 2025 OpenAI.
  - `D:\Github\Agent Bug Bounty\research\cai\DISCLAIMER` - research/education/evaluation only; no disruption of live production systems; authorized access required; trained professionals; EU AI Act alignment framing.
  - `D:\Github\Agent Bug Bounty\research\cai\pyproject.toml` line 7: `license = {text = "Dual-licensed MIT and Proprietary"}`.
  - `D:\Github\Agent Bug Bounty\research\cai\CITATION.cff` - citation obligation for academic use.
- **Obligations:** retain copyright/licence notice in all copies; non-commercial research/academic only for Alias-authored parts; commercial licence required otherwise; cite the paper for research use.
- **Copyleft:** none. **Patent:** none explicit.
- **Research-only restrictions:** **YES - the defining feature.** Also note the ambiguity: MIT code is said to live in `src/cai/agents`, but proprietary additions are broadly "found in the `src/cai`" tree. Without file-level markings, assume any cai-authored file outside the clearly MIT-derived agent subset is proprietary.
- **Classification:** `RESTRICTED/DO_NOT_COPY` (narrow exception: the verifiably MIT `src/cai/agents` subset is `CODE_COPY_WITH_ATTRIBUTION_OK` if provenance is confirmed).

### 2.7 langgraph - MIT

- **Repo:** `https://github.com/langchain-ai/langgraph`. **Commit:** `58a6e1cc5b7dfc3619fc6e7e7573b040d554649b` (2026-11-20).
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\langgraph\LICENSE` (MIT (c) 2024 LangChain, Inc.). All nine sub-package `LICENSE` files (root, `libs/checkpoint`, `libs/checkpoint-postgres`, `libs/checkpoint-sqlite`, `libs/cli`, `libs/cli/js-examples`, `libs/langgraph`, `libs/prebuilt`, `libs/sdk-py`) were verified MIT/LangChain.
- **Obligations:** MIT notice. **Copyleft:** none. **Patent:** none explicit. **Research-only:** none.
- **Classification:** `CODE_COPY_WITH_ATTRIBUTION_OK`.

### 2.8 temporal - MIT (dual copyright)

- **Repo:** `https://github.com/temporalio/temporal`. **Commit:** `a8f8328b001bd3302e658cdd062e18a5e92cf50f` (2026-11-19).
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\temporal\LICENSE` - "The MIT License", **two copyright lines**: (c) 2025 Temporal Technologies Inc. **and** (c) 2020 Uber Technologies, Inc. Five additional `LICENSE` files under `common/persistence/...`, `common/testing/protoassert`, `schema/sqlite`, `temporaltest` carry the same text.
- **Obligations:** MIT notice - reproduce **both** copyright lines when copying.
- **Copyleft:** none. **Patent:** none explicit. **Research-only:** none.
- **Classification:** `CODE_COPY_WITH_ATTRIBUTION_OK`.

### 2.9 mcp - mixed MIT / Apache-2.0 / CC-BY-4.0

- **Repo:** `https://github.com/modelcontextprotocol/modelcontextprotocol`. **Commit:** `8a18b4b3292b9f9b3aee73f6325f9f62f19a89f9` (2026-11-19).
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\mcp\LICENSE` - a single file containing all three regimes. Header: "undergoing a licensing transition from MIT to Apache-2.0. All new code and specification contributions ... Apache-2.0. Documentation contributions (excluding specifications) ... CC-BY-4.0. Contributions ... originally MIT ... remain MIT."
  - Apache-2.0 body; MIT (c) 2024-2025 "Model Context Protocol a Series of LF Projects, LLC"; CC-BY-4.0 pointer for docs.
  - Secondary asset licences: `...\mcp\blog\assets\icons\LICENSE`, `LICENSE-lucide`, `...\blog\assets\js\vendor\LICENSE`, `...\blog\static\fonts\Geist-LICENSE.txt`.
- **Obligations:** determine per-file regime; Apache-2.0 section 4 notices/change markers and `NOTICE` propagation if a `NOTICE` ships; CC-BY-4.0 attribution for docs.
- **Copyleft:** none. **Patent:** Apache-2.0 express grant with litigation termination; MIT/CC-BY silent.
- **Research-only:** none (also `AI_POLICY.md`, `ANTITRUST.md` - policy, not copyright).
- **Classification:** `CODE_COPY_WITH_ATTRIBUTION_OK` (check each file's applicable licence).

---

## 3. Detailed findings - standards / body of knowledge

### 3.1 OWASP WSTG / ASVS / API-Security - all CC BY-SA 4.0

- **Repos/commits:** `owasp-wstg` `4126c29f4f585cc2b19897f90f9f252a9e36f4c8`; `owasp-asvs` `82fb2f41cdb623e0b11e4d9a6b97c4306c1d119c`; `owasp-api-security` `33cea37b2ffde3e2e62f6b5d79a029a22a846633`.
- **Sources of truth:**
  - `D:\Github\Agent Bug Bounty\research\owasp-wstg\info.md` line 27 ("CC BY-SA 4.0") - **no root LICENSE file**.
  - `D:\Github\Agent Bug Bounty\research\owasp-asvs\LICENSE.md` and `...\owasp-asvs\README.md` lines 5-14.
  - `D:\Github\Agent Bug Bounty\research\owasp-api-security\LICENSE`.
- **Obligations:** attribution (creator identification, copyright notice, licence notice, disclaimer notice, URI, indicate changes) + **ShareAlike**: adapted material must be licensed under CC BY-SA 4.0 (or a BY-SA-compatible licence). No additional/downstream restrictions.
- **Copyleft:** not code copyleft, but **documentation ShareAlike** - do not paste adapted OWASP text into a proprietary, differently-licensed report without satisfying SA.
- **Patent/trademark:** explicitly **not licensed** under CC. OWASP name/logo usage is separate.
- **Research-only:** none.
- **Classification:** `SAFE_TO_LEARN_PATTERNS`. Restate methodology/checklist items in our own wording with an OWASP attribution link. If verbatim excerpts are used, keep the excerpt small, attribute, and ensure the containing work can satisfy ShareAlike.

### 3.2 CWE - MITRE CWE Terms of Use

- **Repo/commit:** `cwe` `ea5a2ea88febdf26d293e604ecd4b4dae183a93d`.
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\cwe\LICENSE` ("The CWE Terms of Use are reprinted ... from https://cwe.mitre.org/about/termsofuse.html").
- **Obligations:** "free to use ... for any research, development, and/or commercial purposes" under a non-exclusive royalty-free licence; **any copy must reproduce MITRE's copyright designation and this licence**; "CWE is a trademark of The MITRE Corporation." Contributors grant a perpetual, worldwide, royalty-free, irrevocable licence to their contributions.
- **Copyleft:** none. **Patent:** none stated. **Research-only:** none - commercial use is explicitly permitted.
- **Classification:** `SAFE_TO_LEARN_PATTERNS` (attribution + licence reproduction required for substantive copies; CWE IDs and weakness facts are safe to use).

### 3.3 CVSS - no LICENSE file; FIRST conditions in the spec

- **Repo/commit:** `cvss` `d766d0c8ab4368b67bf27dd0e411eb481f05fdbb`.
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\cvss\spec-rev\specification-document.md` lines 26-37. No `LICENSE`/`NOTICE` file anywhere in the repo.
- **Terms:** "CVSS is owned and managed by FIRST.Org, Inc. ... FIRST owns all rights and interest in CVSS, [and] licenses it to the public freely for use, subject to the conditions below ... FIRST **require[s] that any individual or entity using CVSS give proper attribution, where applicable, that CVSS is owned by FIRST and used by permission**. Further, FIRST requires as a condition of use that any individual or entity which publishes CVSS data conforms to the guidelines ... and provides **both the score and the vector string**."
- **Obligations:** attribute CVSS to FIRST; if AgentBug publishes scores, publish the vector string alongside and follow the spec.
- **Copyleft:** none. **Patent:** none stated. **Research-only:** none.
- **Classification:** `SAFE_TO_LEARN_PATTERNS` - implement scoring from the spec independently; do not reproduce large portions of FIRST's specification text without attribution.

### 3.4 hackerone-docs - CC BY-NC-SA 4.0 (community mirror)

- **Repo/commit:** `hackerone-docs` `ba9ef9b2b3ddd4465312f0c6b94bf6863dd9f5bb` (last commit 2018). Mirror of `docs.hackerone.com`, not an official HackerOne repository.
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\hackerone-docs\LICENSE` - "Copyright (c) 2018 HackerOne, Inc. This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License."
- **Obligations:** attribution; **NonCommercial only** (section 2(a): reproduce/share "for NonCommercial purposes only"); **ShareAlike** (section 3(b): adapted material under CC BY-NC-SA 4.0 or compatible); no patent/trademark licence (section 2(b)(2)).
- **Copyleft / network:** no code copyleft, but **Strong doc ShareAlike + NonCommercial** - a commercial AgentBug cannot redistribute or embed this text.
- **Patent/trademark:** not licensed. **Research-only:** effectively yes - non-commercial only.
- **Classification:** `RESTRICTED/DO_NOT_COPY` (learning about HackerOne platform workflows is fine; do not copy articles/fields into a commercial product or report template).

### 3.5 bugcrowd-docs - MIT (Mintlify starter-kit template)

- **Repo/commit:** `bugcrowd-docs` `558fda7d191d241514613afc92e8714db457e41a`.
- **Source of truth:** `D:\Github\Agent Bug Bounty\research\bugcrowd-docs\LICENSE` - MIT, "Copyright (c) 2026 Mintlify". `README.md` is literally "Mintlify Starter Kit".
- **Obligations:** MIT notice for template/tooling code.
- **Copyleft:** none. **Patent:** none explicit. **Research-only:** none.
- **Caveat:** the MIT licence attaches to the **Mintlify starter-kit repository code**; it does not clearly establish a grant over Bugcrowd's editorial documentation content. Treat the prose as reference only.
- **Classification:** `SAFE_TO_LEARN_PATTERNS` (template code may be reused with MIT attribution).

### 3.6 portswigger-academy - no licence, community write-ups

- **Repo/commit:** `portswigger-academy` `d01874157191b49bcba642771b0a9d3b2e3f69f4` (last commit 2023).
- **Source of truth:** none - **no LICENSE, NOTICE or EULA file exists** anywhere in the repo. `D:\Github\Agent Bug Bounty\research\portswigger-academy\README.md` describes "my write-ups and scripts" by a private author (Frank Leitner), a community mirror, not PortSwigger content.
- **Obligations:** none granted. Under default copyright, all rights reserved by the author; PortSwigger's lab descriptions/material are separately owned by PortSwigger.
- **Copyleft / patent:** n/a. **Research-only:** de facto - no reuse permission.
- **Classification:** `RESTRICTED/DO_NOT_COPY`. Learn the vulnerability classes from the labs directly; do not vendor the write-ups or scripts.

---

## 4. Special-attention deep dives (as requested)

- **opencode (MIT):** cleanest source in the set. Safe to adapt session/runner/inbox/execution/compaction patterns *and* code, provided the MIT notice travels with any substantial copy. No copyleft, no patent clause, no research restriction. Keep a `THIRD_PARTY_NOTICES` for any copied package-level licences.
- **pentagi (MIT core + AGPL-3.0 SDK + EULA):** the **only network-copyleft exposure** in the 17. NOTICE claims AGPL-3.0 for the VXControl Cloud SDK with an exception limited to the *official* PentAGI project; README claims the SDK is MIT. This contradiction must be resolved in writing before any code reuse. Independently, the EULA restricts use to authorized pen-testing/research, forbids production deployment without assessment, grants a revocable non-transferable licence, imposes indemnity and UK arbitration. **Do not copy.**
- **cai (MIT + research-only proprietary):** MIT only for the `src/cai/agents` portion derived from `openai/openai-agents-python`; Alias Robotics additions (broadly `src/cai`) are non-commercial research/academic only, with commercial/professional/production use prohibited. Archived as a research artefact. **Do not copy** beyond a provenance-verified MIT subset.
- **strix (Apache-2.0):** permissive but with the Apache-2.0 patent grant and litigation-termination clause, plus section 4 change-notice/NOTICE duties. Safe to copy with full attribution; do not strip the licence or change markers.

---

## 5. Concrete rules for AgentBug

### 5.1 May be adapted (patterns and code, with attribution)

- **opencode, goose, rig, strix, langgraph, temporal, mcp** - permissive licences (MIT / Apache-2.0). Port architecture ideas and, where genuinely useful, small attributed code fragments.
- **cwe, cvss, owasp-\*** - facts, weakness taxonomies, scoring rules, testing methodology. Re-derive in our own words.
- **bugcrowd-docs** - Mintlify starter-kit template mechanics only (MIT).

### 5.2 Must not be copied into AgentBug

- **pentagi:** no code from the repo, and absolutely nothing from the VXControl Cloud SDK / cloud integration path until the AGPL-vs-MIT conflict is resolved. No EULA-governed UI/config assets.
- **cai:** no Alias Robotics-authored code, prompts, agent definitions or benchmark content. The MIT `src/cai/agents` subset only after per-file provenance verification.
- **hackerone-docs:** no substantive article text (NonCommercial + ShareAlike incompatible with a commercial AgentBug).
- **portswigger-academy:** no write-ups, scripts, images or lab solution text (no licence granted).
- **OWASP text:** no large verbatim blocks inside a differently-licensed proprietary document (ShareAlike).

### 5.3 Required attribution / NOTICE when we do copy

1. **MIT sources** (opencode, rig, langgraph, temporal, cai-MIT subset, mcp-MIT, bugcrowd template): reproduce the exact copyright line(s) (temporal needs **both** Temporal Technologies and Uber lines) plus the full MIT permission text in a `THIRD_PARTY_NOTICES` file shipped with AgentBug, and in a source header for any copied file.
2. **Apache-2.0 sources** (goose, strix, mcp-Apache): ship the full Apache-2.0 text, add prominent "changed by AgentBug" notices to modified files, retain all original copyright/patent/trademark/attribution notices, and propagate any upstream `NOTICE` file. Do not use upstream trademarks (Block, Strix/OmniSecure, MCP) in a way that implies endorsement.
3. **CC BY-SA / CC BY / MITRE / FIRST docs:** attribution line with source URL and licence name; mark modifications; for CC BY-SA adapted material, license our adaptation under CC BY-SA 4.0 (or keep it as a separate, clearly-marked document). For CWE, reproduce MITRE's copyright designation and the CWE Terms of Use. For CVSS, credit FIRST ("CVSS is owned by FIRST and used by permission") and always publish score **plus** vector string.
4. Maintain a single canonical `THIRD_PARTY_NOTICES` (or equivalent) in the AgentBug distribution; do not rely on README links alone. Reference the exact commit hashes in section 1 so provenance is auditable.

### 5.4 Distribution / avoid

- **Never** ship AgentBug as or with a derivative of PentAGI (EULA "as a whole" + revocable licence + AGPL SDK). Do not bundle VXControl Cloud SDK code, `vxcontrol/*` Docker images, or any code fetched from `vxcontrol/cloud`.
- **Never** incorporate the AGPL SDK into a network-facing AgentBug service without counsel - AGPL section 13 would require offering corresponding source to remote users; the official-project exception does not cover us.
- **Never** present CAI-derived components as ours in a commercial/production offering without a commercial licence from Alias Robotics.
- **Never** embed HackerOne/PortSwigger mirrored prose in commercially distributed playbooks, report templates, or datasets.
- **Do not** use upstream names/logos ("opencode", "PentAGI", "CAI", "Strix", "HackerOne", "PortSwigger", "OWASP", "CWE", "CVSS") as AgentBug branding or in a way implying endorsement; several licences withhold trademark rights (all CC licences, Apache-2.0 section 6, MITRE ToU).
- Keep the `research/` tree out of any AgentBug release artifact (it is already gitignored); the audit exists to govern what crosses the boundary, not to ship the clones.
- Add a licence-check gate to CI that flags any source file copied from a `RESTRICTED/DO_NOT_COPY` reference.

---

## 6. Open questions / caveats

1. **PentAGI AGPL contradiction** - NOTICE says AGPL-3.0-with-exception; README section License says the cloud SDK code is MIT. Escalate to VXControl (`info@vxcontrol.com`) before any reuse; until then treat as AGPL-3.0.
2. **CAI file-level boundary** - the licence says MIT code is in `src/cai/agents` but proprietary additions are broadly "found in src/cai". No per-file SPDX markers were observed; default to restricted.
3. **bugcrowd-docs** - MIT licence is Mintlify's (starter-kit code); editorial Bugcrowd documentation ownership is not established by that file. Do not bulk-copy the prose.
4. **owasp-wstg** - no root `LICENSE`; licence is asserted in `info.md`. If distributing WSTG-derived material, confirm the CC BY-SA 4.0 designation with OWASP.
5. **cvss** - no `LICENSE` file; conditions are inside the spec document. FIRST may update terms; re-check at `https://www.first.org/cvss/` before publishing scores.
6. Apache-2.0 patent-termination clauses (goose, strix, mcp) mean an AgentBug patent suit against those projects (or related entities) forfeits our patent licence - a legal/business decision, not just an engineering one.

---

## 7. Appendix - all audited source-of-truth paths

```
D:\Github\Agent Bug Bounty\research\opencode\LICENSE
D:\Github\Agent Bug Bounty\research\pentagi\LICENSE
D:\Github\Agent Bug Bounty\research\pentagi\NOTICE
D:\Github\Agent Bug Bounty\research\pentagi\EULA.md
D:\Github\Agent Bug Bounty\research\pentagi\README.md               (lines 4231-4247)
D:\Github\Agent Bug Bounty\research\pentagi\licenses\README.md
D:\Github\Agent Bug Bounty\research\goose\LICENSE
D:\Github\Agent Bug Bounty\research\rig\LICENSE
D:\Github\Agent Bug Bounty\research\rig\plugins\rig-claude-cloak\THIRD_PARTY_NOTICES
D:\Github\Agent Bug Bounty\research\strix\LICENSE
D:\Github\Agent Bug Bounty\research\cai\LICENSE
D:\Github\Agent Bug Bounty\research\cai\LICENSE-MIT
D:\Github\Agent Bug Bounty\research\cai\DISCLAIMER
D:\Github\Agent Bug Bounty\research\cai\CITATION.cff
D:\Github\Agent Bug Bounty\research\cai\pyproject.toml
D:\Github\Agent Bug Bounty\research\langgraph\LICENSE              (+ 8 sub-package LICENSE files)
D:\Github\Agent Bug Bounty\research\temporal\LICENSE               (+ 5 sub-LICENSE files)
D:\Github\Agent Bug Bounty\research\mcp\LICENSE
D:\Github\Agent Bug Bounty\research\owasp-wstg\info.md             (line 27; no root LICENSE)
D:\Github\Agent Bug Bounty\research\owasp-asvs\LICENSE.md
D:\Github\Agent Bug Bounty\research\owasp-asvs\README.md           (lines 5-14)
D:\Github\Agent Bug Bounty\research\owasp-api-security\LICENSE
D:\Github\Agent Bug Bounty\research\cwe\LICENSE
D:\Github\Agent Bug Bounty\research\cvss\spec-rev\specification-document.md  (lines 26-37; no LICENSE)
D:\Github\Agent Bug Bounty\research\hackerone-docs\LICENSE
D:\Github\Agent Bug Bounty\research\bugcrowd-docs\LICENSE
D:\Github\Agent Bug Bounty\research\portswigger-academy\README.md  (no LICENSE anywhere)
```
