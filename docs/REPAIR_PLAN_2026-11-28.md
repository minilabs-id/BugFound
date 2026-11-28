# Rencana Perbaikan BugFound — 2026-11-28

> **Dokumen perencanaan saja. Tidak ada kode, konfigurasi, atau test yang diubah.**
> Dasar: `docs/AUDIT_2026-11-27.md` (register ~150 temuan) + riset 7 agen paralel
> yang mengevaluasi desain fix, test yang akan berubah, dependensi lintas-crate,
> migrasi schema, dan risiko regresi.
> Baseline: branch `dev`, HEAD `e344cc022ec0cb732f95cddbb7add33c865bc509`.
> Working tree **129 + 1 file audit** = 130 entri; banyak file berstatus `AM`/`MM`
> (staged + unstaged). **Jangan `git reset` / `checkout` / regenerate massal** —
> terapkan edit target per finding.

---

## 1. Kesimpulan riset yang mengubah rencana

Riset tidak sekadar mengulang audit — beberapa klaim audit perlu dibatalkan atau
disederhanakan sebelum dieksekusi:

| # | Topik | Keputusan riset | Dampak ke plan |
| --- | --- | --- | --- |
| R1 | **M1 "dict-vs-string"** | **REFUTED.** Payload audit `techniques` adalah array of strings (`engagement/src/investigation.rs:378-384` dari `NextStep.playbook_id`); dict milik LLM diparsing di `planner.rs:62-83` dan tidak pernah masuk audit event. | **Jangan perbaiki M1.** Defek nyata: `M4_coverage` di `agent_eval.py:113-121` hanya emit `rows`, tanpa `value`. |
| R2 | **`frontend/dist` & `node_modules` tracked** | **REFUTED.** `git ls-files` → 0 tracked; keduanya ignored (`.gitignore:19-20`). | Tidak perlu untrack. Cukup dokumentasikan `npm ci` (F22). |
| R3 | **`_fix_e2e_tmp.py`** | File **untracked** dan menarget string usang di `e2e_test.ps1`. | Hapus biasa (bukan `git rm`), jangan dijalankan (F18). |
| R4 | **Double-count token provider** | **REFUTED.** `record_token_usage` menyimpan delta per call; `token_usage` menjumlahkan dengan benar; `bugfound-llm` tidak mengakumulasi. | Koreksi `docs/architecture/01:155-157` dan `05:216`. Yang nyata: `tokens_offset` ditulis tapi tak dibaca (D2). |
| R5 | **`start-desktop.bat` / `custom-protocol` / `ApprovalRequired`** | Launcher egui disengaja; stale-`dist` termitigasi build order CI; `ApprovalRequired` dead tapi approval tampil via polling 1.5 s. | Tidak masuk plan perbaikan (hanya catatan docs). |
| R6 | **Biaya ceiling "inert"** | `0 = unlimited` **memang terdokumentasi**; gate bekerja bila `max_cost_usd` diset. | Defek nyatanya: tak ada surface config yang mengekspos `max_cost_usd` — masuk Fase 2/4, bukan "gate rusak". |
| R7 | **Jalur promosi finding (C1)** | `verify_findings_with_oob` (`engagement/lib.rs:4033-4120`) dipanggil produksi **hanya di `:2124`**. `Verifier::decide` hanya dipakai test. `set_finding_validation` (`:4116`) = satu-satunya writer status `validated`. | **Jangan tambah call site.** Ubah fungsi itu agar semua verdict dibuat `Verifier::decide`; turunkan `CandidateVerdict.confirmed` jadi advisory. |
| R8 | **Redaksi bersama** | 3 implementasi penuh + 4 canary scrubber, tanpa parity. `kernel-traits → store` sudah ada ⇒ `store → kernel-traits` akan **cycle**. `collaborator` sengaja bebas dependency internal. | **Buat leaf crate baru `bugfound-redact`** (serde_json saja). `tools`/`store` tetap `pub use` agar ~100 call site tak berubah; collaborator depend langsung. |
| R9 | **Stop/Steer (E1/E2)** | `runner.steer` ternyata hanya `store.enqueue_inbox` + `wake_scoped` — tidak butuh `LlmClient`/API key. Worker thread park di `block_on`, jadi channel prioritas tak cukup. | Tangani **sinkron di `RuntimeHandle`**: `request_stop(&store, id)` + core free function `steer(store, session, text)`. Hapus variant `RuntimeCommand::{Stop,Steer}`. |
| R10 | **Gate evidence (D4)** | `verify_evidence` `Ok(true)` saat 0 row memang disengaja & diuji. | Perbaiki **di caller** (`engagement/lib.rs:4040`): loop per finding memanggil `verify_finding_evidence`. Jangan ubah semantik store. |
| R11 | **Engagement id (D3)** | `list_findings_for_engagement` baru saja landed (V3_STATUS §3) dengan regression test. | **Boundary parse sekarang** (zero migrasi); kolom `engagement_id` nyata opsional di schema v4. |
| R12 | **Hash chain historis (D11)** | Rehash baris lama = menghancurkan bukti tampering. | Verifikasi terima formula lama **atau** baru (version gate), bukan rewrite data. |
| R13 | **Monitor hash (A9)** | Benar secara kode, tapi hanya menyempitkan dedup ke bucket 1 s dengan `key_index` terbatas; bukan security gate. | Tetap diperbaiki, prioritas turun ke Fase 3. |
| R14 | **A18 goal-lock scope** | Butuh perubahan trait `kernel-traits` + override `BountyDomain` + migrasi digest. Status masih **needs evidence**. | **Defer** sampai ada reproducer nyata. |

---

## 2. Prinsip & safeguard global

1. **Read-only saat perencanaan** — dokumen ini tidak mengubah kode. Eksekusi
   dilakukan terpisah, satu batch per fase, dengan commit atomik per *land-together group*.
2. **Fail-closed bertahap** untuk perubahan yang bisa memecah lab:
   scope kosong, schema `Enforce`, auth admin OOB, verifier authority, redaksi ketat.
   Pola: *shadow/warn → opt-in → default → hapus escape hatch*.
3. **Jangan reset working tree.** Banyak file `AM`/`MM` dan several eval files
   untracked. Edit target, commit eksplisit file baru.
4. **Backup DB sebelum schema v4** (`docs/deployment.md:207-224`). `.bugfound/bugfound.db`
   yang korup **sengaja tak disentuh** — `Store::open()` gagal sebelum migrasi;
   recovery bersifat operasional, jangan tambah auto-repair.
5. **Raw capture bytes tetap otoritatif** — redaksi hanya untuk view model,
   never feed redacted text kembali ke hash/evidence.
6. **Setiap fix harus punya regression test** yang gagal sebelum fix. Daftar
   test minimum ada di §7.

### Land-together groups (hard constraints)

| Grup | Fix | Alasan |
| --- | --- | --- |
| G-A | **A2 + A3 + A19** | Satu invariant approval: injection re-approval selalu enforced; flag hanya dihapus oleh reapprove-park & setelah claim sukses; detector simetris dengan `neutralize_envelope`. Dipisah → loop reapproval atau bypass tetap terbuka. |
| G-B | **A1 + A13** | Keduanya mengubah `resume_after_approval` deferred-tail loop / return type `execute_deferred_call`. |
| G-C | **A4 → sebelum A6** | Terminal transition harus owner-guarded sebelum lease heartbeat diperketat. |
| G-D | **C1 + C5 + C6** | Satu PR otoritas verifier: `Verifier::decide` + ROE gate semua oracle + demote status. |
| G-E | **B1 + B2 + E27** | Full-URL ke scope matcher di tools **dan** proxy, plus strictest-wins. Tanpa proxy, path rule tetap fail-open. |
| G-F | **A10 → A15** | Atomic `promote_inbox` dulu, baru cap drain. |
| G-G | **A12 = core + cli + desktop-core + desktop** | Kalau tidak bersama, produksi tetap kirim `max_steps = 20` ⇒ fix inert. |
| G-H | **B17 → B7 → B8 → B14 → B16** | Error classification → truncation → CRLF → cap → retry streaming. |
| G-I | **B12 → B4/B11** | Shared redact crate dulu, canary scrubbers pakai constant yang sama. |
| G-J | **M1 schema v4** (lihat §5) | Semua perubahan `Store::open()` atomik dalam satu transaksi. |

### Migration batches

| Batch | Isi | Catatan |
| --- | --- | --- |
| **M1 — schema v4** | D5 coverage unique index + dedupe; D10 event anchor table; D8 canonical timestamp; D16 migration ledger; D21 capture digest; D25 index cleanup; **C9 `AuthorizationAck.restriction_json`**; opsional D3 `findings.engagement_id` | Satu `schema_version(4)` ditulis hanya setelah semua statement sukses. D5 dedupe = risiko data tertinggi (row duplikat legacy hilang) — backup + fresh-vs-upgraded parity test. |
| **M2 — write atomicity** (code-only) | D6, D9, D11, D26 | Pola `transaction_with_behavior(Immediate)` + `changes()`; verifier berubah bersama writer. |
| **M3 — redaction** (code-only) | D1 + D20 + B12 | Redact field-by-field `Value`, hapus fallback raw. |
| **M4 — evidence gates** (code-only) | D4 + D12 + D19 + C6 + B5/B9/B22/B23 | Invarians bukti & promosi. |
| **M5 — budget** (code-only) | D2 + D22 | `tokens_offset` masuk `token_usage()`; guard konversi u64→i64. |
| **M6 — authorization** (code-only + D8 di M1) | D7, D18, D23, D24 | State machine approval/revalidation. |

---

## 3. Urutan fase eksekusi

```
Fase 0  STOP-BLEED       (code-only, tanpa migrasi)      ← paling mendesak
Fase 1  TRUST CHAIN      (verifier/OOB/ROE + config surface)
Fase 2  SCOPE & EVIDENCE (fail-closed bertahap + capture/hash)
Fase 3  DURABILITY       (schema v4 + atomic writes + lease)
Fase 4  CONTROL & UI     (Stop/Steer, config unified, report integrity)
Fase 5  LLM & EVAL       (streaming, defaults, metrik, docs)
Fase 6  RESIDUAL         (low/medium + cleanup + A18 if evidenced)
```

Setiap fase ditutup dengan **acceptance gate** (§6). Fase 0–3 adalah blocking;
Fase 4–5 bisa paralleled oleh owner berbeda setelah Fase 0 hijau.

---

## 4. Detail per fase

### Fase 0 — STOP-BLEED (code-only, tanpa migrasi schema)

**Objective:** tutup eksploitasi langsung yang bisa dipicu operator/model hari ini.

| Grup | Fix | Desain fix (ringkas) | File | Test baru / diubah | E/R |
| --- | --- | --- | --- | --- | --- |
| G-A | A2 | Hapus wrapper `if !auto_approve_all` pada cek `injection_suspected`/`target_changed`; hapus `reapprove = None` di `:1019`; tambah field `auto_approve_target_change: bool` (default false) hanya untuk target-change. | `core/lib.rs:1005-1020`, `AgentConfig` | Ubah `auto_approve_all_bypasses_target_change_guard` (:1438) & `autonomous_mode_allows_multi_target_batches` (:1013); baru `injection_flag_forces_approval_even_with_auto_approve_all` | M / **High** |
| G-A | A3 | Pindah `clear_session_flag` ke **setelah** `acquire_claim` sukses; gate pada `approval.reason` mengandung `GUARD_REAPPROVE` + `"injection"`. | `core/lib.rs:1542-1563` | Ubah `resume_approve_clears_injection_flag_and_executes_tool` (:1554); baru `resume_approve_with_failed_claim_keeps_injection_flag` | S-M / Med |
| G-A | A19 | Tambah regex whitespace-tolerant untuk role marker & `to = functions.`; jangan flatten seluruh teks (phrase needles tetap utuh). | `core/lib.rs:137-174,210-235` | Perluas `injection_detector_catches_role_and_tool_call_markers` (:2714) | S / Low |
| G-B | A1 | Tail `take_pending_calls` tetap diambil, tapi **eksekusi hanya saat approve**. Saat deny, tulis tool message `ok=false error=cancelled` per parked call (dengan `tool_call_id`), lalu tetap `run_loop`. Jangan pakai `settle_pending_calls` (sweep semua approval). | `core/lib.rs:2003-2019` | Baru `deny_of_multi_call_batch_cancels_deferred_tail_without_executing` | S / Med |
| G-B | A13 | `execute_deferred_call` → `Result<Option<String>>`; break tail loop pada terminal/blocked dan return hasil tanpa `run_loop` baru. | `core/lib.rs:1800-1803,2016-2019` | Baru `terminal_tool_in_deferred_batch_stops_remaining_calls` | S-M / Med |
| G-C | A4 | `finish()` → `transition_state_owned(&owner_id, …)`; pecah `finish_coordinator`: `settle_coordinator_state` selalu jalan (anti-hang), `clear_honored_stop` (ack + `STOP_REQUESTED_FLAG`) hanya saat `Ok(true)`. | `core/lib.rs:1273-1296` | Baru `stale_runner_finish_does_not_modify_state_or_clear_stop_flag` | M / **High** |
| G-D | C1 | `verify_findings_with_oob` tetap satu-satunya funnel; semua verdict dibuat `Verifier::decide` (map `paired_control_verdict`→`ControlOutcome`, `effective_oracle`→`OracleOutcome`, ROE→param/denied helper); hapus dual `"proven"` di `:4056`/`:4071`. | `engagement/lib.rs:4033-4120`, `verification.rs:209-274` | Update `live_oob_promotes_only_with_matching_interaction`, `real_http_capture_promotes_finding`, `differential_role_captures_promote`; baru: no promotion without `decide` | M / **High** |
| G-D | C5 | `roe_ok = roe_allows_finding(...)` di top loop, dipakai `Verifier::decide` untuk **semua** oracle termasuk OOB. | `engagement/lib.rs:4051-4063` | Baru: ROE-denied + OOB hit → tidak dipromosi | S / Low |
| G-D | C6 | `set_finding_verdict` demote status & clear `validated_at` saat verdict ≠ confirmed; `set_finding_validation` stamp hanya status positif (+ defense `verified_findings`). | `store/lib.rs:1672-1688,1825-1837,2955-2961` | Update `finding_verdict_never_stamps_validation`; baru validated→ruled_out demotion | S / Med |
| OOB | C2 | `run_http`: bajolock sama dengan DNS — `known = !token.is_empty() && is_known_token(&token)`; unknown → generic response, tidak record/echo. | `collaborator/main.rs:471-509` | Update `interaction_store_caps_total_and_records_by_token`; baru unknown Host tidak tercatat | S / Low |
| OOB | C3 | Bearer shared secret `--admin-token`/env untuk `/token` & `/interactions`, constant-time compare manual (tanpa dep baru); `--max-tokens` pool **tanpa eviction**; loopback bind sudah ada di `:628`. | `collaborator/main.rs:339-356,577-621` | Tulis ulang `tokens_are_unique_and_reuse_is_bounded` (codifies eviction); baru unauth admin ditolak | M / Med |
| OOB | C4 | Thread admin token: `OobFile`→`EngagementOptions.oob_admin_token`→`ToolOptions.oob_admin_token`→`HttpOobOracle::new(endpoint, token)`; bearer header; `HttpOobOracle::new(endpoint,"")` harus error. | `cli/main.rs:358-362,771-787`, `engagement/lib.rs:117-152,2120-2123`, `tools/lib.rs:153-157,3427,3528-3617`, `desktop-core/config.rs`, `desktop/config.rs` | Update `http_oob_oracle_reads_loopback_admin_api` (assert bearer + structured token) | M / Med |
| Store | D1 | Hapus `unwrap_or_else(|_| effective_args.clone())` di `persist_tool_result`; redaksi field-by-field `Value` termasuk scalar leaf; **tidak ada fallback raw**. | `store/lib.rs:3902-3904`, pipeline `:3120-3415` | Update `redaction_covers_json_headers_and_multiple_bearers` (:5039), `...pii_without_hiding_short_numbers` (:5502); baru malformed-JSON args tak masuk DB | M / Med |
| Store | D3 | Boundary parse marker `engagement_id=<id>` (awal/baris baru + whitespace/newline/EOL), bukan `instr` substring. Fallback `list_findings(engagement_id)` tetap hanya jika tak ada marker. | `store/lib.rs:1695-1715` | **Keep green** `findings_for_engagement_use_runner_session_marker` (:7422); baru `eng-1` vs `eng-10`/`eng-1x` | S / Low |
| Store | D4 | Gate di `engagement/lib.rs:4040`: loop per finding → `verify_finding_evidence(&id)`, reject `false`. Biarkan `verify_evidence` tetap `Ok(true)` saat 0 row. | `engagement/lib.rs:4040` | Baru: promotion dengan zero-evidence finding ditolak | S / Low |
| Scope | B1 | Teruskan **URL lengkap** ke `scope_target_allowed` di HTTP initial hop, redirect loop, proxy HTTP; DNS tetap host-only (comment); CONNECT sintesiskan `https://{authority}/`. Signature helper tidak berubah. | `tools/lib.rs:1546,1837-1841`, `proxy/main.rs:521,634-638` | Update 5 tools scope tests (:6963-7060); baru `http_request_blocks_out_of_scope_path_on_first_hop`, `http_request_redirect_to_out_of_scope_path_denied`, `proxy_http_path_scope_enforced` | M / Med |
| Scope | B2 | Bare entry = equality only; wildcard rules tetap include subdomain; hapus specificity escape `:775-784` → strictest-wins; samakan `policy::ScopeConfig::matches`. | `tools/lib.rs:656-704,766-784`, `policy/lib.rs:120-150,253-265` | Update scope tests tools + policy (:692,724,764,788,898,913,924); baru `bare_in_scope_entry_does_not_cover_subdomains`, `wildcard_out_beats_exact_in` | M / Med |
| Scope | E27 | Lihat B1 (proxy). | `proxy/main.rs:519-521` | Baru `scope_target_allowed("https://host/secret/x", out=["host/secret/*"]) == false` | S / Low-Med |
| Canary | B4 | `finalize`: scrub canary dari `current.as_str()` + tiap `redirect_chain[].from/.to`; `denial_result` pakai `redact_canaries` rekursif pada `fields`. **Jangan** scrub `capture` bytes. | `tools/lib.rs:1421-1440,1167,1550-1861` | Baru `canary_reflected_in_location_header_never_reaches_model`, `capture_still_contains_raw_canary` | S / Low |
| Eval | F1 | `assert_run_ok(completed, db)`: `returncode==0`, DB exists, tabel wajib ada, row count >0. Call sebelum export. CI → setup-python + gate metrics. | `agent_lab.py:193-217`, `adversarial_lab.py:110-165`, `desktop-ui.yml:43-49` | Self-test crashed binary / empty DB | M / Med |
| Eval | F4 | Lockdown fixture: `mode=ask`, `auto_approve_all=false`, no write/intrusive, `[scope] in_scope=["127.0.0.1"]`, endpoint loopback/omit. **File `AM` — edit, jangan reset.** | `eval/fixtures/local-target/bugfound.toml:2-19`, `brief.txt:12-13` | Config-lock assertion di lab | S / Med |
| Eval | F5 | `shell:false`, `spawnSync(process.execPath,[cli,...args])`, validasi URL (`new URL`, http/https, no control chars), selector via `JSON.stringify` (bukan blacklist quote). Template config tak perluubah. | `eval/fixtures/chrome-mcp/chrome-mcp-wrapper.js:12-22,42,63`, `.cmd` | Baru case URL dengan `&`/`\|` | S / **High** (RCE) |
| Eval | F6 | Env allowlist (PATH/SystemRoot/TEMP/HOME), `pop` `BUGFOUND_API_KEY`/`OPENAI_API_KEY`/`BUGFOUND_BASE_URL`/`BUGFOUND_MODEL`/`ANTHROPIC_API_KEY`; offline `base_url` → loopback placeholder. | `agent_lab.py:184-195`, `adversarial_lab.py:66-90` | Assertion env bersih | S / Med |
| Eval | F7 | `sys.executable` di semua `Popen`; `setup-python` di `desktop-ui.yml`; `$PyExe` di PS1. | `agent_lab.py:248,253`, `adversarial_lab.py:80,93`, `desktop-ui.yml:47-49`, PS1 scripts | CI job live hijau di ubuntu | S / Low |
| Eval | F20 | `shlex.split`, `shell=False`, `check=True`, `timeout=300`, env minimal. | `repeat_lab.py:161` | Self-test baseline mengandung `;` ditolak | S / Low |

**Acceptance Fase 0:** G1–G5 + G6/G7/G9 green; 6 integration test inti (§7) hadir &
passing; `adversarial_lab.py` & `agent_lab.py` **exit non-zero saat CLI crash**;
ADR-001 boundary check masih lolos; `git diff` hanya berisi file yang disengaja.

---

### Fase 1 — TRUST CHAIN & ROE (verifier, OOB, ROE, config surface)

| Fix | Desain fix (ringkas) | File | Test | E/R |
| --- | --- | --- | --- | --- |
| C7 | Detektor self-grading nyata: self-asserting phrases + canary hanya di header/absent → reject sebelum `accepted`; butuh paired control. Test lama lolos karena alasan salah. | `engagement/lib.rs:4186-4195,4361-4364` | Tulis ulang `self_graded_finding_is_rejected` (:5638) dengan canary hadir | M / Med (FP risk) |
| C8 | `classify_line`: OPERATIONAL + technical action didahulukan sebelum REWARD_SIGNALS; map restriction yang bisa direpresentasikan ke `RoePolicy.denied_target_patterns`/`denied_finding_classes`; unmapped → `unparsed` → abort. | `roe_classifier.rs:201-255,284-292`, `engagement/lib.rs:3331-3360` | Baru "Do not scan third-party..." → abort; reward murni tetap non-actionable | M / Med |
| C9 | Ack = *operator mengikat restriction ke policy*, bukan "abaikan baris". `AuthorizationAck.restriction_json` (kolom baru di **M1**), `RoePolicy.acked_restrictions`; `roe_classify` terapkan restriction sebelum hapus dari `unparsed`; tak representable ⇒ tak ada ack yang clear ⇒ fail closed. Config-auto ack tetap force `incomplete`. | `store/lib.rs:3454-3464` (M1), `engagement/lib.rs:1293-1403,2180,3331-3360` | Baru: ack "never scan prod" → target denied, bukan scanned | L / **High** |
| C10 | Ganti `host_key` string dengan typed key `{wildcard, host, path}`; LLM wildcard hanya diterima jika deterministic wildcard identik/subset; exact host hanya jika tercakup. | `engagement/lib.rs:1458-1466,3174-3196` | Baru: brief apex tolak LLM `*.apex` | M / Med |
| C11 | `reject_private_brief_host` resolve sekali → `SocketAddr`; client `.resolve(host, addr)`; no redirects; **stream + cap body (G2)**; semua answer harus public. | `engagement/lib.rs:2721-2757,2779-2820`, `platform.rs:112-199` | Baru: DNS berubah antara check & kirim → token tak bocor | M / Med |
| C12/C13/C14 | Path matching simetris in/out + normalisasi case; wildcard minimal 1 label; **scope enforcement pada setiap target**, hapus gating risk/tool-name. | `policy/lib.rs:120-150,526-550` | Baru in-scope `host/admin/*` tak izinkan `host/login`; `*.example.com` tak cocok apex; tool `fetch` network-read tetap deny | S-M / Low-Med |
| C15/C16 | Fingerprint 3 hash (content/scope/roe) untuk revalidation; `let _ = save_*` → `?` fail closed. | `engagement/lib.rs:1251,1505,1535,1710-1717,1236-1265` | Baru: text sama tapi parsing ROE berubah → revalidation blocked; forced DB error → abort | S-M / Low |
| C17 | `HeuristicPlanner::with_catalog(self.catalog.clone())`. | `planner.rs:118` | Baru custom catalog technique bisa dipilih | S / Low |
| C18 | `preconditions_met()` untuk precondition ids dikenal; unknown → false; `state_changing_flow` butuh `ctx.allow_state_change`. | `catalog.rs:312-331`, `investigation.rs:184-189` | Baru `wstg-authz` skip tanpa dua identitas | M / Med |
| C19 | Satu canonical status enum/table (termasuk `confirmed-candidate`, `not-applicable` vs `not_applicable`) dipakai 3 situs. | `investigation.rs:165-170,547-551`, `engagement/lib.rs:2307-2324` | Update `open_hypotheses_block_completed_outcome` | S / Low |
| C20/C21 | `resume_from_checkpoint` flag; `resume_checkpoint` dipanggil sebelum loop; digest keyed (HMAC/secret‖state), **exact revision equality**, tolak legacy v1. | `investigation.rs:455-512`, `engagement/lib.rs:2111-2112`, `store/lib.rs:7050-7065` | Update `checkpoint_resume_is_version_checked_and_fails_closed`; baru tampered state & newer revision | M / Med |
| C22 | Parse `TLP:CLEAR/GREEN/AMBER/RED` dari brief → `RoePolicy.tlp_label`; Verifier tolak evidence tanpa TLP. | `investigation.rs:61-63,404-406`, `engagement/lib.rs:1249,4046-4047` | Baru TLP:RED propagating ke provenance/report | M / Low |
| C23/C24/C25 | `ReportFinding.id = redact(&finding.id)`; verified finding wajib punya authoritative hash + artifact write sukses (drop fallback ke model hash); `TraceRun::record` return `Result`, `?` di verifier. | `engagement/lib.rs:976-980,4488-4538,4522` | Baru 2 finding ID berbeda; workspace tak writable → tak ada hash model di report | S-M / Med |
| C26/C27/C28 | `known_findings` recompute tiap round; `max_rounds.clamp(1,10)`; verification session cari by nonce, newest first (tanpa `.rev()`). | `engagement/lib.rs:1602-1614,2543-2550` | Baru finding round-2 diverifikasi; `usize::MAX` bounded | S / Low |
| C29 | Ganti mojibake `" â€”"` dengan Unicode dash nyata; simpan source UTF-8. | `engagement/lib.rs:2472,3144,1192,1417,1555,1591` | Baru `pattern — annotation` stripped | S / Low |
| G2 | G2 | `verify_evidence` vacuous benar, tapi **caller** (C1) sudah pakai per-finding gate — tutup di Fase 0; pastikan M4 batch tidak menambah writer `validated`. | `engagement/lib.rs:4040` | — | — |

**Rollout safeguards:** verifier shadow-mode satu cycle lab sebelum jadi authority;
admin auth dengan transition `admin_auth=false` (lab) → default `true`; C9 butuh
kolom M1 — jangan deploy kode sebelum schema v4 aktif.

---

### Fase 2 — SCOPE & EVIDENCE (fail-closed bertahap + capture/hash)

| Fix | Desain fix (ringkas) | File | Test | E/R |
| --- | --- | --- | --- | --- |
| B3 | `ToolOptions::require_explicit_scope` default true; gate di `core::Runner::run_tool_recorded` via host-risk; CLI/desktop/engagement set false hanya untuk lab non-network. **Staged:** warn → opt-in → default. | `tools/lib.rs:153-157`, `core/lib.rs:1673-1691`, 3 builders | Baru `network_tool_denied_when_scope_unconfigured` | M / Med |
| B10 | `SchemaValidationMode::default` → `Enforce`; `AgentConfig::default` → `Enforce`; backstop `Tool::run_checked` di runner. **Staged:** warn di eval/dev, enforce di produksi. | `tools/lib.rs:3988-3993,220`, `core/lib.rs:446,1691` | Baru `default_schema_mode_is_enforce`, `runner_backstop_blocks_invalid_args_in_warn_mode` | M / Med |
| B11 | `ToolOptions`/`SaveFindingTool` default `require_falsification: true`; `save_finding` output pakai `redact_canaries(&canonical)`. | `tools/lib.rs:115-167,2503-2551,4403` | Ubah `save_finding_falsification_gate_respects_option`; baru output tanpa canary | S / Med |
| B18 | Substitusi `path`,`key`,`value`,`text`; scope-check **semua** nilai termasuk `script` (tolak URL di browser adapter). | `tools/lib.rs:2881-2908,2926-2959` | Update 3 external tests; baru `script_placeholder_with_external_url_is_rejected` | M / Med |
| B19 | Default-deny `PUT/DELETE/PATCH` kecuali `allowed_methods` eksplisit atau `allow_network_write`; mirror di PoC. | `tools/lib.rs:1461-1477,1494-1503,1927` | Baru `put_denied_without_network_write_optin` | S / Low |
| B25 | Decode IPv4-embedded IPv6 di `is_blocked_ip`; `dns_lookup` jangan echo IP blocked (count + error saja). | `tools/lib.rs:356-393,2141-2167` | Ubah `dns_lookup_enforces_scope_and_rejects_blocked_addresses` (:8102) | S / Low |
| B6 | `cookie_jar_store` validasi `Domain` terhadap response host (exact/parent suffix), tolak public-suffix-only; cap jar & header. | `tools/lib.rs:1301-1329,1357-1394` | Update cookie tests (:8315,8351); baru cross-domain & `Domain=com` rejected | M / Med |
| B20 | `validate_oob_endpoint` mirroring `validate_proxy_url` (http/https, **loopback only**, reject `0.0.0.0`); validasi `domain_suffix` hostname; token `[A-Za-z0-9_-]+`. | `tools/lib.rs:3528-3617` | Baru `oob_endpoint_non_loopback_rejected`, `oob_domain_suffix_ip_rejected` | S / Med |
| B5 | `persist_tool_result` hanya ingest capture dari allowlist server-owned (`http_request`, `validate_poc`, alias dinormalisasi); `save_finding`/`record_asset` jangan copy `structured.capture`. | `store/lib.rs:3865-3872,3955-3971`, `tools/lib.rs:2548,2677` | Baru `forged_capture_from_save_finding_not_persisted` | M / Med |
| B9 | Raw wire buffer → `HttpCapture` (request/response/canary) tetap mentah; `headers`/`body_text` view model tetap diredaksi. Hash dari raw bytes. | `tools/lib.rs:1727-1763` | Baru `capture_bytes_are_unredacted_while_output_is_redacted`, `sha256_replayable_from_capture_bytes` | M / Med |
| B13 | Evidence artifact di luar workspace agent (`evidence_root` param) **atau** minimal `fs_read`/`shell_exec` tolak path `evidence/*` + `redact_canary_text` di output. | `tools/lib.rs:5690-5717,920,931` | Baru `fs_read_cannot_read_evidence_artifact` | M / Med |
| B22 | Report writer: hash dihitung dari bytes, abaikan `evidence_hash` & `verified` dari model; escape backtick di semua interpolasi. | `tools/lib.rs:5835-6052` | Baru `report_writer_recomputes_hash`, `model_verified_flag_ignored`, `backtick_in_title_cannot_close_code_span` | M / Med |
| B23 | `has_capture_reference` hanya terima reference minted tool (`bugfound-capture-<hex>` / `{source,sha256}`); free-form string → `ready=false`. Tetap advisory. | `tools/lib.rs:2436-2441,2584-2587` | Ubah `validate_finding_accepts_aliases_and_reports_ready` (:9643) | M / Med |
| B24 | Benign control gagal → `ok=false, inconclusive=true, error=redact(...)`; jangan `.ok()`. | `tools/lib.rs:1999,2034-2042` | Baru `benign_control_error_is_inconclusive` | S / Low |
| G1 | G1 | Path-scope B1/B2 di tools + proxy sudah di Fase 0; di sini tambah normalisasi case/percent-decode di kedua matcher (C12) + parity test. | `policy` + `tools` + `proxy` | Parity test 3 matcher | S / Med |

**Rollout:** B3/B10/B11 pakai warn→enforce; B9/B22 mengubah golden report &
evidence hash — regenerate fixture hanya setelah fix, simpan snapshot lama untuk diff.

---

### Fase 3 — DURABILITY & CONCURRENCY (schema v4 + atomic writes + lease)

| Fix / batch | Desain fix (ringkas) | File | Test | E/R |
| --- | --- | --- | --- | --- |
| **M1 schema v4** | Lihat §2. `schema_version(4)` ditulis setelah semua statement. | `store/lib.rs:618-744` | Fresh-vs-upgraded parity test | M / **High** (data) |
| D5 | Dedupe legacy rows (pilih `MAX(updated_at)`/rowid terbaru, bawa status terbaru) lalu `CREATE UNIQUE INDEX IF NOT EXISTS ux_coverage_key`. | `store/lib.rs:734-744,2366-2371` | Baru legacy-duplicate fixture | M / Med |
| D10 | Tabel `event_chain_anchor(session_id PK, head_hash, event_count, updated_at)`; update dalam tx yang sama dengan `add_event`; verifier bandingkan count+head, tolak empty-log-with-anchor; backfill saat migrasi. | `store/lib.rs:1177-1248` | Baru tail-truncation & empty-log test | M / Med |
| D8 | `parse_ts` + filter Rust (`Z` ≡ `+00:00`); canonical write `+00:00`; migrasi `replace(Z,'+00:00')`; unparseable → fail closed. | `store/lib.rs:1094-1167,1050,2271` | Update `approval_ttl_filtering`, `resolve_approval_rejects_expired`; baru legacy `Z` | M / Med |
| D16/D25 | Migration ledger + `current_version()` read; hapus index duplikat, tambah `idx_findings_dedupe`, `idx_tasks_goal`. | `store/lib.rs:618-665,448,655-656` | Update version assertion | S-M / Med |
| D21 | `tool_captures.digest` + verify on read. | `store/lib.rs:1519-1536` | Baru tamper test | M / Med |
| D6/D9 | `transaction_with_behavior(Immediate)` read-hash+insert; `transition_state` conditional `UPDATE … WHERE state IN` + `changes()`; `add_finding_with_evidence` `INSERT … WHERE NOT EXISTS`; inbox select+update atomic. Signature tetap. | `store/lib.rs:943-961,1177-1204,1378-1422,4221-4264` | Baru two-connection concurrency tests | L / Med |
| D11 | Hash preimage + `id`,`engagement_id`,`created_at`; verifikasi terima formula lama **atau** baru (version gate). | `store/lib.rs:7306-7315,7389-7398` | Baru metadata tamper + legacy acceptance | L / **High** |
| D26 | `save_checkpoint` cek `execute()` rows; error saat 0 (stale revision). | `store/lib.rs:7050-7065` | Baru stale checkpoint error | S / Low |
| D2/D22 | `token_usage()` tambah `tokens_offset` via correlated subquery; guard `u64→i64`. | `store/lib.rs:2079-2107,2587-2600` | **Update `:5105` 48→147**; baru nested handoff token cap | S / Low |
| D7/D18/D23/D24 | Revalidation tak reset `blocked`; reclaim hanya saat lease benar expired; allowlist status approval; validasi `approval.session_id == session_id`. | `store/lib.rs:844-848,1161-1175,2244-2293,3532-3544` | Update `authorization_revalidation_is_idempotent_and_scoped`; baru blocked & cross-session | S / Low |
| D12/D13 | Skip legacy evidence rows dengan byte NULL; dedupe hit → upsert field koreksi (verifier-owned menang, LLM hanya jika kosong). | `store/lib.rs:1371-1388,2895-2920,4000-4013` | Baru legacy-row fixture & corrected-severity test | M / Med |
| D14 | Heuristic `contains("finding")` → allowlist tool name eksplisit; unknown tool = no-op. | `store/lib.rs:3889-3909,4017-4036,4093-4097` | Baru read-only tool tak buat row | M / Low |
| D15 | `let _ =` pada migrasi & capture write → propagasi/`error!`; migrasi all-or-nothing. | `store/lib.rs:667-744,3870-3872,3989-3996,4117-4124` | Bisa muncul failure tersembunyi di fixture lama | M / Med |
| D19 | `validated_at` hanya untuk status positif; else NULL via `CASE WHEN`. | `store/lib.rs:1825-1837` | Baru dismissed tak stamp | S / Low |
| A7 | Extract `settle_interrupted` bersama `settle_on_boot` & `recover_stale_sessions` (`count_resume=false`). | `core/lib.rs:52-82,733-749` | Baru settlement di recovery | S-M / Low |
| A8 | Coordinator `HashMap<session_id, Store>`; `register_store_for_session` dipanggil dari `acquire_claim`, bukan `Runner::new`; `interrupt` lookup per session. | `core/execution.rs:75-104,174-182`, `core/lib.rs:582` | Baru two-store test | M / Med |
| A6 | `with_lease_heartbeat(fut)`: `tokio::select!` fut vs sleep `LEASE/3`; renew error → abort future (fail closed). Apply 2 LLM call sites + tool.run. **Setelah A4+A8.** | `core/lib.rs:2138-2142,2189-2196,1691,1831` | Baru heartbeat & lease-stolen abort test (interval configurable under `#[cfg(test)]`) | M-L / Med |
| A5 | Partisi summary: `system` hanya dari non-tool; tool content → pesan `user` dengan `<untrusted_tool_output>` framing; truncate inner dulu lalu bungkus; pakai `neutralize_envelope`. **Setelah A19.** | `compaction.rs:100-117`, `core/lib.rs:1658-1667` | Baru `compaction_never_puts_tool_output_in_system_role` | M / Med |
| A14 | Pindah `dup:*` flag write ke `run_tool_recorded` setelah eksekusi nyata; tambah time bucket. | `core/lib.rs:304-317,1025-1036,1673-1690` | Baru cooldown/budget-blocked tak konsumsi kuota | S-M / Med |
| A10→A15 | Atomic `promote_inbox` + `changes()` dulu; lalu cap drain 64/item boundary. | `store/lib.rs:4244-4264`, `core/lib.rs:662-690` | Baru single-consumer & bounded drain test | S-M / Med |
| A9+A17 | `dedup_key = event.id` (hapus `ts_ms/1000`); journal `last_hash` hanya update jika write+flush sukses. | `monitor.rs:237-247,504-514,572-579,618-629` | Baru replay-dedup & journal continuity | S / Low |
| G2 | G2 | `verify_evidence` vacuous benar, tapi **caller** (C1) sudah pakai per-finding gate — tutup di Fase 0; pastikan M4 batch tidak menambah writer `validated`. | `engagement/lib.rs:4040` | — | — |

**Acceptance Fase 3:** fresh DB & upgraded DB keduanya lolos `cargo test`;
`verify_event_chain` true setelah 2 koneksi konkuren menulis; tail-truncation
terdeteksi; `zaman` expiry `Z` vs `+00:00` ekuivalen; A6 bail saat lease dicuri.

---

### Fase 4 — CONTROL & UI

| Fix | Desain fix (ringkas) | File | Test | E/R |
| --- | --- | --- | --- | --- |
| E1 | Hapus `RuntimeCommand::Stop`; `RuntimeHandle::stop` → `request_stop(&store, id)` + optional `coordinator.interrupt`; untuk engagement id juga `abort_at`. **Jangan clear busy.** | `desktop-core/runtime.rs:55-61,97-113,182-191,330-336` | Baru fake-Llm blocking: stop return immediately, flag set sebelum `Finished` | M / Med |
| E2 | Core free function `steer(store, session, text)` = `enqueue_inbox` + `wake_scoped`; `RuntimeHandle::steer` panggil langsung, tanpa `build_runner`/`AppConfig::default()`. | `core/lib.rs:624-651`, `runtime.rs:182-187,330-332` | Baru steer dengan api key kosong tetap masuk inbox + wake | M / Med |
| E3/E5 | `forward_deltas` return `JoinHandle`; join sebelum `Finished`. Redaksi carry-window K=128 char (atau buffer penuh → satu Delta saat close). | `runtime.rs:123-136,405-419`, `App.tsx:64-68` | Baru urutan delta-sebelum-finished; secret terbelah tak muncul | S / Low |
| E22 | `decide()` set busy true; Approval arm set busy false + forward deltas + emit `Finished`; frontend optimistic busy + disable Send. | `runtime.rs:192-221`, `App.tsx:300-319` | Baru busy true sampai Finished saat approve | S / Low |
| E13 | `Store::latest_report()` + `verify_report_hash(sha, bytes)` (sha2 sudah dep); `commands::report_read` verifikasi **bytes sebelum redact**. `latest_report_path` tetap wrapper. | `store/lib.rs:3087-3096`, `commands.rs:199-216` | Baru report tampered → `Err(Storage)`; construct `AppState` langsung, tanpa window | M / Low |
| E7/E17 | Satu tipe config bersama di `desktop-core::config` + field `authorization`, `oob`, `max_rounds`, `llm_planning`, `workspace`, `fallback_models`; `parse_mode` → `Result` dipakai 3 surface. **POLICY_CONFIG fixture dipusatkan.** | `desktop/config.rs:6-16,173-176,227-234`, `cli/main.rs:312-609,369`, `runtime.rs:275,277,385`, `worker.rs` | Update `defaults_match_example_config`, `validate_rejects_bad_values`, `config_defaults_are_fail_closed`, `budget_aliases_are_wired_into_agent_config`, `policy_fields_and_budget_aliases_are_forwarded`; baru round-trip save/load preserve sections | M-L / **Med-High** |
| E9/E10/E11 | `config: Option<PathBuf>` + error saat explicit missing; unknown mode → `Err`; `effective_budgets()` di **dua** layer di semua builder. **G-G, satu commit dengan A12.** | `cli/main.rs:19,611-621,647-706`, `runtime.rs:421-460`, `worker.rs:50-85` | Baru typo config → error; mode yolo → error; three builders budget parity | S / Med |
| E12/E6/E18 | `Doctor` error saat key absence; warning config/store ditampilkan; API key `TextEdit::password(true)` + `env:VAR` hint. | `cli/main.rs:1150-1169`, `desktop/main.rs:87-89,573-575` | Doctor exit non-zero (CI memang akan merah — intended) | S / Low |
| E14/E15/E16/E20 | Selection state di `<li>` → button; clear `activeSession` hanya jika session yang finished = active; `reportError` helper + error banner; implement/delete dead buttons. | `frontend/App.tsx:64-104,114-150,238-313` | Ekstrak `applyRuntimeEvent`, Vitest: finished clearing, late event, error append | S / Low |
| E19 | `workspace` dari `AppConfig`/`SettingsSnapshot`; Rust canonicalize + confinement (G5). | `App.tsx:219`, `projection.rs:55-59`, `runtime.rs:275,461` | Baru path di luar workspace ditolak | S-M / Med |
| E4/E8/E23/E24 | Hapus `ApprovalRequired` atau emitkan; `ArgGroup` mutual-exclusive pause/resume/abort; mutex poison handling; app-data dir dengan cwd fallback. | `runtime.rs:26-30`, `types.ts:95`, `cli/main.rs:226-242,1453,1528`, `desktop-core/lib.rs:38` | Baru `--pause --abort` ditolak | S / Med |
| E21/E25/E26/E27 | DB I/O ke worker thread; CA key ACL current-user-only di Windows; `tokio::spawn` per connection + timeout + body cap; proxy full URL (sudah di G-E). | `desktop/main.rs:151-159,312-343`, `proxy/main.rs:183-186,247-274,314-353,554-578` | Baru proxy timeout/body cap | M / Med |

---

### Fase 5 — LLM & EVAL (robustness + kejujuran metrik + docs)

| Fix | Desain fix (ringkas) | File | Test | E/R |
| --- | --- | --- | --- | --- |
| B17 | Hapus substring `"429"/"401"/"403"` → hanya token `status <n>`/`HTTP <n>`; 501/505 → `InvalidRequest`; `Unknown` tak retryable. **Urutan G-H.** | `llm/error.rs:30-64,112-117` | Update `legacy_message_classification_covers_common_failures`, `status_mapping_is_deterministic`, `recovery_table_is_total` | S / Med |
| B7/B8/B14 | Tolak `finish_reason=length/content_filter` di SSE; normalisasi CRLF dengan carry 1 byte; cap buffer/content/args/calls + delta. | `llm/lib.rs:311-442` | Baru truncate reject, CRLF split-across-chunks, cap reject | S-M / Low |
| B16 | `chat_stream_full` retry loop mirror `chat_full` (Retry-After, fallback, transport). | `llm/lib.rs:653-749` | Baru stream 429 retry & model-not-found fallback | M / Med |
| B15 | `LlmClient::new` panggil `validate_base_url`; discovery body capped 4 KB; error tanpa URL userinfo/body. | `llm/lib.rs:212-309` | Baru `client_new_rejects_bad_base_url`, error tanpa credential | S / Med |
| B26 | `register_external_adapters` selalu `resolve_program`; `fallback_models` dari CLI/desktop config ke semua constructor. | `tools/lib.rs:4609-4676`, `cli/main.rs:475-501,727`, `desktop-core/config.rs:26-33`, `runtime.rs:428`, `worker.rs:97`, `engagement/lib.rs:1436` | Ubah `external_adapters_are_opt_in`; baru fallback_models forwarded | M / Med |
| B12/G-I | **Buat `bugfound-redact`** (leaf crate, serde_json); pindah union keys + bearer + prefix + PII + canary constant; `pub use` di tools/store; collaborator depend langsung; corpus parity 4 crate. | `crates/bugfound-redact/**`, `tools/lib.rs:9209`, `store/lib.rs:3398`, `collaborator/main.rs:192`, `proxy/main.rs` | Parity corpus (Basic, quoted values, glpat/AKIA, DB keys, cookie, PII, negative controls, canary) | L / Med |
| B21 | `wait_with_output` → capped async pipe reads (stdout/stderr), drain remainder, kill-tree timeout tetap. | `tools/lib.rs:1017-1031,3163-3210` | Baru output above cap truncated | M / Med |
| F11+M4 | `agent_eval.py`: hash-chain verify, safe JSON, clamp ratio, M4 emit `value`+`rows`; `run_id` diekspor di `agent_lab.py:99-112`. **Jangan sentuh M1.** | `agent_eval.py:24-62,91-95,113-121,178-189`, `agent_lab.py:99-112` | Update self_test; baru tamper/malformed/ratio | M / Med |
| F2/F3 | Pisahkan `false_discovery_rate_proxy = 1-precision` dari `false_positive_rate` (hanya dari `tested` negatif); `--max-fpr` tolak proxy; filter verdict positif. | `score.py:487-492,519-537,612-674,871-875` | 4 self-test baru (FPR 0.5, no-negatives, verifier-only, finding-map) | M / Med |
| F8/F9/F10 | Explicit `finding-map` (tanpa map → verdict None); validasi struktur manifest; `export_trace`: payload dulu lalu authoritative columns terakhir, `mode=ro`, dedupe per event + merging evidence. | `score.py:236-253,431-437,822-826`, `export_trace.py:67-122,212-220` | Self-test payload override & evidence-preserving merge | M / Med |
| F12/F13/F14/F15 | Brief = proyeksi ROE fixture; regenerate `example-synthetic/score.json` UTF-8 no-BOM **setelah F2/F3**; e2e clean + assert exit; benchmark fresh run dir + `$LASTEXITCODE`. | `fixtures/agent/brief.txt:11`, `fixtures/agent/fixture.json:10-15`, `results/**`, `e2e_test.ps1:25-26,85,95`, `run_benchmark.ps1:164-217` | CI json.load check | S-M / Low |
| F16/F18/F19/F21/F22 | `deny.toml`: expiry pada 10 ignores, wildcards=`deny`, bans=`warn` sampai egui removal, pin cargo-deny; hapus `_fix_e2e_tmp.py`; POSIX driver atau docs smoke-only; koreksi `--strict`/N≥3/metrik belum ada; dokumentasi `npm ci`. | `deny.toml:14-25,58,63-64`, `ci.yml:43-45`, `docs/evaluation.md:44,54-58,90`, `eval/README.md` | Fresh-checkout smoke | S-M / **High** (dep) |
| Docs | Koreksi klaim refuted (R1–R6, R13) di `docs/architecture/01:155-157,157,34,37,166-171,174-175,192-196,262-263`, `05:216`, `docs/V3_STATUS.md:15-17,27,33,39-45,49,100-103` | — | Grep check: tak ada klaim double-count / "non-negotiables kept" tanpa caveat | S / Low |

---

### Fase 6 — RESIDUAL

- Sisa medium/low: C30/A18 (only with reproducer), D17 retention, D2 verification
  pagination, A20 `list_sessions(500)` → predicate query, E25/E26 Windows ACL &
  proxy timeouts bila belum masuk Fase 4.
- Setiap item register audit harus punya regression test **atau** catatan
  "won't fix / needs evidence".
- Live OOB (`C8` verification command) hanya dijalankan dengan provider &
  collaborator lokal berotorisasi — **bukan** merge gate CI.

---

## 5. Perubahan config & API yang perlu disepakati sebelum eksekusi

| Surface | Field baru / berubah | Konsumen |
| --- | --- | --- |
| `AgentConfig` (core) | `auto_approve_target_change: bool` (false), `lease_heartbeat_secs` (opsional), `max_steps` default 0, schema mode `Enforce` | CLI, desktop, desktop-core, engagement |
| `ToolOptions` (tools) | `require_explicit_scope`, `oob_admin_token`, `allowed_methods` default GET/HEAD/POST, `require_falsification` true | core runner, engagement |
| `EngagementOptions` | `oob_admin_token`, `resume_from_checkpoint` | CLI/desktop/Tauri builders |
| `OobFile` (CLI) | `admin_token_env`, opsional pinned `token` | `engagement_options` |
| 2× `AppConfig` (desktop-core + egui) | `authorization`, `oob`, `max_rounds`, `llm_planning`, `workspace`, `fallback_models` | settings save/load, projection, worker |
| `AuthorizationAck` (store) | `restriction_json` → **migrasi v4** | `roe_classify` |
| Store | `latest_report()` + `verify_report_hash()`; `event_chain_anchor`; `tool_captures.digest`; `findings.engagement_id` (opsional) | commands, verifier, migration |
| Collaborator CLI | `--admin-token`, `--max-tokens` | lab & OOB end-to-end |
| Baru | crate `bugfound-redact` | tools, store, proxy, collaborator |

---

## 6. Acceptance gate per fase

Definisi gate (dari `docs/V3_STATUS.md §4`):

- **G1** `cargo fmt --all --check`
- **G2** `cargo clippy --workspace --all-targets -- -D warnings`
- **G3** `cargo test --workspace`
- **G4** `cargo deny check`
- **G5** `pnpm --dir frontend build`
- **G6** `python eval/agent_eval.py --self-test`
- **G7** `python eval/agent_lab.py --runs 3 --adaptive`
- **G8** `python eval/agent_lab.py --runs 3 --adaptive --live` (informasional, butuh kredensial)
- **G9** `python eval/adversarial_lab.py`
- **G10** ADR-001 boundary check di `.github/workflows/ci.yml`

| Fase | Gate wajib | Syarat tambahan |
| --- | --- | --- |
| 0 | G1,G2,G3,G4,G5,G6,G7,G9,G10 | 6 integration test inti masuk G3; G7/G9 **exit non-zero saat CLI crash**; fixture tak unlock-all; G8 boleh manual |
| 1 | G1–G7,G9,G10 | Verifier shadow-mode satu cycle; OOB end-to-end loopback dengan bearer; ack-enforces-deny |
| 2 | G1–G7,G9,G10 | Parity test 4 crate untuk redaksi; golden report regenerated & diff-disetujui; scope warn→enforce completed |
| 3 | G1–G7,G9,G10 | Fresh-vs-upgraded DB parity; 2-connection hash-chain & rotation test; backup DB sebelum migrasi |
| 4 | G1–G7,G9,G10 | Runtime control integration test; config round-trip preserve unknown sections; `report_read` tamper test |
| 5 | G1–G7,G9,G10 | M4 `value` hadir; FPR/FDR proxy terpisah; `score.json` UTF-8; docs grep check; G7/G9 fresh artifact dir |
| 6 | G1–G10 (G8 only authorised) | Setiap register item bertest atau ber-status eksplisit |

**Cross-phase invariant:** G3 memuat semua integration test offline; G8 tidak pernah
jadi merge gate (tidak deterministik & butuh kredensial).

---

## 7. Test minimum yang wajib ada (offline, masuk `cargo test --workspace`)

| Cluster | Test minimal yang akan menangkap bug | Lokasi |
| --- | --- | --- |
| Approval (G-A, G-B, G-C) | Batch 2 tool: tool 1 `Ask`→**deny**, tool 2 `Allow` ⇒ tool 2 tak dieksekusi & pending di-settle `cancelled`; plus auto_approve+injection tetap park; approve dengan lease held → flag utuh; stale finish tak clear stop flag | `bugfound-core/tests/runner_integration.rs` (extending `:265`, invert `:1438`, `:1554`) |
| Verifier/OOB (G-D) | End-to-end promotion via `verify_findings_with_oob` + fake `OobOracle`: token asing ⇒ no promotion; ROE-denied ⇒ no promotion; verdict non-confirmed ⇒ demote; zero evidence ⇒ reject; collaborator unknown Host ⇒ tak tercatat; unauth admin ⇒ ditolak | Baru `bugfound-engagement/tests/verifier_oob_integration.rs` + `collaborator/main.rs` tests |
| Scope/ROE (G-E) | Mock server: `out=["host/help/*"]` ⇒ `/help/x` denied langsung & via 301; empty scope ⇒ fail closed; "Do not scan third party" ⇒ abort | Baru `bugfound-tools/tests/scope_path_integration.rs` + `policy` tests + `roe_classifier` tests + proxy tests |
| Redaksi/canary (G-I) | Server echo canary di body+header+`Location` ⇒ nol kemunculan token di semua field model-visible (termasuk `url`, `redirect_chain`, `save_finding`), tapi capture bytes & hash masih mengandung; argumen JSON secret tak pernah masuk DB; corpus parity 4 crate | `bugfound-tools/tests/redaction_parity.rs`, `store` tests, `collaborator` tests |
| Store durability (M1–M6) | 2 `Store` konkuren `add_event` ⇒ chain single-head & count benar; tail truncation terdeteksi; `tokens_offset` ikut budget; `Z` ≡ `+00:00`; coverage index di DB lama | Baru `bugfound-store/tests/durability_integration.rs` (temp dir) |
| UI stop/steer (E1/E2) | Fake LLM blocking: `stop()` return segera & flag set sebelum `Finished`; `steer()` dengan api key kosong tetap buat inbox row + wake; secret terbelah di 2 delta tak tampil | Baru `bugfound-desktop-core/tests/runtime_control_integration.rs` |

Semua test di atas **offline**: mock TCP loopback, in-memory `Store`, fake oracle —
tanpa provider nyata, tanpa collaborator eksternal.

---

## 8. Risiko & mitigasi ringkas

| Perubahan | Risiko | Safeguard |
| --- | --- | --- |
| Scope fail-closed (B3/C14) | Lab tanpa `[scope]` berhenti mengirim HTTP | Warn → opt-in → default; fixture lab diperbarui di commit yang sama |
| Schema `Enforce` (B10) | Tool call lab dengan argumen sebagian ditolak | `warn` di eval/dev, `Enforce` di produksi; dry-run validator dulu |
| Admin auth OOB (C3/C4) | Live OOB lab putus | `admin_auth=false` untuk lab, default `true` kemudian; token minted per finding |
| Verifier authority (C1) | Finding yang dilaporkan turun status ⇒ M3 berubah | Shadow mode satu cycle, freeze metrik lama untuk diff |
| Redaksi ketat (B12/D1/D20) | Over-redaksi merusak hash/timestamp/ID; under-redaksi bocor | Raw capture di luar hashing; negative-control corpus; versioned redactor + alias satu rilis |
| Transaksi DB & error propagation (D6/D9/D15) | `Result` yang dulu diabaikan jadi hard failure | `busy_timeout` sudah ada; 2-connection test dulu; propagate bertahap |
| Stop/Steer sinkron (E1/E2) | Race flag vs `Finished`; steer mengubah perilaku mid-run | Flag idempotent + state-machine test; polling API dipertahankan |
| Config unification (E7) | Save menghapus section lama | Parity fixture dulu; round-trip save/load test; staged per surface |
| Schema v4 (D5) | Duplikat legacy hilang | Backup DB; pilih row `MAX(updated_at)`; fresh-vs-upgraded parity |
| `cargo-deny` tighten (F16) | Build merah karena dep lama | Pin dulu, expiry pada ignore, bans tetap warn sampai egui removal |

---

## 9. Catatan eksekusi

- Plan ini **tidak mengubah kode**. Eksekusi dimulai dari Fase 0 setelah
  reviewer menyetujui *land-together groups* (§2) dan perubahan config (§5).
- Beberapa file eval berstatus `AM`/`MM` dan untracked: **jangan** menjalankan
  `_fix_e2e_tmp.py`, jangan regenerate `eval/results/**` massal, jangan
  `git checkout .`.
- `docs/AUDIT_2026-11-27.md` tetap menjadi register temuan; dokumen ini hanya
  menjawab *bagaimana* dan *dalam urutan apa* perbaikan dilakukan.
- R13/A18 sengaja diturunkan/defer — jangan "diperbaiki" tanpa reproducer.
