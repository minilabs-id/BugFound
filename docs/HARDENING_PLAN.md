# BugFound — Rencana Hardening & Truthfulness

Tanggal: 2026-11-19
Sumber: audit independen `HARNESS AUDIT` (temuan A1–A9, B1–B5)

Dokumen ini adalah rencana kerja yang ditulis dari audit 2026-11-19. B1–B14
adalah pass lanjutan yang dicatat terpisah di `docs/B1_B14_FIX_PLAN.md`.
Untuk kondisi kode saat ini, jalankan perintah di `docs/PRODUCTION_PLAN.md` §2
dan baca angka serta hasilnya dari output tersebut — bukan dari dokumen ini.

---

## 0. Tujuan

Membuat klaim BugFound sesuai dengan kode yang benar-benar jalan, dan mengubah
harness dari "scripted 9-step LLM loop" menjadi agent yang aman, terverifikasi,
dan bisa diukur.

> **ID note:** B1–B5 in this 2026-11-19 audit are the original follow-ups to
> H-10…H-14. The newer `docs/B1_B14_FIX_PLAN.md` reuses the "B" prefix for a
> separate remaining-gap set; see `docs/REMAINING_GAPS.md` §2 for that list.

Prinsip:

1. **Truth over features** — kalau tidak ada call site production, hapus atau wire. Jangan ship klaim kosong.
2. **ROE adalah kontrak executable** — bukan teks yang hanya disimpan di DB.
3. **Verifier tidak boleh self-grading** — oracle harus independen dari LLM yang diuji.
4. **Bukti adalah bytes + SHA-256** — bukan string hasil estimasi.
5. **Evaluasi harus bisa menggagalkan klaim** — ada ground truth, replay, baseline.
6. **Autonomi tetap tunduk pada operator** — mode, budget, dan batas tool dari config.

Urutan prioritas (dari audit): **A2 → A3 → A7 → A1 → A4/A5 → A8 → A6 → B**.

---

## 1. Phase 0 — Safety & config truth (3–5 hari)

### H-01 — A2: Jalur otonom hormati operator & batasi tool berisiko
**File:** `crates/bugfound-engagement/src/lib.rs`, `crates/bugfound-cli/src/main.rs`,
`crates/bugfound-desktop/src/main.rs`, `crates/bugfound-policy/src/lib.rs`,
`crates/bugfound-tools/src/lib.rs`.

Aksi:
- Perkenalkan `EngagementOptions { mode, budgets, max_rps, max_requests, max_estimated_tokens, allow_network_write, allow_intrusive }`, dikirim dari CLI/desktop ke `engage()`.
- Hentikan `auto_approve_tools = semua tool`. Auto-approve hanya untuk tool risk `safe`/`read` dan hanya jika mode `full_auto`.
- Default-deny `network-write` dan `intrusive` di engagement; butuh opt-in eksplisit.
- `http_fuzz`: batasi panjang wordlist (mis. 200), total request per call, dan method — ikuti ROE.
- Desktop: teruskan `run_mode_choice` ke `engage()`; CLI: pakai `cfg.agent.mode`, budget, scope, network.

Kriteria penerimaan:
- `engage` dengan mode `ask` menghasilkan approval, bukan eksekusi langsung.
- Config `max_tool_calls`, `max_network_calls`, `requests_per_minute`, `max_estimated_tokens` mempengaruhi jalannya engagement (terbukti via tes).
- `http_fuzz` dengan wordlist 1.000 ditolak/dipotong.
- Tes: `engagement_options_are_honoured`, `fuzz_wordlist_cap_enforced`.

### H-02 — A7: ROE sebagai typed policy, fail-closed
**File:** `crates/bugfound-engagement/src/lib.rs`, `crates/bugfound-tools/src/lib.rs`.

Aksi:
- `RoePolicy { ua_marker, max_rps, max_requests, allow_fuzzing, allow_state_change, allow_disclosure }`.
- Parse dari **teks brief utuh**, bukan `reporting_rules` yang sudah difilter.
- Intersect scope hasil LLM dengan parse deterministik; kalau bertentangan → fail-closed.
- `fetch_brief`: blokir IP privat, redirect 0, tolak non-2xx/login page.
- Terapkan `RoePolicy` ke `ToolOptions` dan `PolicyConfig`.

Kriteria penerimaan:
- Brief BoursoBank nyata menghasilkan `ua_marker` mengandung `-BugBounty-boursobank-31337` dan `max_rps = 10`.
- Halaman 404/login dengan token bertitik tidak menghasilkan scope aktif.
- Tes regresi: `roe_overrides` dipanggil lewat jalur produksi, bukan hanya langsung di test.

### H-03 — A1: Wire atau hapus modul core parity
**File:** `crates/bugfound-core/src/*.rs`, `crates/bugfound-engagement/src/lib.rs`, docs.

Aksi (pilih satu, rekomendasi: **wire minimal**):
- `EventBus` dipakai engagement untuk event; `Inbox` untuk item kontrol; `ExecutionCoordinator.interrupt()` dipanggil `pause/abort` dan dicek tiap step; `CompactionV2` menggantikan inline compaction; `AgentError` mengklasifikasikan outcome.
- `SubagentJobs`, `SkillLoader`, `UsageTracker` yang tidak di-wire → hapus, atau beri call site nyata.
- `SubagentJobs` tidak boleh hanya echo goal.

Kriteria penerimaan:
- Pause/Abort menghentikan Runner dalam ≤1 step (bukan hanya di boundary task).
- Tidak ada duplikasi kompaksi/estimator di `core/lib.rs`.
- Grep menunjukkan setiap modul punya ≥1 call site production.
- Docs tidak lagi menjanjikan steer/wake-coalescing bila tidak diimplementasi.

---

## 2. Phase 1 — Verifier & evidence (4–6 hari)

### H-04 — A3: Verifier dengan oracle independen
**File:** `crates/bugfound-engagement/src/lib.rs`, `crates/bugfound-tools/src/lib.rs`, `crates/bugfound-core/src/lib.rs`, `crates/bugfound-store/src/lib.rs`.

Aksi:
- Saat finding dibuat, simpan request/response **mentah** + nonce/canary ke `evidence`.
- `validate_poc` wajib punya `finding_id`; verifier replay bytes tersimpan, bukan argumen LLM.
- Oracle: canary unguessable disuntikkan sebagai header `X-BugFound-Canary` ke request nyata oleh `HttpRequestTool`, lalu verifier mensyaratkan token itu direfleksikan oleh target di `response_bytes` tool (status 2xx). Bukan `expected_status`/`marker` dari model. Token dibersihkan dari output yang terlihat model. Lihat `docs/adr/ADR-008-verification-oracle.md`.
- Status finding: `candidate` → `validated`; hanya finding yang dikonfirmasi `verify_candidate` yang masuk laporan.

Kriteria penerimaan:
- Finding buatan dengan marker `<html` tidak lolos verifikasi.
- Tes: `self_graded_finding_is_rejected`, `replay_uses_stored_bytes`,
  `real_http_capture_promotes_finding` (server lokal nyata merefleksikan canary),
  `non_reflecting_capture_is_rejected` (2xx tanpa refleksi tetap `candidate`).

### H-05 — A5: SHA-256 evidence nyata
**File:** `crates/bugfound-store/src/lib.rs`, `crates/bugfound-engagement/src/lib.rs`.

Aksi:
- Ganti `DefaultHasher` dengan `Sha256::digest(request || response || artifact)`.
- `add_evidence` dipanggil di production saat finding/artifact dibuat.
- Tampilkan 64-hex evidence hash di setiap finding report.

Kriteria penerimaan:
- Hash reproducible dari bytes yang sama.
- `verify-log` diperluas untuk evidence, bukan hanya `events`.

---

## 3. Phase 2 — Report & evaluation (4–6 hari)

### H-06 — A4: Satu renderer kanonik
**File:** `crates/bugfound-engagement/src/lib.rs`, `crates/bugfound-tools/src/lib.rs`, `eval/score.py`.

Aksi:
- Hapus duplicate renderer di engagement; panggil renderer kanonik dari tools.
- Pastikan semua section: Executive Summary, Scope & ROE, Methodology, Findings (`F-001`), Coverage, Timeline, Appendices, evidence hash.
- Tes: jalankan logika `score.py` terhadap laporan hasil generate.

Kriteria penerimaan:
- `score.py --strict` dijalankan terhadap laporan produksi.

### H-07 — A6: Evaluasi yang bisa menggagalkan klaim
**File:** `eval/**`, `crates/bugfound-engagement/src/lib.rs`.

Aksi:
- Scorer join laporan ke ground-truth manifest: recall, precision, FPR, reproducibility, branch coverage, token/finding.
- Emit replay log terstruktur dari `EngagementEvent` + `trace_events` (Cochise-style).
- Mode `--baseline` (plain agent vs harness) dengan model-matched.
- Golden dataset kecil + satu hasil terekam; script PowerShell untuk Windows (tidak bergantung WSL).

Kriteria penerimaan:
- `eval/run_benchmark.ps1` jalan di Windows.
- Ada `eval/results/` berisi replay + skor, dan README menjelaskan cara reproduce.

---

## 4. Phase 3 — Planner, guard, correctnes (4–6 hari)

### H-08 — A8: Planner adaptif & guard durable
**File:** `crates/bugfound-engagement/src/lib.rs`, `crates/bugfound-core/src/lib.rs`, `crates/bugfound-store/src/lib.rs`, `crates/bugfound-tools/src/lib.rs`.

Aksi:
- Hipotesis first-class: status, score, update dari clue/finding.
- Urutan task dihitung dari `prioritize_targets()` + hypothesis score, bukan fixed 9.
- `task_put`/`clue_put` benar-benar persist (bukan echo).
- Stall guard pakai *confirmed evidence*, bukan coverage row mentah.
- Duplicate/cooldown durable di store, key dinormalisasi (sort JSON key).
- Target-change & injection re-approval berlaku juga di `full_auto`.

Kriteria penerimaan:
- Dua task dengan target sama tidak duplikat coverage.
- Fuzz dengan query berbeda tetap stall setelah N step tanpa finding baru.
- Tes: `adaptive_reorder`, `durable_duplicate_guard`.

### H-09 — A9: Token/cost dari API usage
**File:** `crates/bugfound-llm/src/lib.rs`, `crates/bugfound-core/src/lib.rs`, `crates/bugfound-store/src/lib.rs`.

Aksi:
- `ChatResponse` simpan `usage.prompt_tokens` / `completion_tokens`.
- Budget & cost pakai angka API, bukan `len/4`.

Kriteria penerimaan:
- `bugfound tokens` sama dengan_usage respons mock.

### H-10 — B1: Satu DB path untuk kontrol
**File:** `crates/bugfound-engagement/src/lib.rs`, `crates/bugfound-cli/src/main.rs`, `crates/bugfound-desktop/src/main.rs`.

Aksi:
- Thread `db_path` eksplisit ke semua `status/pause/resume/abort`.
- Hapus `OnceLock` global atau jadikan wajib & tervalidasi.

Kriteria penerimaan:
- `engage --db live.db` lalu `engagement --pause --db live.db` benar-benar pause (bukan DB default).

### H-11 — B2: Fail-closed brief
**File:** `crates/bugfound-engagement/src/lib.rs`.

Aksi:
- Tolak non-2xx dan halaman login; minta konfirmasi operator untuk scope hasil ekstraksi sebelum eksekusi.
- Hapus `save_brief` awal dengan field kosong.

Kriteria penerimaan:
- Branch-only mode tidak menulis snapshot menyesatkan.

---

## 5. Phase 4 — Tool harness & hygiene (3–4 hari)

### H-12 — B3: Tool gaps
- `http_fuzz`: cap request & method, ikuti ROE.
- `ExternalCommandTool`: scope/egence check di dalam tool, bukan hanya Runner.
- `browser`: dokumentasikan jujur sebagai CLI adapter atau implementasi nyata.

### H-13 — B4: Dokumen satu kebenaran
- `PRODUCTION_PLAN.md`, `threat-model.md`, `architecture.md`, `README.md` diselaraskan.
- Ganti tabel status dengan evidence matrix: fitur → call site → tes.

### H-14 — B5: Release hygiene
- Tambah `LICENSE` (MIT), pin toolchain sesuai CI, `.gitignore` `eval/work/`, E2E test: server brief lokal → `engage()` → report → `score.py`.

---

## 6. Workstream paralel (bila dieksekusi banyak agent)

| WS | Ownership | Task |
| --- | --- | --- |
| WS1 | `bugfound-core/**` | H-03, H-08 (guard), H-09 |
| WS2 | `bugfound-engagement/**` | H-01, H-02, H-04, H-06, H-10, H-11 |
| WS3 | `bugfound-tools/**`, `bugfound-store/**` | H-04/H-05 evidence, H-12, H-06 renderer |
| WS4 | `eval/**`, `docs/**`, `README.md`, `.gitignore`, `LICENSE`, `.github/**` | H-07, H-13, H-14 |

Aturan: WS tidak boleh mengubah file di luar ownership. Integrasi dilakukan setelah keempat workstream menyampaikan hasilnya.

---

## 7. Kriteria keluar

- Task H-01…H-14 memiliki tes yang menyertai.
- Jalankan perintah di `docs/PRODUCTION_PLAN.md` §2 dan catat output dari run tersebut.
- Periksa kembali temuan A1–A9, B1–B5 (audit lama) terhadap kode saat ini.
- B1–B14 dirujuk di `docs/B1_B14_FIX_PLAN.md` dan `docs/REMAINING_GAPS.md` §2; verifikasi dengan perintah di `docs/PRODUCTION_PLAN.md` §2.
- Laporan produksi dinilai dengan `eval/score.py --strict`; `eval/e2e_test.ps1` memeriksa bagian laporan dan menjalankan scorer dengan `--strict`.
- Pause/Abort teruji menghentikan step dalam ≤1 langkah.
- Dokumen tidak punya klaim tanpa call site.

Estimasi: **18–27 hari kerja** tergantung kedalaman H-07 dan H-03.
