# Threat Model AgentBug (baseline 2026-11-19, hardened)

Ruang lingkup: agent bug-bounty self-hosted, single-operator / small team,
berjalan di container/VM dengan egress terbatas, memakai LLM OpenAI-compatible.
ID merujuk ke temuan di `PRODUCTION_PLAN.md` §3 dan item H di `HARDENING_PLAN.md`.

Status: F-01…F-05 (blocker P0 lama) **sudah ditutup di kode** dan tidak lagi
dianggap open; bukti call site ada di evidence matrix `PRODUCTION_PLAN.md` §2.
F-06…F-17 sedang dieksekusi lewat H-01…H-12; status akhir dicatat oleh integrator
setelah verification gate (`PRODUCTION_PLAN.md` §4). Tabel di bawah memakai kolom
"Rujukan" untuk item hardening, bukan klaim "selesai" yang belum diverifikasi.

## Mitigasi lintas (deployment)

Isolasi OS (container non-root, `--cap-drop ALL`, `--read-only`), egress
default-deny di host, `mode = "ask"` dengan review approval, serta kunci API
dari environment bukan dari image. Rincian ada di `deployment.md`.

| ID | Aset | Ancaman | Mitigasi di kode | Risiko residual | Rujukan |
| --- | --- | --- | --- | --- | --- |
| F-01 | Integritas host & workspace | `shell_exec` dilabeli `risk:"write"`, scope tidak dicek; denylist substring bisa dilewati | `ExternalCommandTool` dengan allowlist argv tanpa shell, env allowlist, risk `exec`, approval `ask` | Sedang — tetap butuh isolasi OS; allowlist bukan sandbox | H-01, H-12 (matrix #4, #6) |
| F-02 | Validasi alamat & jalur egress | DNS pinning kalah saat proxy aktif → DNS rebinding / TOCTOU | `HttpRequestTool` memakai `dns_overrides`, `no_proxy`, blokir IP private/reserved | Sedang — proxy eksplisit tetap harus diaudit operator | H-02, H-12 (matrix #7) |
| F-03 | Budget & kuota sesi | Counter in-memory reset saat resume/restart → limit efektif unbounded | Tabel `session_budgets`, `ensure_budget`/`budget_usage`, step index durable | Rendah — verifikasi ulang concurrency saat integrasi | H-01 (matrix #3) |
| F-04 | Approval & session claim | Dua proses `approve` bisa sama-sama mengklaim & menjalankan aksi | `resolve_approval` berpredikat `status='pending'`, `claim_session`/`transition_state_owned` conditional + owner/lease | Rendah — race lintas proses diuji via tes store | H-01, H-10 (matrix #1, #2) |
| F-05 | Kredensial & data sensitif | Secret bocor via JSON `"api_key"`, `Set-Cookie`, multi-`Bearer`, report/CLI/event/tool output | Satu `redact` dipakai di `report()`, CLI, event, dan output tool | Rendah — redaction berbasis pola, bukan jaminan semantik penuh | H-01 (matrix #8) |
| F-06 | Jaringan internal / metadata cloud | Blokir IP belum mencakup 6to4/Teredo/NAT64 | Blokir IPv4 private + sebagian IPv6 di `HttpRequestTool` | Sedang — matrix IPv6 perlu diverifikasi | H-12 (matrix #7) |
| F-07 | State machine sesi | Recovery dapat menimpa state `interrupted`/live menjadi `completed` | `transition_state_owned` + owner/lease guard di store | Rendah — pastikan semua transisi melewati guard | H-03 (matrix #1) |
| F-08 | Batch tool call | `[A, B, C]`: A butuh approval → B/C hilang setelah resume | Batch deferred dipersist bersama approval | Sedang — uji `[ask, allow, allow]` saat integrasi | H-03 (matrix #1, #13) |
| F-09 | Environment secret | `DATABASE_URL`, `MYSQL_PWD`, dll lolos dari scrub | Env allowlist di `ExternalCommandTool` | Rendah | H-12 (matrix #6) |
| F-10 | Filesystem host | `create_dir_all(parent)` sebelum validasi; TOCTOU symlink | Path pre-validation & confinement di tool filesystem | Sedang — symlink TOCTOU butuh OS isolation | H-12 (matrix #5) |
| F-11 | Integritas hasil & kontrol alur | `choices` kosong → sesi `completed`; `finish_reason` diabaikan | Validasi shape LLM + `finish_reason` | Sedang — verifikasi respons malformed | H-09 (matrix #16) |
| F-12 | Konfigurasi & input user | `base_url` tak divalidasi, alias budget mati, panic pada cwd | Validasi boundary & constructor `Result` | Sedang | H-11 (matrix #4) |
| F-13 | Laporan & evidence | Field `goal`/`title`/`asset`/`path` tidak teredaksi; evidence terpotong | `redact` di semua field report; hash SHA-256 per finding | Rendah — cek `--strict` | H-06 (matrix #12) |
| F-14 | Scope / allowlist | Allowlist substring menerima `notexample.com` | `parse_scope_brief` + host/CIDR parse di policy | Rendah — matrix lookalike | H-02 (matrix #4) |
| F-15 | Akurasi registry & docs | `echo` tidak terdaftar; `dnsx` hanya alias | Registry deterministik; docs diselaraskan di H-13 | Rendah | H-12, H-13 (matrix #5) |
| F-16 | Skema & performa SQLite | `ALTER` best-effort tanpa versi; list query full-scan | `schema_version` + index pada `trace_events`/`tasks`/dll | Rendah | H-10 (matrix #1) |
| F-17 | Reasoning agent | Tool output masuk sebagai `role:"tool"` apa adanya | Framing `<untrusted_tool_output>`, goal lock, re-approval saat target berubah | Sedang — prompt injection tetap ancaman desain | H-02 (matrix #4, #14) |

## Ancaman baru: autonomous engagement flow

Tambahan untuk alur `agentbug engage --url <program-url>` dan tab Engagement desktop.
Semua ancaman di bawah dipetakan ke guardrail yang sama dengan tabel di atas, ditambah
guardrail khusus engagement (ROE fail-closed, verifier deterministik, local-only).

| ID | Aset | Ancaman | Mitigasi di kode | Risiko residual | Rujukan |
| --- | --- | --- | --- | --- | --- |
| F-19 | Ekstraksi ROE dari halaman program | **ROE extraction poisoning**: teks menyisipkan scope melebar / menekan aturan | Brief di-snapshot; `roe_overrides` + scope fail-closed; untrusted framing | Sedang — validasi deterministik harus dipakai sebelum tiap aksi jaringan | H-02 (matrix #14) |
| F-20 | Halaman program / pemilihan target | **Login portal / honeypot** memicu probe tidak sah & finding palsu | Scope gate, verifier deterministik, local report only | Sedang — budget terbuang & finding palsu | H-04, H-11 |
| F-21 | Validasi finding | **False positive dari LLM self-grading** | Verifier deterministik (`validate_poc`) sebagai gerbang; evidence SHA-256 | Rendah — self-graded finding ditolak | H-04, H-05 (matrix #9, #10) |
| F-22 | Kredensial lintas target | **Credential reuse across targets** | API key dari environment, redactor, cooldown per target | Sedang — rotasi kunci tetap tanggung jawab operator | H-01 (matrix #8) |
| F-23 | Reasoning agent / halaman program | **Prompt injection dari program page** mengubah goal/scope | Goal lock + framing `<untrusted_tool_output>` + event hash chain | Sedang — tidak ada jalur auto-submit | H-02, H-05 (matrix #11) |

### Pemetaan ancaman engagement ke guardrail

| Ancaman | Guardrail utama | Guardrail pendukung |
| --- | --- | --- |
| F-19 ROE poisoning | Scope parse + fail-closed + `roe_overrides` | Untrusted framing (F-17), re-approval saat scope berubah |
| F-20 login portal / honeypot | Scope gate + fail-closed pada target ambigu | Verifier deterministik, local-only, egress isolation |
| F-21 false positive self-grading | `validate_poc` sebagai gerbang penerimaan | Evidence hash, metrik presisi/FPR di evaluasi |
| F-22 credential reuse | Isolasi & larangan reuse kredensial lintas target | Redactor + env allowlist + rotasi |
| F-23 prompt injection program page | Goal lock + untrusted framing + re-approval | Tanpa auto-submit, event hash chain, approval |

Kontrol alur engagement (pause/resume/abort) bergantung pada guardrail durability:
claim/lease dan transisi state ter-guarded (F-04, F-07), budget persisten (F-03),
dan approval atomik (F-04). abort bersifat terminal dan tidak membuka jalur
eksekusi baru. Modul `core` seperti inbox dan execution coordinator **tidak**
diklaim sebagai fitur engagement: tidak ada call site produksinya di
`agentbug-engagement`. Modul subagent, skill loader dan usage tracker sudah dihapus
saat hardening. Steer dan wake-coalescing tidak diimplementasikan/diklaim
(lihat `PRODUCTION_PLAN.md` §2, catatan "Explicitly not advertised").

## Catatan pemetaan

- F-01…F-05 tidak lagi open; bukti ada di evidence matrix. Finalisasi lewat
  verification gate, bukan lewat teks status di dokumen ini.
- F-06…F-17 masuk eksekusi H-01…H-12; sampai diverifikasi, risiko residual di atas
  berlaku.
- F-19…F-23 adalah ancaman khusus autonomous engagement. Guardrail wajibnya:
  ROE fail-closed + re-evaluasi scope, verifier deterministik (bukan self-grading
  LLM), isolasi kredensial, untrusted framing untuk halaman program, dan local
  report only tanpa auto-submit. Rincian ada di `docs/engagement.md` dan
  `docs/evaluation.md`.
- Egress firewall, user non-root, dan shell default-deny adalah kompensasi
  deployment yang **wajib** untuk semua ID di atas, terutama F-01, F-02, dan F-06.
- Tidak ada klaim hasil benchmark; `eval/` hanya harness dan contoh ground truth.
