# Rencana Perbaikan Gap Tersisa (B1–B14)

Dokumen ini mencatat kontrak lintas crate dan kriteria untuk pass B1–B14.
Untuk kondisi kode saat ini, jalankan perintah di `docs/PRODUCTION_PLAN.md` §2
dan baca hasilnya dari output tersebut.

## Kontrak lintas crate

STORE:
- `attach_capture(finding_id, request:&[u8], response:&[u8], canary:&str) -> Result<()>`
- `get_capture(finding_id) -> Result<Option<ToolCapture>>`
- `clear_session_flag(session_id, flag) -> Result<()>`
- `park_with_approval(...) -> Result<()>` (transaction: approval + pending calls + park)
- `resolve_approval` cek expiry.

TOOLS:
- `ToolOptions.allowed_methods: Option<Vec<String>>`
- `structured.capture = {request, response, canary}` dari HttpRequestTool/validate_poc.
- `HttpRequestTool` enforces allowed_methods; capture dikirim ke core via ToolResult.
- `validate_poc` risk = `network-write`.
- DnsLookupTool pakai ToolOptions (scope + blocked IP).
- strict numeric host parser (hex/octal/decimal).
- trusted_local_targets: bypass hanya syntactic block, IP tetap diverifikasi.
- proxy: tolak 0.0.0.0.
- recon_pipeline revalidasi tiap target; adapter kill tree.
- external tool scope untuk semua placeholder.

CORE:
- `persist_bounty_tool_result` simpan capture via `attach_capture`.
- stop flag di-clear fisik via `clear_session_flag`.
- parking approval pakai `park_with_approval`.
- `task_put`/`clue_put` dipersisten ke tasks/clues.
- `expire_stale_approvals()` dipanggil saat startup.
- goal lock SHA-256 + injection detector regex.

ENGAGEMENT:
- verifier pakai `get_capture`, bukan field LLM.
- filter `validate_poc` saat `!allow_state_change`.
- trace events: `run_start`, `finding`, `action`, `usage`, `verifier` dengan `run_id`/token.
- benchmark driver feed replay ke score.py.

CLI/DESKTOP:
- config: allowed/denied tools & targets, budget aliases, forward ke PolicyConfig/AgentConfig.

DOCS/EVAL:
- golden + satu hasil nyata, e2e cek isi, mismatch dibersihkan.

## Kriteria

Setiap item B memiliki tes yang menyertai; canary tidak dapat dipalsukan;
pause/resume tidak menyebabkan re-abort; evaluator dapat menghitung metrik
dari replay. Verifikasi dengan perintah di `docs/PRODUCTION_PLAN.md` §2.
