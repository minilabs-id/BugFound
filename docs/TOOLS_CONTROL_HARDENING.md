# Tools & Control Plane Hardening Plan

Tanggal: 2026-11-19
Sumber: audit tools/control plane (temuan 1–4 + correctness)
Status: **TC-1…TC-10 ditutup oleh 3 workstream paralel; suite saat ini 180+ tes.
Jumlah pasti dan status hijau harus dibaca dari `cargo test --workspace`
(`PRODUCTION_PLAN.md` §4), bukan dari status dokumen ini.**

## Target (must fix)

| ID | Masalah | Fix ringkas | Owner |
| --- | --- | --- | --- |
| TC-1 | `shell_exec` allowlist tidak aman (`git`/`cargo`/`cat`, `!`, path absolut, env HOME) | Hapus `git/cargo/cat/dir/ls/pwd`; hanya `echo`/`whoami`; blokir `!`, `=`, `/`, `\`, `:`, `..`; env allowlist tanpa HOME/USERPROFILE; cek argumen path via `resolve_in_cwd` | WS-TOOLS |
| TC-2 | Resume approval lolos guard chain | Ekstrak `pre_execute_guards()` dan pakai di `run_loop`, `resume_after_approval`, `execute_deferred_call` | WS-CORE |
| TC-3 | Pause/abort lintas-proses lambat | Flag stop durable per-session, dicek tiap step & sebelum tool spawn di Runner; `pause_at/abort_at` tulis flag + interrupt | WS-CORE + WS-ENG |
| TC-4 | ROE tidak dieksekusi | `max_requests` → budget; `http_request` method gate via `allowed_methods`; buang tool `intrusive/network-write` saat opt-in false; FullAuto konsultasi risk | WS-TOOLS + WS-POLICY + WS-ENG |

> **Status `allowed_methods` (diperbarui B4):** `ToolOptions.allowed_methods`
> sekarang **diimplementasikan dan ditegakkan oleh `HttpRequestTool` (WS-TOOLS)**.
> Klaim lama bahwa `ToolOptions` "tidak punya gate `allowed_methods`" sudah tidak
> berlaku. Engagement tetap fails-closed secara berlapis: bila ROE melarang
> perubahan state, tool `http_request` tidak didaftarkan sama sekali sedangkan
> `http_probe` / `dns_lookup` tetap tersedia. Rincian ada di
> `REMAINING_GAPS.md` §2 (B4, B5).

## Correctness tambahan

- TC-5: `resp.bytes()` → streamed capped read (16 KB + batas total).
- TC-6: redaction tools: loop semua bearer + JSON-aware (pakai helper).
- TC-7: adapter scope check untuk `{url}` juga; kill child saat timeout; redact stdout.
- TC-8: canary verifier dari bytes asli (bukan field LLM); `validate_poc` butuh `finding_id`.
- TC-9: goal lock fail-closed; `extract_policy_target` key sempit; `expire_stale_approvals` dipanggil production; is_network_tool pakai risk.
- TC-10: config schema CLI=desktop; `auto_approve_all` dipakai semua frontend; docs diselaraskan.

## Kriteria penerimaan

- `git -c alias.x=!calc x` ditolak; `cargo build` ditolak; `cat /etc/shadow` ditolak.
- Resume setelah scope diubah/injection flag → tool tidak jalan.
- `abort` dari proses lain menghentikan Runner dalam ≤1 step.
- Brief dengan "no state change" membuat PUT/DELETE ditolak; intrusive tool tidak terdaftar.
- fmt/clippy/test/build hijau; tes baru untuk tiap TC.
