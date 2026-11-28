# Eksekusi Rencana Perbaikan — 2026-11-28

> Implementasi dari `docs/REPAIR_PLAN_2026-11-28.md` terhadap register
> `docs/AUDIT_2026-11-27.md`. Semua perubahan sudah diverifikasi dengan rangkaian
> command di bawah. File audit/plan tetap menjadi catatan asli; dokumen ini
> hanya merangkum hasil eksekusi dan sisa gap.

## 1. Status eksekusi

| Fase | Status | Ringkasan |
| --- | --- | --- |
| 0 STOP-BLEED | Selesai | Approval/deny tail, injection guard, owner-guarded finish, verifier authority, OOB auth, scope path, canary, eval false-green |
| 1 Trust chain & ROE | Selesai | Self-grading detector, scope key typed, DNS pin, 3-hash revalidation, TLP, planner catalog, precondition, status vocabulary, checkpoint keyed, A12 budget |
| 2 Scope & evidence | Selesai | Raw capture authority, report hash recompute, cookie domain, method gate, OOB endpoint validation, placeholder scope, falsification default, core schema backstop, shell target, duplicate bucket, inbox cap |
| 3 Schema v4 & durability | Selesai | Migration atomik + ledger, event anchor, conditional writes, lease heartbeat, settlement, coordinator map, compaction role partition, monitor dedup, C9 ack binding, token offset, C9 `restriction_json` |
| 4 Control & UI | Selesai | Synchronous Stop/Steer, delta join, carry-window redaction, report integrity verify, config unification + merge-on-save, CLI hygiene, frontend selection/errors/busy, proxy timeouts/Win32 DACL |
| 5 LLM & eval & docs | Selesai | SSE truncation/CRLF/caps/retry, error classification, `bugfound-redact` leaf crate + corpus, FPR/FDR split, finding-map, manifest validation, trace export fixes, docs truth, cargo-deny pin |
| 6 Residual | Selesai | A16 public aliases removed, A20 predicate session queries, E21 UI I/O ke worker thread, D17 retention API + prune saat startup/CLI, N≥2 doc alignment |
| 7 Residual putaran-2 | Selesai | Goal-lock v2 bind scope + relock eksplisit, OOB token per-finding (harness-owned, match eksak), retensi otomatis `retention_days`, DACL Win32 penuh (current-user-only ACE) |

## 2. Verifikasi final (semua hijau)

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo build -p bugfound-cli
pnpm --dir frontend test          # 7/7 Vitest
pnpm --dir frontend build
python eval/agent_eval.py --self-test
python eval/score.py --self-test  # 44/44
python eval/export_trace.py --self-test  # 13/13
python eval/agent_lab.py --runs 3 --adaptive
python eval/adversarial_lab.py    # 3/3
```

Jumlah test Rust per target: cli 24, collaborator 12, core 41 + 79 integration,
desktop 17, desktop-core 30, engagement 127 + 29 integration + 1 handoff,
kernel-traits 0, llm 32, policy 23, proxy 10, redact 6, store 96, tools 132.

## 3. Perubahan penting

- **Crate baru**: `crates/bugfound-redact` (leaf, serde_json) — satu implementasi
  redaksi + canary untuk tools/store/collaborator, dengan corpus parity 6 test.
- **Schema DB v4**: ledger `schema_migrations`, anchor event chain, coverage
  unique index + dedupe, timestamp kanonik, capture digest, `hash_version=2`
  dengan verifikasi formula lama, `restriction_json`.
- **Kontrak keamanan**: semua promosi finding lewat `Verifier::decide`; ROE gate
  sebelum semua oracle; ack mengikat typed restriction; admin OOB bearer auth;
  scope fail-closed di core + tools + proxy; capture hanya dari tool HTTP.
- **UI**: Stop/Steer sinkron, approval busy state, error banner, session selection,
  report hash verification, DB I/O di worker thread.
- **Eval**: exit code/DB gate nyata, FPR terpisah dari FDR proxy, finding-map
  eksplisit, manifest divalidasi, hash chain diverifikasi.

## 4. Perbaikan residual putaran kedua (selesai)

- **A18 / C30 — goal lock kini bind scope**: trait `GoalLock` mendapat method
  default `digest_with_context`; `KernelDomain`/`BountyDomain` memakai context
  kanonik; lock ditulis sebagai `v2:` + digest(goal, scope JSON) yang sudah
  di-sort. Lock v1 (lama) ditolak dengan event `goal_lock.migration_required`
  dan jalur eksplisit `Runner::relock_session(id, "approve")` — tidak auto-accept,
  tidak brick. Test reproducer: `goal_lock_v2_binds_authorization_scope`,
  `scope_change_after_park_blocks_approved_tool_until_relock`.
- **OOB per-finding token**: collaborator `start` mengeluarkan `oob_proof.token`
  (hanya `start`, bukan `fetch`); harness yang menyimpannya lewat
  `session_oob_tokens` lalu `findings.oob_token` saat `save_finding`, bukan dari
  teks model. `HttpOobOracle` mencocokkan FIELD `token` secara eksak dan menolak
  kunci kosong; finding lama tanpa token tidak bisa dipromosi oleh OOB saja.
- **D17 retention**: API prune + chain guard sudah ada, dan sekarang dipakai:
  `storage.retention_days` (0 = nonaktif, maks 36500) membawa prune audit/trace
  event saat startup desktop, dengan verifikasi ulang hash chain sebelum trace
  dihapus; perintah `bugfound prune [--session] [--days] [--dry-run]` melakukan
  hal yang sama untuk CLI dan keluar non-zero bila chain rusak. Penjadwalan
  ulang latar belakang (cron/TTL worker) masih belum diimplementasi — jadi
  retensi berjalan saat proses mulai, bukan periodik. Verifikasi sudah paginasi.
- **OS sandbox & parallel sessions**: tetap out of scope sesuai ADR/V3_STATUS.
- **Live GUI smoke dengan provider nyata**: belum dijalankan; semua pengujian
  UI bersifat offline/unit.
- **GUI smoke Windows proxy CA**: smoke GUI dengan provider nyata belum dijalankan;
  `--ca-dir` tetap harus berada di bawah `%LOCALAPPDATA%`/`%USERPROFILE%` sebagai
  pertahanan berlapis, tetapi DACL Win32 sekarang **diterapkan dan diverifikasi
  secara eksplisit** pada Windows: direktori
  CA dan `ca-key.pem` mendapat satu ACE `GENERIC_ALL` untuk SID user saat ini
  (non-inherit, ACE turunan dihapus, DACL dilindungi). DACL NULL / luas atau ACE
  yang bukan milik user saat ini ditolak keras; bila API Win32 gagal dicek (mis.
  filesystem virtual) dan lokasi per-user lolos, hanya peringatan yang
  dikeluarkan. **Perubahan perilaku**: kunci yang dibuat build lama tidak memiliki
  DACL ini dan harus dibuat ulang (hapus direktori `--ca-dir` lalu jalankan lagi).
- **`BUGFOUND_CHECKPOINT_KEY`**: harus diset operator agar resume checkpoint
  bertahan lintas restart; tanpa itu fail closed (ephemeral key).
- **`fallback_models`**: sudah dibaca dari CLI/desktop config dan env
  `BUGFOUND_FALLBACK_MODELS`; array kosong secara default (perilaku lama).
- **`docs/research/**`**: snapshot riset historis, sengaja tidak diperbarui.

## 5. Catatan working tree

Perubahan implementation transparan di atas file-file yang sudah dimodifikasi
sebelumnya (staged + unstaged dari inkremen V3). Tidak ada `git reset`,
`git checkout .`, atau regenerasi massal `eval/results/**`. File audit/plan dan
dokumen eksekusi ini adalah file baru; `eval/_fix_e2e_tmp.py` dihapus.
