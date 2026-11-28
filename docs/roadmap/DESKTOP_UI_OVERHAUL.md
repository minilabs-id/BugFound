# Rencana Perombakan Total Desktop UI — BugFound

> Status: **disetujui 2026-11-26; Phase 0 (scaffolding) sedang dikerjakan**.
> Keputusan stack: Tauri 2 + React/TypeScript — lihat `docs/adr/ADR-009-tauri-react-desktop-ui.md`.
> Riset: `docs/research/19_desktop_ui_ux_benchmark.md`.
> Domain workflow yang harus tetap dipatuhi: `docs/research/17_ideal_workflow.md`.

---

## 0. TL;DR

UI sekarang bukan sekadar "jelek", tapi **sebagian tidak berfungsi**: tombol
"Start engagement with URL" tidak pernah mengisi `engage_url`, jadi alur
engagement tidak pernah bisa dijalankan dari desktop. Seluruh percakapan hilang
saat app ditutup, approval tidak di-refresh, dan pengaturan cuma field config
mentah.

Rencananya: **ganti shell egui/eframe dengan Tauri 2 + React**, pindahkan logika
ke `bugfound-desktop-core`, dan bangun ulang UI sebagai *supervision console*
ala ChatGPT/Codex/Claude Code: sidebar session, control row di bawah composer,
timeline dengan aktivitas terlipat, kartu approval inline, rail findings +
bukti, viewer laporan, theme, dan keyboard shortcut. Agent core, policy, budget,
dan aturan local-report-only **tidak berubah**.

Kalau rencana ini dibatalkan sebelum Phase 1, opsi bersihnya ada di §11:
hapus seluruh interface desktop dan biarkan CLI saja.

---

## 1. Prinsip desain (dari riset)

1. **UI adalah konsol supervise, bukan sekadar chat.** Manusia mengatur batas,
   mengawasi progres, meninjau bukti, dan mengambil keputusan.
2. **Satu engine, banyak surface** (S4). Semua logika tetap di Rust; shell
   desktop hanya adapter.
3. **Progressive disclosure.** Default tenang: ringkasan tool call; detail raw
   args/bytes/diff satu klik.
4. **Kontrol dekat aksi.** Mode, model, workspace, dan budget ada di bawah
   composer, bukan tersembunyi di halaman Settings.
5. **Keputusan manusia selalu eksplisit.** Approval, ROE, dan finalisasi laporan
   tidak pernah otomatis. Tidak ada auto-submit.
6. **State berasal dari store, bukan memori UI.** Riwayat harus bisa dibuka
   lagi setelah restart.
7. **Semua teks yang tampil sudah diredaksi di sisi Rust.** Webview tidak pernah
   melihat secret mentah.

---

## 2. Audit UI sekarang (evidence-based)

Berdasarkan `crates/bugfound-desktop/src/{main,config,worker}.rs`.

| # | Masalah | Bukti | Dampak |
| --- | --- | --- | --- |
| A1 | **Alur engagement mati.** `engage_url` dideklarasikan dan dibaca, tapi tidak pernah diisi widget manapun. | `main.rs:60,97,264-267` | Tombol "Start engagement with URL" selalu mengatakan "enter a program URL first". `ChatCommand::Engagement` tidak pernah terkirim. |
| A2 | Riwayat percakapan hanya di memory. | `main.rs:69`; `list_messages` tidak dipanggil | Tutup app = hilang semua chat, walaupun core menyimpan session/message. |
| A3 | Composer mati saat `busy`, tapi jalur engagement **tidak pernah** menyetel `busy`. | `main.rs:454,228-230,207-219` | Saat engagement jalan, input terlihat aktif tapi perintah hanya antre diam-diam di worker. |
| A4 | Tidak ada stop / steer. | composer hanya Enter→send, `main.rs:460-461` | Tidak bisa menghentikan atau mengarahkan agent sedang berjalan, padahal core punya `steer`. |
| A5 | Render teks polos. | `main.rs:504,510` | Tidak ada markdown, code block, link, copy, timestamp, atau seleksi pesan. Laporan juga cuma `text_edit_multiline` yang bisa diedit (`main.rs:551`). |
| A6 | Approval lemah. | `main.rs:151-159,250-258` | Di-refresh hanya saat start/finish; kartu tidak hilang setelah keputusan; `reason`, `expires_at`, `id` disembunyikan; tidak ada umpan balik. |
| A7 | Informasi event dibuang. | `event_line()` `main.rs:355-381` | `Action.target`, `Finding.id`, detail brief, dan task plan tidak pernah tampil. |
| A8 | Settings tidak lengkap & API key plaintext. | `main.rs:557-619`; `config.rs:173-176` | Tidak ada widget untuk policy, budget, storage, timeout, ROE, external tools. Key literal disimpan apa adanya; opsi `env:VAR` tidak disosialisasikan. |
| A9 | I/O DB blocking di UI thread. | `main.rs:313-315,327,389-397` | `pause/resume/abort/status_at` membuka koneksi SQLite baru tiap 700 ms. |
| A10 | Dua koneksi store terpisah (UI + worker). | `main.rs:88-89`; `worker.rs:120-122` | Risiko lock/inkonsistensi; fallback diam-diam ke `:memory:` kalau path invalid. |
| A11 | Validasi setelah user message masuk transcript. | `main.rs:235-240` | Error config meninggalkan pesan user yang menyesatkan. |
| A12 | Error ditelan. | `main.rs:153,155`; `worker.rs:367-369` | `unwrap_or_default()` / `let _ =` menyembunyikan kegagalan. |
| A13 | Tidak ada theme, shortcut, pencarian, atau state window yang persisten. | seluruh file | Tidak ada jalur keyboard-only, tidak ada dark mode. |
| A14 | Copy bahasa campur. | `main.rs:458,489-490` vs sisanya | "Program URL, lalu follow-up…" vs "Settings"/"Report". |
| A15 | Dead code & asumsi rapuh. | `worker.rs:13-175,255-275` | `Job`/`JobEvent`/`spawn_job` tidak terpakai; session discovery pakai `list_sessions(1)`; follow-up mengabaikan config baru. |

**Kesimpulan:** ini bukan masalah styling. Perlu perombakan arsitektur view,
bukan ganti warna.

---

## 3. Kenapa Tauri + React (bukan egui, bukan TUI)

- egui = immediate mode: tanpa DOM/CSS, text layout terbatas, tidak ada pane
  system, markdown harus dibangun sendiri. Biaya untuk menyaingi target ≈
  menulis toolkit.
- Tauri 2 menyediakan `invoke` commands, events, dan **Channels** untuk
  streaming berurutan; backend tetap Rust (`develop/calling-rust/`).
- Binary small (native webview), tidak mengirim Chromium seperti Electron.
- React memberi layout, typography, theming, aksesibilitas, dan ekosistem
  markdown/diff viewer yang matang.
- CLI tetap utuh; perubahan hanya di lapisan presentasi.

Risiko yang diterima: toolchain frontend masuk ke CI dan webview menjadi
permukaan review keamanan baru (ACL + CSP). Mitigasinya ada di §6.4 dan §12.

---

## 4. Target experience & Information Architecture

### 4.1 Wireframe desktop (utama)

```
┌──────────────┬─────────────────────────────────────┬───────────────────┐
│ BugFound     │  ● acme-program / Recon-Auth        │  Session          │
│ ──────────── │  3/9 tasks · 1 finding · 62% cov.   │  ───────────────  │
│ + New        │                                     │  Context 34%      │
│ ──────────── │  YOU                                │  Steps 18/20      │
│ Pinned       │  Cek apakah /api/v1/orders milik    │  Tools 22/100     │
│ Scheduled    │  user lain.                         │  Net 9/50         │
│ ──────────── │                                     │  ───────────────  │
│ RECENTS      │  BUGFOUND                           │  FINDINGS         │
│ ● Recon-Auth │  Membaca 3 file, menyusun 2         │  [HIGH] IDOR ...  │
│ ○ Scope H1   │  hipotesis…                ▾ detail │   ✓ validated     │
│ ✓ Report Q3  │  → http.get 200 · canary match ▾    │   evidence →      │
│ ⚠ Needs you  │  ┌───────────────────────────────┐  │  ───────────────  │
│              │  │ APPROVAL NEEDED               │  │  PLAN / TASKS     │
│              │  │ http.post ke /api/v1/orders   │  │  1 ✓ brief        │
│              │  │ risk: network-write           │  │  2 ● recon        │
│              │  │ [Approve] [Always] [Deny]     │  │  3 ○ test         │
│              │  └───────────────────────────────┘  │                   │
│              │                                     │  [Report ▸]       │
│ ──────────── │  ─────────────────────────────────  │                   │
│ ⚙ Settings   │  [Ask ▾] [./engagement] [model ▾]  │                   │
│ ? Shortcuts  │  ┌───────────────────────────────┐  │                   │
│              │  │ Lanjutkan dengan negative     │  │                   │
│              │  │ control…                  ⏎  │  │                   │
│              │  └───────────────────────────▲───┘  │                   │
│              │                         [Stop] [+] │                   │
└──────────────┴─────────────────────────────────────┴───────────────────┘
```

### 4.2 Layar / status

| Layar | Tujuan | Prioritas |
| --- | --- | --- |
| **Welcome / empty state** | Jelaskan 9 fase engagement, satu aksi utama: "Mulai engagement" (URL program / file brief). | P0 |
| **Session workspace** | Timeline + control row + composer + right rail. Layar utama. | P0 |
| **Approval queue** | Daftar semua approval lintas session (filter by session). Badge di sidebar. | P0 |
| **Findings & evidence** | Kartu finding + status verifier + bukti (request/response bytes, canary, digest) + link artifact. | P1 |
| **Report viewer** | Markdown read-only, daftar isi, copy/export lokal. Tidak bisa diedit di UI. | P1 |
| **Settings dialog** | Semua field config dikelompokkan: Provider, Agent, Policy/Scope, Network, Storage, External tools. | P1 |
| **Shortcut help overlay** | `Ctrl+/`, daftar keyboard map. | P1 |
| **Session history search** | Cari judul/isi session. | P2 |
| **Parallel / split sessions** | Beberapa session aktif, `Ctrl+Tab`, split view. | P3 |

### 4.3 Customer journey (happy path)

1. Buka app → welcome → pilih "Mulai engagement", masukkan URL program.
2. UI menampilkan **authorization/ROE gate**: ringkasan scope, pertanyaan
   terbuka, checkbox "Saya memiliki otorisasi". Tidak ada target yang disentuh.
3. Agent jalan: sidebar berubah status, task plan terisi, aktivitas muncul
   sebagai ringkasan terlipat.
4. Agent menemui tool berisiko → kartu approval muncul inline + badge sidebar.
   Operator pilih Approve / Always allow (session ini) / Deny.
5. Operator bisa **steer** (ketik koreksi, Enter) atau **stop** (Esc) kapan saja.
6. Finding muncul di rail dengan status dari verifier deterministik, bukan label
   model.
7. Report ready → viewer terbuka, bertanda `draft — operator review required`.
   Tidak ada tombol submit ke platform.
8. Tutup app, buka lagi → session dan timeline kembali dari store.

---

## 5. Design system

| Token | Nilai awal | Catatan |
| --- | --- | --- |
| `--bg` / `--surface` / `--surface-2` | `#0d0f12` / `#16191e` / `#1d2128` (dark); `#fafafa` / `#fff` / `#f4f4f5` (light) | System-follow default, override persist. |
| `--border` / `--text` / `--muted` | kontras ≥ 4.5:1 untuk body | Status pill boleh warna, teks tetap legible. |
| `--accent` | satu warna aksen (mis. biru) | Dipakai untuk fokus, primary action, in-progress. |
| Severity | critical / high / medium / low / info | Pills kecil, tidak mewarnai seluruh kartu. |
| Status | running / needs-decision / done / blocked / archived / ruled_out / open_proof_gap | Satu vocabulary dipakai sidebar + rail + timeline. |
| Font | system UI stack; `ui-monospace` untuk tool/evidence | Tabular numbers untuk counter. |
| Type scale | 11 / 12 / 13 / 14 / 16 / 20 / 24 px | Body 14, metadata 12. |
| Spacing | skala 4 px: 4, 8, 12, 16, 24, 32 | Card padding 16–24. |
| Radius / motion | 6–10 px; 150–200 ms; `prefers-reduced-motion` | Tidak ada animasi dekoratif. |
| Layout | sidebar 260 px, content max 720 px, rail 300 px | Rail bisa disembunyikan. |

**Aturan visual:** tiga zona, column chat terpusat, tidak ada panel berwarna
tebal, tidak ada bevel, satu border halus per kartu, empty state mengajarkan
workflow, progressive disclosure untuk semua data mentah.

**Aksesibilitas:** semua interaksi keyboard-reachable, focus ring jelas, ARIA
label untuk icon button, `aria-live` untuk approval baru, respect reduced
motion, kontras minimum, tidak ada warna sebagai satu-satunya pembeda status.

---

## 6. Arsitektur teknis

### 6.1 Struktur target

```
crates/
  bugfound-desktop-core/     BARU — library, bisa dipakai CLI/surface lain
    src/lib.rs               AppState, event bridge, lifecycle
    src/dto.rs               tipe Serialize untuk frontend
    src/projection.rs        Store → DTO (satu-satunya jalan baca UI)
    src/commands.rs          handler bisnis (tanpa atribut Tauri)
  bugfound-app/              BARU — shell Tauri 2 (menggantikan bugfound-desktop)
    Cargo.toml               tauri + ACL minimal
    src/main.rs, src/lib.rs  Builder, managed state, invoke_handler
    tauri.conf.json
    capabilities/default.json
    icons/
frontend/                    BARU
  package.json, pnpm-lock.yaml, vite.config.ts, tsconfig.json, index.html
  src/main.tsx, src/App.tsx
  src/lib/{ipc,events,types,format}.ts
  src/state/appStore.ts
  src/features/{sidebar,timeline,composer,findings,report,settings,onboarding}/
  src/components/ui/{Button,Pill,Markdown,CodeBlock,Tooltip,Kbd,EmptyState}.tsx
  src/styles/{tokens,global}.css
```

`crates/bugfound-desktop` (egui) **dibiarkan dulu** sampai Phase 3 lolos parity,
lalu dihapus (§11).

### 6.2 IPC contract

**Commands** (`invoke`, camelCase arg, async, `Result<T, AppError>` dengan error
enum serializable):

| Command | Arg | Hasil |
| --- | --- | --- |
| `app_ready` | – | snapshot awal: sessions, settings ringkas, budgets, startup warnings (**Phase 0: implemented**) |
| `sessions_list` | `limit?` | `SessionSummary[]` |
| `session_history` | `sessionId` | `TimelineItem[]` (sudah diredaksi) |
| `chat_send` | `text, cwd, mode` | ack (stream lewat Channel) |
| `chat_steer` | `text` | ack |
| `chat_stop` | – | ack |
| `approval_decide` | `sessionId, approvalId, decision, always?` | ack |
| `approval_list` | `sessionId?` | `ApprovalDetail[]` |
| `engagement_start` | `url, cwd, options, roe, loopOptions` | ack (event untuk progres) |
| `engagement_control` | `id, action` | ack |
| `engagement_status` | `id` | `EngagementSnapshot` |
| `findings_list` | `sessionId` | `FindingDetail[]` |
| `report_open` | `path` | teks markdown (redacted, read-only) |
| `settings_get` / `settings_save` | – / `SettingsDto` | `SettingsDto` / ack |

> Nama command di atas memakai snake_case sesuai implementasi Tauri; titik
> hanya dipakai di tabel ini sebagai pemisah konseptual di dokumen lama.

**Events** (typed, Rust → frontend): `runtime.started`, `runtime.finished`,
`runtime.error`, `approval.new`, `approval.resolved`, `engagement.event`,
`finding.new`, `status.changed`, `settings.changed`.

**Channel** (ordered): `chat.send` menerima `tauri::ipc::Channel<Delta>` untuk
`Delta { text }`. Sumber: `ChatWorkerEvent::Delta` yang sekarang dijembatani
lewat thread ekstra — diganti langsung ke Channel.

**DTO penting:** `SessionSummary`, `TimelineItem` (user/assistant/activity/
approval/finding/notice/system + `ts`, `redacted`, `expandable`),
`ApprovalDetail` (`id`, `tool`, `risk`, `reason`, `argsRedacted`, `expiresAt`),
`FindingDetail` (`id`, `severity`, `status`, `verifiedBy`, `evidenceRefs`),
`BudgetSnapshot`, `EngagementSnapshot`, `SettingsDto`.

### 6.3 State & data flow

```
Store (SQLite, satu koneksi di Rust)
   │ projection.rs
   ▼
AppState (managed by Tauri) ──events/channel──▶ React appStore
   ▲                                              │ invoke
   └── commands.rs ◀──────────────────────────────┘
```

- React **hanya** menampilkan proyeksi; tidak ada fetch DB langsung, tidak ada
  koneksi SQLite kedua.
- Webview menyimpan UI state (theme, sidebar width, rail visibility, draft
  input) di `localStorage` — bukan data agent.
- Setiap event memperbarui store frontend secara inkremental; `session.history`
  dipanggil saat membuka session atau saat reconnect.
- Semua teks melewati `redact()` di Rust sebelum serialisasi (pertahankan
  `store::redact`).

### 6.4 Keamanan

- Tauri ACL minimal: tidak ada `shell` plugin, tidak ada `fs` plugin bebas,
  tidak ada `http` plugin di webview. Semua aksi melewati command Rust yang
  sudah melewati policy/core.
- CSP ketat, `devUrl` hanya saat dev, tidak ada remote origin di production.
- API key: default `env:VAR`; field UI menampilkan status "tersimpan sebagai env:OPENAI_API_KEY", bukan nilai. Jika literal dipakai, tampilkan peringatan.
- Tidak ada `dangerouslySetInnerHTML` tanpa sanitasi; markdown dirender dengan
  parser yang menghindari raw HTML atau dengan sanitizer.
- Tidak ada tombol submit ke platform bounty. Finalisasi = tanda tangan lokal
  + review operator.

### 6.5 Perubahan di crates yang sudah ada

- `bugfound-core`: tetap. Karena `steer` sudah ada, tinggal diekspos.
- `bugfound-engagement`: tetap. Perbaiki `EngagementEvent` bridge supaya
  `target`, `Finding.id`, task list tidak dibuang.
- `bugfound-store`: tambah query proyeksi bila perlu (`list_pending_approvals`
  sudah ada tapi belum dipakai). Jangan tambah logika bisnis di sini.
- `bugfound-desktop`: dihapus setelah parity (§11).
- Root `Cargo.toml`: buang `eframe`/`egui` setelah penghapusan; tambah `tauri`,
  `tauri-build`, `serde` untuk core.

---

## 7. Inventaris komponen & mapping state lama → baru

| State lama | Komponen baru | Perubahan |
| --- | --- | --- |
| `chat: Vec<ChatLine>` | `Timeline` + `TimelineItem[]` dari `session.history` | Persisten, typed, ada `ts`, bisa expand/collapse. |
| `ChatRole::{User,Agent,Activity,Notice}` | `UserMessage`, `AssistantMessage`, `ActivityRow`, `SystemNotice` + `ApprovalCard`, `FindingCard` | Role baru untuk approval & finding. |
| `stream_line: Option<usize>` | `StreamingMessage` di appStore via Channel | Tidak ada indeks rapuh; final text tidak dibuang. |
| `pending: Vec<(String, Approval)>` | `ApprovalCard[]` + sidebar badge | Di-refresh event-driven, hilang setelah keputusan, ada "always". |
| `chat_input`, `busy` | `Composer` + `runtime.status` | Input tetap usable untuk steer; Stop eksplisit. |
| Top bar status | `SessionHeader` + `BudgetSnapshot` | Counter dari store, bukan string statis. |
| `show_settings` | `SettingsDialog` (overlay) | Tidak menggantikan workspace. |
| `cfg_*`, `scope_in_text` | `SettingsDto` | Semua field config ter-cover, validasi sisi Rust. |
| `engage_report` (editable) | `ReportViewer` (read-only markdown) | Tidak bisa diedit tidak sengaja. |
| `EngageAction` | `engagement.control` + control buttons | Idempoten, feedback jelas. |
| `event_line()` | `ActivityRow` + `VerboseToggle` | `target`, `id`, task tidak dibuang. |

---

## 8. UX khusus BugFound (yang tidak bisa disalin mentah)

1. **Authorization/ROE gate sebagai layar, bukan checkbox tersembunyi.**
   Sebelum target disentuh, tampilkan ringkasan scope, in/out-of-scope, open
   questions, dan konfirmasi operator. Selaras `docs/research/17` fase 1–2.
2. **Status finding dari verifier, bukan model.** UI menampilkan
   `validated | ruled_out | open_proof_gap | blocked`, dengan badge
   "advisory" jika nilai berasal dari model. `open_proof_gap` memblokir
   finalisasi.
3. **Bukti = bytes + canary + digest.** Kartu finding menautkan artifact lokal;
   viewer menampilkan request/response teredaksi dan hash. Tidak ada
   "self-graded" confidence yang tampil sebagai kebenaran.
4. **Coverage ledger terlihat.** Rail menampilkan covered / blocked / skipped /
   not-applicable + rationale. "Zero findings" hanya valid dengan coverage
   non-zero, sesuai definition of done.
5. **Budget sebagai first-class info.** Steps, tools, network, RPM, token —
   ditampilkan terhadap limit, dengan peringatan sebelum habis.
6. **Approval explainer.** Untuk setiap tool berisiko: mengapa ini butuh
   approval, aturan policy yang aktif, dan apakah "always allow" hanya berlaku
   untuk session ini.
7. **Laporan lokal saja.** Tidak ada aksi kirim/submit. Label `draft — operator
   review required` selalu ada sampai operator menandai selesai.

---

## 9. Scope & prioritas (acceptance criteria)

### P0 — Fondasi (Phase 0–2)
- [ ] App Tauri build di Windows; koneksi IPC `app.ready` berhasil.
- [ ] Sidebar menampilkan session dari `Store::list_sessions`; klik session
      memuat `session.history`.
- [ ] Mengirim pesan menghasilkan stream token yang tampil sebagai markdown;
      riwayat tetap ada setelah restart.
- [ ] Control row menampilkan mode (Ask/FullAuto), workspace, model, budget.
- [ ] Tombol Stop dan steer bekerja.
- [ ] Semua tes Rust lulus; ADR-001 boundary check lulus.

### P1 — Supervisor (Phase 3–5)
- [ ] Tombol "Mulai engagement" benar-benar mengisi URL dan mengirim command.
- [ ] ROE gate tampil sebelum eksekusi; approval inline + queue + badge.
- [ ] Approve / Always / Deny mengubah state dan kartu hilang setelah keputusan.
- [ ] Finding card menampilkan status verifier + bukti; report viewer read-only.
- [ ] Settings mencakup semua field yang ada di `AppConfig`; API key default
      `env:VAR`.
- [ ] Theme light/dark + system-follow; keyboard map + `Ctrl+/`.
- [ ] ACL/CSP audit: webview tidak bisa mengakses shell/fs/http langsung.

### P2 — Kualitas
- [ ] Pencarian session, grouping, archive, rename.
- [ ] View mode Normal / Verbose; copy button; jump-to-latest.
- [ ] OS notification saat session selesai saat tidak aktif.
- [ ] Empty states, error states, reduced-motion, kontras AA.

### P3 — Lanjutan (tidak masuk rencana ini)
- Parallel sessions, split view, file/diff pane, browser pane, scheduling.

---

## 10. Rencana eksekusi per phase

| Phase | Nama | Deliverable konkret | Definition of done |
| --- | --- | --- | --- |
| **0** | Scaffolding & keputusan — **SELESAI (2026-11-26)** | ADR-009 accepted; `bugfound-desktop-core`, `bugfound-app` (Tauri), `frontend/` (Vite+React+TS+Zustand); command `app_ready`; design tokens + layout 3 zona; `.github/workflows/desktop-ui.yml`. | ✅ `pnpm typecheck/test/build`, `cargo check -p bugfound-app`, `cargo clippy` new crates, `cargo test --workspace` lolos. Shell menampilkan status "connected" dari `app_ready`. Lihat §15. |
| **1** | Read path & fondasi visual | `session.list`, `session.history`, DTO + `redact`; tokens CSS, theme, sidebar, welcome state. | Riwayat lama tampil setelah restart; toggle theme bekerja; webview tidak menyentuh DB. |
| **2** | Composer & runtime control | `chat.send` via Channel, `chat.stop`, `chat.steer`, control row, budget chips, keyboard map, markdown renderer. | Stream lancar & berurutan; Stop menghentikan; steer masuk di boundary; config invalid tidak mengotori transcript. |
| **3** | Engagement & approvals | Perbaiki A1; `engagement.start/control/status`, ROE gate, approval cards + queue, event detail lengkap. | Engagement bisa dijalankan penuh dari UI; approval bisa dijawab; parity fungsional dengan niat lama → **hapus crate egui di sini**. |
| **4** | Findings, evidence & report | `findings.list`, finding cards, evidence drawer, `report.open` read-only markdown, view modes. | Finding status sesuai verifier; bukti bisa dibuka; laporan tidak bisa diedit tidak sengaja. |
| **5** | Settings & hardening | Settings dialog lengkap, env:VAR key, ACL/CSP review, error surfaces, copy bahasa konsisten. | Checklist keamanan §6.4 lulus; tidak ada secret plaintext default. |
| **6** | Polish & P2 | Search/archive/rename, shortcut help, notifications, aksesibilitas, dokumentasi README. | Semua P2 di §9 selesai; smoke test manual lolos. |

**Urutan penghapusan UI lama:** Phase 3 selesai → hapus `crates/bugfound-desktop`,
hapus `eframe`/`egui` dari root `Cargo.toml`, perbarui workspace member,
`README.md`, `start-desktop.bat`. Tidak ada dua GUI aktif bersamaan di rilis.

---

## 11. Opsi alternatif: hapus interface sekarang (clean cut)

Kalau perombakan dibatalkan dan yang diinginkan cuma "biar clear":

1. Hapus direktori `crates/bugfound-desktop/` beserta `main.rs`, `config.rs`,
   `worker.rs`, `Cargo.toml`.
2. Hapus `"crates/bugfound-desktop"` dari `members` di root `Cargo.toml`, lalu
   hapus `eframe` dan `egui` dari `[workspace.dependencies]`.
3. Hapus `start-desktop.bat` (atau ganti jadi launcher CLI).
4. Perbarui `README.md`: hapus baris tabel `bugfound-desktop`, hapus paragraf
   "The desktop build uses the same crates…", ganti dengan fokus CLI.
5. Pertahankan `assets/bugfound-logo.*` (masih dipakai branding/docs) dan
   seluruh crate core/CLI.
6. Jalankan `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
   -- -D warnings`, `cargo test --workspace`, `cargo build --release --workspace`.

Hasil: satu interface (CLI), tidak ada kode GUI yang setengah jadi, tidak ada
dependensi GUI. Ini jalur paling cepat dan paling bersih, tapi **bukan** target
"sekelas Codex/ChatGPT/Claude Code" secara visual.

---

## 12. Risiko & mitigasi

| Risiko | Mitigasi |
| --- | --- |
| Webview jadi celah (XSS → command) | ACL minimal, CSP ketat, markdown sanitized, tidak ada remote URL, redaction di Rust. |
| Ordering streaming hilang | Pakai Tauri Channel, bukan event berfrekuensi tinggi; satu urutan Delta per session. |
| Payload besar melambat IPC | Kirim path/ID, baca bytes di Rust saat diminta; paginasi timeline. |
| Dua koneksi SQLite | Satu koneksi di Rust (`AppState`); hilangkan `Store::open` dari UI thread. |
| Error disembunyikan lagi | Error enum serializable + toast/inline error; tidak ada `let _ =` di command path. |
| Scope creep (parallel sessions, browser, diff pane) | Tabel P3 dikunci; tidak dikerjakan di phase 0–6. |
| Windows tanpa WebView2 | Deteksi saat install, pesan jelas; CLI tetap jalan. |
| Toolchain frontend bikin CI gagal | Lockfile pnpm, Node version pin, job CI terpisah dari Rust check. |
| Kehilangan fitur lama saat migrasi | Phase 3 parity gate sebelum hapus egui; checklist §9. |

---

## 13. Validasi & metrik sukses

- **Fungsional:** semua checklist P0/P1 lulus; smoke test delapan langkah di §4.3.
- **Performa:** tidak ada blocking I/O > 100 ms di UI thread; stream mulai tampil
  < 200 ms setelah delta pertama.
- **Keamanan:** audit ACL/CSP; tidak ada secret di localStorage/DOM; tidak ada
  tombol submit eksternal.
- **Kualitas UI:** keyboard-only menyelesaikan task dasar; kontras AA; reduced
  motion; tidak ada teks campur bahasa tanpa sengaja.
- **Regresi:** `cargo fmt/clippy/test/build`, `pnpm lint/typecheck/test/build`,
  ADR-001 domain-boundary check, `cargo deny check`.
- **Subjektif (diukur lewat demo):** operator bisa menjelaskan status engagement
  dalam < 10 detik hanya dengan melihat sidebar + rail; tidak perlu membuka log.

---

## 14. Keputusan (disetujui 2026-11-26)

1. **Bahasa copy:** English semua (konsisten dengan docs & CLI); locale menyusul.
2. **Platform:** Windows + Linux di CI; macOS menyusul.
3. **Package manager:** pnpm, lockfile di-commit.
4. **State management React:** Zustand.
5. **Parallel sessions:** tetap P3 — tidak dikerjakan di Phase 0–6.
6. **Logo:** pakai `assets/bugfound-logo.svg` dulu; redesign menyusul.
7. **Jalur CLI/TUI:** TUI bukan bagian dari rencana ini; bisa jadi surface
   terpisah setelah desktop selesai.

---

## 15. Catatan penyelesaian Phase 0

**Yang dibuat:**

- `crates/bugfound-desktop-core/` — `AppState` (satu koneksi `Store`, config
  dalam `Mutex`), `AppConfig` dipindah dari crate egui, DTO serializable,
  `AppError` dengan `kind`, dan `projection.rs` sebagai satu-satunya jalan
  baca ke webview. Semua string yang berasal dari user/tool/brief melewati
  `redact()` di Rust; field struktural (`mode`, `state`, timestamp, versi)
  tidak perlu diredaksi. API key hanya dikirim sebagai
  `apiKeySource: env | literal | missing`.
- `crates/bugfound-app/` — shell Tauri 2, `app_ready` command, `tauri.conf.json`
  dengan CSP, ACL minimal (`core:default` saja; tanpa plugin shell/fs/http),
  dan icon hasil generate dari `assets/bugfound-logo.png`.
- `frontend/` — Vite + React 19 + TypeScript + Zustand, lockfile pnpm,
  design tokens light/dark, layout sidebar / workspace / rail, tes Vitest.
- `.github/workflows/desktop-ui.yml` — frontend (typecheck/test/build),
  desktop-core (Windows+Linux), shell Tauri (Windows).
- Root `Cargo.toml`, `README.md`, `.gitignore`, `deny.toml` diperbarui.

**Verifikasi yang lolos:**

```
pnpm --dir frontend typecheck
pnpm --dir frontend test          # 3 tests
pnpm --dir frontend build
cargo check -p bugfound-app
cargo clippy -p bugfound-desktop-core -p bugfound-app --all-targets -- -D warnings
cargo test --workspace            # semua test existing tetap hijau
```

**Catatan `cargo deny check` (jujur):**

- Config `version = 2` sudah ditolak cargo-deny 0.21+; key dihapus agar config
  bisa di-parse. `Unicode-3.0` ditambahkan ke allowlist (lisensi permissive).
- `multiple-versions` sementara `warn`: Phase 0–3 dua stack GUI (egui + Tauri)
  hidup bareng sehingga ~55 nama crate bertambah duplikat. **Kembalikan ke
  `deny` di Phase 3** saat `bugfound-desktop` dihapus.
- Setelah audit: advisory (10 ID) diberi `ignore` beralasan dengan tanggal
  review 2027-02-26; lisensi permissive tambahan (`MIT-0`, `BSL-1.0`,
  `OFL-1.1`, `Ubuntu-font-1.0`, `Apache-2.0 WITH LLVM-exception`,
  `CDLA-Permissive-2.0`) masuk allowlist; `wildcards` jadi `warn` karena
  dependency path antar crate internal. **`cargo deny check` sekarang exit 0**
  (sisa: warning duplikat & wildcard selama migrasi). Utang nyata tetap ada —
  upgrade `rusqlite`/`chrono` dan penghapusan egui di Phase 3 menjadi syarat
  penghapusan ignore. Tidak ada perubahan perilaku agent.

**Perbaikan audit (2026-11-26):** smoke test runtime menemukan app panic
(`exit 101`) saat `.bugfound/bugfound.db` lokal korup (file 16 MB dengan byte
UTF-8 replacement `EF BF BD` di header). File tersebut **data lama, tidak gue
sentuh**. Sekarang `AppState::load` menangani kegagalan buka DB dengan fallback
`:memory:` + field `storage_error` di `AppSnapshot`, dan frontend menampilkan
banner "Storage degraded". Ada test regresi yang memastikan file rusak tidak
ditimpa. Smoke test ulang: app tetap hidup setelah 6 detik, DB asli tidak berubah.

**Next:** Phase 1 — `session.list` + `session.history`, render riwayat dari
store, theme persistence, empty state. Crate egui sengaja dibiarkan sampai
parity di Phase 3.
