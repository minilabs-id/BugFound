# MiniBug — Audit & Production Readiness Plan

**Status:** final (audit ulang selesai, 2026-11-19).
**Verdict audit:** MiniBug adalah **prototype yang ter-hardening dengan baik**, bukan agent bug-bounty siap produksi. Fitur inti berjalan dan tes hijau, tetapi ada tiga kelas blocker: (1) pinning SSRF kalah saat proxy aktif, (2) boundary shell/scope bisa dilewati dan salah dilabeli, (3) budget & approval tidak durable/concurrency-safe. Klaim "production-ready" saat ini terlalu optimistis.

---

## Status eksekusi (update setelah implementasi)

Phase 0–2 dan sebagian Phase 3 sudah dieksekusi. Ringkasan perubahan:

| Finding | Status | Bukti |
| --- | --- | --- |
| F-01 shell risk/scope/allowlist | done | `shell_exec` → `risk:"exec"`, scope no-target check, allowlist command runner, env allowlist; tes policy & tools |
| F-02 proxy/SSRF | done | `.no_proxy()` di kedua builder; matrix IPv6/IPv4 ditolak |
| F-03 budget durable | done | tabel `session_budgets`, step index durable; tes `budget_survives_resume_with_a_new_runner` |
| F-04 approval atomik | done | `resolve_approval ... WHERE status='pending'`, claim conditional UPDATE, policy re-eval; tes konkuren & scope-berubah |
| F-05 redaction | done | redactor JSON/header/multi-bearer di store, dipakai report/CLI/event/tool output; tes redaction |
| F-06 IP ranges | done | 6to4/Teredo/NAT64 + range IANA tambahan |
| F-07 guarded transition | done | `transition_state_owned` + `finish` di runner |
| F-08 deferred batch | done | `pending_tool_calls` + eksekusi tail saat resume; tes |
| F-09 env allowlist | done | tes secret env tidak bocor |
| F-10 path pre-validation | done | tolak `..`/absolute + validasi ancestor sebelum `create_dir_all`; tes |
| F-11 LLM malformed | done (subagent) | `parse_chat_response`, finish_reason, Retry-After, 8 tes |
| F-12 config/panic | done (subagent) | validasi base_url/budget, canonicalize cwd, `try_default_registry` |
| F-13 report fields | done | goal/title/asset/path/metadata di-redact |
| F-14 allowlist substring | done | host parse + CIDR; tes lookalike & CIDR |
| F-15 echo | done | terdaftar di `default_registry` |
| F-16 schema/index | partial | `schema_version` + index ada; migrasi `ALTER` masih best-effort |
| F-17 tool output framing | done | `<untrusted_tool_output>` + redaction |
| F-18 tests | partial | tes baru untuk mayoritas finding; soak/E2E belum |
| P0 release hygiene | partial | CI, Dockerfile, deny.toml, docs deployment/threat-model dibuat; git init/commit & `cargo deny check` belum dijalankan |

Verifikasi terakhir: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace` (**54 tes**), `cargo build --release --workspace` — semua hijau.

---

## 1. Konteks & asumsi

- Target: agent bug-bounty **self-hosted, single-operator / small team**, berjalan di container/VM dengan egress terbatas, memakai LLM OpenAI-compatible.
- Belum termasuk: multi-tenancy, clustering, web UI. Ini sengaja ditunda.
- "Siap produksi" di sini berarti: bisa dipakai untuk engagement nyata dengan risiko yang diketahui, terukur, dan terdokumentasi — bukan berarti semua fitur Phase 2 selesai.
- Semua temuan di bawah diverifikasi dari source (`crates/*/src/*.rs`), manifest, config, dan hasil build/test, termasuk pengecekan perilaku `reqwest 0.12.28` dari registry lokal.

## 2. Keadaan terkini (terverifikasi)

| Item | Hasil |
| --- | --- |
| Workspace | 6 crate: `core`, `cli`, `llm`, `policy`, `store`, `tools` |
| `cargo fmt --all --check` | lolos |
| `cargo test --workspace` | 31 tes lolos |
| `cargo build --release --workspace` | lolos |
| Config contoh | `config/minibug.example.toml` valid TOML |
| Sudah benar-benar ada | approval/resume, lease & stale recovery, scope in/out, budget in-process, blokir IP private, guardrail shell substring, redaction parsial, report, persistensi finding/asset/artifact |
| Tidak ada / belum benar | git repo, CI, lockfile di-commit, Dockerfile, redaction JSON/header, budget durable, atomic approval, guarded transition, compaction, adapter Phase 2 |

---

## 3. Temuan audit (prioritas)

### P0 — Blocker sebelum engagement live

**F-01 — `shell_exec` dilabeli `risk: "write"`, scope tidak pernah dicek; guardrail bypassable** (High)
- `tools/lib.rs:281` → `risk: "write"`; `policy/lib.rs:240-262` hanya cek scope untuk `network|intrusive|exec` dan nama tool `http|dns|scan|probe`; cabang "tanpa target" tidak memasukkan `exec`.
- Dampak: di `full_auto` dengan scope aktif, LLM bisa menjalankan perintah apa pun tanpa evaluasi scope — termasuk `curl`/`python` ke metadata/internal. Traffic shell juga tidak dihitung `max_network_calls` (`core/lib.rs:293-318`).
- Denylist substring (`tools/lib.rs:296-321`) dilewati oleh `rm  -rf /`, `find . -delete`, `curl x|sh`, `python -c "shutil.rmtree(...)"`, `dd of=/dev/sda`, dll; juga false-positive pada perintah jinak.
- Fix: ubah ke `risk: "exec"`; masukkan `exec` ke cabang no-target scope; hitung sebagai network-capable untuk budget; jangan jadikan denylist security boundary — default-disable shell di produksi atau ganti runner argv allowlist di sandbox OS.

**F-02 — DNS pinning kalah saat sistem memakai proxy** (High)
- `tools/lib.rs:383-393, 436-446`. `reqwest 0.12.28` menyetel `auto_sys_proxy = true` secara default; `dns_overrides` hanya dipasang ke resolver `HttpConnector` lokal. Saat `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` aktif, koneksi pergi ke proxy dan DNS target di-resolve oleh proxy — IP tervalidasi tidak dipakai.
- Dampak: DNS rebinding/TOCTOU tetap possible; klaim "pinning menutup gap" tidak benar di lingkungan corporate/CI/container.
- Fix: `.no_proxy()` di kedua builder + tolak request jika env proxy hadir (atau jadikan proxy pilihan eksplisit yang diaudit). Lebih kuat: connect langsung ke `SocketAddr` tervalidasi dengan `Host`/SNI manual.

**F-03 — Budget & step counter in-memory, reset saat resume/restart** (High)
- `core/lib.rs:172-174` (AtomicUsize/Mutex di Runner), `:700` (`for step in 0..max_steps` mulai dari 0 tiap kali), `:674` → `run_loop` lagi; `cli/main.rs:411-424` membuat Runner baru tiap `approve`.
- Dampak: limit efektif = `max × (approval + restart)`, yaitu unbounded. RPM juga reset.
- Fix: tabel `session_budgets` (steps/tool_calls/network_calls/window) yang di-increment dalam transaksi sama dengan eksekusi tool; step index durable agar resume lanjut, bukan ulang.

**F-04 — Approval bisa dieksekusi dua kali; resolve & claim tidak atomik; policy tidak dievaluasi ulang** (High)
- `store/lib.rs:507-514` (`UPDATE` tanpa predicate `status='pending'` / affected-row check), `:258-291` (`claim_session` SELECT lalu UPDATE); `core/lib.rs:475-535` (state check, baca approval, claim terpisah), `:578-612` (approve menjalankan args tanpa `policy.evaluate` ulang).
- Dampak: dua proses `minibug approve` (desain memang lintas proses) bisa sama-sama mengklaim, resolve, dan menjalankan aksi destruktif. Perubahan scope/config antara park dan resume tidak terlihat.
- Fix: `UPDATE approvals ... WHERE id=? AND status='pending'` + cek affected; claim dengan single conditional `UPDATE ... WHERE owner_id IS NULL OR lease_expires_at < now` + cek affected; bungkus dengan `BEGIN IMMEDIATE`; evaluasi ulang policy sebelum eksekusi.

**F-05 — Redaction tidak lengkap, tidak konsisten, dan duplikatnya dead code** (High / data exposure)
- `store/lib.rs:836-914`; `tools/lib.rs:920-1006` tidak pernah dipanggil.
- Redactor key/value hanya cocok jika `=`/`:` langsung mengikuti key, sehingga **JSON `"api_key": "value"` tidak teredaksi**. Hanya prefix `sk-/ghp_/...` yang tertangkap. `Bearer ` hanya yang pertama.
- `report()` mengeluarkan `goal`, finding `title`, finding `asset`, artifact `path` **tanpa redaction** (`store/lib.rs:770,774,781,783`); CLI `logs/findings/assets/artifacts` mencetak nilai mentah (`cli/main.rs:473-516`); tool output/error dipersisten apa adanya (`core/lib.rs:356-358,615,824-855`); header HTTP `Set-Cookie` dan body dikembalikan mentah (`tools/lib.rs:481-501`).
- Fix: satu implementasi redactor bersama; parse JSON/header dan redact berdasarkan key name + sensitive header; terapkan di semua egress (report, CLI, event, tool output sebelum persist).

### P1 — High/Medium

**F-06 — Range IP diblokir belum lengkap** (Medium–High) — `tools/lib.rs:96-125`: tidak memblokir `2002::/16` (6to4), `2001::/32` (Teredo), `64:ff9b::/96` (NAT64), `192.88.99/24`, dll. Fallback desimal salah untuk bentuk short/leading-zero. Fix: tabel special-purpose IANA / default-deny non-globally-routable.

**F-07 — State machine guarded sudah ada tapi tidak dipakai runner** (Medium) — `store/lib.rs:368-386` vs `core/lib.rs:205-210`. `transition()` memakai `set_session_state` tanpa guard; recovery bisa menimpa state `interrupted` menjadi `completed`. Fix: lewat `transition_state(id, &allowed_from, to)` + cek lease/owner.

**F-08 — Batch tool_call dengan approval kehilangan call setelahnya** (Medium) — `core/lib.rs:757-917`. `[A, B, C]`, A butuh approval → B/C diberi pesan `deferred` lalu tidak pernah dijalankan setelah resume. Fix: persist sisa batch bersama approval; jalankan tail sebelum memanggil LLM lagi.

**F-09 — Scrub env shell memakai denylist key** (Medium) — `tools/lib.rs:322-338`: `DATABASE_URL`, `MYSQL_PWD`, `REDIS_URL`, `CONNECTION_STRING` lolos. Fix: allowlist (`PATH`, `HOME`/`USERPROFILE`, `TEMP`, `SYSTEMROOT`, locale).

**F-10 — FS confinement membuat direktori di luar workspace sebelum validasi** (Medium) — `tools/lib.rs:190-214` (`create_dir_all(parent)` sebelum `starts_with`), dipakai `FsWriteTool`/`SaveArtifactTool`. Path `../outside/dir/file` membuat direktori luar walau write ditolak; ada TOCTOU symlink. Fix: validasi path penuh/symlink-safe sebelum mutasi; `O_NOFOLLOW`/`openat2`.

**F-11 — Respons LLM malformed dianggap jawaban final** (Medium) — `llm/lib.rs:270-310`, `core/lib.rs:744,920-930`. `choices` kosong → `ChatResponse` kosong → session `completed` dengan `(no content)`. `finish_reason=length` diabaikan; argument tool invalid jadi `{"_raw":...}` dan silently diabaikan; `Retry-After` tidak dipakai. Fix: validasi shape, surface finish_reason, error pada argumen invalid, honor Retry-After.

**F-12 — Validasi config & budget wiring incomplete; panic pada input user** (Medium) — `cli/main.rs:154-182,297-337`; `tools/lib.rs:391,792-802`. `base_url` tidak divalidasi, alias budget di `PolicyConfig` tidak pernah diisi (`..Default::default()`), `default_registry(cwd).expect("cwd")` panic untuk path tidak ada, `max_steps` clamp 200 vs validasi 0 tidak konsisten. Fix: validasi boundary, constructor mengembalikan `Result`, wire atau hapus alias budget.

**F-13 — Report redaction miss field & evidence terpotong** (Low–Medium) — `store/lib.rs:770,774,781,783,817` (goal/title/asset/path), timeline cap 1000 event; `core/lib.rs:15-25` `truncate_event` 4000 char bisa memotong bagian penting.

**F-14 — Allowlist legacy memakai substring** (Low–Medium) — `policy/lib.rs:220-237`: `allow="example.com"` menerima `notexample.com` dan `evil.com/?to=example.com`. `norm_host` juga salah untuk IPv6/bracket. Fix: parse host + exact/suffix + IP/CIDR nyata.

**F-15 — `echo` tidak terdaftar di `default_registry`** (Low) — README mengklaim ada; tes mendaftarkan manual sehingga tertutup. Alias `dnsx` hanyalah alias DNS lookup, bukan adapter eksternal. Fix: daftarkan `echo` atau koreksi docs; ganti nama/dokumentasi `dnsx`.

**F-16 — Tidak ada schema versioning; migrasi diabaikan; tidak ada index** (Low) — `store/lib.rs:155-166`. `ALTER` best-effort; list query full-scan seiring evidence bertambah. Fix: migrasi forward-only + `schema_version`, index `session_id`.

**F-17 — Prompt injection via tool output belum dimitigasi** (Low–Medium, desain) — body HTTP/stdout/file masuk ke `role:"tool"` apa adanya (`core/lib.rs:615,824-832`). Policy membatasi aksi lanjutan (bagus), tetapi model bisa disetir memilih target/argumen. Fix: framing "untrusted data", trust label per tool result, mandatory re-approval saat target berubah.

**F-18 — Coverage test kosong untuk kasus kritis** (Low) — tidak ada tes proxy SSRF, 6to4/Teredo, bypass shell, efek samping direktori traversal, budget lintas resume, approval konkuren, batch approval, redaction JSON, CLI redaction, LLM malformed. Tes `shell_exec_scrubs_secret_environment` memakai `set_var` global (racy paralel).

### Phase 2: must-fix vs nice-to-have

**Must-fix sebelum produksi:** concurrency/claim safety (F-04, F-07), durable budgets (F-03), redaction nyata (F-05), **context compaction** — `run_loop` mengirim ulang seluruh history tiap step (`core/lib.rs:706-719`), biaya tumbuh kuadratik dan akhirnya error pada engagement panjang; serta egress enforcement OS-level (README sudah mengakui ini).

**Nice-to-have / product scope:** adapter nuclei/ffuf/nmap/katana/Playwright, asset graph, scheduler prioritas, playbook, clustering, dan klaim docs soal inbox/steer/wake-coalescing yang sebenarnya belum ada — **implementasi atau hapus klaimnya**.

---

## 4. Roadmap

Estimasi dalam hari kerja satu engineer. ID merujuk ke temuan di atas.

### Phase 0 — Release hygiene (2–3 hari)
| ID | Task | Acceptance |
| --- | --- | --- |
| P0-1 | Init git repo minibug, commit baseline, tag `v0.1.0-mvp`, branch `dev` | `git status` bersih, tag ada |
| P0-2 | Hapus `Cargo.lock` dari `.gitignore`, commit lockfile | `git ls-files Cargo.lock` tidak kosong |
| P0-3 | CI: `fmt --check`, `clippy -D warnings`, `test`, `build --release` di Linux + Windows | Badge hijau dua job |
| P0-4 | Dockerfile multi-stage, runtime non-root, image `<100MB` | `docker run --rm minibug --help` sukses |
| P0-5 | Hapus `thiserror` unused, tambah `deny.toml` + `cargo deny check` | Clean |
| P0-6 | Pin toolchain versi konkret (bukan `stable`) | `cargo --version` sesuai pin di CI |

### Phase 1 — Security blockers (7–10 hari)
| ID | Task (F-ID) | Acceptance |
| --- | --- | --- |
| P1-1 | (F-02) `.no_proxy()` di kedua client + tolak request saat env proxy aktif; opsi direct-IP connect | Tes dengan `HTTP_PROXY` tetap blokir target private |
| P1-2 | (F-01) `shell_exec` → `risk:"exec"`; scope check cabang no-target; hitung network budget | Tes policy `full_auto` + scope menolak shell tanpa target |
| P1-3 | (F-01) Ganti denylist shell dengan allowlist profil argv (tanpa shell), default-disable di produksi | Mutasi bypass lama gagal; `echo`, `git status`, `cargo test` lolos |
| P1-4 | (F-05) Satu redactor bersama: JSON key, `Set-Cookie`, `Authorization`, multi-Bearer; terapkan di report/CLI/event/tool output | Tes JSON secret & cookie tidak muncul di mana pun |
| P1-5 | (F-06) Tabel special-purpose IANA / default-deny non-global; blokir 6to4/Teredo/NAT64 | Matrix IPv6/IPv4 lulus |
| P1-6 | (F-09) Env allowlist untuk shell | `DATABASE_URL`/`MYSQL_PWD` tidak muncul di output |
| P1-7 | (F-10) Validasi path symlink-safe sebelum `create_dir_all` | `../outside/dir/file` tidak membuat direktori luar |
| P1-8 | (F-12) `LlmConfig` Debug tidak memuat api_key; constructor `Result` (tidak panic) | Tes unit & CLI cwd invalid keluar error, bukan panic |
| P1-9 | (F-17) Framing tool output sebagai untrusted + re-approval saat target berubah | TesMockLLM melihat delimiter; integrasi lolos |

### Phase 2 — Durability & concurrency (7–10 hari)
| ID | Task (F-ID) | Acceptance |
| --- | --- | --- |
| P2-1 | (F-03) Tabel `session_budgets`; increment di transaksi sama dengan tool execution; step index durable | `approve` + restart tidak mereset budget |
| P2-2 | (F-04) `resolve_approval` conditional + cek affected rows | Dua approve konkuren → satu sukses, satu conflict |
| P2-3 | (F-04) `claim_session` single conditional UPDATE + `BEGIN IMMEDIATE` | Tes race dua proses hanya satu menang |
| P2-4 | (F-04) Evaluasi ulang policy sebelum eksekusi approved tool | Tes: scope diubah setelah park → tool ditolak |
| P2-5 | (F-07) Semua transisi lewat `transition_state` + owner/lease guard | Tes recovery vs live process tidak saling timpa |
| P2-6 | (F-08) Persist sisa batch tool_call; jalankan tail saat resume | Tes `[ask, allow, allow]` → semua tereksekusi |
| P2-7 | (F-16) Migrasi versioned + index `session_id` | Upgrade v0→v1 idempotent; query plan pakai index |
| P2-8 | (F-12) Validasi config penuh + wire/remove alias budget | `doctor` lolos; tidak ada knob mati |

### Phase 3 — Correctness & observability (5–7 hari)
| ID | Task (F-ID) | Acceptance |
| --- | --- | --- |
| P3-1 | (F-11) Validasi shape LLM, `finish_reason`, argumen tool invalid → error, `Retry-After` | Tes response malformed → session failed, bukan completed |
| P3-2 | (F-13) Redact semua field report + evidence tidak terpotong; CLI lewat redactor | Tes report & CLI output bersih |
| P3-3 | (F-14) Scope/allowlist parse host + IP/CIDR nyata, hilangkan substring | Tes lookalike & IPv6 scope |
| P3-4 | (F-15) Daftarkan `echo`; rename/dokumentasi `dnsx` | `default_registry().get("echo")` Some |
| P3-5 | (F-18) Tambah 8 kategori tes di atas; hapus global env mutation | Count tes ≥60, paralel stabil |
| P3-6 | CLI `doctor`/`status`; `RUST_LOG` dihormati; `init` setara config contoh | Perintah keluar 0/1 sesuai kondisi |

### Phase 4 — Capability & scale (12–18 hari)
| ID | Task | Acceptance |
| --- | --- | --- |
| P4-1 | Context compaction/summary saat history melebihi N karakter | Tes: history turun, hasil akhir tidak berubah |
| P4-2 | Adapter `subfinder`, `dnsx`, `katana`, `ffuf` dengan output terstruktur + risk profile | Tiap adapter punya tes mock |
| P4-3 | Adapter gated `nuclei`, `nmap`, Playwright — default-disable via `allowed_tools` | Tes tidak aktif di config default |
| P4-4 | Finding dedupe + status workflow (`open→validated→reported`) | Duplikat tidak menambah baris |
| P4-5 | Asset graph relasional + template report per program | Tes relasi & dua template |

### Phase 5 — Validation & rollout (4–6 hari)
| ID | Task | Acceptance |
| --- | --- | --- |
| P5-1 | E2E: LLM mock server + HTTP mock target, skenario discover→probe→finding→report | Skenario lolos tanpa jaringan nyata |
| P5-2 | Soak 100 sesi + crash/restart recovery | 0 orphan `running`, 0 deadlock |
| P5-3 | Threat model review ulang, `cargo audit`/`deny` clean | Dokumen diperbarui |
| P5-4 | Rilis `v1.0.0` + release note berisi limitasi | Tag & note publik |
| P5-5 | Sesuaikan docs: hapus klaim inbox/steer/wake-coalescing bila tidak diimplementasi | README/architecture tidak berlebihan klaim |

---

## 5. Exit criteria global

MiniBug baru disebut "siap produksi" jika:

- Phase 0–3 dan Phase 5 selesai. Phase 4 boleh sebagian dengan flag eksplisit, **kecuali P4-1 (compaction) wajib**.
- `cargo deny check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `cargo build --release` hijau di CI Linux + Windows.
- Tidak ada temuan **P0** terbuka; semua P1 punya mitigation terdokumentasi.
- Ada runbook deployment (container, env, egress firewall, backup DB, rotasi kunci) dan bukti soak test.
- README menyatakan dengan jelas keterbatasan: single-node, butuh isolasi OS, shell default-disable.

## 6. Estimasi ringkas

| Phase | Hari | Prioritas |
| --- | --- | --- |
| 0 Release hygiene | 2–3 | Tinggi |
| 1 Security | 7–10 | **Kritis** |
| 2 Durability | 7–10 | **Kritis** |
| 3 Correctness/observability | 5–7 | Tinggi |
| 4 Capability | 12–18 | Sedang |
| 5 Validation | 4–6 | Tinggi |
| **Total** | **37–54 hari kerja** | — |

Jika hanya mengejar "aman untuk engagement internal terbatas": Phase 0 + 1 + 2 + P3-1/P3-2 + Phase 5 ≈ **25–32 hari kerja**.

## 7. Out of scope untuk v1

Multi-tenancy, clustering/distributed claim, web UI, billing, plugin marketplace,
auto-submit laporan ke platform pihak ketiga, dan implementasi penuh semantics
inbox/steer yang masih tertulis di `docs/architecture.md:14-16`.
