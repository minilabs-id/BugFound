# Threat Model MiniBug (baseline audit 2026-11-19)

Ruang lingkup: agent bug-bounty self-hosted, single-operator / small team,
berjalan di container/VM dengan egress terbatas, memakai LLM OpenAI-compatible.
ID merujuk ke temuan di `PRODUCTION_PLAN.md` §3. Mitigasi "terencana" adalah
pekerjaan Phase 1–3; belum ada di kode saat baseline ini ditulis. (F-18 tentang
cakupan tes sengaja di luar tabel ini sesuai permintaan cakupan F-01..F-17.)

## Mitigasi lintas (deployment)

Isolasi OS (container non-root, `--cap-drop ALL`, `--read-only`), egress
default-deny di host, `mode = "ask"` dengan review approval, serta kunci API
dari environment bukan dari image. Rincian ada di `deployment.md`.

| ID | Aset | Ancaman | Mitigasi saat ini | Risiko residual | Mitigasi terencana |
| --- | --- | --- | --- | --- | --- |
| F-01 | Integritas host & workspace | `shell_exec` ber-label `risk:"write"`, scope tidak dicek; denylist substring bisa dilewati (`rm  -rf /`, `curl\|sh`), trafik shell tak dihitung budget | Guardrail substring, env scrub, approval `ask` | Tinggi — eksekusi perintah arbitrary di `full_auto` | `risk:"exec"`, scope check cabang tanpa target, hitung network budget, allowlist argv tanpa shell, default-disable (P1-2, P1-3) |
| F-02 | Validasi alamat & jalur egress | DNS pinning kalah saat `HTTP_PROXY`/`HTTPS_PROXY` aktif → DNS rebinding / TOCTOU | `dns_overrides` + blokir IP private di `reqwest` | Tinggi di lingkungan proxy/CI/container | `.no_proxy()` pada kedua client, tolak request saat env proxy hadir, opsi connect langsung ke `SocketAddr` + `Host`/SNI (P1-1) |
| F-03 | Budget & kuota sesi | Counter in-memory reset saat resume/restart → limit efektif unbounded | `AtomicUsize`/`Mutex` di Runner, `for step in 0..max_steps` | Tinggi — exhaust budget & biaya LLM | Tabel `session_budgets`, increment dalam transaksi sama dengan eksekusi tool, step index durable (P2-1) |
| F-04 | Approval & session claim | Dua proses `approve` bisa sama-sama mengklaim & menjalankan aksi; policy tidak dievaluasi ulang setelah park | Status `pending`, lease/claim SELECT lalu UPDATE | Tinggi — desain memang lintas proses | `UPDATE ... WHERE status='pending'` + affected rows, claim conditional + `BEGIN IMMEDIATE`, re-evaluasi policy (P2-2–P2-4) |
| F-05 | Kredensial & data sensitif | Secret bocor via JSON `"api_key"`, `Set-Cookie`, multi-`Bearer`, report/CLI/event/tool output | Redactor prefix-only (`sk-`, `ghp_`, …), sebagian field | Tinggi — kebocoran kunci & data klien | Satu redactor bersama untuk JSON key + sensitive header, terapkan di semua egress (P1-4, P3-2) |
| F-06 | Jaringan internal / metadata cloud | Blokir IP belum mencakup 6to4 `2002::/16`, Teredo `2001::/32`, NAT64 `64:ff9b::/96`, `192.88.99/24`; fallback desimal salah | Blokir IPv4 private + sebagian IPv6 | Sedang–tinggi — pivot ke jaringan internal | Tabel special-purpose IANA / default-deny non-globally-routable (P1-5) |
| F-07 | State machine sesi | Recovery dapat menimpa state `interrupted`/live menjadi `completed` | `transition_state()` guarded ada, tapi runner pakai `set_session_state` | Sedang — state race saat crash/restart | Semua transisi lewat `transition_state` + owner/lease guard (P2-5) |
| F-08 | Batch tool call | `[A, B, C]`: A butuh approval → B/C diberi `deferred` lalu hilang setelah resume | Pesan `deferred` ke model | Sedang — aksi yang disetujui tidak jalan | Persist sisa batch bersama approval, jalankan tail sebelum LLM berikutnya (P2-6) |
| F-09 | Environment secret | `DATABASE_URL`, `MYSQL_PWD`, `REDIS_URL`, `CONNECTION_STRING` lolos dari scrub | Denylist key environment | Sedang — kredensial DB/Redis muncul di output shell | Allowlist env (`PATH`, `HOME`, `TEMP`, `SYSTEMROOT`, locale) (P1-6) |
| F-10 | Filesystem host | `create_dir_all(parent)` sebelum `starts_with`; TOCTOU symlink pada path confinement | Confinement `starts_with` pada workspace | Sedang — direktori di luar workspace tetap dibuat | Validasi path penuh & symlink-safe sebelum mutasi, `O_NOFOLLOW`/`openat2` (P1-7) |
| F-11 | Integritas hasil & kontrol alur | `choices` kosong → sesi `completed` `(no content)`; `finish_reason=length` diabaikan; argumen invalid jadi `{"_raw":...}`; `Retry-After` diabaikan | Retry dengan backoff | Sedang — false positive & kontrol alur hilang | Validasi shape, surface `finish_reason`, error pada argumen invalid, honor `Retry-After` (P3-1) |
| F-12 | Konfigurasi & input user | `base_url` tak divalidasi, alias budget mati, `default_registry(cwd).expect()` panic, clamp vs validasi `max_steps` inkonsisten | `FileConfig::validate()` sebagian | Sedang — DoS/perilaku tak terduga dari input | Validasi boundary, constructor mengembalikan `Result`, wire atau hapus alias budget (P1-8, P2-8) |
| F-13 | Laporan & evidence | Field `goal`/`title`/`asset`/`path` tidak teredaksi; timeline cap 1000; `truncate_event` 4000 char memotong bukti | Redaction parsial di `report()` | Sedang–rendah — kebocoran & hilangnya bukti | Redact semua field report + evidence tidak terpotong, CLI lewat redactor (P3-2) |
| F-14 | Scope / allowlist | `allow="example.com"` menerima `notexample.com` dan `evil.com/?to=example.com`; host IPv6/bracket salah | `ScopeConfig::matches` berbasis substring | Sedang — target out-of-scope lolos | Parse host + exact/suffix + IP/CIDR nyata (P3-3) |
| F-15 | Akurasi registry & docs | `echo` tidak terdaftar di `default_registry` (tes mendaftar manual); `dnsx` hanya alias DNS lookup | Tes mendaftarkan tool secara manual | Rendah — klaim docs menyesatkan | Daftarkan `echo`, rename/dokumentasikan `dnsx` (P3-4) |
| F-16 | Skema & performa SQLite | `ALTER` best-effort tanpa `schema_version`; list query full-scan seiring evidence bertambah | WAL + migrasi ad-hoc | Sedang — upgrade rapuh & degradasi performa | Migrasi forward-only + `schema_version`, index `session_id` (P2-7) |
| F-17 | Reasoning agent | Tool output (HTTP body/stdout/file) masuk sebagai `role:"tool"` apa adanya → prompt injection mengarahkan target/argumen | Policy membatasi aksi lanjutan, approval untuk aksi berisiko | Sedang — model bisa disetir memilih target | Framing "untrusted data", trust label per tool result, re-approval wajib saat target berubah (P1-9) |

## Catatan pemetaan

- F-01, F-02, F-03, F-04, F-05 adalah blocker P0: harus tertutup sebelum
  engagement live (lihat `PRODUCTION_PLAN.md` §3).
- F-06 sampai F-17 masuk Phase 1–3 dengan mitigasi terencana sesuai ID di
  kolom terakhir; sampai selesai, risiko residual di atas berlaku.
- Egress firewall, user non-root, dan `shell_exec` default-deny adalah
  kompensasi deployment yang **wajib** untuk semua ID di atas, terutama F-01,
  F-02, dan F-06.
