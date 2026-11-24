# Model ancaman BugFound

Dokumen ini memetakan ancaman ke mekanisme di kode. Ini bukan penilaian risiko
final dan bukan pernyataan bahwa ancaman telah hilang. Rujukan H/B/F merujuk ke
dokumen perencanaan; bukti call site ada di `PRODUCTION_PLAN.md` §3.

## Lingkungan yang diasumsikan

Satu operator atau tim kecil, satu proses, host/VM/container terisolasi dengan
egress dibatasi, endpoint LLM OpenAI-compatible. Kunci API dibaca dari
environment. Isolasi OS dan firewall egress berada di luar kode ini.

## Ancaman dan mekanisme di kode

| ID | Aset | Ancaman | Mekanisme di kode | Rujukan |
| --- | --- | --- | --- | --- |
| F-01 | Host & workspace | `shell_exec` sebagai RCE atau akses di luar cwd | allowlist `echo`/`whoami`, argv tanpa shell, env dibatasi, path divalidasi terhadap cwd, goal lock SHA-256 | TC-1, TC-7, B9, B10, B12 |
| F-02 | Egress | DNS rebinding, SSRF, alamat private/loopback | DNS pin, `no_proxy` default, blok IPv4/IPv6 termasuk 6to4/Teredo/NAT64, proxy harus loopback, parser host numerik ketat | H-02, B6–B8 |
| F-03 | Budget | counter hilang saat resume | tabel `session_budgets`, offset turunan, flag stop dihapus saat resume | H-01, B2, B13 |
| F-04 | Approval & klaim | dua proses menyetujui aksi yang sama | `park_with_approval` transaksional, `resolve_approval` berpredikat pending + expiry, klaim/lease dengan owner | H-01, H-10, B3, B11 |
| F-05 | Kredensial & data | secret di JSON, header, bearer, laporan | `redact` di jalur laporan/CLI/event; bukti berupa bytes dari tool | H-01, B1 |
| F-06 | IPv6 | alamat privat lewat 6to4/Teredo/NAT64 | `is_blocked_ip` memblokir ketiganya | H-12 |
| F-07 | State machine | recovery menimpa state | `transition_state_owned` dengan owner/lease | H-03 |
| F-08 | Batch tool call | call berikutnya hilang setelah approval | tail dipersist bersama approval | H-03 |
| F-09 | Environment secret | variabel sensitif ikut terkirim | env allowlist di `ExternalCommandTool` | H-12 |
| F-10 | Filesystem | traversal dan symlink | validasi lexical + canonicalisasi ancestor | H-12 |
| F-11 | Respons LLM | `choices` kosong dianggap selesai | validasi bentuk respons dan `finish_reason` | H-09 |
| F-12 | Konfigurasi | `base_url` tak divalidasi, panic pada cwd | validasi boundary dan constructor `Result` | H-11 |
| F-13 | Laporan | field tak teredaksi, bukti terpotong | `redact` di field laporan, hash SHA-256 per finding | H-06 |
| F-14 | Scope | allowlist substring menerima lookalike | parser host/CIDR di policy | H-02 |
| F-15 | Registry | nama tool tidak sesuai docs | registry deterministik | H-12, H-13 |
| F-16 | SQLite | ALTER tanpa versi, query full-scan | `schema_version` dan index | H-10 |
| F-17 | Output tool | teks tool dianggap instruksi | framing `<untrusted_tool_output>`, goal lock, re-approval saat target berubah | H-02, H-04 |

## Ancaman pada alur engagement

| ID | Ancaman | Mekanisme | Catatan |
| --- | --- | --- | --- |
| F-18 | ROE extraction poisoning | snapshot brief, `roe_classify`, scope fail-closed, provenance hanya advisory | baris yang tidak dipetakan menghentikan run |
| F-19 | Halaman program / honeypot | scope gate, verifier bytes, laporan lokal | budget bisa terpakai tanpa temuan |
| F-20 | Finding self-graded LLM | verifier membaca `get_capture`, canary dari tool, `validate_poc` bukan gerbang | review operator tetap bagian alur |
| F-21 | Kredensial lintas target | kunci dari environment, redactor, cooldown per target | rotasi kunci di luar kode ini |
| F-22 | Prompt injection dari halaman program | goal lock, untrusted framing, hash chain, approval | tidak ada jalur kirim otomatis |

## Perubahan yang berkaitan dengan scope

- Prefix relatif (`providers.`) di-anchor ke apex dari brief sebelum scope
  intersection. Sebelum perubahan ini target nyata tidak pernah cocok.
- Aturan out-of-scope berpath (`host/help/*`) diterapkan pada path yang
  disebut, bukan dibuang dan bukan memblokir host secara keseluruhan.
- `validate_finding` hanya memeriksa kontrak field secara lokal; ia tidak
  membaca store. Pemeriksaan bukti dilakukan `verify_findings`.

## Catatan pemetaan

Tabel di atas mencatat mekanisme yang ada di kode, bukan jaminan bahwa ancaman
tidak mungkin terjadi. Isolasi host, egress default-deny dan shell
default-deny adalah bagian dari deployment yang berada di luar kode ini.
Tidak ada angka efektivitas yang dicatat di repositori ini.
