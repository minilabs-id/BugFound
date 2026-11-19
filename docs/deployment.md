# Runbook Deployment AgentBug

Dokumen ini menjelaskan cara menjalankan AgentBug sebagai container di lingkungan
produksi (self-hosted, single-operator / small team). AgentBug **bukan sandbox**:
isolasi OS, pembatasan egress, dan review approval adalah bagian dari desain
 deployment. Lihat juga `PRODUCTION_PLAN.md` untuk status audit dan sisa blocker.

## 1. Prasyarat

- Docker Engine 24+ (atau Podman dengan perintah `docker` di-alias).
- Akses ke endpoint LLM OpenAI-compatible dan kunci API yang valid.
- `agentbug.toml` hasil salinan `config/agentbug.example.toml`, sudah diisi
  `scope.in_scope` sesuai rules engagement.
- Host dengan firewall egress yang bisa dikonfigurasi (nftables/iptables).

## 2. Build image

Dari root workspace `agentbug/` (lokasi `Dockerfile` dan `Cargo.toml`):

```sh
cd agentbug
docker build -t agentbug:0.1.0 .
```

Verifikasi cepat — ini harus keluar tanpa perlu kunci API:

```sh
docker run --rm agentbug:0.1.0 --help
```

Image memakai builder `rust:1.90-slim` dan runtime `debian:bookworm-slim`,
berjalan sebagai user non-root `agentbug`, dengan binary di `/usr/local/bin/agentbug`.
Tidak ada secret yang di-*bake* ke dalam image.

## 3. Konfigurasi

Siapkan config di host. Nilai `api_key = "env:OPENAI_API_KEY"` berarti AgentBug
membaca kunci dari environment variable pada saat proses start.

```sh
mkdir -p ./runtime
cp config/agentbug.example.toml ./runtime/agentbug.toml
$EDITOR ./runtime/agentbug.toml
```

Contoh bagian yang relevan:

```toml
[llm]
base_url = "https://llm.internal.example.com/v1"
api_key = "env:OPENAI_API_KEY"
default_model = ""

[agent]
mode = "ask"

[storage]
path = ".agentbug/agentbug.db"

[scope]
engagement = "PROGRAM-2026"
in_scope = ["*.example.com"]
out_of_scope = ["prod-admin.example.com"]
```

## 4. API key via environment variable

Jangan menaruh kunci literal di `agentbug.toml` dan jangan menaruhnya di image.
Suntikkan lewat environment saat `docker run`:

```sh
export OPENAI_API_KEY="$(cat /run/secrets/openai_api_key)"

docker run --rm \
  -e OPENAI_API_KEY \
  -v "$PWD/runtime/agentbug.toml:/work/agentbug.toml:ro" \
  agentbug:0.1.0 run --goal "cek scope" --cwd /work
```

Jika lebih suka file env (pastikan file tersebut punya mode `0600` dan tidak
di-commit):

```sh
docker run --rm --env-file ./runtime/agentbug.env ...
```

> `RUST_LOG` dihormati (mis. `-e RUST_LOG=agentbug_core=debug`). Ingat bahwa
> redaction belum lengkap (temuan F-05): jangan mengaktifkan level `debug`/`trace`
> di lingkungan yang menghasilkan log sensitif sampai P1-4/P3-2 selesai.

## 5. Volume untuk SQLite dan workspace

`storage.path` bersifat relatif terhadap `WORKDIR` (`/work`), jadi database
default berada di `/work/.agentbug/agentbug.db`. Gunakan **named volume** untuk DB
dan **bind mount** untuk workspace engagement:

```sh
docker volume create agentbug-db
mkdir -p ./engagement
```

Contoh menjalankan sesi lengkap:

```sh
docker run --rm -it \
  --name agentbug \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network agentbug-egress \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  -e OPENAI_API_KEY \
  -e RUST_LOG=info \
  -v "$PWD/runtime/agentbug.toml:/work/agentbug.toml:ro" \
  -v "agentbug-db:/work/.agentbug" \
  -v "$PWD/engagement:/work/engagement" \
  agentbug:0.1.0 \
  run --goal "enumerate in-scope hosts" --cwd /work/engagement
```

Perintah operasional lain memakai mount yang sama:

```sh
# Setelah sesi parkir waiting_approval — selalu tinjau tool call sebelum approve
docker run --rm -it \
  -v "$PWD/runtime/agentbug.toml:/work/agentbug.toml:ro" \
  -v "agentbug-db:/work/.agentbug" \
  -v "$PWD/engagement:/work/engagement" \
  agentbug:0.1.0 approve --session <SESSION_ID> --cwd /work/engagement

docker run --rm \
  -v "$PWD/runtime/agentbug.toml:/work/agentbug.toml:ro" \
  -v "agentbug-db:/work/.agentbug" \
  -v "$PWD/engagement:/work/engagement" \
  agentbug:0.1.0 sessions

docker run --rm \
  -v "$PWD/runtime/agentbug.toml:/work/agentbug.toml:ro" \
  -v "agentbug-db:/work/.agentbug" \
  -v "$PWD/engagement:/work/engagement" \
  agentbug:0.1.0 report --session <SESSION_ID> --output /work/engagement/report.md
```

Catat **SESSION_ID** dari output `run`/`sessions`; semua perintah harus memakai
`--cwd` yang sama dengan sesi awal.

## 6. Egress firewall

Pembatasan jaringan di level aplikasi (DNS pinning, blokir IP private) belum
cukup: proxy sistem dapat mengalahkan pinning (F-02), dan IPv6 6to4/Teredo/NAT64
belum diblokir (F-06). Terapkan **default-deny egress** di host.

Contoh nftables — sesuaikan alamat LLM API dan target in-scope:

```sh
nft add table inet agentbug_egress
nft add chain inet agentbug_egress output '{ type filter hook output priority 0 ; policy drop ; }'

# Koneksi yang sudah established dan loopback
nft add rule inet agentbug_egress output ct state established,related accept
nft add rule inet agentbug_egress output oif lo accept

# DNS ke resolver internal saja
nft add rule inet agentbug_egress output udp dport 53 ip daddr <RESOLVER_IP> accept

# Blokir RFC1918, link-local, metadata cloud, multicast (IPv4)
nft add rule inet agentbug_egress output ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 224.0.0.0/4, 240.0.0.0/4 } drop

# Blokir loopback/link-local/ULA/unique IPv6 (termasuk 6to4 2002::/16, Teredo 2001::/32)
nft add rule inet agentbug_egress output ip6 daddr { ::1/128, fc00::/7, fe80::/10, 2002::/16, 2001::/32, ff00::/8 } drop

# Izinkan hanya endpoint LLM dan target yang memang in-scope
nft add rule inet agentbug_egress output ip daddr <LLM_API_IP> tcp dport 443 accept
nft add rule inet agentbug_egress output ip daddr <IN_SCOPE_CIDR> tcp dport { 80, 443 } accept

# Tolak proxy environment: AgentBug belum mengabaikan HTTP_PROXY/HTTPS_PROXY/ALL_PROXY
docker run ... \
  -e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= \
  -e http_proxy= -e https_proxy= -e all_proxy= \
  agentbug:0.1.0 ...
```

Jalankan container di network khusus (`--network agentbug-egress`) dan jangan
memakai `network_mode: host` kecuali aturan firewall di atas sudah aktif. Untuk
produksi yang lebih ketat, minta semua egress lewat proxy allowlist yang
diaudit, dan blokir akses langsung ke internet dari container.

## 7. Backup dan restore SQLite

Database memakai mode WAL. Jangan menyalin file `.db` saja saat proses aktif —
pakai perintah `.backup` (atau `.restore`) dari `sqlite3`.

Hentikan dulu semua proses AgentBug yang memakai volume:

```sh
docker ps --filter name=agentbug
docker stop <CONTAINER>
```

Backup (menulis file dengan timestamp ke host):

```sh
mkdir -p ./backup
docker run --rm \
  -v "agentbug-db:/work/.agentbug" \
  -v "$PWD/backup:/backup" \
  alpine:3.20 \
  sh -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /work/.agentbug/agentbug.db ".backup /backup/agentbug-$(date +%F).db"'
```

Restore (timpa DB dari backup yang dimaksud):

```sh
docker run --rm \
  -v "agentbug-db:/work/.agentbug" \
  -v "$PWD/backup:/backup:ro" \
  alpine:3.20 \
  sh -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /work/.agentbug/agentbug.db ".restore /backup/agentbug-2026-11-19.db"'
```

Verifikasi integritas dan simpan backup di lokasi terpisah (enkripsi at-rest):

```sh
docker run --rm -v "agentbug-db:/work/.agentbug" alpine:3.20 \
  sh -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /work/.agentbug/agentbug.db "PRAGMA integrity_check;"'
```

## 8. Rotasi kunci API

Kunci dibaca dari environment **sekali saat proses start**, jadi rotasi harus
disertai restart container.

```sh
# 1. Terbitkan kunci baru di provider LLM, simpan di secret store host
printf '%s' 'sk- BARU' > /run/secrets/openai_api_key
chmod 600 /run/secrets/openai_api_key

# 2. Hentikan container lama
docker stop <CONTAINER> 2>/dev/null || true
docker rm <CONTAINER> 2>/dev/null || true

# 3. Jalankan ulang dengan kunci baru (lihat contoh docker run di bagian 5)
export OPENAI_API_KEY="$(cat /run/secrets/openai_api_key)"

# 4. Uji kunci baru, lalu cabut/revoke kunci lama di provider
docker run --rm -e OPENAI_API_KEY \
  -v "$PWD/runtime/agentbug.toml:/work/agentbug.toml:ro" \
  -v "agentbug-db:/work/.agentbug" \
  agentbug:0.1.0 sessions
```

Simpan kunci lama beberapa saat untuk rollback, lalu hapus dari provider dan
dari secret store. Jangan pernah menaruh kunci di `docker inspect` (env memang
terlihat di sana — batasi akses ke Docker socket).

## 9. Log handling

- AgentBug menulis log ke stdout/stderr lewat `tracing`; atur verbositas dengan
  `RUST_LOG`.
- Batasi ukuran log Docker seperti contoh di bagian 5 (`max-size=10m`,
  `max-file=3`) dan kirim ke collector pusat via `--log-driver syslog` atau
  fluentbit.
- Gunakan `docker logs <CONTAINER>` untuk investigasi; jangan mengaktifkan
  `debug`/`trace` tanpa kebutuhan jelas karena redaction belum menyeluruh
  (F-05, F-13).
- Event audit juga tersimpan di SQLite (`agentbug logs --session <ID>`) dan ikut
  ter-backup bersama DB.

## 10. Limitasi yang harus dipertahankan di produksi

- **Shell execution harus tetap default-deny / dinonaktifkan.** Pertahankan
  `mode = "ask"` dan tinjau setiap approval. Jangan menambahkan `shell_exec` ke
  `allowed_tools`; setelah Phase 1 (P1-3) terimplementasi, daftarkan secara
  eksplisit di `denied_tools` bila tersedia di config. Guardrail substring yang
  ada sekarang bisa dilewati (F-01) dan bukan security boundary.
- Isolasi OS wajib: container/VM dengan egress default-deny, user non-root,
  `--cap-drop ALL`, dan `--read-only`.
- Single-node, single-operator. Belum ada multi-tenancy, clustering, atau web UI.
- Budget dan approval belum durable/concurrency-safe (F-03, F-04): jalankan
  hanya satu proses `agentbug` per DB sampai Phase 2 selesai.
- Belum ada context compaction untuk sesi sangat panjang (P4-1) — pantau
  pertumbuhan history dan biaya LLM.
