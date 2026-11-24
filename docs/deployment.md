# Runbook Deployment BugFound

Dokumen ini menjelaskan cara menjalankan BugFound sebagai container di lingkungan
self-hosted (single-operator / tim kecil). BugFound bukan sandbox: isolasi OS,
pembatasan egress, dan review approval merupakan bagian dari desain deployment.

Lihat `docs/PRODUCTION_PLAN.md` untuk pemetaan perilaku ke call site. Verifikasi
perilaku saat ini dengan perintah di `docs/PRODUCTION_PLAN.md` §2.

## 1. Prasyarat

- Docker Engine 24+ (atau Podman dengan perintah `docker` di-alias).
- Akses ke endpoint LLM OpenAI-compatible dan kunci API.
- `bugfound.toml` hasil salinan `config/bugfound.example.toml`, dengan `scope.in_scope`
  diisi sesuai rules engagement.
- Host dengan firewall egress yang bisa dikonfigurasi (nftables/iptables).

## 2. Build image

Dari root workspace `bugfound/` (lokasi `Dockerfile` dan `Cargo.toml`):

```sh
cd bugfound
docker build -t bugfound:0.1.0 .
```

Verifikasi cepat tanpa kunci API:

```sh
docker run --rm bugfound:0.1.0 --help
```

Image memakai builder `rust:1.90-slim` dan runtime `debian:bookworm-slim`, berjalan
sebagai user non-root `bugfound`, dengan binary di `/usr/local/bin/bugfound`. Image
tidak menyimpan kunci API.

## 3. Konfigurasi

Siapkan config di host. Nilai `api_key = "env:OPENAI_API_KEY"` berarti BugFound
membaca kunci dari environment variable saat proses start.

```sh
mkdir -p ./runtime
cp config/bugfound.example.toml ./runtime/bugfound.toml
$EDITOR ./runtime/bugfound.toml
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
path = ".bugfound/bugfound.db"

[scope]
engagement = "PROGRAM-2026"
in_scope = ["*.example.com"]
out_of_scope = ["prod-admin.example.com"]
```

## 4. API key via environment variable

Jangan menaruh kunci literal di `bugfound.toml` atau di image. Suntikkan lewat
environment saat `docker run`:

```sh
export OPENAI_API_KEY="$(cat /run/secrets/openai_api_key)"

docker run --rm \
  -e OPENAI_API_KEY \
  -v "$PWD/runtime/bugfound.toml:/work/bugfound.toml:ro" \
  bugfound:0.1.0 run --goal "cek scope" --cwd /work
```

Jika memakai file env, pastikan mode `0600` dan file tidak di-commit:

```sh
docker run --rm --env-file ./runtime/bugfound.env ...
```

> `RUST_LOG` dihormati (mis. `-e RUST_LOG=bugfound_core=debug`). Batasi level
> `debug`/`trace` pada lingkungan yang menghasilkan log sensitif.

## 5. Volume untuk SQLite dan workspace

`storage.path` bersifat relatif terhadap `WORKDIR` (`/work`), sehingga database
default berada di `/work/.bugfound/bugfound.db`. Gunakan **named volume** untuk DB
dan **bind mount** untuk workspace engagement:

```sh
docker volume create bugfound-db
mkdir -p ./engagement
```

Contoh sesi lengkap:

```sh
docker run --rm -it \
  --name bugfound \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network bugfound-egress \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  -e OPENAI_API_KEY \
  -e RUST_LOG=info \
  -v "$PWD/runtime/bugfound.toml:/work/bugfound.toml:ro" \
  -v "bugfound-db:/work/.bugfound" \
  -v "$PWD/engagement:/work/engagement" \
  bugfound:0.1.0 \
  run --goal "enumerate in-scope hosts" --cwd /work/engagement
```

Perintah operasional lain memakai mount yang sama:

```sh
# Tinjau tool call sebelum approve
docker run --rm -it \
  -v "$PWD/runtime/bugfound.toml:/work/bugfound.toml:ro" \
  -v "bugfound-db:/work/.bugfound" \
  -v "$PWD/engagement:/work/engagement" \
  bugfound:0.1.0 approve --session <SESSION_ID> --cwd /work/engagement

docker run --rm \
  -v "$PWD/runtime/bugfound.toml:/work/bugfound.toml:ro" \
  -v "bugfound-db:/work/.bugfound" \
  -v "$PWD/engagement:/work/engagement" \
  bugfound:0.1.0 sessions

docker run --rm \
  -v "$PWD/runtime/bugfound.toml:/work/bugfound.toml:ro" \
  -v "bugfound-db:/work/.bugfound" \
  -v "$PWD/engagement:/work/engagement" \
  bugfound:0.1.0 report --session <SESSION_ID> --output /work/engagement/report.md
```

Catat **SESSION_ID** dari output `run`/`sessions`; semua perintah harus memakai
`--cwd` yang sama dengan sesi awal.

## 6. Egress firewall

Terapkan **default-deny egress** di host sebagai tambahan pembatasan di level
aplikasi. Contoh nftables di bawah menolak proxy environment dan alamat IPv6
6to4/Teredo; sesuaikan alamat LLM API dan target in-scope:

```sh
nft add table inet bugfound_egress
nft add chain inet bugfound_egress output '{ type filter hook output priority 0 ; policy drop ; }'

# Koneksi established dan loopback
nft add rule inet bugfound_egress output ct state established,related accept
nft add rule inet bugfound_egress output oif lo accept

# DNS ke resolver internal saja
nft add rule inet bugfound_egress output udp dport 53 ip daddr <RESOLVER_IP> accept

# Blokir RFC1918, link-local, metadata cloud, multicast (IPv4)
nft add rule inet bugfound_egress output ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 224.0.0.0/4, 240.0.0.0/4 } drop

# Blokir loopback/link-local/ULA/unique IPv6 (termasuk 6to4 2002::/16, Teredo 2001::/32)
nft add rule inet bugfound_egress output ip6 daddr { ::1/128, fc00::/7, fe80::/10, 2002::/16, 2001::/32, ff00::/8 } drop

# Izinkan endpoint LLM dan target in-scope
nft add rule inet bugfound_egress output ip daddr <LLM_API_IP> tcp dport 443 accept
nft add rule inet bugfound_egress output ip daddr <IN_SCOPE_CIDR> tcp dport { 80, 443 } accept

# Kosongkan proxy environment pada container
docker run ... \
  -e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= \
  -e http_proxy= -e https_proxy= -e all_proxy= \
  bugfound:0.1.0 ...
```

Jalankan container di network khusus (`--network bugfound-egress`). Untuk pembatasan
lebih ketat, arahkan semua egress lewat proxy allowlist dan blokir akses langsung ke
internet dari container.

## 7. Backup dan restore SQLite

Database memakai mode WAL. Jangan menyalin file `.db` saja saat proses aktif —
pakai perintah `.backup` (atau `.restore`) dari `sqlite3`.

Hentikan dulu proses BugFound yang memakai volume:

```sh
docker ps --filter name=bugfound
docker stop <CONTAINER>
```

Backup:

```sh
mkdir -p ./backup
docker run --rm \
  -v "bugfound-db:/work/.bugfound" \
  -v "$PWD/backup:/backup" \
  alpine:3.20 \
  sh -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /work/.bugfound/bugfound.db ".backup /backup/bugfound-$(date +%F).db"'
```

Restore:

```sh
docker run --rm \
  -v "bugfound-db:/work/.bugfound" \
  -v "$PWD/backup:/backup:ro" \
  alpine:3.20 \
  sh -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /work/.bugfound/bugfound.db ".restore /backup/bugfound-2026-11-19.db"'
```

Verifikasi integritas dan simpan backup di lokasi terpisah (enkripsi at-rest):

```sh
docker run --rm -v "bugfound-db:/work/.bugfound" alpine:3.20 \
  sh -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /work/.bugfound/bugfound.db "PRAGMA integrity_check;"'
```

## 8. Rotasi kunci API

Kunci dibaca dari environment sekali saat proses start, jadi rotasi memerlukan restart
container.

```sh
# 1. Terbitkan kunci baru di provider LLM, simpan di secret store host
printf '%s' 'sk- BARU' > /run/secrets/openai_api_key
chmod 600 /run/secrets/openai_api_key

# 2. Hentikan container lama
docker stop <CONTAINER> 2>/dev/null || true
docker rm <CONTAINER> 2>/dev/null || true

# 3. Jalankan ulang dengan kunci baru (lihat contoh docker run di bagian 5)
export OPENAI_API_KEY="$(cat /run/secrets/openai_api_key)"

# 4. Uji kunci baru, lalu cabut kunci lama di provider
docker run --rm -e OPENAI_API_KEY \
  -v "$PWD/runtime/bugfound.toml:/work/bugfound.toml:ro" \
  -v "bugfound-db:/work/.bugfound" \
  bugfound:0.1.0 sessions
```

Simpan kunci lama beberapa saat untuk rollback, lalu hapus dari provider dan secret
store. Batasi akses ke Docker socket karena environment terlihat di `docker inspect`.

## 9. Log handling

- BugFound menulis log ke stdout/stderr lewat `tracing`; atur verbositas dengan
  `RUST_LOG`.
- Batasi ukuran log Docker seperti contoh di bagian 5 (`max-size=10m`, `max-file=3`)
  dan kirim ke collector pusat via `--log-driver syslog` atau fluentbit.
- Gunakan `docker logs <CONTAINER>` untuk investigasi. Batasi `debug`/`trace` pada
  lingkungan dengan log sensitif.
- Event audit juga tersimpan di SQLite (`bugfound logs --session <ID>`) dan ikut
  ter-backup bersama DB.

## 10. Batasan operasional

- Jalankan dengan `mode = "ask"` dan tinjau setiap approval. Jangan menambahkan
  `shell_exec` ke `allowed_tools`. Guardrail substring pada `ShellExecTool` bukan
  security boundary; gunakan isolasi OS.
- Isolasi OS: container/VM dengan egress default-deny, user non-root,
  `--cap-drop ALL`, dan `--read-only`.
- Single-node, single-operator. Tidak ada multi-tenancy, clustering, atau web UI.
- Jalankan hanya satu proses `bugfound` per DB.
- Pantau pertumbuhan history dan biaya LLM untuk sesi panjang.
