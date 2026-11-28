//! Bounded HTTP/HTTPS intercepting proxy. Each request is forwarded or dropped
//! by a scope gate. With `--require-ack`, a request is forwarded only after an
//! explicit `y` on stdin; other input drops the request. No LLM or auto-approval
//! path is present.
//!
//! HTTPS uses operator-controlled MITM: `CONNECT` goes through the same scope
//! check as plain HTTP, then a locally generated CA signs a leaf certificate for
//! the requested host. The client has to trust that CA; this proxy does not
//! modify client trust stores.

#[cfg(windows)]
mod win_acl;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// One stalled peer is bounded; it must never block other connections (E26).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap the buffered upstream response body as well as the request body (E26).
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const CA_CN: &str = "BugFound Proxy CA";

#[derive(Parser, Debug)]
#[command(name = "bugfound-proxy")]
struct Args {
    /// Loopback listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
    /// In-scope host entries (exact host, .suffix, *.suffix or IPv4 CIDR).
    #[arg(long)]
    scope_in: Vec<String>,
    /// Out-of-scope host entries.
    #[arg(long)]
    scope_out: Vec<String>,
    /// Require an explicit operator `y` on stdin before forwarding each request.
    #[arg(long)]
    require_ack: bool,
    /// Hard cap on total processed requests, including CONNECT and TLS requests.
    #[arg(long, default_value_t = 100)]
    max_requests: usize,
    /// JSONL history output.
    #[arg(long, default_value = "proxy-history.jsonl")]
    out: PathBuf,
    /// Directory holding the locally generated CA certificate and private key.
    #[arg(long, default_value = "./bugfound-proxy-ca")]
    ca_dir: PathBuf,
    /// Optional second proxy listener for CONNECT/TLS traffic; omit to use the main listener.
    #[arg(long, num_args = 0..=1, default_missing_value = "127.0.0.1:8443")]
    tls_listen: Option<String>,
    /// Disable HTTPS interception; CONNECT is answered with 403 and reason `mitm_disabled`.
    #[arg(long)]
    no_mitm: bool,
}

/// Locally generated CA used only to sign per-host leaf certificates.
struct Ca {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Ca").field("cn", &CA_CN).finish()
    }
}

struct Proxy {
    args: Args,
    history: Mutex<std::fs::File>,
    ca: Option<Arc<Ca>>,
    acceptors: std::sync::Mutex<HashMap<String, Arc<TlsAcceptor>>>,
    processed: AtomicUsize,
    /// Per-connection budget; also applied to the reqwest client and body reads.
    request_timeout: Duration,
    /// Hard cap on buffered upstream response bytes.
    max_response_bytes: usize,
}

impl Proxy {
    /// Reserve one slot in the global request budget, returning its index.
    fn reserve(&self) -> Option<usize> {
        self.processed
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (current < self.args.max_requests).then_some(current + 1)
            })
            .ok()
    }

    async fn record(&self, record: Value) {
        let mut file = self.history.lock().await;
        let _ = writeln!(file, "{record}");
        let _ = file.flush();
    }

    /// Generate and cache a leaf certificate/ TLS acceptor for one host.
    fn acceptor_for(&self, host: &str) -> Result<Arc<TlsAcceptor>> {
        let host = host.to_ascii_lowercase();
        if let Some(acceptor) = self
            .acceptors
            .lock()
            .map_err(|_| anyhow!("certificate cache is unavailable"))?
            .get(&host)
        {
            return Ok(Arc::clone(acceptor));
        }
        let ca = self.ca.as_ref().context("MITM is disabled")?;
        let key = rcgen::KeyPair::generate().context("generate leaf key")?;
        let mut params = rcgen::CertificateParams::new(vec![host.clone()])?;
        params.is_ca = rcgen::IsCa::NoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params
            .signed_by(&key, &ca.issuer)
            .context("sign leaf certificate with local CA")?;
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![certificate.der().clone()], key_der)?;
        let acceptor = Arc::new(TlsAcceptor::from(Arc::new(config)));
        self.acceptors
            .lock()
            .map_err(|_| anyhow!("certificate cache is unavailable"))?
            .insert(host, Arc::clone(&acceptor));
        Ok(acceptor)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.scope_in.is_empty() && args.scope_out.is_empty() {
        return Err(anyhow!(
            "at least one --scope-in or --scope-out entry is required (fail-closed)"
        ));
    }
    let history_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.out)
        .with_context(|| format!("open {}", args.out.display()))?;
    let ca = if args.no_mitm {
        None
    } else {
        Some(Arc::new(load_or_create_ca(&args.ca_dir)?))
    };
    let proxy = Arc::new(Proxy {
        args,
        history: Mutex::new(history_file),
        ca,
        acceptors: std::sync::Mutex::new(HashMap::new()),
        processed: AtomicUsize::new(0),
        request_timeout: REQUEST_TIMEOUT,
        max_response_bytes: MAX_RESPONSE_BYTES,
    });
    let listener = TcpListener::bind(&proxy.args.listen)
        .await
        .with_context(|| format!("bind {}", proxy.args.listen))?;
    // E26: each accepted connection runs in its own task. A stalled peer cannot
    // block the accept loop (or any other connection); finished tasks are reaped.
    let mut connections = JoinSet::new();
    let mut tls_task = None;
    if let Some(address) = &proxy.args.tls_listen {
        let tls_listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("bind --tls-listen {address}"))?;
        let tls_proxy = Arc::clone(&proxy);
        tls_task = Some(tokio::spawn(async move {
            let mut tls_connections = JoinSet::new();
            while tls_proxy.processed.load(Ordering::Relaxed) < tls_proxy.args.max_requests {
                let Ok((stream, _peer)) = tls_listener.accept().await else {
                    break;
                };
                let connection_proxy = Arc::clone(&tls_proxy);
                tls_connections.spawn(async move {
                    handle_plain(stream, connection_proxy).await;
                });
                while tls_connections.try_join_next().is_some() {}
            }
            if timeout(REQUEST_TIMEOUT, async {
                while let Some(result) = tls_connections.join_next().await {
                    let _ = result;
                }
            })
            .await
            .is_err()
            {
                tls_connections.abort_all();
            }
        }));
    }
    eprintln!(
        "bugfound-proxy listening on {} (require_ack={}, max_requests={}, mitm={}, ca_dir={})",
        proxy.args.listen,
        proxy.args.require_ack,
        proxy.args.max_requests,
        !proxy.args.no_mitm,
        proxy.args.ca_dir.display()
    );

    while proxy.processed.load(Ordering::Relaxed) < proxy.args.max_requests {
        let (stream, _peer) = listener.accept().await?;
        let connection_proxy = Arc::clone(&proxy);
        connections.spawn(async move {
            handle_plain(stream, connection_proxy).await;
        });
        while connections.try_join_next().is_some() {}
    }
    if timeout(REQUEST_TIMEOUT, async {
        while let Some(result) = connections.join_next().await {
            let _ = result;
        }
    })
    .await
    .is_err()
    {
        connections.abort_all();
    }

    if let Some(task) = tls_task {
        task.abort();
    }
    eprintln!("wrote history to {}", proxy.args.out.display());
    Ok(())
}

/// Create or load the local CA. The private key is never printed or logged.
fn load_or_create_ca(dir: &Path) -> Result<Ca> {
    let cert_path = dir.join("ca-cert.pem");
    let key_path = dir.join("ca-key.pem");
    create_ca_dir(dir)?;
    // Defense in depth on Windows (the explicit Win32 DACL is set in
    // `create_ca_dir` / `write_secret` and verified in `verify_ca_key`).
    ensure_private_ca_location(dir)?;
    let cert_exists = cert_path.is_file();
    let key_exists = key_path.is_file();
    if cert_exists != key_exists {
        return Err(anyhow!(
            "incomplete CA in {}; remove that directory and retry",
            dir.display()
        ));
    }
    if cert_exists {
        // Refuse a key that is group/world readable or reachable through a
        // symlink/junction outside the CA directory (E25).
        verify_ca_key(&key_path, dir)?;
        let cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("read {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("read {}", key_path.display()))?;
        let key = rcgen::KeyPair::from_pem(&key_pem).context("parse CA private key")?;
        let issuer =
            rcgen::Issuer::from_ca_cert_pem(&cert_pem, key).context("parse CA certificate")?;
        return Ok(Ca { issuer });
    }

    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, CA_CN);
    let key = rcgen::KeyPair::generate().context("generate CA key")?;
    let certificate = params
        .self_signed(&key)
        .context("generate CA certificate")?;
    write_secret(&cert_path, &certificate.pem())?;
    write_secret(&key_path, &key.serialize_pem())?;
    verify_ca_key(&key_path, dir)?;
    eprintln!("Generated local MITM CA: {}", cert_path.display());
    eprintln!(
        "TRUST REQUIRED: install {} as a trusted CA in the client/OS trust store before HTTPS interception is accepted. The private key is at {} and must stay secret.",
        cert_path.display(),
        key_path.display()
    );
    Ok(Ca {
        issuer: rcgen::Issuer::new(params, key),
    })
}

fn create_ca_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(dir)?;
    }
    #[cfg(windows)]
    {
        std::fs::create_dir_all(dir)?;
        // Lock the directory itself with an explicit current-user-only DACL.
        // The ACE is non-inheritable, so the key file gets its own DACL in
        // `write_secret`. An API failure is only warned about here: the
        // per-user location check still applies, and a known broad ACL is a
        // hard error in `verify_ca_key`.
        match win_acl::current_user_sid() {
            Ok(sid) => {
                if let Err(error) = win_acl::set_current_user_only_dacl(dir, &sid) {
                    warn_acl_failure(dir, &error);
                }
            }
            Err(error) => warn_acl_failure(dir, &error),
        }
    }
    #[cfg(not(any(unix, windows)))]
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// A Win32 ACL call failed, so the DACL could not be confirmed. Continue only
/// because `ensure_private_ca_location` still gates the CA location; never weaken
/// an ACL and never silently accept a known broad DACL (a hard error elsewhere).
#[cfg(windows)]
fn warn_acl_failure(path: &Path, error: &anyhow::Error) {
    eprintln!(
        "WARNING: could not enforce a current-user-only DACL on {}: {:#}. Continuing only because the per-user CA location is verified; a known broad DACL is still a hard error.",
        path.display(),
        error
    );
}

/// Defense in depth: the Win32 DACL is authoritative, but only accept a CA
/// directory that also resolves inside the user's own profile/local app data.
/// Symlinks/junctions are resolved here. If an ACL API is unavailable (for
/// example on a virtual filesystem), this location check is the fallback.
#[cfg(windows)]
fn ensure_private_ca_location(dir: &Path) -> Result<()> {
    let resolved =
        std::fs::canonicalize(dir).with_context(|| format!("resolve {}", dir.display()))?;
    let user_roots = ["LOCALAPPDATA", "USERPROFILE"]
        .iter()
        .filter_map(std::env::var_os)
        .filter_map(|value| std::fs::canonicalize(PathBuf::from(value)).ok());
    if !user_roots
        .into_iter()
        .any(|root| resolved.starts_with(&root))
    {
        return Err(anyhow!(
            "refusing to store the MITM CA key in {}: Windows requires a per-user directory (e.g. %LOCALAPPDATA%\\bugfound-proxy\\ca); an explicit current-user-only DACL could not be applied here, so the per-user location is the remaining safeguard",
            resolved.display()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn ensure_private_ca_location(_dir: &Path) -> Result<()> {
    Ok(())
}

/// A loaded/generated key must be current-user-only and must not be a symlink
/// out of the CA directory. On Windows the explicit Win32 DACL is inspected
/// here; `ensure_private_ca_location` is an additional location safeguard.
fn verify_ca_key(path: &Path, dir: &Path) -> Result<()> {
    let canonical_key =
        std::fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()))?;
    let canonical_dir =
        std::fs::canonicalize(dir).with_context(|| format!("resolve {}", dir.display()))?;
    if canonical_key.parent() != Some(canonical_dir.as_path()) {
        return Err(anyhow!(
            "CA private key escapes its directory via a symlink/junction"
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&canonical_key)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "CA private key {} has overly broad permissions; refusing to load",
                path.display()
            ));
        }
    }
    #[cfg(windows)]
    {
        // A known broad DACL is a hard error. Only an API failure is downgraded
        // to a warning, and only because the caller already verified the
        // per-user CA location with `ensure_private_ca_location`.
        match win_acl::current_user_sid() {
            Ok(sid) => match win_acl::verify_current_user_only_dacl(&canonical_key, &sid) {
                Ok(win_acl::DaclStatus::Secure) => {}
                Ok(win_acl::DaclStatus::Weak(reason)) => {
                    return Err(anyhow!(
                        "CA private key {} has an unsafe DACL: {reason}; refusing to load",
                        path.display()
                    ));
                }
                Ok(win_acl::DaclStatus::Unavailable(reason)) => {
                    eprintln!(
                        "WARNING: could not verify the DACL on {}: {reason}; relying on the verified per-user CA location",
                        path.display()
                    );
                }
                Err(error) => return Err(error.context("verify CA key DACL")),
            },
            Err(error) => {
                eprintln!(
                    "WARNING: could not read the current user SID: {error:#}; relying on the verified per-user CA location"
                );
            }
        }
    }
    Ok(())
}

fn write_secret(path: &Path, contents: &str) -> Result<()> {
    // create_new: never replace a pre-existing key whose ACL we did not create.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(windows)]
    {
        // The DACL is the security boundary; the read-only bit is only extra
        // defense in depth. create_new ensures we never take over a key whose
        // ACL was set by someone else.
        match win_acl::current_user_sid() {
            Ok(sid) => {
                if let Err(error) = win_acl::set_current_user_only_dacl(path, &sid) {
                    warn_acl_failure(path, &error);
                }
            }
            Err(error) => warn_acl_failure(path, &error),
        }
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

async fn handle_plain(stream: TcpStream, proxy: Arc<Proxy>) {
    let mut stream = stream;
    let Some(index) = proxy.reserve() else {
        let _ = write_response(&mut stream, "403 Forbidden", "max requests reached").await;
        return;
    };
    // E26: a peer that never finishes its request is closed after the budget.
    let read = timeout(proxy.request_timeout, read_request(&mut stream))
        .await
        .unwrap_or_else(|_| Err(anyhow!("request timed out")));
    let (header, raw) = match read {
        Ok(value) => value,
        Err(error) => {
            proxy
                .record(json!({
                    "index": index,
                    "scheme": "http",
                    "decision": "error",
                    "scope_allowed": false,
                    "reason": error.to_string()
                }))
                .await;
            let _ = stream.shutdown().await;
            return;
        }
    };
    let (method, target) = request_line_parts(&header);
    if method == "CONNECT" {
        handle_connect(stream, &target, &proxy, index).await;
        return;
    }
    let input = RequestInput {
        scheme: "http",
        tunnel_host: None,
        ack_done: false,
        index,
    };
    let record = process_request(&mut stream, &header, &raw, &input, &proxy).await;
    proxy.record(record).await;
    let _ = stream.shutdown().await;
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(String, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(MAX_HEADER_BYTES);
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(anyhow!("empty request"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(anyhow!("request header too large"));
        }
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let content_length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(anyhow!("request body too large"));
    }
    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    Ok((header, buffer))
}

fn request_line_parts(header: &str) -> (String, String) {
    let mut parts = header.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("").to_string();
    (method, target)
}

fn parse_connect_authority(target: &str) -> Result<(String, u16)> {
    if target.contains('@') {
        return Err(anyhow!("CONNECT authority must not contain userinfo"));
    }
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .context("invalid IPv6 CONNECT authority")?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().context("invalid CONNECT port")?,
            None => 443,
        };
        (host.to_string(), port)
    } else {
        match target.rsplit_once(':') {
            Some((host, port)) => (
                host.to_string(),
                port.parse().context("invalid CONNECT port")?,
            ),
            None => (target.to_string(), 443),
        }
    };
    if host.is_empty() {
        return Err(anyhow!("empty CONNECT host"));
    }
    Ok((host, port))
}

fn https_url(host: &str, target: &str) -> Result<url::Url> {
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let path = if target.starts_with('/') {
        target.to_string()
    } else {
        format!("/{target}")
    };
    url::Url::parse(&format!("https://{authority}{path}")).context("invalid HTTPS request target")
}

async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: &str,
    message: &str,
) -> Result<()> {
    let body = format!("{{\"error\":\"{message}\"}}");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

async fn write_forbidden<S: AsyncWrite + Unpin>(stream: &mut S, reason: &str) -> Result<()> {
    let message = match reason {
        "out_of_scope" => "out of scope",
        "operator_declined" => "operator declined",
        "mitm_disabled" => "MITM disabled",
        "max_requests_reached" => "max requests reached",
        "connect_host_mismatch" => "CONNECT host mismatch",
        "unsupported_connect_port" => "only CONNECT port 443 is supported",
        _ => reason,
    };
    write_response(stream, "403 Forbidden", message).await
}

async fn operator_approve(prompt: &str) -> bool {
    println!("{prompt}");
    let answer = tokio::task::spawn_blocking(|| {
        let mut answer = String::new();
        match std::io::stdin().read_line(&mut answer) {
            Ok(_) => answer,
            Err(_) => String::new(),
        }
    })
    .await;
    match answer {
        Ok(answer) => answer.trim().eq_ignore_ascii_case("y"),
        Err(_) => false,
    }
}

/// The gate and forwarding logic shared by plain TCP and intercepted TLS streams.
struct RequestInput<'a> {
    scheme: &'a str,
    tunnel_host: Option<&'a str>,
    ack_done: bool,
    index: usize,
}

async fn process_request<S>(
    stream: &mut S,
    header: &str,
    raw: &[u8],
    input: &RequestInput<'_>,
    proxy: &Arc<Proxy>,
) -> Value
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut record = json!({
        "index": input.index,
        "scheme": input.scheme,
        "decision": "error",
        "scope_allowed": false,
        "host": ""
    });
    if let Err(error) = process_request_inner(stream, header, raw, input, proxy, &mut record).await
    {
        record["decision"] = json!("error");
        record["reason"] = json!(error.to_string());
    }
    record
}

async fn process_request_inner<S>(
    stream: &mut S,
    header: &str,
    raw: &[u8],
    input: &RequestInput<'_>,
    proxy: &Arc<Proxy>,
    record: &mut Value,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (method, target) = request_line_parts(header);
    let parsed = if input.scheme == "https" {
        if target.starts_with('/') {
            https_url(input.tunnel_host.context("missing tunnel host")?, &target)?
        } else {
            let parsed =
                url::Url::parse(&target).context("request target is not an absolute URL")?;
            if parsed.scheme() != "https" {
                return Err(anyhow!("unsupported scheme inside TLS tunnel"));
            }
            if let Some(host) = input.tunnel_host {
                if parsed.host_str().unwrap_or_default() != host {
                    write_forbidden(stream, "connect_host_mismatch").await?;
                    record["decision"] = json!("drop");
                    record["reason"] = json!("connect_host_mismatch");
                    return Ok(());
                }
            }
            parsed
        }
    } else {
        let parsed = url::Url::parse(&target).context("request target is not an absolute URL")?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(anyhow!("unsupported scheme"));
        }
        parsed
    };
    let host = parsed.host_str().unwrap_or_default().to_string();
    // Pass the full URL: the matcher reduces it to host + path so a
    // path-scoped exclusion is enforced on the actual request path (E27/B1).
    let allowed = bugfound_tools::scope_target_allowed(
        parsed.as_str(),
        &proxy.args.scope_in,
        &proxy.args.scope_out,
    );
    record["method"] = json!(method);
    record["url"] = json!(bugfound_tools::redact(&target));
    record["host"] = json!(host);
    record["scope_allowed"] = json!(allowed);

    if !allowed {
        write_forbidden(stream, "out_of_scope").await?;
        record["decision"] = json!("drop");
        record["reason"] = json!("out_of_scope");
        return Ok(());
    }

    if proxy.args.require_ack && !input.ack_done {
        let prompt = format!(
            "INTERCEPT {} {} -> approve? [y/N]",
            bugfound_tools::redact(&method),
            bugfound_tools::redact(&target)
        );
        if !operator_approve(&prompt).await {
            write_forbidden(stream, "operator_declined").await?;
            record["decision"] = json!("drop");
            record["reason"] = json!("operator_declined");
            return Ok(());
        }
    }

    let body_start = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap_or(raw.len());
    let request_body = raw[body_start..].to_vec();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        // Hard upper bound for the whole upstream exchange, including body.
        .timeout(proxy.request_timeout)
        // This proxy must not chain to an ambient HTTP proxy from the env.
        .no_proxy()
        .build()?;
    let mut request = client.request(
        method.parse().context("unsupported HTTP method")?,
        parsed.clone(),
    );
    for line in header.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "host" | "connection" | "proxy-connection" | "content-length" | "transfer-encoding"
            ) {
                continue;
            }
            request = request.header(name.trim(), value.trim());
        }
    }
    if !request_body.is_empty() {
        request = request.body(request_body);
    }
    let response = timeout(proxy.request_timeout, request.send())
        .await
        .map_err(|_| anyhow!("upstream request timed out"))??;
    let status = response.status().as_u16();
    let response_headers = response.headers().clone();
    // `response.bytes()` buffers unbounded memory. Read in bounded chunks
    // instead, with the same 30s budget on every chunk (E26).
    let mut response = response;
    let response_body = read_bounded_response(
        &mut response,
        proxy.request_timeout,
        proxy.max_response_bytes,
    )
    .await?;
    record["decision"] = json!("forward");
    record["status"] = json!(status);
    record["response_bytes"] = json!(response_body.len());

    let mut out = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in response_headers.iter() {
        if matches!(
            name.as_str(),
            "connection" | "transfer-encoding" | "content-length"
        ) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            out.push_str(&format!("{}: {}\r\n", name, value));
        }
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    ));
    stream.write_all(out.as_bytes()).await?;
    stream.write_all(&response_body).await?;
    Ok(())
}

/// Bounded replacement for `response.bytes()`: never buffer more than `cap`
/// bytes and never wait more than `budget` for a single chunk.
async fn read_bounded_response(
    response: &mut reqwest::Response,
    budget: Duration,
    cap: usize,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let chunk = timeout(budget, response.chunk())
            .await
            .map_err(|_| anyhow!("upstream response timed out"))?
            .context("read upstream response")?;
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(anyhow!("upstream response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn handle_connect<S>(mut stream: S, authority: &str, proxy: &Arc<Proxy>, index: usize)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut record = json!({
        "index": index,
        "scheme": "https",
        "method": "CONNECT",
        "url": bugfound_tools::redact(authority),
        "host": "",
        "scope_allowed": false,
        "decision": "drop"
    });
    let (host, port) = match parse_connect_authority(authority) {
        Ok(value) => value,
        Err(error) => {
            record["decision"] = json!("error");
            record["reason"] = json!(error.to_string());
            let _ =
                write_response(&mut stream, "400 Bad Request", "invalid CONNECT authority").await;
            proxy.record(record).await;
            return;
        }
    };
    record["host"] = json!(host);

    let denial = if port != 443 {
        Some("unsupported_connect_port")
    } else if proxy.args.no_mitm {
        Some("mitm_disabled")
    } else if !bugfound_tools::scope_target_allowed(
        // CONNECT is host-only: the client has not sent an inner path yet.
        // Synthesize `https://{authority}/` so the matcher sees the real
        // authority and the root path, keeping host rules active while
        // path-scoped rules are not applied to a path the client never sent
        // (E27/B1). The inner HTTP request is gated again with its full URL.
        &format!("https://{authority}/"),
        &proxy.args.scope_in,
        &proxy.args.scope_out,
    ) {
        Some("out_of_scope")
    } else {
        None
    };
    if let Some(reason) = denial {
        record["reason"] = json!(reason);
        let _ = write_forbidden(&mut stream, reason).await;
        proxy.record(record).await;
        return;
    }
    record["scope_allowed"] = json!(true);

    if proxy.args.require_ack
        && !operator_approve(&format!("INTERCEPT CONNECT {host} -> approve? [y/N]")).await
    {
        record["reason"] = json!("operator_declined");
        let _ = write_forbidden(&mut stream, "operator_declined").await;
        proxy.record(record).await;
        return;
    }

    if let Err(error) = stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
    {
        record["decision"] = json!("error");
        record["reason"] = json!(error.to_string());
        proxy.record(record).await;
        return;
    }

    let acceptor = match proxy.acceptor_for(&host) {
        Ok(acceptor) => acceptor,
        Err(error) => {
            record["decision"] = json!("error");
            record["reason"] = json!(error.to_string());
            proxy.record(record).await;
            return;
        }
    };
    let mut tls = match timeout(proxy.request_timeout, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(error)) => {
            record["decision"] = json!("error");
            record["reason"] = json!(error.to_string());
            proxy.record(record).await;
            return;
        }
        Err(_) => {
            record["decision"] = json!("error");
            record["reason"] = json!("TLS handshake timed out");
            proxy.record(record).await;
            return;
        }
    };
    // SNI is advisory: when a client sends it, it must match the CONNECT host.
    if let Some(sni) = tls.get_ref().1.server_name() {
        if !sni.eq_ignore_ascii_case(&host) {
            record["decision"] = json!("drop");
            record["reason"] = json!("sni_mismatch");
            proxy.record(record).await;
            return;
        }
    }
    record["decision"] = json!("tunnel");
    proxy.record(record).await;

    if let Some(index) = proxy.reserve() {
        let read = timeout(proxy.request_timeout, read_request(&mut tls))
            .await
            .unwrap_or_else(|_| Err(anyhow!("request timed out")));
        match read {
            Ok((header, raw)) => {
                let input = RequestInput {
                    scheme: "https",
                    tunnel_host: Some(&host),
                    ack_done: true,
                    index,
                };
                let inner_record = process_request(&mut tls, &header, &raw, &input, proxy).await;
                proxy.record(inner_record).await;
            }
            Err(error) => {
                proxy
                    .record(json!({
                        "index": index,
                        "scheme": "https",
                        "decision": "error",
                        "scope_allowed": false,
                        "host": host,
                        "reason": error.to_string()
                    }))
                    .await;
            }
        }
    }
    let _ = tls.shutdown().await;
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::win_acl;
    use super::*;

    fn test_ca_dir(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        #[cfg(windows)]
        let root = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        #[cfg(not(windows))]
        let root = std::env::temp_dir();
        root.join(format!("bugfound-proxy-{label}-{nonce}"))
    }

    fn test_proxy(request_timeout: Duration, max_response_bytes: usize) -> Proxy {
        let path = test_ca_dir("history").with_extension("jsonl");
        let history = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        Proxy {
            args: Args {
                listen: "127.0.0.1:0".to_string(),
                scope_in: vec!["127.0.0.1".to_string()],
                scope_out: Vec::new(),
                require_ack: false,
                max_requests: 8,
                out: path,
                ca_dir: PathBuf::new(),
                tls_listen: None,
                no_mitm: true,
            },
            history: Mutex::new(history),
            ca: None,
            acceptors: std::sync::Mutex::new(HashMap::new()),
            processed: AtomicUsize::new(0),
            request_timeout,
            max_response_bytes,
        }
    }

    #[test]
    fn parses_connect_authority() {
        assert_eq!(
            parse_connect_authority("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_connect_authority("example.com").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_connect_authority("[::1]:8443").unwrap(),
            ("::1".to_string(), 8443)
        );
        assert!(parse_connect_authority("user@example.com:443").is_err());
        assert!(parse_connect_authority("example.com:notaport").is_err());
    }

    #[test]
    fn proxy_http_path_scope_enforced() {
        let empty: Vec<String> = Vec::new();
        let out = vec!["host/secret/*".to_string()];
        // The HTTP gate passes the parsed full URL, so a path-scoped exclusion
        // must be enforced on the actual request path (E27/B1).
        assert!(!bugfound_tools::scope_target_allowed(
            "https://host/secret/x",
            &empty,
            &out
        ));
        assert!(bugfound_tools::scope_target_allowed(
            "https://host/public/x",
            &empty,
            &out
        ));
        let in_scope = vec!["host".to_string()];
        assert!(!bugfound_tools::scope_target_allowed(
            "https://host/secret/x",
            &in_scope,
            &out
        ));
    }

    #[test]
    fn connect_scope_is_host_only() {
        // CONNECT carries no path: the synthesized root URL must not trigger
        // path-scoped rules, while the inner request is gated with its full URL.
        let empty: Vec<String> = Vec::new();
        let out = vec!["host/secret/*".to_string()];
        assert!(bugfound_tools::scope_target_allowed(
            "https://host/",
            &empty,
            &out
        ));
        assert!(!bugfound_tools::scope_target_allowed(
            "https://host/secret/x",
            &empty,
            &out
        ));
    }

    #[test]
    fn generates_and_reloads_local_ca() {
        let dir = test_ca_dir("ca");
        let ca = load_or_create_ca(&dir).unwrap();
        drop(ca);
        let cert = std::fs::read_to_string(dir.join("ca-cert.pem")).unwrap();
        let key = std::fs::read_to_string(dir.join("ca-key.pem")).unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
        assert!(load_or_create_ca(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ca_key_is_owner_only_and_broad_key_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_ca_dir("perm");
        let ca = load_or_create_ca(&dir).unwrap();
        drop(ca);
        let key = dir.join("ca-key.pem");
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "CA key must be owner-only");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_or_create_ca(&dir).is_err(),
            "a group/world-readable CA key must be refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn ca_key_outside_user_directory_rejected() {
        // Defense in depth: fail closed outside a per-user location even when
        // the Win32 DACL could be enforced.
        assert!(ensure_private_ca_location(Path::new(r"C:\Windows")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn generated_ca_key_has_single_current_user_ace() {
        let dir = test_ca_dir("acl-generated");
        let ca = load_or_create_ca(&dir).unwrap();
        drop(ca);
        let sid = win_acl::current_user_sid().unwrap();
        let status = win_acl::verify_current_user_only_dacl(&dir.join("ca-key.pem"), &sid)
            .expect("inspect generated CA key DACL");
        assert!(
            matches!(status, win_acl::DaclStatus::Secure),
            "generated key must have exactly one current-user ACE, got {status:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn broad_ca_key_dacl_is_rejected() {
        let dir = test_ca_dir("acl-broad");
        let ca = load_or_create_ca(&dir).unwrap();
        drop(ca);
        let key = dir.join("ca-key.pem");
        let ca_dir = dir.clone();
        assert!(
            verify_ca_key(&key, &ca_dir).is_ok(),
            "baseline must be secure"
        );

        // Simulate a key whose DACL was widened by an older build: grant
        // Everyone (S-1-1-0) full control instead of the single user ACE.
        win_acl::set_everyone_full_dacl_for_test(&key).unwrap();

        let sid = win_acl::current_user_sid().unwrap();
        let status = win_acl::verify_current_user_only_dacl(&key, &sid)
            .expect("inspect widened CA key DACL");
        assert!(
            matches!(status, win_acl::DaclStatus::Weak(_)),
            "a broad/NULL DACL must be reported as weak, got {status:?}"
        );
        assert!(
            verify_ca_key(&key, &ca_dir).is_err(),
            "a broad/NULL DACL must be a hard error"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn inherited_ace_is_removed_from_ca_dacl() {
        // Put an inheritable Everyone/FULL ACE on the parent, then generate the
        // CA in a child. The protected, single-user DACL must drop that ACE.
        let root = test_ca_dir("acl-inherit-root");
        std::fs::create_dir_all(&root).unwrap();
        win_acl::set_inheritable_everyone_dacl_for_test(&root).unwrap();
        let dir = root.join("ca");
        let ca = load_or_create_ca(&dir).unwrap();
        drop(ca);
        let sid = win_acl::current_user_sid().unwrap();
        // Secure requires exactly one ACE with no INHERITED_ACE flag.
        let dir_status =
            win_acl::verify_current_user_only_dacl(&dir, &sid).expect("inspect CA directory DACL");
        let key_status = win_acl::verify_current_user_only_dacl(&dir.join("ca-key.pem"), &sid)
            .expect("inspect CA key DACL");
        assert!(
            matches!(dir_status, win_acl::DaclStatus::Secure),
            "CA directory must not retain inherited ACEs: {dir_status:?}"
        );
        assert!(
            matches!(key_status, win_acl::DaclStatus::Secure),
            "CA key must not retain inherited ACEs: {key_status:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn proxy_request_timeout_closes_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // A partial request: the proxy waits forever unless it times out.
            socket
                .write_all(b"GET / HTTP/1.1\r\nHost: host\r\n")
                .await
                .unwrap();
            let mut buffer = [0u8; 16];
            socket.read(&mut buffer).await.unwrap()
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let proxy = Arc::new(test_proxy(Duration::from_millis(150), MAX_RESPONSE_BYTES));
        let history = proxy.args.out.clone();
        handle_plain(stream, proxy).await;
        let read = timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0, "a stalled connection must be closed on timeout");
        let _ = std::fs::remove_file(history);
    }

    #[tokio::test]
    async fn proxy_body_cap_enforced() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            let body = vec![b'x'; 1024];
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&body).await;
            let _ = socket.flush().await;
        });
        let proxy = Arc::new(test_proxy(Duration::from_secs(2), 64));
        let history = proxy.args.out.clone();
        let header = format!("GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\n\r\n");
        let raw = header.as_bytes().to_vec();
        let (mut client, mut proxy_side) = tokio::io::duplex(8192);
        let input = RequestInput {
            scheme: "http",
            tunnel_host: None,
            ack_done: false,
            index: 1,
        };
        let record = process_request(&mut proxy_side, &header, &raw, &input, &proxy).await;
        assert_eq!(record["decision"], json!("error"));
        assert!(record["reason"].as_str().unwrap().contains("too large"));
        drop(proxy_side);
        let mut forwarded = Vec::new();
        let _ = client.read_to_end(&mut forwarded).await;
        assert!(forwarded.is_empty(), "oversized body must not be forwarded");
        let _ = timeout(Duration::from_secs(2), server).await;
        let _ = std::fs::remove_file(history);
    }
}
