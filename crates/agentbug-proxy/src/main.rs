//! Bounded, deterministic HTTP/HTTPS intercepting proxy.
//!
//! This is the headless analogue of Burp's Proxy interception decision: every
//! request is either forwarded or dropped by an explicit deterministic gate.
//! With `--require-ack` the operator must approve each request on stdin, and
//! anything other than an explicit `y` is a fail-closed drop. There is no LLM
//! in this path and no auto-approval.
//!
//! HTTPS is supported through operator-controlled MITM: `CONNECT` is gated by
//! the same scope check as plain HTTP, then a locally generated CA signs a
//! leaf certificate for the requested host. The client must be configured to
//! trust that CA; this proxy never modifies client trust stores itself.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const CA_CN: &str = "AgentBug Proxy CA";

#[derive(Parser, Debug)]
#[command(name = "agentbug-proxy")]
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
    #[arg(long, default_value = "./agentbug-proxy-ca")]
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
    });
    let listener = TcpListener::bind(&proxy.args.listen)
        .await
        .with_context(|| format!("bind {}", proxy.args.listen))?;
    let mut tls_task = None;
    if let Some(address) = &proxy.args.tls_listen {
        let tls_listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("bind --tls-listen {address}"))?;
        let tls_proxy = Arc::clone(&proxy);
        tls_task = Some(tokio::spawn(async move {
            while tls_proxy.processed.load(Ordering::Relaxed) < tls_proxy.args.max_requests {
                let Ok((stream, _peer)) = tls_listener.accept().await else {
                    break;
                };
                handle_plain(stream, &tls_proxy).await;
            }
        }));
    }
    eprintln!(
        "agentbug-proxy listening on {} (require_ack={}, max_requests={}, mitm={}, ca_dir={})",
        proxy.args.listen,
        proxy.args.require_ack,
        proxy.args.max_requests,
        !proxy.args.no_mitm,
        proxy.args.ca_dir.display()
    );

    while proxy.processed.load(Ordering::Relaxed) < proxy.args.max_requests {
        let (stream, _peer) = listener.accept().await?;
        handle_plain(stream, &proxy).await;
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
    let cert_exists = cert_path.is_file();
    let key_exists = key_path.is_file();
    if cert_exists != key_exists {
        return Err(anyhow!(
            "incomplete CA in {}; remove that directory and retry",
            dir.display()
        ));
    }
    if cert_exists {
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
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;
    Ok(())
}

fn write_secret(path: &Path, contents: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, contents)?;
    Ok(())
}

async fn handle_plain(stream: TcpStream, proxy: &Arc<Proxy>) {
    let mut stream = stream;
    let Some(index) = proxy.reserve() else {
        let _ = write_response(&mut stream, "403 Forbidden", "max requests reached").await;
        return;
    };
    let (header, raw) = match read_request(&mut stream).await {
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
        handle_connect(stream, &target, proxy, index).await;
        return;
    }
    let input = RequestInput {
        scheme: "http",
        tunnel_host: None,
        ack_done: false,
        index,
    };
    let record = process_request(&mut stream, &header, &raw, &input, proxy).await;
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
    let allowed =
        agentbug_tools::scope_target_allowed(&host, &proxy.args.scope_in, &proxy.args.scope_out);
    record["method"] = json!(method);
    record["url"] = json!(agentbug_tools::redact(&target));
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
            agentbug_tools::redact(&method),
            agentbug_tools::redact(&target)
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
    let response = request.send().await?;
    let status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let response_body = response.bytes().await?;
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

async fn handle_connect<S>(mut stream: S, authority: &str, proxy: &Arc<Proxy>, index: usize)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut record = json!({
        "index": index,
        "scheme": "https",
        "method": "CONNECT",
        "url": agentbug_tools::redact(authority),
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
    } else if !agentbug_tools::scope_target_allowed(
        &host,
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
    let mut tls = match acceptor.accept(stream).await {
        Ok(tls) => tls,
        Err(error) => {
            record["decision"] = json!("error");
            record["reason"] = json!(error.to_string());
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
        match read_request(&mut tls).await {
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
    use super::*;

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
    fn generates_and_reloads_local_ca() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("agentbug-proxy-ca-{nonce}"));
        let ca = load_or_create_ca(&dir).unwrap();
        drop(ca);
        let cert = std::fs::read_to_string(dir.join("ca-cert.pem")).unwrap();
        let key = std::fs::read_to_string(dir.join("ca-key.pem")).unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
        assert!(load_or_create_ca(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
