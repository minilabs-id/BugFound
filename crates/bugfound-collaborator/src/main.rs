//! Self-hosted out-of-band (OOB) interaction oracle for BugFound.
//!
//! This is an operational tool, not an agent tool: it is run by the operator on
//! a host they control and exposes three listeners:
//!
//! * an HTTP/S listener that accepts *any* method and path and records the raw
//!   exchange,
//! * a DNS listener that answers A queries for `<token>.<domain-suffix>` and
//!   records the query, and
//! * a loopback-only admin listener used to mint tokens and read interactions.
//!
//! The oracle records interactions and exposes them through the admin listener;
//! it does not send reports. The HTTP payload is derived from a token minted
//! through the admin API, so an out-of-band hit can be correlated to a tool call.

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Parser;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Hard bound on a single UDP DNS packet and on the HTTP request/response bytes
/// we are willing to buffer per interaction.
const MAX_PACKET: usize = 4096;
const MAX_HTTP_REQUEST: usize = 16 * 1024;
/// TTL returned with the A record, in seconds.
const DNS_TTL: u32 = 60;

/// Short, dependency-free token echo written in the HTTP 200 response body.
const ECHO_PREFIX: &str = "bugfound-oob ";

#[derive(Parser, Debug)]
#[command(
    name = "bugfound-collaborator",
    version,
    about = "Self-hosted OOB HTTP/DNS interaction oracle (no auto-submit, no reporting)."
)]
struct Cli {
    /// Address for the public-facing HTTP/S interaction listener.
    #[arg(long, default_value = "0.0.0.0:8081")]
    http_listen: SocketAddr,

    /// Address for the public-facing DNS (UDP) interaction listener.
    #[arg(long, default_value = "0.0.0.0:5353")]
    dns_listen: SocketAddr,

    /// DNS suffix under which per-token subdomains are issued, e.g. oob.example.com.
    #[arg(long)]
    domain_suffix: String,

    /// IPv4 address returned in A records. Must be the public IP that reaches this host.
    #[arg(long)]
    public_ip: Ipv4Addr,

    /// Loopback-only admin listener (mint tokens, read interactions). Never expose publicly.
    #[arg(long, default_value = "127.0.0.1:8082")]
    admin_listen: SocketAddr,

    /// Shared secret required by both admin routes via `Authorization: Bearer <token>`.
    /// Falls back to BUGFOUND_OOB_ADMIN_TOKEN. With no secret configured the admin API
    /// rejects every request (fail closed).
    #[arg(long)]
    admin_token: Option<String>,

    /// Maximum number of minted tokens kept as known. Exhaustion rejects minting; tokens
    /// (and their interactions) are never evicted.
    #[arg(long, default_value_t = 256)]
    max_tokens: usize,

    /// Total number of interactions retained across all tokens. Further HTTP hits get 429.
    #[arg(long, default_value_t = 256)]
    max_interactions: usize,

    /// Path of the JSONL file interactions are appended to.
    #[arg(long)]
    out: PathBuf,
}

/// A parsed standard DNS query (the subset we need to answer collaborator names).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQuery {
    txid: u16,
    /// Lower-cased QNAME, labels joined with '.', without the root dot.
    qname: String,
    qtype: u16,
    qclass: u16,
    /// Number of bytes occupied by the question section, starting at offset 12.
    question_len: usize,
}

/// Parse a DNS query packet without panicking on malformed input.
///
/// Returns `None` for truncated packets, replies (QR set), empty question
/// sections, invalid label encodings, or malformed compression pointers.
fn parse_dns_query(packet: &[u8]) -> Option<DnsQuery> {
    if packet.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 != 0 {
        return None; // this is a response, not a query
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut labels: Vec<String> = Vec::new();
    let mut idx = 12usize;
    loop {
        if idx >= packet.len() {
            return None;
        }
        let len = packet[idx] as usize;
        // Compression pointers are a response-only feature (RFC 1035); a
        // query QNAME is always uncompressed. Reject instead of chasing one.
        if len & 0xC0 == 0xC0 {
            return None;
        }
        idx += 1;
        if len == 0 {
            break;
        }
        if len > 63 || idx + len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[idx..idx + len])
            .ok()?
            .to_ascii_lowercase();
        labels.push(label);
        idx += len;
    }

    let qname_end = idx;
    let question_end = qname_end.checked_add(4)?;
    if question_end > packet.len() {
        return None;
    }
    Some(DnsQuery {
        txid,
        qname: labels.join("."),
        qtype: u16::from_be_bytes([packet[qname_end], packet[qname_end + 1]]),
        qclass: u16::from_be_bytes([packet[qname_end + 2], packet[qname_end + 3]]),
        question_len: question_end - 12,
    })
}

/// Build a DNS response that echoes the query section and either supplies an A
/// answer or returns NXDOMAIN.
fn build_dns_response(query: &DnsQuery, packet: &[u8], answer: Option<Ipv4Addr>) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + query.question_len + 16);
    out.extend_from_slice(&query.txid.to_be_bytes());

    // QR=1 (response), AA=1 (authoritative), RA=1; copy RD from the query.
    let mut flags = 0x8000u16 | 0x0400 | 0x0080;
    if packet.len() >= 3 {
        flags |= u16::from(packet[2] & 0x01);
    }
    if answer.is_none() {
        flags |= 0x0003; // NXDOMAIN
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(u16::from(answer.is_some())).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Echo the original question verbatim.
    out.extend_from_slice(&packet[12..12 + query.question_len]);

    if let Some(ip) = answer {
        out.extend_from_slice(&[0xC0, 0x0C]); // name pointer to the question QNAME
        out.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        out.extend_from_slice(&DNS_TTL.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// Return the leftmost label when `name` lives under `suffix`.
fn token_from_name<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let name = name.trim_end_matches('.');
    let prefix = name.strip_suffix(&format!(".{suffix}"))?;
    if prefix.is_empty() {
        return None;
    }
    Some(prefix.split('.').next().unwrap_or(""))
}

// Secret scrubbing for the JSONL artifact uses the shared redaction crate.
use bugfound_redact::redact_text;

/// Base64 of a redacted, UTF-8-safe rendering of raw bytes. Binary input is
/// lossy-converted; HTTP/DNS payloads are textual in practice.
fn redacted_b64(bytes: &[u8]) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    let text = String::from_utf8_lossy(bytes);
    engine.encode(redact_text(&text).as_bytes())
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Shared, bounded interaction store. A single `std::sync::Mutex` keeps all
/// critical sections short; no guard is ever held across an `await`.
struct Store {
    domain_suffix: String,
    public_ip: Ipv4Addr,
    max_interactions: usize,
    max_tokens: usize,
    token_counter: u64,
    interaction_counter: u64,
    tokens: VecDeque<String>,
    token_set: HashSet<String>,
    interactions: VecDeque<Value>,
    by_token: HashMap<String, Vec<Value>>,
    total: usize,
    jsonl: Option<File>,
}

impl Store {
    fn new(
        domain_suffix: String,
        public_ip: Ipv4Addr,
        max_interactions: usize,
        max_tokens: usize,
        out: Option<PathBuf>,
    ) -> Result<Self> {
        let jsonl = match out {
            Some(path) => Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .with_context(|| format!("open JSONL output {}", path.display()))?,
            ),
            None => None,
        };
        Ok(Self {
            domain_suffix,
            public_ip,
            max_interactions,
            max_tokens,
            token_counter: 0,
            interaction_counter: 0,
            tokens: VecDeque::new(),
            token_set: HashSet::new(),
            interactions: VecDeque::new(),
            by_token: HashMap::new(),
            total: 0,
            jsonl,
        })
    }

    /// Mint a token, rejecting the request when the pool is exhausted instead of
    /// evicting an older token: eviction would invalidate interactions still live
    /// for that token.
    fn mint_token(&mut self) -> Result<String> {
        if self.tokens.len() >= self.max_tokens {
            bail!(
                "token pool exhausted (max_tokens={}); refusing to evict a live token",
                self.max_tokens
            );
        }
        for _ in 0..16 {
            self.token_counter += 1;
            let mut x = now_nanos() ^ self.token_counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            let token = format!("{:016x}", x.wrapping_mul(0x2545_F491_4F6C_DD1D));
            if self.token_set.insert(token.clone()) {
                self.tokens.push_back(token.clone());
                return Ok(token);
            }
        }
        bail!("unable to generate a unique token")
    }

    fn is_known_token(&self, token: &str) -> bool {
        self.token_set.contains(token)
    }

    fn is_full(&self) -> bool {
        self.total >= self.max_interactions
    }

    fn interactions_for(&self, token: &str) -> Vec<Value> {
        self.by_token.get(token).cloned().unwrap_or_default()
    }

    /// Record one interaction. Returns `false` when the global cap is reached.
    fn record(&mut self, mut interaction: Value) -> Result<bool> {
        if self.is_full() {
            return Ok(false);
        }
        self.interaction_counter += 1;
        let id = format!("{:08x}", self.interaction_counter);
        if let Value::Object(map) = &mut interaction {
            map.entry("interaction_id".to_string())
                .or_insert_with(|| json!(id));
        }
        let token = interaction
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        if let Some(file) = &mut self.jsonl {
            let line = serde_json::to_string(&interaction).context("serialize interaction")?;
            writeln!(file, "{line}").context("append interaction to JSONL")?;
            file.flush().context("flush JSONL")?;
        }

        self.interactions.push_back(interaction.clone());
        self.by_token.entry(token).or_default().push(interaction);
        self.total += 1;
        Ok(true)
    }
}

type SharedStore = Arc<Mutex<Store>>;

fn json_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn first_request_line(request: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(request);
    let line = text.lines().next().unwrap_or("").trim();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    (method, target)
}

fn header_value(request: &[u8], name: &str) -> String {
    let text = String::from_utf8_lossy(request);
    for line in text.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(name) {
                return value.trim().to_string();
            }
        }
    }
    String::new()
}

fn query_param(target: &str, name: &str) -> String {
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == name {
                return value.to_string();
            }
        }
    }
    String::new()
}

/// Constant-time comparison for short secrets: every byte index is visited and
/// length differences fold into the accumulator, so no prefix match leaks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let n = a.len().max(b.len());
    for i in 0..n {
        let left = a.get(i).copied().unwrap_or(0);
        let right = b.get(i).copied().unwrap_or(0);
        diff |= (left ^ right) as usize;
    }
    diff == 0
}

/// Extract the `Bearer` credential from an Authorization header (case-insensitive
/// scheme). Missing or malformed headers yield an empty credential.
fn bearer_credential(request: &[u8]) -> String {
    let value = header_value(request, "authorization");
    let value = value.trim();
    match value.split_once(' ') {
        Some((scheme, credential)) if scheme.eq_ignore_ascii_case("bearer") => {
            credential.trim().to_string()
        }
        _ => String::new(),
    }
}

/// Resolve the admin secret from the CLI flag first, then the environment.
/// Empty (or whitespace-only) values are treated as absent.
fn resolve_admin_token(flag: Option<&str>) -> Option<String> {
    flag.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            std::env::var("BUGFOUND_OOB_ADMIN_TOKEN")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
}

/// Both admin routes require the configured shared secret. With no secret
/// configured there is no valid caller, so requests are rejected (fail closed).
fn admin_authorized(request: &[u8], admin_token: Option<&str>) -> bool {
    let Some(expected) = admin_token else {
        return false;
    };
    if expected.is_empty() {
        return false;
    }
    constant_time_eq(bearer_credential(request).as_bytes(), expected.as_bytes())
}

/// Handle one HTTP interaction request. Only a known token gets an echo and an
/// interaction record; unknown Host tokens get a generic response. Kept out of
/// the accept loop so the check is directly exercisable offline.
fn handle_http_request(request: &[u8], peer_ip: IpAddr, store: &SharedStore) -> Vec<u8> {
    let (method, target) = first_request_line(request);
    let protocol = String::from_utf8_lossy(request)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(2))
        .unwrap_or("unknown")
        .to_string();
    let host = header_value(request, "host");

    let (token, known, full) = {
        let guard = store.lock().unwrap();
        let token = token_from_name(&host, &guard.domain_suffix)
            .unwrap_or("")
            .to_string();
        let known = !token.is_empty() && guard.is_known_token(&token);
        (token, known, guard.is_full())
    };

    if !known {
        return b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec();
    }
    if full {
        return b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec();
    }

    let body = format!("{ECHO_PREFIX}{token}\n");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();

    let interaction = json!({
        "type": "http",
        "token": token,
        "client_ip": peer_ip.to_string(),
        "time_stamp": now_nanos(),
        "protocol": protocol,
        "method": method,
        "path": target,
        "request_b64": redacted_b64(request),
        "response_b64": redacted_b64(&response),
    });
    match store.lock().unwrap().record(interaction) {
        Ok(true) => {}
        Ok(false) => eprintln!("bugfound-collaborator: interaction cap reached"),
        Err(err) => eprintln!("bugfound-collaborator: record failed: {err}"),
    }
    response
}

/// Handle one admin request. Authentication gates *both* `/token` and
/// `/interactions` so a loopback caller cannot mint or read without the secret.
fn handle_admin_request(request: &[u8], store: &SharedStore, admin_token: Option<&str>) -> Vec<u8> {
    if !admin_authorized(request, admin_token) {
        return json_response("401 Unauthorized", "{\"error\":\"unauthorized\"}");
    }

    let (method, target) = first_request_line(request);
    let path = target.split('?').next().unwrap_or("");

    if method == "POST" && path == "/token" {
        let minted = {
            let mut guard = store.lock().unwrap();
            let result = guard.mint_token();
            let suffix = guard.domain_suffix.clone();
            result.map(|token| (token, suffix))
        };
        match minted {
            Ok((token, domain_suffix)) => {
                let body = json!({
                    "token": token,
                    "domain_suffix": domain_suffix,
                    "server_location": domain_suffix,
                })
                .to_string();
                json_response("200 OK", &body)
            }
            Err(err) => {
                eprintln!("bugfound-collaborator: token mint rejected: {err}");
                json_response(
                    "503 Service Unavailable",
                    "{\"error\":\"token_pool_exhausted\"}",
                )
            }
        }
    } else if method == "GET" && path == "/interactions" {
        let token = query_param(&target, "token");
        let interactions = store.lock().unwrap().interactions_for(&token);
        let body = serde_json::to_string(&interactions).unwrap_or_else(|_| "[]".to_string());
        json_response("200 OK", &body)
    } else {
        json_response("404 Not Found", "{\"error\":\"not_found\"}")
    }
}

async fn run_http(listen: SocketAddr, store: SharedStore) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind HTTP listener {listen}"))?;
    eprintln!("bugfound-collaborator: HTTP listener on {listen}");
    loop {
        let (mut socket, peer) = listener.accept().await.context("accept HTTP connection")?;
        let store = store.clone();
        tokio::spawn(async move {
            let limit = tokio::time::Duration::from_secs(5);
            let read = tokio::time::timeout(limit, async {
                let mut buf = vec![0u8; MAX_HTTP_REQUEST];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                buf.truncate(n);
                buf
            })
            .await
            .unwrap_or_default();

            let response = handle_http_request(&read, peer.ip(), &store);

            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
        });
    }
}

async fn run_dns(listen: SocketAddr, store: SharedStore) -> Result<()> {
    let socket = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("bind DNS listener {listen}"))?;
    eprintln!("bugfound-collaborator: DNS listener on {listen}");
    let mut buf = [0u8; MAX_PACKET];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .context("recv DNS packet")?;
        let packet = &buf[..len];
        let Some(query) = parse_dns_query(packet) else {
            // Malformed packet: drop it rather than panicking or reflecting junk.
            eprintln!("bugfound-collaborator: dropping malformed DNS packet from {peer}");
            continue;
        };

        let (answer, known, full, domain_suffix) = {
            let guard = store.lock().unwrap();
            let token = token_from_name(&query.qname, &guard.domain_suffix)
                .unwrap_or("")
                .to_string();
            let known = !token.is_empty() && guard.is_known_token(&token);
            (
                guard.public_ip,
                known,
                guard.is_full(),
                guard.domain_suffix.clone(),
            )
        };

        let token = token_from_name(&query.qname, &domain_suffix)
            .unwrap_or("")
            .to_string();
        let response = if known {
            build_dns_response(&query, packet, Some(answer))
        } else {
            build_dns_response(&query, packet, None)
        };
        let _ = socket.send_to(&response, peer).await;

        if known && !full {
            let interaction = json!({
                "type": "dns",
                "query_type": query.qtype,
                "raw_query_b64": redacted_b64(packet),
                "token": token,
                "client_ip": peer.ip().to_string(),
                "time_stamp": now_nanos(),
            });
            match store.lock().unwrap().record(interaction) {
                Ok(true) => {}
                Ok(false) => eprintln!("bugfound-collaborator: interaction cap reached"),
                Err(err) => eprintln!("bugfound-collaborator: record failed: {err}"),
            }
        }
    }
}

async fn run_admin(
    listen: SocketAddr,
    store: SharedStore,
    admin_token: Option<String>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind admin listener {listen}"))?;
    eprintln!("bugfound-collaborator: admin listener on {listen} (loopback only - DO NOT EXPOSE)");
    loop {
        let (mut socket, _peer) = listener.accept().await.context("accept admin connection")?;
        let store = store.clone();
        let admin_token = admin_token.clone();
        tokio::spawn(async move {
            let request = tokio::time::timeout(tokio::time::Duration::from_secs(5), async {
                let mut buf = vec![0u8; MAX_PACKET];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                buf.truncate(n);
                buf
            })
            .await
            .unwrap_or_default();
            let response = handle_admin_request(&request, &store, admin_token.as_deref());
            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.admin_listen.ip().is_loopback() {
        bail!("--admin-listen must be a loopback address; refusing to expose the admin API");
    }
    let domain_suffix = cli
        .domain_suffix
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if domain_suffix.is_empty() {
        bail!("--domain-suffix must not be empty");
    }
    if cli.max_interactions == 0 {
        bail!("--max-interactions must be at least 1");
    }
    if cli.max_tokens == 0 {
        bail!("--max-tokens must be at least 1");
    }

    let admin_token = resolve_admin_token(cli.admin_token.as_deref());
    if admin_token.is_none() {
        eprintln!(
            "bugfound-collaborator: WARNING: no admin token configured; all admin requests will be rejected"
        );
    }

    let store = Arc::new(Mutex::new(Store::new(
        domain_suffix,
        cli.public_ip,
        cli.max_interactions,
        cli.max_tokens,
        Some(cli.out.clone()),
    )?));

    eprintln!(
        "bugfound-collaborator: domain_suffix={} public_ip={} max_interactions={} max_tokens={} out={}",
        cli.domain_suffix,
        cli.public_ip,
        cli.max_interactions,
        cli.max_tokens,
        cli.out.display()
    );

    tokio::try_join!(
        run_http(cli.http_listen, store.clone()),
        run_dns(cli.dns_listen, store.clone()),
        run_admin(cli.admin_listen, store, admin_token),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_packet(name: &str, qtype: u16) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }

    fn test_store(max_interactions: usize, max_tokens: usize) -> SharedStore {
        Arc::new(Mutex::new(
            Store::new(
                "oob.example.com".to_string(),
                Ipv4Addr::new(203, 0, 113, 10),
                max_interactions,
                max_tokens,
                None,
            )
            .unwrap(),
        ))
    }

    fn http_request(host: &str, path: &str) -> Vec<u8> {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
    }

    fn admin_request(method: &str, target: &str, credential: Option<&str>) -> Vec<u8> {
        let auth = credential
            .map(|value| format!("Authorization: Bearer {value}\r\n"))
            .unwrap_or_default();
        format!("{method} {target} HTTP/1.1\r\n{auth}\r\n").into_bytes()
    }

    fn response_text(response: &[u8]) -> String {
        String::from_utf8_lossy(response).to_string()
    }

    fn response_body(response: &[u8]) -> String {
        let marker = b"\r\n\r\n";
        let start = response
            .windows(marker.len())
            .position(|window| window == marker)
            .map(|index| index + marker.len())
            .unwrap_or(response.len());
        String::from_utf8_lossy(&response[start..]).to_string()
    }

    #[test]
    fn parses_standard_query() {
        let packet = query_packet("abc123.oob.example.com", 1);
        let q = parse_dns_query(&packet).unwrap();
        assert_eq!(q.txid, 0x1234);
        assert_eq!(q.qname, "abc123.oob.example.com");
        assert_eq!(q.qtype, 1);
        assert_eq!(q.qclass, 1);
        assert_eq!(q.question_len, packet.len() - 12);
    }

    #[test]
    fn rejects_malformed_queries_without_panicking() {
        assert!(parse_dns_query(&[]).is_none());
        assert!(parse_dns_query(&[0; 11]).is_none());
        // QR bit set => response, not a query.
        let mut response = query_packet("a.oob.example.com", 1);
        response[2] |= 0x80;
        assert!(parse_dns_query(&response).is_none());
        // Truncated label (length 10 but only 2 bytes follow).
        let mut truncated = query_packet("a.oob.example.com", 1);
        truncated[12] = 10;
        assert!(parse_dns_query(&truncated).is_none());
    }

    #[test]
    fn builds_a_answer_and_nxdomain() {
        let packet = query_packet("abc123.oob.example.com", 1);
        let q = parse_dns_query(&packet).unwrap();

        let answer = build_dns_response(&q, &packet, Some(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(&answer[0..2], &0x1234u16.to_be_bytes());
        assert_ne!(answer[2] & 0x80, 0); // QR
        assert_eq!(&answer[6..8], &1u16.to_be_bytes()); // ANCOUNT
                                                        // QR | AA | RA | RD (the query packet sets RD).
        assert_eq!(&answer[2..4], &0x8481u16.to_be_bytes());
        assert_eq!(&answer[answer.len() - 4..], &[203, 0, 113, 10]);
        assert_eq!(answer.len(), 12 + q.question_len + 16);

        let nxdomain = build_dns_response(&q, &packet, None);
        assert_eq!(&nxdomain[6..8], &0u16.to_be_bytes());
        assert_eq!(nxdomain[3] & 0x03, 0x03); // rcode NXDOMAIN
    }

    #[test]
    fn token_is_leftmost_label_under_suffix() {
        assert_eq!(
            token_from_name("abc123.oob.example.com", "oob.example.com"),
            Some("abc123")
        );
        assert_eq!(token_from_name("oob.example.com", "oob.example.com"), None);
        assert_eq!(token_from_name("a.b.evil.com", "oob.example.com"), None);
    }

    #[test]
    fn redaction_removes_common_secrets() {
        let out = redact_text("GET /?token=SUPERSECRET&x=1 Authorization: Bearer abcdef");
        assert!(!out.contains("SUPERSECRET"));
        assert!(!out.contains("abcdef"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn interaction_store_caps_total_and_records_by_token() {
        let store = test_store(2, 4);
        let token = {
            let mut guard = store.lock().unwrap();
            guard.mint_token().unwrap()
        };
        assert!(store.lock().unwrap().is_known_token(&token));
        assert!(!store.lock().unwrap().is_known_token("nope"));

        let known_request = http_request(&format!("{token}.oob.example.com"), "/hit");
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..2 {
            let response = handle_http_request(&known_request, peer, &store);
            assert!(response_text(&response).contains(&format!("{ECHO_PREFIX}{token}")));
        }
        assert!(store.lock().unwrap().is_full());

        // A token that was never minted is neither echoed nor recorded.
        let unknown_request = http_request("unminted.oob.example.com", "/hit");
        let unknown = handle_http_request(&unknown_request, peer, &store);
        assert!(unknown.starts_with(b"HTTP/1.1 404"));
        assert!(!response_text(&unknown).contains(ECHO_PREFIX));
        assert!(store
            .lock()
            .unwrap()
            .interactions_for("unminted")
            .is_empty());
        assert_eq!(store.lock().unwrap().total, 2);

        // Once the interaction cap is reached, even a known token gets 429.
        let capped = handle_http_request(&known_request, peer, &store);
        assert!(capped.starts_with(b"HTTP/1.1 429"));
        assert_eq!(store.lock().unwrap().interactions_for(&token).len(), 2);
        assert_eq!(store.lock().unwrap().total, 2);
    }

    #[test]
    fn tokens_are_unique_and_reuse_is_bounded() {
        let mut store = Store::new(
            "oob.example.com".to_string(),
            Ipv4Addr::new(203, 0, 113, 10),
            4,
            2,
            None,
        )
        .unwrap();
        let a = store.mint_token().unwrap();
        let b = store.mint_token().unwrap();
        assert_ne!(a, b);
        assert!(store.is_known_token(&a));
        assert!(store.is_known_token(&b));
        // Exhaustion is rejected instead of evicting a still-known token.
        assert!(store.mint_token().is_err());
        assert!(store.is_known_token(&a));
        assert!(store.is_known_token(&b));
    }

    #[test]
    fn mint_rejected_when_pool_exhausted_keeps_live_interaction() {
        let store = test_store(8, 1);
        let token = {
            let mut guard = store.lock().unwrap();
            guard.mint_token().unwrap()
        };
        let hit = http_request(&format!("{token}.oob.example.com"), "/live");
        let response = handle_http_request(&hit, IpAddr::V4(Ipv4Addr::LOCALHOST), &store);
        assert!(response_text(&response).contains(&format!("{ECHO_PREFIX}{token}")));

        let rejected = handle_admin_request(
            &admin_request("POST", "/token", Some("s3cret")),
            &store,
            Some("s3cret"),
        );
        assert!(rejected.starts_with(b"HTTP/1.1 503"));
        assert!(response_body(&rejected).contains("token_pool_exhausted"));

        let guard = store.lock().unwrap();
        assert!(guard.is_known_token(&token));
        assert_eq!(guard.interactions_for(&token).len(), 1);
        assert_eq!(guard.tokens.len(), 1);
    }

    #[test]
    fn unauthenticated_admin_requests_are_rejected() {
        let store = test_store(4, 4);
        let secret = "s3cret";

        let no_header =
            handle_admin_request(&admin_request("POST", "/token", None), &store, Some(secret));
        assert!(no_header.starts_with(b"HTTP/1.1 401"));
        assert!(!response_body(&no_header).contains("\"token\""));

        let wrong_secret = handle_admin_request(
            &admin_request("POST", "/token", Some("wrong")),
            &store,
            Some(secret),
        );
        assert!(wrong_secret.starts_with(b"HTTP/1.1 401"));

        let read_route = handle_admin_request(
            &admin_request("GET", "/interactions?token=x", None),
            &store,
            Some(secret),
        );
        assert!(read_route.starts_with(b"HTTP/1.1 401"));

        // No configured secret means every admin request fails closed.
        let no_secret =
            handle_admin_request(&admin_request("POST", "/token", Some(secret)), &store, None);
        assert!(no_secret.starts_with(b"HTTP/1.1 401"));
        assert!(store.lock().unwrap().tokens.is_empty());
    }

    #[test]
    fn authenticated_admin_mint_and_read_work() {
        let store = test_store(4, 4);
        let secret = "s3cret";
        let response = handle_admin_request(
            &admin_request("POST", "/token", Some(secret)),
            &store,
            Some(secret),
        );
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let body: Value = serde_json::from_str(&response_body(&response)).unwrap();
        let token = body["token"].as_str().unwrap().to_string();
        assert!(!token.is_empty());
        assert_eq!(body["domain_suffix"].as_str(), Some("oob.example.com"));
        assert!(store.lock().unwrap().is_known_token(&token));

        let read = handle_admin_request(
            &admin_request("GET", &format!("/interactions?token={token}"), Some(secret)),
            &store,
            Some(secret),
        );
        assert!(read.starts_with(b"HTTP/1.1 200"));
        assert_eq!(response_body(&read), "[]");
    }

    #[test]
    fn constant_time_comparison_rejects_length_and_prefix_variants() {
        assert!(constant_time_eq(b"s3cret", b"s3cret"));
        assert!(!constant_time_eq(b"s3cret", b"s3cre"));
        assert!(!constant_time_eq(b"s3cret", b"s3creT"));
        assert!(!constant_time_eq(b"", b"s3cret"));
    }

    #[test]
    fn admin_token_flag_is_trimmed_and_takes_precedence() {
        // A non-empty flag short-circuits the env fallback, so this is deterministic.
        assert_eq!(
            resolve_admin_token(Some("  s3cret  ")).as_deref(),
            Some("s3cret")
        );
    }
}
