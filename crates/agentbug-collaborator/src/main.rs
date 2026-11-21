//! Self-hosted out-of-band (OOB) interaction oracle for Agent Bug Bounty.
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
//! There is deliberately **no auto-submit and no report transmission**: the
//! oracle only records interactions and hands them to whoever can reach the
//! admin listener. The HTTP payload is derived from a token minted through the
//! admin API, so an out-of-band hit can be correlated to a specific tool call.

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Parser;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
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
const ECHO_PREFIX: &str = "agentbug-oob ";

#[derive(Parser, Debug)]
#[command(
    name = "agentbug-collaborator",
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

/// Minimal secret scrubbing used for the JSONL artifact. This is deliberately
/// dependency-free; it targets the common `Bearer x` and `key=value` shapes.
fn redact_text(input: &str) -> String {
    const MARK: &str = "[REDACTED]";
    let mut out = input.to_string();

    loop {
        let lower = out.to_ascii_lowercase();
        let Some(idx) = lower.find("bearer ") else {
            break;
        };
        let start = idx + "bearer ".len();
        let end = out[start..]
            .find(|c: char| c.is_whitespace())
            .map(|n| start + n)
            .unwrap_or(out.len());
        if end == start {
            break;
        }
        out.replace_range(idx..end, MARK);
    }

    for key in [
        "token",
        "api_key",
        "apikey",
        "api-key",
        "x-api-key",
        "secret",
        "password",
        "passwd",
        "authorization",
        "session",
    ] {
        let mut search = 0usize;
        loop {
            let lower = out.to_ascii_lowercase();
            let Some(rel) = lower[search..].find(key) else {
                break;
            };
            let at = search + rel;
            let after = at + key.len();
            let bytes = out.as_bytes();
            let mut pos = after;
            while pos < bytes.len() && (bytes[pos] as char).is_whitespace() {
                pos += 1;
            }
            if pos < bytes.len() && (bytes[pos] == b'=' || bytes[pos] == b':') {
                pos += 1;
                while pos < bytes.len() && (bytes[pos] as char).is_whitespace() {
                    pos += 1;
                }
                if pos < bytes.len() && (bytes[pos] == b'"' || bytes[pos] == b'\'') {
                    pos += 1;
                }
                let value_start = pos;
                let mut value_end = value_start;
                while value_end < bytes.len() {
                    let c = bytes[value_end];
                    if c == b'&'
                        || c == b'"'
                        || c == b'\''
                        || c == b';'
                        || c == b'\r'
                        || c == b'\n'
                        || (c as char).is_whitespace()
                    {
                        break;
                    }
                    value_end += 1;
                }
                if value_end > value_start {
                    out.replace_range(value_start..value_end, MARK);
                    search = value_start + MARK.len();
                    continue;
                }
            }
            search = after;
            if search >= out.len() {
                break;
            }
        }
    }
    out
}

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

    fn mint_token(&mut self) -> String {
        self.token_counter += 1;
        let mut x = now_nanos() ^ self.token_counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let token = format!("{:016x}", x.wrapping_mul(0x2545_F491_4F6C_DD1D));

        // Keep the known-token set bounded as well.
        if self.tokens.len() >= self.max_interactions.max(1) {
            if let Some(old) = self.tokens.pop_front() {
                self.token_set.remove(&old);
            }
        }
        self.tokens.push_back(token.clone());
        self.token_set.insert(token.clone());
        token
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

async fn run_http(listen: SocketAddr, store: SharedStore) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind HTTP listener {listen}"))?;
    eprintln!("agentbug-collaborator: HTTP listener on {listen}");
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

            let (method, target) = first_request_line(&read);
            let protocol = String::from_utf8_lossy(&read)
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(2))
                .unwrap_or("unknown")
                .to_string();
            let host = header_value(&read, "host");

            let (domain_suffix, full) = {
                let guard = store.lock().unwrap();
                (guard.domain_suffix.clone(), guard.is_full())
            };

            let token = token_from_name(&host, &domain_suffix)
                .unwrap_or("")
                .to_string();

            let body = format!("{ECHO_PREFIX}{token}\n");
            let response = if full {
                b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes()
            };

            if !full {
                let interaction = json!({
                    "type": "http",
                    "token": token,
                    "client_ip": peer.ip().to_string(),
                    "time_stamp": now_nanos(),
                    "protocol": protocol,
                    "method": method,
                    "path": target,
                    "request_b64": redacted_b64(&read),
                    "response_b64": redacted_b64(&response),
                });
                match store.lock().unwrap().record(interaction) {
                    Ok(true) => {}
                    Ok(false) => eprintln!("agentbug-collaborator: interaction cap reached"),
                    Err(err) => eprintln!("agentbug-collaborator: record failed: {err}"),
                }
            }

            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
        });
    }
}

async fn run_dns(listen: SocketAddr, store: SharedStore) -> Result<()> {
    let socket = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("bind DNS listener {listen}"))?;
    eprintln!("agentbug-collaborator: DNS listener on {listen}");
    let mut buf = [0u8; MAX_PACKET];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .context("recv DNS packet")?;
        let packet = &buf[..len];
        let Some(query) = parse_dns_query(packet) else {
            // Malformed packet: drop it rather than panicking or reflecting junk.
            eprintln!("agentbug-collaborator: dropping malformed DNS packet from {peer}");
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
                Ok(false) => eprintln!("agentbug-collaborator: interaction cap reached"),
                Err(err) => eprintln!("agentbug-collaborator: record failed: {err}"),
            }
        }
    }
}

async fn run_admin(listen: SocketAddr, store: SharedStore) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind admin listener {listen}"))?;
    eprintln!("agentbug-collaborator: admin listener on {listen} (loopback only - DO NOT EXPOSE)");
    loop {
        let (mut socket, _peer) = listener.accept().await.context("accept admin connection")?;
        let store = store.clone();
        tokio::spawn(async move {
            let request = tokio::time::timeout(tokio::time::Duration::from_secs(5), async {
                let mut buf = vec![0u8; MAX_PACKET];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                buf.truncate(n);
                buf
            })
            .await
            .unwrap_or_default();
            let (method, target) = first_request_line(&request);

            let response = if method == "POST" && target.split('?').next() == Some("/token") {
                let (token, domain_suffix) = {
                    let mut guard = store.lock().unwrap();
                    let token = guard.mint_token();
                    (token, guard.domain_suffix.clone())
                };
                let body = json!({
                    "token": token,
                    "domain_suffix": domain_suffix,
                    "server_location": domain_suffix,
                })
                .to_string();
                json_response("200 OK", &body)
            } else if method == "GET" && target.split('?').next() == Some("/interactions") {
                let token = query_param(&target, "token");
                let interactions = store.lock().unwrap().interactions_for(&token);
                let body =
                    serde_json::to_string(&interactions).unwrap_or_else(|_| "[]".to_string());
                json_response("200 OK", &body)
            } else {
                json_response("404 Not Found", "{\"error\":\"not_found\"}")
            };
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

    let store = Arc::new(Mutex::new(Store::new(
        domain_suffix,
        cli.public_ip,
        cli.max_interactions,
        Some(cli.out.clone()),
    )?));

    eprintln!(
        "agentbug-collaborator: domain_suffix={} public_ip={} max_interactions={} out={}",
        cli.domain_suffix,
        cli.public_ip,
        cli.max_interactions,
        cli.out.display()
    );

    tokio::try_join!(
        run_http(cli.http_listen, store.clone()),
        run_dns(cli.dns_listen, store.clone()),
        run_admin(cli.admin_listen, store),
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
        let mut store = Store::new(
            "oob.example.com".to_string(),
            Ipv4Addr::new(203, 0, 113, 10),
            2,
            None,
        )
        .unwrap();
        let token = store.mint_token();
        assert!(store.is_known_token(&token));
        assert!(!store.is_known_token("nope"));

        for i in 0..2 {
            let ok = store
                .record(json!({
                    "type": "http",
                    "token": token,
                    "protocol": "HTTP/1.1",
                    "client_ip": "127.0.0.1",
                    "time_stamp": i,
                    "request_b64": "",
                    "response_b64": "",
                }))
                .unwrap();
            assert!(ok);
        }
        assert!(store.is_full());
        let rejected = store.record(json!({"type":"dns", "token": token})).unwrap();
        assert!(!rejected);
        assert_eq!(store.interactions_for(&token).len(), 2);
        assert_eq!(store.total, 2);
        assert!(store.interactions_for("nope").is_empty());
    }

    #[test]
    fn tokens_are_unique_and_reuse_is_bounded() {
        let mut store = Store::new(
            "oob.example.com".to_string(),
            Ipv4Addr::new(203, 0, 113, 10),
            2,
            None,
        )
        .unwrap();
        let a = store.mint_token();
        let b = store.mint_token();
        assert_ne!(a, b);
        assert!(store.is_known_token(&a));
        let _c = store.mint_token();
        // Cap is 2 tokens, so the oldest is no longer known.
        assert!(!store.is_known_token(&a));
        assert!(store.is_known_token(&b));
    }
}
