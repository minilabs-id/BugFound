// Public type aliases/redaction helpers intentionally live below the test module.
#![allow(clippy::items_after_test_module)]

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::time::{sleep, timeout, Duration};

const MAX_OUTPUT_BYTES: usize = 8 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 16 * 1024;
/// One extra chunk of headroom prevents a single borderline chunk from being
/// discarded just because it crosses the cap; we still stop immediately after.
const MAX_HTTP_BODY_SLACK: usize = 8 * 1024;
const MAX_READ_BYTES: u64 = 512 * 1024;
/// Hard ROE caps for `http_fuzz`: at most 200 wordlist items and 200 requests
/// per call. Methods are restricted to non-destructive GET/HEAD/POST.
const MAX_FUZZ_WORDLIST: usize = 200;
const MAX_FUZZ_REQUESTS: usize = 200;
const FUZZ_METHODS: &[&str] = &["GET", "HEAD", "POST"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for arguments. `parameters` is accepted as a serde alias so
    /// provider-shaped payloads deserialize into the same canonical descriptor.
    #[serde(alias = "parameters")]
    pub input_schema: Value,
    /// Tool-supplied hint. Never used as a security decision; the host assigns
    /// capabilities at registration.
    pub risk: String, // read|write|destructive|network
}

impl ToolSpec {
    pub fn new(name: impl Into<String>, description: impl Into<String>, parameters: Value) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema: parameters,
            risk: "safe".to_string(),
        }
    }

    pub fn parameters(&self) -> &Value {
        &self.input_schema
    }

    pub fn into_parameters(self) -> Value {
        self.input_schema
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub ok: bool,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
}

/// Authoritative evidence captured from a real outbound HTTP exchange. The
/// bytes here are stored by core, not trusted from LLM-visible text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCapture {
    pub request: String,
    pub response: String,
    pub canary: String,
}

impl HttpCapture {
    pub fn as_value(&self) -> Value {
        json!({
            "request": self.request,
            "response": self.response,
            "canary": self.canary,
        })
    }
}

/// Extract `(request, response, canary)` from a tool's `structured` value.
/// Accepts either the whole `structured` object (`{"capture": {...}}`) or the
/// capture object itself.
pub fn capture_from_structured(v: &Value) -> Option<(String, String, String)> {
    let capture = v.get("capture").unwrap_or(v);
    let request = capture.get("request")?.as_str()?.to_string();
    let response = capture.get("response")?.as_str()?.to_string();
    let canary = capture.get("canary")?.as_str()?.to_string();
    Some((request, response, canary))
}

/// Operator-supplied policy for tool construction. Defaults keep the runner
/// locked down (no proxy, no trusted local targets, no external tools).
#[derive(Clone, Default)]
pub struct ToolOptions {
    pub allow_proxy: bool,
    pub proxy_url: Option<String>,
    pub trusted_local_targets: Vec<String>,
    pub enable_external_tools: bool,
    pub external_commands: BTreeMap<String, String>,
    /// Inclusive scope entries. When non-empty, a target must match at least
    /// one entry before any request is made.
    pub scope_in: Vec<String>,
    /// Exclusive scope entries. A matching target is always denied.
    pub scope_out: Vec<String>,
    /// When true, external adapters are registered only if their binary is
    /// discovered on PATH.
    pub auto_detect_external: bool,
    /// Full User-Agent override required by an engagement's rules of engagement.
    pub user_agent: Option<String>,
    /// Hard cap on outgoing HTTP requests per second (ROE enforcement).
    pub max_rps: Option<u64>,
    /// When set, only these HTTP methods may be issued (case-insensitive).
    /// Enforced centrally in `HttpRequestTool::run`, so every HTTP-backed tool
    /// (including `validate_poc` and `http_fuzz`) inherits the same gate.
    pub allowed_methods: Option<Vec<String>>,
    /// Shared rolling window used by the rate limiter (Clone/Default friendly).
    pub rate_window: Arc<Mutex<VecDeque<Instant>>>,
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn spec(&self) -> ToolSpec;
    async fn run(&self, input: Value) -> Result<ToolResult>;
}

#[derive(Default, Clone)]
pub struct ToolRegistry {
    tools: BTreeMap<String, Arc<dyn Tool>>,
    /// Host-owned classification frozen at registration. `ToolSpec.risk` is a
    /// tool-supplied hint and must never decide a security action on its own.
    host_risk: BTreeMap<String, String>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
            host_risk: BTreeMap::new(),
        }
    }
    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        let spec = tool.spec();
        self.host_risk.insert(spec.name.clone(), spec.risk.clone());
        self.tools.insert(spec.name, tool);
    }

    /// Register with an explicit host classification (config/plugin paths).
    /// The tool's self-reported `risk` is ignored.
    pub fn register_with_host_risk(&mut self, tool: Arc<dyn Tool>, risk: impl Into<String>) {
        let name = tool.spec().name;
        self.host_risk.insert(name.clone(), risk.into());
        self.tools.insert(name, tool);
    }

    /// Classification decided by the host, not by the tool descriptor.
    pub fn host_risk(&self, name: &str) -> &str {
        self.host_risk
            .get(name)
            .map(String::as_str)
            .unwrap_or("unknown")
    }

    pub fn register_alias(&mut self, name: impl Into<String>, tool: Arc<dyn Tool>) {
        let name = name.into();
        let risk = self
            .host_risk
            .get(&tool.spec().name)
            .cloned()
            .unwrap_or_else(|| tool.spec().risk);
        struct AliasTool {
            name: String,
            inner: Arc<dyn Tool>,
        }
        #[async_trait]
        impl Tool for AliasTool {
            fn spec(&self) -> ToolSpec {
                let mut s = self.inner.spec();
                s.name = self.name.clone();
                s
            }
            async fn run(&self, input: serde_json::Value) -> Result<ToolResult> {
                self.inner.run(input).await
            }
        }
        self.host_risk.insert(name.clone(), risk);
        self.tools
            .insert(name.clone(), Arc::new(AliasTool { name, inner: tool }));
    }
    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.get(name).cloned()
    }
    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.values().map(|t| t.spec()).collect()
    }
}

fn truncate(s: &str) -> String {
    if s.len() <= MAX_OUTPUT_BYTES {
        return s.to_string();
    }
    // Cut on a UTF-8 boundary so multi-byte output cannot panic.
    let mut end = MAX_OUTPUT_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n...[truncated]", &s[..end])
}

/// Only the two harmless local commands may be spawned by the agent. Anything
/// that can read files, spawn tools or reach the network must go through the
/// scoped `http_request`/`dns_lookup` tool instead, where policy is enforced.
fn validate_shell_command(cmd: &str) -> Result<()> {
    const ALLOWED: &[&str] = &["echo", "whoami"];
    let first = cmd.split_whitespace().next().unwrap_or("");
    let exe = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !ALLOWED.contains(&exe.as_str()) {
        anyhow::bail!("command '{exe}' is not in the shell allowlist");
    }
    // Chaining, redirection and expansion characters must never survive into
    // the shell string: a prompt-injected command could otherwise smuggle a
    // second program past the allowlist or read files outside the workspace.
    for ch in [
        '|', ';', '&', '`', '>', '<', '\n', '\r', '!', '=', '/', '\\', ':', '$', '{', '}', '(',
        ')', '[', ']',
    ] {
        if cmd.contains(ch) {
            anyhow::bail!("shell metacharacter '{ch}' is not allowed");
        }
    }
    for seq in ["..", "$("] {
        if cmd.contains(seq) {
            anyhow::bail!("shell sequence '{seq}' is not allowed");
        }
    }
    for token in cmd.split_whitespace() {
        if token.contains('=') || token.contains('!') || looks_like_path(token) {
            anyhow::bail!("argument '{token}' is not allowed");
        }
    }
    Ok(())
}

/// A token that refers to a filesystem path (absolute, relative, home-relative
/// or a bare dot entry). Rejecting these keeps `shell_exec` from being used as
/// a file reader even before other structural checks apply.
fn looks_like_path(token: &str) -> bool {
    token.contains(['/', '\\', ':', '~']) || token.starts_with('.')
}

/// Deny private, loopback, link-local, metadata, CGNAT and other reserved ranges.
/// Bug bounty targets are user-controlled, so only globally routable addresses
/// are allowed to leave the runner.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b)) // CGNAT + metadata
                || (a == 169 && b == 254) // link-local / cloud metadata
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192
                    && ((b == 0 && (c == 0 || c == 2))
                        || (b == 31 && c == 196)
                        || (b == 52 && c == 193)
                        || (b == 88 && c == 99)
                        || (b == 175 && c == 48)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113)
                || a >= 224 // multicast + reserved
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || s[0] == 0x2002 // 2002::/16 6to4 (encodes private IPv4)
                || (s[0] == 0x2001 && s[1] == 0) // 2001::/32 Teredo
                || (s[0] == 0x0064 && s[1] == 0xff9b) // 64:ff9b::/96 NAT64
        }
    }
}

fn is_local_name(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
}

/// Parse one component of an IPv4 authority. Browsers accept decimal, `0x`
/// hexadecimal and leading-zero octal numbers; all three must be decoded so a
/// private address cannot be smuggled past the string checks.
fn parse_ipv4_number(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if part.len() > 1 && part.starts_with('0') {
        return u64::from_str_radix(&part[1..], 8).ok();
    }
    part.parse::<u64>().ok()
}

/// Parse every numeric IPv4 spelling a URL authority may take: a single packed
/// number (`2130706433`, `0x7f000001`, `017700000001`) or a dotted combination
/// whose final component may carry more than one byte (`127.1`). Returns
/// `None` for ordinary hostnames and IPv6 literals.
fn parse_numeric_host_ipv4(host: &str) -> Option<IpAddr> {
    let h = host.trim().trim_matches(['[', ']']).trim_end_matches('.');
    let parts: Vec<&str> = h.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let values: Vec<u64> = parts
        .iter()
        .map(|p| parse_ipv4_number(p))
        .collect::<Option<Vec<_>>>()?;
    let last = values.len() - 1;
    if values[..last].iter().any(|v| *v > u64::from(u8::MAX)) {
        return None;
    }
    let trailing_bytes = 4 - last;
    let max_last = u64::from(u32::MAX >> (8 * (4 - trailing_bytes)));
    if values[last] > max_last {
        return None;
    }
    let high = values[..last]
        .iter()
        .fold(0u32, |acc, v| (acc << 8) | *v as u32);
    let ip = if trailing_bytes == 4 {
        values[last] as u32
    } else {
        (high << (8 * trailing_bytes)) | values[last] as u32
    };
    Some(IpAddr::V4(Ipv4Addr::from(ip)))
}

/// Numeric-address checks that apply even to trusted names. A blocked address
/// is only permitted when that exact IP (or its CIDR/prefix) is trusted.
fn validate_numeric_host(host: &str, trusted: &[String]) -> Result<()> {
    let h = normalize_host(host);
    let Some(ip) = h
        .parse::<IpAddr>()
        .ok()
        .or_else(|| parse_numeric_host_ipv4(&h))
    else {
        return Ok(());
    };
    if is_blocked_ip(ip) && !ip_is_explicitly_trusted(ip, trusted) {
        anyhow::bail!("private/reserved target address is not allowed: {ip}");
    }
    Ok(())
}

/// String-level checks that do not need DNS. Fail closed on anything ambiguous.
fn validate_host_string(host: &str) -> Result<()> {
    let h = normalize_host(host);
    if h.is_empty() {
        anyhow::bail!("url has no host");
    }
    if is_local_name(&h) {
        anyhow::bail!("local/metadata targets are not allowed");
    }
    validate_numeric_host(&h, &[])
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn ipv4_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(base) = base.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(base) & mask
}

/// A trusted entry is an exact host, a `*.suffix` wildcard, an IPv4 address,
/// an IPv4 CIDR block, or a simple dotted IPv4 prefix (e.g. `192.168.1.`).
fn trusted_entry_matches(entry: &str, host: &str) -> bool {
    let trimmed = entry.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    let entry = trimmed.trim_end_matches('.');
    if let Some(suffix) = entry.strip_prefix("*.") {
        return !suffix.is_empty() && host != suffix && host.ends_with(&format!(".{suffix}"));
    }
    if entry.contains('/') {
        return host
            .parse::<Ipv4Addr>()
            .map(|ip| ipv4_in_cidr(ip, entry))
            .unwrap_or(false);
    }
    if let Ok(entry_ip) = entry.parse::<Ipv4Addr>() {
        return host
            .parse::<Ipv4Addr>()
            .map(|ip| ip == entry_ip)
            .unwrap_or(false);
    }
    // A trailing dot is meaningful for a dotted IPv4 prefix, so inspect the
    // untrimmed form here.
    if trimmed.ends_with('.') && trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return host.starts_with(&trimmed);
    }
    entry == host
}

fn host_is_trusted(host: &str, trusted: &[String]) -> bool {
    let host = normalize_host(host);
    trusted
        .iter()
        .any(|entry| trusted_entry_matches(entry, &host))
}

/// Whether an IP itself (not just a hostname resolving to it) was explicitly
/// trusted by the operator. Trusted names do not authorise private IPs.
fn ip_is_explicitly_trusted(ip: IpAddr, trusted: &[String]) -> bool {
    let text = ip.to_string();
    trusted
        .iter()
        .any(|entry| trusted_entry_matches(entry, &text))
}

/// Trust bypasses only the syntactic local-name block. Numeric addresses and
/// every address returned by DNS are still verified independently.
fn validate_host_with_options(host: &str, options: &ToolOptions) -> Result<()> {
    let h = normalize_host(host);
    if h.is_empty() {
        anyhow::bail!("url has no host");
    }
    let trusted = &options.trusted_local_targets;
    if !host_is_trusted(&h, trusted) {
        return validate_host_string(host);
    }
    // A trusted entry bypasses only the local-name block. Numeric addresses
    // are still checked; only an explicitly trusted IP is exempt.
    validate_numeric_host(&h, trusted)
}

/// Reduce a scope target to a comparable host string. URLs are reduced to
/// their host so scope entries can stay host-oriented.
fn normalize_scope_target(target: &str) -> String {
    let trimmed = target.trim();
    if trimmed.contains("://") {
        if let Ok(parsed) = url::Url::parse(trimmed) {
            if let Some(host) = parsed.host_str() {
                return normalize_host(host);
            }
        }
    }
    normalize_host(trimmed)
}

/// One scope entry against one normalized target. Supports exact hosts,
/// plain suffixes (including a leading dot), `*.suffix` wildcards and IPv4
/// CIDR blocks.
fn scope_entry_matches(entry: &str, target: &str) -> bool {
    let entry = entry.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    let entry = entry.trim_end_matches('.');
    if entry.is_empty() {
        return false;
    }
    if let Some(suffix) = entry.strip_prefix("*.") {
        return !suffix.is_empty() && target != suffix && target.ends_with(&format!(".{suffix}"));
    }
    if entry.contains('/') {
        return target
            .parse::<Ipv4Addr>()
            .map(|ip| ipv4_in_cidr(ip, entry))
            .unwrap_or(false);
    }
    if let Some(suffix) = entry.strip_prefix('.') {
        return !suffix.is_empty() && (target == suffix || target.ends_with(&format!(".{suffix}")));
    }
    let ip_match = entry
        .parse::<Ipv4Addr>()
        .map(|entry_ip| {
            target
                .parse::<Ipv4Addr>()
                .map(|ip| ip == entry_ip)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    ip_match || target == entry || target.ends_with(&format!(".{entry}"))
}

/// Decide whether `target` is permitted by an inclusive/exclusive scope.
/// Exclusive entries always win. An empty inclusive list allows any target
/// that is not explicitly excluded.
pub fn scope_target_allowed(target: &str, in_scope: &[String], out_of_scope: &[String]) -> bool {
    let target = normalize_scope_target(target);
    if target.is_empty() {
        return false;
    }
    if out_of_scope
        .iter()
        .any(|entry| scope_entry_matches(entry, &target))
    {
        return false;
    }
    in_scope.is_empty()
        || in_scope
            .iter()
            .any(|entry| scope_entry_matches(entry, &target))
}

/// Resolve a trusted host. Trust only bypasses the syntactic `.local`/
/// `localhost` block; every returned address is still verified, and only an
/// explicitly trusted IP is allowed to be private/reserved.
async fn resolve_trusted_host(host: &str, options: &ToolOptions) -> Result<std::net::SocketAddr> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("resolve trusted host {host}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("trusted host resolved to no addresses: {host}");
    }
    for addr in &addrs {
        if is_blocked_ip(addr.ip())
            && !ip_is_explicitly_trusted(addr.ip(), &options.trusted_local_targets)
        {
            anyhow::bail!(
                "trusted host resolved to a non-trusted private/reserved address: {}",
                addr.ip()
            );
        }
    }
    Ok(addrs[0])
}

/// Resolve every address before connecting and pin the request to a validated IP.
/// This closes the DNS-rebinding/TOCTOU gap between validation and connection.
async fn resolve_public_ip(host: &str) -> Result<std::net::SocketAddr> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("resolve target host {host}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("target host resolved to no addresses: {host}");
    }
    for addr in &addrs {
        if is_blocked_ip(addr.ip()) {
            anyhow::bail!(
                "target resolves to a private/reserved address: {}",
                addr.ip()
            );
        }
    }
    Ok(addrs[0])
}

fn resolve_cwd(cwd: impl AsRef<Path>) -> Result<PathBuf> {
    let cwd = cwd.as_ref().to_path_buf();
    let canon = cwd
        .canonicalize()
        .with_context(|| format!("invalid cwd: {}", cwd.display()))?;
    if !canon.is_dir() {
        anyhow::bail!("cwd is not a directory: {}", canon.display());
    }
    Ok(canon)
}

fn resolve_in_cwd(cwd: &Path, rel: &str, must_exist: bool, for_write: bool) -> Result<PathBuf> {
    // Reject traversal and absolute paths lexically, before touching the FS.
    let rel_path = Path::new(rel);
    if rel_path.is_absolute()
        || rel_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        anyhow::bail!("path escapes workspace root");
    }
    let p = cwd.join(rel_path);
    let canon_cwd = cwd.canonicalize().unwrap_or(cwd.to_path_buf());
    let canon = if p.exists() {
        p.canonicalize().context("canonicalize path")?
    } else {
        if must_exist || !for_write {
            anyhow::bail!("path not found: {rel}");
        }
        let parent = p.parent().ok_or_else(|| anyhow!("bad path"))?;
        // Validate the deepest existing ancestor before creating anything. A
        // symlinked parent must not let us create directories outside cwd.
        let mut ancestor = parent;
        while !ancestor.exists() {
            ancestor = ancestor.parent().ok_or_else(|| anyhow!("bad path"))?;
        }
        if !ancestor
            .canonicalize()
            .context("canonicalize ancestor")?
            .starts_with(&canon_cwd)
        {
            anyhow::bail!("path escapes workspace root");
        }
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
        parent
            .canonicalize()
            .context("canonicalize parent")?
            .join(p.file_name().ok_or_else(|| anyhow!("bad file name"))?)
    };
    if !canon.starts_with(&canon_cwd) {
        anyhow::bail!("path escapes workspace root");
    }
    Ok(canon)
}

pub struct FsReadTool {
    cwd: PathBuf,
}
impl FsReadTool {
    pub fn new(cwd: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            cwd: resolve_cwd(cwd)?,
        })
    }
}
#[async_trait]
impl Tool for FsReadTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "fs_read".into(),
            description: "Read a UTF-8 text file from the workspace (confined to cwd). Returns truncated content (512KB max).".into(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string","description":"Workspace-relative file path"}},"required":["path"]}),
            risk: "read".into(),
        }
    }
    async fn run(&self, input: Value) -> Result<ToolResult> {
        let path = input
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("path required"))?;
        let full = resolve_in_cwd(&self.cwd, path, true, false)?;
        let meta = tokio::fs::metadata(&full).await.context("stat file")?;
        if meta.len() > MAX_READ_BYTES {
            anyhow::bail!(
                "file too large ({} bytes, limit {}): {}",
                meta.len(),
                MAX_READ_BYTES,
                path
            );
        }
        let data = tokio::fs::read(&full).await.context("read file")?;
        let mut out = redact(&String::from_utf8_lossy(&data));
        if out.is_empty() {
            out = "(empty file)".into();
        }
        Ok(ToolResult {
            ok: true,
            output: truncate(&out),
            structured: None,
        })
    }
}

/// Pass only what a child process needs to start; never inherit secrets such
/// as DATABASE_URL or program API tokens.
fn safe_process_env() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    std::env::vars_os()
        .filter(|(k, _)| {
            let key = k.to_string_lossy().to_ascii_uppercase();
            [
                "PATH",
                "PATHEXT",
                "SYSTEMROOT",
                "COMSPEC",
                "TEMP",
                "TMP",
                "LANG",
                "LC_ALL",
            ]
            .iter()
            .any(|allowed| *allowed == key)
        })
        .collect()
}

pub struct ShellExecTool {
    cwd: PathBuf,
}
impl ShellExecTool {
    pub fn new(cwd: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            cwd: resolve_cwd(cwd)?,
        })
    }
}
#[async_trait]
impl Tool for ShellExecTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "shell_exec".into(),
            description: "Execute an allowlisted trivial shell command (echo/whoami) in the workspace cwd (30s timeout, 8KB output cap). Not a general shell.".into(),
            input_schema: json!({"type":"object","properties":{"cmd":{"type":"string","description":"Shell command to run in workspace cwd"}},"required":["cmd"]}),
            risk: "exec".into(),
        }
    }
    async fn run(&self, input: Value) -> Result<ToolResult> {
        let cmd = input
            .get("cmd")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("cmd required"))?
            .trim()
            .to_string();
        if cmd.is_empty() {
            anyhow::bail!("cmd required");
        }
        // Allowlist, not denylist: only a few local, non-network commands are
        // permitted. Chaining/substitution is rejected so a prompt-injected
        // command cannot smuggle a second program past the allowlist.
        validate_shell_command(&cmd)?;
        let env = safe_process_env();
        #[cfg(windows)]
        let mut c = {
            let mut c = Command::new("cmd");
            c.arg("/C").arg(&cmd);
            c
        };
        #[cfg(not(windows))]
        let mut c = {
            let mut c = Command::new("sh");
            c.arg("-lc").arg(&cmd);
            c
        };
        c.current_dir(&self.cwd)
            .env_clear()
            .envs(env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = timeout(Duration::from_secs(30), c.output())
            .await
            .context("command timeout (30s)")??;
        let stdout = redact(&String::from_utf8_lossy(&out.stdout));
        let stderr = redact(&String::from_utf8_lossy(&out.stderr));
        let code = out.status.code().unwrap_or(-1);
        let text = format!(
            "exit={code}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            stdout, stderr
        );
        Ok(ToolResult {
            ok: out.status.success(),
            output: truncate(&text),
            structured: Some(json!({"exit_code": code, "success": out.status.success()})),
        })
    }
}

pub struct HttpRequestTool {
    client: reqwest::Client,
    options: ToolOptions,
}
impl Default for HttpRequestTool {
    fn default() -> Self {
        Self::new()
    }
}

/// Proxy is opt-in. Without a usable configured proxy we disable all proxies
/// so a system proxy cannot resolve the hostname and bypass our DNS pin.
fn apply_proxy(builder: reqwest::ClientBuilder, options: &ToolOptions) -> reqwest::ClientBuilder {
    if options.allow_proxy {
        if let Some(url) = options.proxy_url.as_deref() {
            if let Ok(proxy) = reqwest::Proxy::all(url) {
                return builder.proxy(proxy);
            }
        }
    }
    builder.no_proxy()
}

fn build_http_client(options: &ToolOptions) -> reqwest::Client {
    let ua = options.user_agent.as_deref().unwrap_or("agentbug/0.1");
    let builder = apply_proxy(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            // Redirects are disabled: following one could land on an internal
            // address that passed validation only for the original target.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(ua),
        options,
    );
    builder.build().unwrap_or_else(|_| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent(ua)
            .build()
            .expect("http client")
    })
}

/// Consume a response body one chunk at a time, accumulating at most the cap
/// (plus a small slack for the chunk that crosses it). This avoids buffering an
/// unbounded response in memory the way `resp.bytes()` would. Returns the bytes
/// collected so far and whether the body was truncated at the cap.
async fn read_body_capped(
    resp: &mut reqwest::Response,
    read_timeout: Duration,
) -> Result<(Vec<u8>, bool)> {
    let cap = MAX_HTTP_BODY_BYTES + MAX_HTTP_BODY_SLACK;
    let mut body = Vec::with_capacity(MAX_HTTP_BODY_BYTES);
    while let Some(chunk) = timeout(read_timeout, resp.chunk())
        .await
        .context("read body timeout")??
    {
        if body.len() + chunk.len() > cap {
            return Ok((body, true));
        }
        body.extend_from_slice(&chunk);
        if body.len() > MAX_HTTP_BODY_BYTES {
            return Ok((body, true));
        }
    }
    Ok((body, false))
}

/// Wait until an outgoing request fits inside the configured ROE rate limit.
async fn obey_rate_limit(options: &ToolOptions) {
    let Some(max_rps) = options.max_rps.filter(|value| *value > 0) else {
        return;
    };
    loop {
        let wait = {
            let mut window = options.rate_window.lock().unwrap();
            let now = Instant::now();
            window.retain(|at| now.duration_since(*at) < Duration::from_secs(1));
            if window.len() < max_rps as usize {
                window.push_back(now);
                None
            } else {
                window
                    .front()
                    .map(|at| Duration::from_secs(1) - now.duration_since(*at))
            }
        };
        match wait {
            None => return,
            Some(delay) => sleep(delay.max(Duration::from_millis(1))).await,
        }
    }
}

/// Proxy configuration is operator-supplied and must stay local. Anything
/// other than an http(s) proxy on a concrete loopback host is rejected in
/// `run()` so a bad configuration cannot silently route scoped traffic off-box.
/// `0.0.0.0` is rejected: it is a wildcard bind address, not a loopback
/// destination. A configured proxy is a trusted egress boundary where DNS
/// pinning does not apply, so scope and host validation are always enforced
/// in code before a proxied request is issued.
fn validate_proxy_url(options: &ToolOptions) -> Result<()> {
    if !options.allow_proxy {
        return Ok(());
    }
    let Some(raw) = options.proxy_url.as_deref() else {
        return Ok(());
    };
    let parsed = url::Url::parse(raw).context("invalid proxy_url")?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => anyhow::bail!("proxy_url must use http or https"),
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("proxy_url has no host"))?;
    let host = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
        Ok(())
    } else {
        anyhow::bail!("proxy_url host must be loopback, got '{host}'")
    }
}

/// A fail-closed denial returned as a structured `ToolResult` rather than an
/// error, so callers can inspect the machine-readable reason.
fn denial_result(reason: &str, fields: Value) -> ToolResult {
    let mut map = serde_json::Map::new();
    map.insert("ok".into(), Value::Bool(false));
    map.insert("error".into(), Value::String(reason.to_string()));
    if let Value::Object(extra) = fields {
        for (key, value) in extra {
            map.insert(key, value);
        }
    }
    ToolResult {
        ok: false,
        output: truncate(reason),
        structured: Some(Value::Object(map)),
    }
}

/// Render the outbound request in HTTP wire form. This is the authoritative
/// request representation pinned into `HttpCapture`.
fn build_request_repr(
    method: &str,
    url: &url::Url,
    options: &ToolOptions,
    headers: Option<&serde_json::Map<String, Value>>,
    body: Option<&str>,
) -> String {
    let host = url.host_str().unwrap_or("");
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let mut text = format!(
        "{method} {target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n",
        options.user_agent.as_deref().unwrap_or("agentbug/0.1")
    );
    if let Some(headers) = headers {
        for (name, value) in headers {
            if let Some(value) = value.as_str() {
                text.push_str(&format!("{name}: {value}\r\n"));
            }
        }
    }
    text.push_str("\r\n");
    if let Some(body) = body {
        text.push_str(body);
    }
    text
}

/// Render the selected response headers and capped body in HTTP wire form.
fn build_response_repr(
    status: u16,
    headers: &serde_json::Map<String, Value>,
    body: &str,
) -> String {
    let reason = reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason().map(str::to_string))
        .unwrap_or_default();
    let mut text = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers {
        text.push_str(&format!("{}: {}\r\n", name, value.as_str().unwrap_or("")));
    }
    text.push_str("\r\n");
    text.push_str(body);
    text
}

/// Mint the capture canary from the exact request bytes plus a fresh nanosecond
/// nonce. The nonce makes the token unguessable by the model: only the tool can
/// mint one, and core stores the resulting bytes as evidence.
fn canary_for(request: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut input = request.as_bytes().to_vec();
    input.extend_from_slice(&nanos.to_be_bytes());
    format!("agentbug-canary-{}", hex_encode(&Sha256::digest(&input)))
}

fn build_capture(request: String, response: String, canary: String) -> HttpCapture {
    HttpCapture {
        request,
        response,
        canary,
    }
}

impl HttpRequestTool {
    pub fn new() -> Self {
        Self::with_options(ToolOptions::default())
    }

    pub fn with_options(options: ToolOptions) -> Self {
        let client = build_http_client(&options);
        Self { client, options }
    }
}
#[async_trait]
impl Tool for HttpRequestTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "http_request".into(),
            description: "Perform an HTTP request to an in-scope target for reconnaissance/validation. Returns status, selected headers, a truncated body, and a byte-authoritative capture (request/response/canary). An unguessable X-AgentBug-Canary header is injected into the real request and scrubbed from the model-visible output; the verifier requires the target to reflect it. Localhost/.local/metadata targets are blocked; engagement scope and allowed_methods are enforced in code. A configured proxy is a trusted egress boundary where DNS pinning does not apply, so scope and host validation still run before any request.".into(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "url":{"type":"string","description":"Absolute http/https URL"},
                    "method":{"type":"string","enum":["GET","HEAD","POST","PUT","DELETE","OPTIONS"],"default":"GET"},
                    "headers":{"type":"object","additionalProperties":{"type":"string"}},
                    "body":{"type":"string"},
                    "timeout_ms":{"type":"integer","default":15000}
                },
                "required":["url"]
            }),
            risk: "network".into(),
        }
    }
    async fn run(&self, input: Value) -> Result<ToolResult> {
        let url = input
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("url required"))?;
        let parsed = url::Url::parse(url).context("invalid url")?;
        match parsed.scheme() {
            "http" | "https" => {}
            _ => anyhow::bail!("only http/https allowed"),
        }
        let method = input
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_ascii_uppercase();
        // Central ROE method gate. Every HTTP-backed tool goes through this
        // method, so the decision is inherited by validate_poc/http_fuzz/etc.
        if let Some(allowed) = &self.options.allowed_methods {
            if !allowed.iter().any(|m| m.eq_ignore_ascii_case(&method)) {
                return Ok(denial_result(
                    "method_not_allowed",
                    json!({"method": method, "allowed_methods": allowed}),
                ));
            }
        }
        // Validate the proxy configuration and engagement scope before any
        // network work. Scope is enforced in code even when a proxy is in use,
        // because the DNS pin below does not apply to proxied requests.
        validate_proxy_url(&self.options)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("url has no host"))?;
        if !scope_target_allowed(host, &self.options.scope_in, &self.options.scope_out) {
            anyhow::bail!("target '{host}' is not permitted by scope policy");
        }
        validate_host_with_options(host, &self.options)?;
        let pinned_ip = if host.parse::<IpAddr>().is_ok() {
            None
        } else if host_is_trusted(host, &self.options.trusted_local_targets) {
            Some(resolve_trusted_host(host, &self.options).await?)
        } else {
            Some(resolve_public_ip(host).await?)
        };
        // Pin the connection to the IP we validated; the TLS SNI and Host header
        // still use the original hostname.
        let client = if let Some(ip) = pinned_ip {
            apply_proxy(
                reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .redirect(reqwest::redirect::Policy::none())
                    .user_agent(self.options.user_agent.as_deref().unwrap_or("agentbug/0.1"))
                    .resolve(host, ip),
                &self.options,
            )
            .build()
            .context("build pinned http client")?
        } else {
            self.client.clone()
        };
        let timeout_ms = input
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(15_000)
            .min(30_000);
        let mut req = match method.as_str() {
            "GET" => client.get(parsed.clone()),
            "HEAD" => client.head(parsed.clone()),
            "POST" => client.post(parsed.clone()),
            "PUT" => client.put(parsed.clone()),
            "DELETE" => client.delete(parsed.clone()),
            "OPTIONS" => client.request(reqwest::Method::OPTIONS, parsed.clone()),
            _ => {
                return Ok(denial_result(
                    "unsupported_method",
                    json!({"method": method}),
                ))
            }
        };
        if let Some(hs) = input.get("headers").and_then(|v| v.as_object()) {
            for (k, v) in hs {
                if let Some(vs) = v.as_str() {
                    req = req.header(k, vs);
                }
            }
        }
        if let Some(body) = input.get("body").and_then(|v| v.as_str()) {
            req = req.body(body.to_string());
        }
        // Build the authoritative request bytes before the send so both the
        // success and error paths can pin the same evidence.
        let mut request_repr = build_request_repr(
            &method,
            &parsed,
            &self.options,
            input.get("headers").and_then(|v| v.as_object()),
            input.get("body").and_then(|v| v.as_str()),
        );
        // Mint once and actually transmit the canary. The verifier requires the
        // target to reflect it, so a token that is only stored as evidence can
        // never be satisfied by a real response. Keep it out of the LLM-visible
        // output; it lives only in the outbound request and the capture.
        let canary = canary_for(&request_repr);
        request_repr = request_repr.replacen(
            "\r\n\r\n",
            &format!("\r\nX-AgentBug-Canary: {canary}\r\n\r\n"),
            1,
        );
        req = req.header("X-AgentBug-Canary", &canary);
        obey_rate_limit(&self.options).await;
        let mut resp = match timeout(Duration::from_millis(timeout_ms), req.send()).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(err)) => {
                let message = redact(&err.to_string());
                let capture =
                    build_capture(request_repr, format!("(no response) {message}"), canary);
                let mut structured = json!({"ok": false, "error": message});
                structured["capture"] = capture.as_value();
                return Ok(ToolResult {
                    ok: false,
                    output: truncate(&format!("http request failed: {message}")),
                    structured: Some(structured),
                });
            }
            Err(_) => {
                let capture =
                    build_capture(request_repr, "(no response) http timeout".into(), canary);
                let mut structured = json!({"ok": false, "error": "http timeout"});
                structured["capture"] = capture.as_value();
                return Ok(ToolResult {
                    ok: false,
                    output: "http timeout".into(),
                    structured: Some(structured),
                });
            }
        };
        let status = resp.status().as_u16();
        let mut headers = serde_json::Map::new();
        for (k, v) in resp.headers().iter().take(40) {
            let value = v
                .to_str()
                .unwrap_or("<binary>")
                .chars()
                .take(200)
                .collect::<String>();
            headers.insert(k.to_string(), Value::String(redact(&value)));
        }
        let (bytes, truncated) =
            match read_body_capped(&mut resp, Duration::from_millis(timeout_ms)).await {
                Ok(value) => value,
                Err(err) => {
                    let message = redact(&err.to_string());
                    let capture = build_capture(
                        request_repr,
                        build_response_repr(status, &headers, &format!("(read error) {message}")),
                        canary,
                    );
                    let mut structured = json!({"ok": false, "status": status, "error": message});
                    structured["capture"] = capture.as_value();
                    return Ok(ToolResult {
                        ok: false,
                        output: truncate(&format!("http read failed: {message}")),
                        structured: Some(structured),
                    });
                }
            };
        let slice = &bytes[..bytes.len().min(MAX_HTTP_BODY_BYTES)];
        let body_text = redact(&String::from_utf8_lossy(slice));
        let ok = (200..400).contains(&status);
        // A reflecting target echoes the injected canary into headers/body.
        // Keep the real bytes in `capture` for the verifier, but scrub the
        // token from the LLM-visible output so the model never learns it.
        let scrub = |value: &str| value.replace(&canary, "<redacted-canary>");
        let out_headers: serde_json::Map<String, Value> = headers
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    Value::String(scrub(value.as_str().unwrap_or(""))),
                )
            })
            .collect();
        let out = json!({
            "ok": ok,
            "url": parsed.to_string(),
            "status": status,
            "headers": out_headers,
            "body": scrub(&body_text),
            "body_truncated": truncated,
            "body_bytes": bytes.len()
        });
        let capture = build_capture(
            request_repr,
            build_response_repr(status, &headers, &body_text),
            canary,
        );
        let mut structured = out.clone();
        structured["capture"] = capture.as_value();
        Ok(ToolResult {
            ok,
            output: truncate(&out.to_string()),
            structured: Some(structured),
        })
    }
}

/// Pure verdict logic for PoC validation. Kept public so it can be tested
/// without performing any network request.
pub fn poc_verdict(status: u16, expected: u16, marker_found: bool, marker_required: bool) -> bool {
    status == expected && (!marker_required || marker_found)
}

/// Validate a proof-of-concept: replay a request through the scoped HTTP tool
/// and check the response status and optional body marker.
pub struct ValidatePoCTool {
    http: HttpRequestTool,
}

impl ValidatePoCTool {
    pub fn new() -> Self {
        Self::with_options(ToolOptions::default())
    }

    pub fn with_options(options: ToolOptions) -> Self {
        Self {
            http: HttpRequestTool::with_options(options),
        }
    }
}

impl Default for ValidatePoCTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for ValidatePoCTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "validate_poc".into(),
            description: "Replay a proof-of-concept request and validate its status code and optional response marker.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Id of the finding this advisory result belongs to"},
                    "url": {"type": "string", "description": "Absolute http/https URL to validate"},
                    "method": {"type": "string", "enum": ["GET","HEAD","POST","PUT","DELETE","OPTIONS"], "default": "GET"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"},
                    "expected_status": {"type": "number", "default": 200},
                    "marker": {"type": "string", "description": "Substring that must appear in the response body"}
                },
                "required": ["finding_id", "url"]
            }),
            risk: "network-write".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let Some(finding_id) = input
            .get("finding_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            return Ok(ToolResult {
                ok: false,
                output: "finding_id required".into(),
                structured: Some(json!({"valid": false, "error": "finding_id required"})),
            });
        };
        let url = input
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("url required"))?;
        let method = input
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");
        let expected_status = input
            .get("expected_status")
            .and_then(|v| v.as_u64())
            .unwrap_or(200);
        let expected_status =
            u16::try_from(expected_status).context("expected_status out of range")?;
        let marker = input.get("marker").and_then(|v| v.as_str());

        // Replay exactly what was supplied: headers and body are part of the
        // proof-of-concept and must reach the request, not just the URL/method.
        let mut replay = json!({"url": url, "method": method});
        if let Some(headers) = input.get("headers") {
            replay["headers"] = headers.clone();
        }
        if let Some(body) = input.get("body") {
            replay["body"] = body.clone();
        }
        let response = self.http.run(replay).await?;
        // Tool-minted benign control: same endpoint and method, but a distinct
        // local label in the request. The HTTP tool derives a fresh canary from
        // the request bytes, so the benign and payload captures can never share
        // a marker. The model never supplies or sees the benign label.
        let benign_label = format!(
            "benign-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let mut benign_replay = json!({"url": url, "method": method});
        if let Some(headers) = input.get("headers") {
            benign_replay["headers"] = headers.clone();
        }
        if benign_replay.get("headers").is_none() {
            benign_replay["headers"] = json!({});
        }
        benign_replay["headers"]["X-AgentBug-Control"] = json!(benign_label);
        if let Some(body) = input.get("body") {
            benign_replay["body"] = body.clone();
        }
        let benign_response = self.http.run(benign_replay).await.ok();
        let status = response
            .structured
            .as_ref()
            .and_then(|v| v.get("status"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let status = u16::try_from(status).unwrap_or(0);
        let body = response
            .structured
            .as_ref()
            .and_then(|v| v.get("body"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let marker_found = marker.map(|m| body.contains(m)).unwrap_or(false);
        let valid =
            response.ok && poc_verdict(status, expected_status, marker_found, marker.is_some());

        // Advisory only: a caller-supplied expected_status/marker is not an
        // authoritative oracle. Core runs an independent canary verifier and
        // is solely responsible for promoting a finding; this verdict never
        // changes finding state.
        let mut structured = json!({
            "advisory": true,
            "finding_id": finding_id,
            "valid": valid,
            "status": status,
            "marker_found": marker_found,
            "url": url,
        });
        // Forward the authoritative capture (and any ROE denial reason) from
        // the replay so core can pin the exact bytes as finding evidence.
        if let Some(http_structured) = response.structured.as_ref() {
            if let Some(capture) = http_structured.get("capture") {
                structured["capture"] = capture.clone();
                if let Some(benign) = benign_response
                    .as_ref()
                    .and_then(|r| r.structured.as_ref().and_then(|v| v.get("capture")))
                {
                    structured["paired_capture"] = json!({
                        "benign": benign,
                        "payload": capture,
                    });
                }
            }
            if let Some(error) = http_structured.get("error") {
                structured["error"] = error.clone();
            }
        }
        let output = if valid {
            format!(
                "Advisory PoC result for finding {finding_id} ({url}): status {status}, marker found: {marker_found}. Independent verification required."
            )
        } else {
            format!(
                "Advisory PoC result for finding {finding_id} ({url}): status {status} (expected {expected_status}), ok={}, marker found: {marker_found}. Independent verification required.",
                response.ok
            )
        };
        Ok(ToolResult {
            ok: valid,
            output: truncate(&output),
            structured: Some(structured),
        })
    }
}

pub struct DnsLookupTool {
    timeout_ms: u64,
    options: ToolOptions,
}
impl DnsLookupTool {
    pub fn new() -> Self {
        Self::new_with_options(ToolOptions::default())
    }

    /// Construct the resolver with engagement scope and host policy. Both are
    /// applied before the lookup, and every returned address is re-checked.
    pub fn new_with_options(options: ToolOptions) -> Self {
        Self {
            timeout_ms: 10000,
            options,
        }
    }
}
impl Default for DnsLookupTool {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl Tool for DnsLookupTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "dns_lookup".into(),
            description: "Resolve a hostname to IP addresses.".into(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "host":{"type":"string"},
                    "domain":{"type":"string"},
                    "name":{"type":"string"},
                    "target":{"type":"string"}
                },
                "required":[]
            }),
            risk: "network".into(),
        }
    }
    async fn run(&self, input: Value) -> Result<ToolResult> {
        let host = input
            .get("host")
            .or_else(|| input.get("domain"))
            .or_else(|| input.get("name"))
            .or_else(|| input.get("target"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing host"))?;
        let host = host.trim();
        let host_key = normalize_scope_target(host);
        if !scope_target_allowed(&host_key, &self.options.scope_in, &self.options.scope_out) {
            return Ok(denial_result(
                "target_not_in_scope",
                json!({"host": host, "target": host_key}),
            ));
        }
        if let Err(err) = validate_host_with_options(&host_key, &self.options) {
            return Ok(denial_result(
                "host_not_allowed",
                json!({"host": host, "reason": redact(&err.to_string())}),
            ));
        }
        let target = format!(
            "{}:0",
            host.trim_start_matches("http://")
                .trim_start_matches("https://")
        );
        let fut = tokio::net::lookup_host(&target);
        let addrs = tokio::time::timeout(std::time::Duration::from_millis(self.timeout_ms), fut)
            .await
            .context("dns timeout")??;
        let mut ips: Vec<String> = Vec::new();
        let mut blocked: Vec<String> = Vec::new();
        for addr in addrs {
            let ip = addr.ip();
            if is_blocked_ip(ip)
                && !ip_is_explicitly_trusted(ip, &self.options.trusted_local_targets)
            {
                blocked.push(ip.to_string());
            }
            ips.push(ip.to_string());
        }
        ips.sort();
        ips.dedup();
        blocked.sort();
        blocked.dedup();
        if !blocked.is_empty() {
            return Ok(ToolResult {
                ok: false,
                output: truncate(&format!(
                    "resolved {host} to blocked addresses: {}",
                    blocked.join(", ")
                )),
                structured: Some(json!({
                    "host": host,
                    "ips": ips,
                    "blocked_ips": blocked,
                    "error": "blocked_ip",
                })),
            });
        }
        let out = if ips.is_empty() {
            format!("no addresses resolved for {host}")
        } else {
            format!("resolved {host}: {}", ips.join(", "))
        };
        Ok(ToolResult {
            ok: !ips.is_empty(),
            output: truncate(&out),
            structured: Some(json!({"host": host, "ips": ips})),
        })
    }
}

pub struct FsWriteTool {
    cwd: PathBuf,
}
impl FsWriteTool {
    pub fn new(cwd: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            cwd: resolve_cwd(cwd)?,
        })
    }
}
#[async_trait]
impl Tool for FsWriteTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "fs_write".into(),
            description: "Write text content to a workspace-relative file path.".into(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "path":{"type":"string"},
                    "content":{"type":"string"},
                    "append":{"type":"boolean"}
                },
                "required":["path","content"]
            }),
            risk: "write".into(),
        }
    }
    async fn run(&self, input: Value) -> Result<ToolResult> {
        let path = input
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing path"))?;
        let content = input
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing content"))?;
        let append = input
            .get("append")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let resolved = resolve_in_cwd(&self.cwd, path, false, true)?;
        if let Some(parent) = resolved.parent() {
            std::fs::create_dir_all(parent).context("create parent dirs")?;
        }
        use std::io::Write;
        if append {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&resolved)
                .context("open file")?;
            f.write_all(content.as_bytes()).context("write file")?;
        } else {
            std::fs::write(&resolved, content).context("write file")?;
        }
        let bytes = content.len();
        Ok(ToolResult {
            ok: true,
            output: truncate(&format!("wrote {bytes} bytes to {path}")),
            structured: Some(json!({"path": path, "bytes": bytes, "append": append})),
        })
    }
}

pub struct SaveFindingTool;
#[async_trait]
impl Tool for SaveFindingTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "save_finding".into(),
            description: "Record a validated security finding for the current session/report. Provide clear evidence and reproduction steps.".into(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "title":{"type":"string"},
                    "severity":{"type":"string","enum":["info","low","medium","high","critical"]},
                    "asset":{"type":"string"},
                    "vuln_type":{"type":"string"},
                    "description":{"type":"string"},
                    "reproduction":{"type":"string"},
                    "impact":{"type":"string"},
                    "remediation":{"type":"string"},
                    "evidence":{"type":"string"},
                    "request":{"type":"string"},
                    "response":{"type":"string"},
                    "cvss":{"type":"string"},
                    "cwe":{"type":"string"}
                },
                "required":["title","severity","description"]
            }),
            risk: "write".into(),
        }
    }
    async fn run(&self, input: Value) -> Result<ToolResult> {
        let title = input
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("(untitled)");
        let sev = input
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("info");
        Ok(ToolResult {
            ok: true,
            output: truncate(&format!(
                "finding recorded (persisted by runner): [{sev}] {title}"
            )),
            structured: Some(input),
        })
    }
}

pub struct RecordAssetTool;
#[async_trait]
impl Tool for RecordAssetTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "record_asset".into(),
            description: "Record or update a discovered in-scope asset (host, url, endpoint, ip, service, parameter, etc.) for the session.".into(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "kind":{"type":"string"},
                    "value":{"type":"string"},
                    "metadata":{"type":"object"}
                },
                "required":["kind","value"]
            }),
            risk: "write".into(),
        }
    }
    async fn run(&self, input: Value) -> Result<ToolResult> {
        let kind = input
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("asset");
        let value = input.get("value").and_then(|v| v.as_str()).unwrap_or("");
        Ok(ToolResult {
            ok: true,
            output: truncate(&format!(
                "asset recorded (persisted by runner): {kind}={value}"
            )),
            structured: Some(input),
        })
    }
}

pub struct SaveArtifactTool {
    cwd: PathBuf,
}
impl SaveArtifactTool {
    pub fn new(cwd: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            cwd: resolve_cwd(cwd)?,
        })
    }
}
#[async_trait]
impl Tool for SaveArtifactTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "save_artifact".into(),
            description: "Save evidence/output as an artifact record. Optionally write content to a workspace-relative file path.".into(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "kind":{"type":"string"},
                    "path":{"type":"string"},
                    "content":{"type":"string"},
                    "metadata":{"type":"object"}
                },
                "required":["kind"]
            }),
            risk: "write".into(),
        }
    }
    async fn run(&self, input: Value) -> Result<ToolResult> {
        let kind = input.get("kind").and_then(|v| v.as_str()).unwrap_or("note");
        let path = input.get("path").and_then(|v| v.as_str());
        let content = input.get("content").and_then(|v| v.as_str());
        let mut written: Option<String> = None;
        if let (Some(p), Some(c)) = (path, content) {
            let full = resolve_in_cwd(&self.cwd, p, false, true)?;
            tokio::fs::write(&full, c)
                .await
                .with_context(|| format!("write {}", full.display()))?;
            written = Some(p.to_string());
        }
        let out = json!({"ok":true,"kind":kind,"path":written,"bytes":content.map(|c| c.len()).unwrap_or(0)});
        Ok(ToolResult {
            ok: true,
            output: truncate(&out.to_string()),
            structured: Some(
                json!({"kind": kind, "path": written, "content": content.map(|s| s.to_string()), "metadata": input.get("metadata").cloned()}),
            ),
        })
    }
}

pub struct EchoTool;
#[async_trait]
impl Tool for EchoTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "echo".into(),
            description: "Echo back the provided text (safe).".into(),
            input_schema: json!({
                "type":"object",
                "properties":{"text":{"type":"string"}},
                "required":["text"]
            }),
            risk: "safe".into(),
        }
    }
    async fn run(&self, input: Value) -> Result<ToolResult> {
        let text = input.get("text").and_then(|v| v.as_str()).unwrap_or("");
        Ok(ToolResult {
            ok: true,
            output: text.to_string(),
            structured: Some(json!({"text": text})),
        })
    }
}

/// Chain pre-registered tools into a recon pipeline. Each step receives the
/// previous step's first non-empty output line as its `target`. No shell and
/// no dynamic code are involved: steps are looked up in the registry only.
pub struct PipelineTool {
    registry: ToolRegistry,
    cwd: PathBuf,
    options: ToolOptions,
}

impl PipelineTool {
    /// Compatibility constructor with an unconstrained policy. Callers that
    /// own an engagement should prefer [`PipelineTool::from_filtered_registry`]
    /// so intermediate targets are re-validated against its scope.
    pub fn new(registry: ToolRegistry, cwd: impl AsRef<Path>) -> Self {
        Self::from_filtered_registry(registry, cwd, &ToolOptions::default())
    }

    /// Build a pipeline over an already filtered registry, carrying the
    /// engagement policy so every intermediate target is re-checked.
    pub fn from_filtered_registry(
        registry: ToolRegistry,
        cwd: impl AsRef<Path>,
        options: &ToolOptions,
    ) -> Self {
        Self {
            registry,
            cwd: cwd.as_ref().to_path_buf(),
            options: options.clone(),
        }
    }

    /// Attach/replace the policy on an existing pipeline.
    pub fn with_options(mut self, options: &ToolOptions) -> Self {
        self.options = options.clone();
        self
    }
}

#[async_trait]
impl Tool for PipelineTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "recon_pipeline".into(),
            description: "Run an ordered list of registered recon tools, feeding each step's first output line into the next step's target.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "steps": {"type": "array", "items": {"type": "string"}, "description": "Ordered tool names"},
                    "target": {"type": "string", "description": "Initial target for the first step"}
                },
                "required": ["steps", "target"]
            }),
            risk: "network".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let steps = input
            .get("steps")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("steps required"))?;
        let mut target = input
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("target required"))?
            .to_string();
        let mut report: Vec<Value> = Vec::new();
        for step in steps {
            let name = step
                .as_str()
                .ok_or_else(|| anyhow!("pipeline step names must be strings"))?;
            // Re-validate on every step: an earlier tool may have produced an
            // out-of-scope intermediate target from untrusted output.
            if !scope_target_allowed(&target, &self.options.scope_in, &self.options.scope_out) {
                anyhow::bail!("pipeline target '{target}' is not permitted by scope policy");
            }
            validate_host_with_options(&target, &self.options)
                .with_context(|| format!("pipeline target '{target}' failed host validation"))?;
            let tool = self
                .registry
                .get(name)
                .ok_or_else(|| anyhow!("unknown pipeline step: {name}"))?;
            let result = tool.run(json!({"target": target})).await?;
            let first_line = result
                .output
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("")
                .trim()
                .to_string();
            report.push(json!({
                "name": name,
                "ok": result.ok,
                "output_first_line": first_line,
            }));
            target = first_line;
        }
        let all_ok = report
            .iter()
            .all(|step| step.get("ok").and_then(|v| v.as_bool()).unwrap_or(false));
        let output = format!(
            "recon pipeline completed {} step(s) in {}: {}",
            report.len(),
            self.cwd.display(),
            if all_ok {
                "all steps succeeded"
            } else {
                "at least one step failed"
            }
        );
        Ok(ToolResult {
            ok: all_ok,
            output: truncate(&output),
            structured: Some(json!({"steps": report})),
        })
    }
}

const MAX_EXTERNAL_LINES: usize = 200;

/// Single-pass placeholder substitution. Values are never re-scanned, so an
/// untrusted input cannot inject another placeholder through its value.
fn substitute_placeholder(arg: &str, input: &Value) -> String {
    let mut out = String::with_capacity(arg.len());
    let mut rest = arg;
    while let Some(pos) = rest.find('{') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let Some(end) = after.find('}') else {
            out.push('{');
            rest = after;
            continue;
        };
        let key = &after[..end];
        if [
            "target", "host", "url", "word", "domain", "ports", "param", "marker", "action",
            "selector", "script", "match",
        ]
        .contains(&key)
        {
            out.push_str(input.get(key).and_then(|v| v.as_str()).unwrap_or(""));
            rest = &after[end + 1..];
            continue;
        }
        out.push('{');
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Build the exact argv for an external adapter from its template and input.
/// Kept public so the substitution can be tested without spawning a process.
pub fn build_external_args(template: &[String], input: &Value) -> Vec<String> {
    template
        .iter()
        .map(|arg| substitute_placeholder(arg, input))
        .collect()
}

/// Every placeholder key that can carry a target. Each value substituted into
/// one of these must be checked against the engagement scope before spawn.
const SCOPE_PLACEHOLDER_KEYS: &[&str] = &[
    "target", "host", "url", "word", "domain", "ports", "param", "marker", "action", "selector",
    "script", "match",
];

/// Collect all non-empty values that would be substituted into scope-bearing
/// placeholders by `build_external_args`, so each is scope-checked. A bare
/// `target` in the input is also returned when no template placeholder exists,
/// preserving the check for templates that receive a target out of band.
pub fn external_scope_values(template: &[String], input: &Value) -> Vec<String> {
    let mut values = Vec::new();
    let mut has_target_placeholder = false;
    for key in SCOPE_PLACEHOLDER_KEYS {
        let placeholder = format!("{{{key}}}");
        if !template.iter().any(|arg| arg.contains(&placeholder)) {
            continue;
        }
        if *key == "target" {
            has_target_placeholder = true;
        }
        if let Some(value) = input.get(*key).and_then(Value::as_str) {
            if !value.is_empty() {
                values.push(value.to_string());
            }
        }
    }
    if !has_target_placeholder {
        if let Some(target) = input.get("target").and_then(Value::as_str) {
            if !target.is_empty() {
                values.push(target.to_string());
            }
        }
    }
    values
}

/// A pre-approved external recon adapter. Arguments are passed as a discrete
/// argv vector, never interpolated into a shell command string.
pub struct ExternalCommandTool {
    pub name: String,
    pub description: String,
    pub command: String,
    pub arg_template: Vec<String>,
    pub risk: String,
    cwd: PathBuf,
    scope_in: Vec<String>,
    scope_out: Vec<String>,
    timeout: Duration,
}

impl ExternalCommandTool {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        command: impl Into<String>,
        arg_template: Vec<String>,
        risk: impl Into<String>,
        cwd: impl AsRef<Path>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            command: command.into(),
            arg_template,
            risk: risk.into(),
            cwd: cwd.as_ref().to_path_buf(),
            scope_in: Vec::new(),
            scope_out: Vec::new(),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn with_cwd(mut self, cwd: impl AsRef<Path>) -> Self {
        self.cwd = cwd.as_ref().to_path_buf();
        self
    }

    /// Override the spawn timeout. Primarily useful for tests that exercise
    /// the kill-on-timeout path without waiting the full production minute.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Attach the engagement scope so the tool can fail closed on its own,
    /// independently of the runner's approval gate.
    pub fn with_scope(mut self, scope_in: Vec<String>, scope_out: Vec<String>) -> Self {
        self.scope_in = scope_in;
        self.scope_out = scope_out;
        self
    }
}

/// Kill a timed-out adapter and every process it spawned. On Windows
/// `taskkill /T /F` walks the process tree. On Unix the child is started as a
/// process-group leader, so `kill(-pid)` signals the whole group; the direct
/// child is killed afterwards as a best-effort fallback and reaped.
fn kill_process_tree(child: &mut tokio::process::Child) {
    let Some(pid) = child.id().map(|pid| pid.to_string()) else {
        return;
    };
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid, "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .arg(format!("-{pid}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[async_trait]
impl Tool for ExternalCommandTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.name.clone(),
            description: self.description.clone(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "target":{"type":"string"},
                    "host":{"type":"string"},
                    "url":{"type":"string"},
                    "word":{"type":"string"}
                },
                "required":[]
            }),
            risk: self.risk.clone(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let args = build_external_args(&self.arg_template, &input);
        // Scope is enforced here as well as by the runner: a prompt-injected
        // or unapproved call must not spawn a process against an out-of-scope
        // target even if it somehow bypasses the outer approval gate. Every
        // substituted value is checked, not just `{target}`.
        for value in external_scope_values(&self.arg_template, &input) {
            if !scope_target_allowed(&value, &self.scope_in, &self.scope_out) {
                anyhow::bail!("target '{value}' is not permitted by scope policy");
            }
        }
        let cwd = resolve_cwd(&self.cwd).unwrap_or_else(|_| self.cwd.clone());
        let mut command = Command::new(&self.command);
        command
            .args(&args)
            .current_dir(cwd)
            .env_clear()
            .envs(safe_process_env())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().context("spawn external command")?;
        // Poll for completion instead of spawn_blocking(output()): on timeout
        // we can now kill and reap the child rather than leaving it running.
        let deadline = Instant::now() + self.timeout;
        let out = loop {
            match child.try_wait().context("poll external command")? {
                Some(_) => break child.wait_with_output().await.context("collect output")?,
                None => {
                    if Instant::now() >= deadline {
                        kill_process_tree(&mut child);
                        // Fallback for the direct child (also reaps it).
                        let _ = child.kill().await;
                        anyhow::bail!("external command timeout");
                    }
                    sleep(Duration::from_millis(20)).await;
                }
            }
        };
        let stdout = redact(&String::from_utf8_lossy(&out.stdout));
        let stderr = redact(&String::from_utf8_lossy(&out.stderr));
        let lines: Vec<String> = stdout
            .lines()
            .take(MAX_EXTERNAL_LINES)
            .map(truncate)
            .collect();
        let text = format!(
            "exit={}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status.code().unwrap_or(-1),
            stdout,
            stderr
        );
        Ok(ToolResult {
            ok: out.status.success(),
            output: truncate(&text),
            structured: Some(json!({"lines": lines})),
        })
    }
}

/// Non-panicking registry constructor for untrusted CLI input.
pub fn try_default_registry(cwd: impl AsRef<Path>) -> Result<ToolRegistry> {
    try_default_registry_with_options(cwd, ToolOptions::default())
}

/// Registry constructor with explicit tool policy. External recon adapters are
/// only present when `enable_external_tools` is set, and `dnsx` then belongs to
/// the adapter rather than the built-in DNS alias.
pub const SESSION_FINISH_TOOL: &str = "session.finish";

/// Explicit terminal tool. The kernel intercepts it; `run` is never called on
/// the production path, but returning a harmless result keeps the type usable
/// in isolation.
pub struct SessionFinishTool;

#[async_trait]
impl Tool for SessionFinishTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: SESSION_FINISH_TOOL.to_string(),
            description: "End the current session with an explicit state and reason.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reason": {"type": "string"},
                    "state": {"type": "string", "enum": ["completed", "failed"]}
                },
                "required": ["reason"]
            }),
            risk: "safe".to_string(),
        }
    }

    async fn run(&self, _input: Value) -> Result<ToolResult> {
        Ok(ToolResult {
            ok: true,
            output: "finish accepted".to_string(),
            structured: None,
        })
    }
}

pub fn try_default_registry_with_options(
    cwd: impl AsRef<Path>,
    options: ToolOptions,
) -> Result<ToolRegistry> {
    let cwd = cwd.as_ref();
    let mut reg = ToolRegistry::new();
    reg.register_with_host_risk(Arc::new(SessionFinishTool), "safe");
    reg.register(Arc::new(FsReadTool::new(cwd)?));
    reg.register(Arc::new(FsWriteTool::new(cwd)?));
    reg.register(Arc::new(ShellExecTool::new(cwd)?));
    reg.register(Arc::new(HttpRequestTool::with_options(options.clone())));
    reg.register(Arc::new(DnsLookupTool::new_with_options(options.clone())));
    reg.register(Arc::new(SaveFindingTool));
    reg.register(Arc::new(RecordAssetTool));
    reg.register(Arc::new(SaveArtifactTool::new(cwd)?));
    reg.register(Arc::new(EchoTool));
    reg.register(Arc::new(ValidatePoCTool::with_options(options.clone())));
    if options.enable_external_tools {
        reg.register(Arc::new(PipelineTool::from_filtered_registry(
            reg.clone(),
            cwd,
            &options,
        )));
    }
    // Aliases for convenience / common tool names.
    let fs_read = Arc::new(FsReadTool::new(cwd)?);
    let fs_write = Arc::new(FsWriteTool::new(cwd)?);
    let dns = Arc::new(DnsLookupTool::new_with_options(options.clone()));
    reg.register_alias("read_file", fs_read.clone());
    reg.register_alias("read", fs_read);
    reg.register_alias("fs_write", fs_write.clone());
    reg.register_alias("write_file", fs_write.clone());
    reg.register_alias("write", fs_write);
    reg.register_alias("dns", dns.clone());
    reg.register_alias("dns_lookup", dns.clone());
    reg.register_alias("dns_resolve", dns);
    if options.enable_external_tools {
        register_external_adapters(&mut reg, cwd, &options);
    }
    register_command_adapters(&mut reg, cwd, &options);

    // New built-in tools. These are always present; network/intrusive ones
    // that depend on an external binary return a gated result when absent.
    reg.register(Arc::new(HttpFuzzTool {
        http: HttpRequestTool::with_options(options.clone()),
    }));
    reg.register(Arc::new(HttpProbeTool {
        http: HttpRequestTool::with_options(options.clone()),
    }));
    reg.register(Arc::new(PayloadForgeTool));
    reg.register(Arc::new(JwtDecodeTool));
    reg.register(Arc::new(HashUtilTool));
    reg.register(Arc::new(KnowledgeLookupTool));
    reg.register(Arc::new(ReportWriterTool));
    reg.register(Arc::new(TaskPutTool));
    reg.register(Arc::new(CluePutTool));

    reg.register(Arc::new(ExternalBackedTool {
        name: "subdomain_enum",
        description:
            "Enumerate subdomains via the registered subfinder adapter (gated when unavailable).",
        risk: "network",
        required: &["target", "domain"],
        commands: &["subfinder"],
        registry: reg.clone(),
    }));
    reg.register(Arc::new(ExternalBackedTool {
        name: "port_scan",
        description:
            "Port scan via nmap/naabu; gated unless explicitly enabled in external_commands.",
        risk: "intrusive",
        required: &["host", "ports"],
        commands: &["nmap", "naabu"],
        registry: reg.clone(),
    }));
    reg.register(Arc::new(ExternalBackedTool {
        name: "content_discovery",
        description: "Discover content via ffuf/katana; gated when no adapter is available.",
        risk: "network",
        required: &["url", "wordlist"],
        commands: &["ffuf", "katana"],
        registry: reg.clone(),
    }));
    reg.register(Arc::new(ExternalBackedTool {
        name: "vuln_scan",
        description:
            "Vulnerability scan via nuclei; gated unless explicitly enabled in external_commands.",
        risk: "intrusive",
        required: &["url", "target"],
        commands: &["nuclei"],
        registry: reg.clone(),
    }));
    reg.register(Arc::new(ExternalBackedTool {
        name: "browser",
        description: "Gated CLI adapter that forwards browser actions to a configured Playwright CLI (navigate/click/screenshot); NOT full browser automation. Requires an explicit external_commands entry and is gated when unavailable.",
        risk: "network",
        required: &["url", "action"],
        commands: &["playwright"],
        registry: reg.clone(),
    }));
    Ok(reg)
}

fn is_executable_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Discover well-known recon binaries by scanning PATH (plus the common
/// `/usr/local/bin`) with std only. Missing entries map to `None`.
pub fn external_tool_availability() -> BTreeMap<String, Option<PathBuf>> {
    const KEYS: &[&str] = &["subfinder", "dnsx", "katana", "ffuf", "nuclei", "nmap"];
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.push(PathBuf::from("/usr/local/bin"));

    #[cfg(windows)]
    let extensions: Vec<String> = {
        let raw = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        raw.split(';')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    #[cfg(not(windows))]
    let extensions: Vec<String> = vec![String::new()];

    let mut out = BTreeMap::new();
    for key in KEYS {
        let mut found = None;
        'search: for dir in &dirs {
            for ext in &extensions {
                let candidate = dir.join(format!("{key}{ext}"));
                if is_executable_file(&candidate) {
                    found = Some(candidate);
                    break 'search;
                }
            }
        }
        out.insert((*key).to_string(), found);
    }
    out
}

fn register_external_adapters(reg: &mut ToolRegistry, cwd: &Path, options: &ToolOptions) {
    let detected = if options.auto_detect_external {
        Some(external_tool_availability())
    } else {
        None
    };
    let adapters = [
        (
            "subfinder",
            "Discover subdomains for a target with subfinder.",
            "subfinder",
            vec![
                "-d".to_string(),
                "{target}".to_string(),
                "-silent".to_string(),
            ],
            "network",
        ),
        (
            "dnsx",
            "Resolve hosts with dnsx.",
            "dnsx",
            vec![
                "-d".to_string(),
                "{host}".to_string(),
                "-silent".to_string(),
            ],
            "network",
        ),
        (
            "katana",
            "Crawl URLs with katana.",
            "katana",
            vec!["-u".to_string(), "{url}".to_string(), "-silent".to_string()],
            "network",
        ),
        (
            "ffuf",
            "Fuzz URLs with ffuf.",
            "ffuf",
            vec![
                "-u".to_string(),
                "{url}".to_string(),
                "-w".to_string(),
                "{word}".to_string(),
                "-silent".to_string(),
            ],
            "network",
        ),
    ];
    for (name, description, command, arg_template, risk) in adapters {
        if let Some(map) = &detected {
            if map.get(name).and_then(|v| v.as_ref()).is_none() {
                continue;
            }
        }
        reg.register(Arc::new(
            ExternalCommandTool::new(name, description, command, arg_template, risk, cwd)
                .with_scope(options.scope_in.clone(), options.scope_out.clone()),
        ));
    }
}

/// Command-driven adapters are gated solely by `external_commands`: providing
/// a command is the explicit opt-in, independent of `enable_external_tools`.
fn register_command_adapters(reg: &mut ToolRegistry, cwd: &Path, options: &ToolOptions) {
    for name in ["nmap", "naabu", "nuclei", "playwright"] {
        let Some(command) = options.external_commands.get(name) else {
            continue;
        };
        let parts: Vec<String> = command.split_whitespace().map(String::from).collect();
        let Some((program, args)) = parts.split_first() else {
            continue;
        };
        reg.register(Arc::new(
            ExternalCommandTool::new(
                name,
                format!("Gated external tool: {name}."),
                program.clone(),
                args.to_vec(),
                "network",
                cwd,
            )
            .with_scope(options.scope_in.clone(), options.scope_out.clone()),
        ));
    }
}

/// Compatibility wrapper. Prefer [`try_default_registry`] for user-supplied paths.
pub fn default_registry(cwd: impl AsRef<Path>) -> ToolRegistry {
    default_registry_with_options(cwd, ToolOptions::default())
}

pub fn default_registry_with_options(cwd: impl AsRef<Path>, options: ToolOptions) -> ToolRegistry {
    try_default_registry_with_options(cwd, options).expect("invalid workspace cwd")
}

// ---------------------------------------------------------------------------
// Local encoding / hashing primitives.
//
// These are implemented in-tree so the crate does not need extra declared
// dependencies. They back `jwt_decode`, `hash_util` and the evidence hashes in
// `report_writer`.
// ---------------------------------------------------------------------------

const B64_STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URLSAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(data: &[u8], url_safe: bool, pad: bool) -> String {
    let table = if url_safe { B64_URLSAFE } else { B64_STANDARD };
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let (chunks, rem) = data.as_chunks::<3>();
    for chunk in chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        out.push(table[((n >> 6) & 63) as usize] as char);
        out.push(table[(n & 63) as usize] as char);
    }
    if rem.len() == 1 {
        let n = (rem[0] as u32) << 16;
        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        if pad {
            out.push_str("==");
        }
    } else if rem.len() == 2 {
        let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        out.push(table[((n >> 6) & 63) as usize] as char);
        if pad {
            out.push('=');
        }
    }
    out
}

/// Accepts both standard and URL-safe alphabets, with or without padding.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut vals: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        };
        vals.push(v);
    }
    if vals.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    let (full, rem) = vals.as_chunks::<4>();
    for c in full {
        let n =
            ((c[0] as u32) << 18) | ((c[1] as u32) << 12) | ((c[2] as u32) << 6) | (c[3] as u32);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
    }
    if rem.len() == 2 {
        let n = ((rem[0] as u32) << 18) | ((rem[1] as u32) << 12);
        out.push((n >> 16) as u8);
    } else if rem.len() == 3 {
        let n = ((rem[0] as u32) << 18) | ((rem[1] as u32) << 12) | ((rem[2] as u32) << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    }
    Some(out)
}

fn hex_encode(data: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0x0f) as usize] as char);
    }
    out
}

fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut msg = data.to_vec();
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut h0, mut h1, mut h2, mut h3) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let j = i * 4;
            *word = u32::from_le_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (h0, h1, h2, h3);
        for (i, (&k, &s)) in K.iter().zip(S.iter()).enumerate() {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let mixed = a
                .wrapping_add(f)
                .wrapping_add(k)
                .wrapping_add(m[g])
                .rotate_left(s);
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(mixed);
            a = tmp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
    }
    let mut out = String::with_capacity(32);
    // MD5 serialises each word in little-endian byte order.
    for w in [h0, h1, h2, h3] {
        out.push_str(&format!("{:08x}", w.swap_bytes()));
    }
    out
}

fn sha1_hex(data: &[u8]) -> String {
    let mut msg = data.to_vec();
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x67452301u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    ];
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = String::with_capacity(40);
    for word in h {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut msg = data.to_vec();
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);
        for (i, &k) in K.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    for word in h {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

fn as_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>()
            .join(","),
        _ => String::new(),
    }
}

fn str_field<'a>(value: &'a Value, keys: &[&str], default: &'a str) -> &'a str {
    for key in keys {
        if let Some(s) = value.get(*key).and_then(Value::as_str) {
            return s;
        }
    }
    default
}

fn gated_result(name: &str, reason: &str, fields: Value) -> ToolResult {
    let mut map = serde_json::Map::new();
    map.insert("ok".into(), Value::Bool(false));
    map.insert("gated".into(), Value::Bool(true));
    map.insert("tool".into(), Value::String(name.to_string()));
    map.insert("message".into(), Value::String(reason.to_string()));
    if let Value::Object(extra) = fields {
        for (key, value) in extra {
            map.insert(key, value);
        }
    }
    let structured = Value::Object(map);
    ToolResult {
        ok: false,
        output: truncate(reason),
        structured: Some(structured),
    }
}

// ---------------------------------------------------------------------------
// Safe, local-only tools.
// ---------------------------------------------------------------------------

/// Generate locally-computed payload strings for a vulnerability class.
pub struct PayloadForgeTool;

fn forge_payloads(kind: &str, context: &str, marker: &str) -> Vec<String> {
    let mut payloads: Vec<String> = match kind {
        "xss" => vec![
            format!("<script>{marker}</script>"),
            format!("<img src=x onerror=\"{marker}\">"),
            format!("\"><svg onload={marker}>"),
            format!("javascript:{marker}"),
        ],
        "sqli" => vec![
            "' OR '1'='1".to_string(),
            format!("' UNION SELECT NULL,{marker}--"),
            "1' AND '1'='1".to_string(),
            format!("' OR 1=1 -- {marker}"),
        ],
        "ssrf" => vec![
            format!("http://{marker}/"),
            "http://169.254.169.254/latest/meta-data/".to_string(),
            "file:///etc/passwd".to_string(),
            "gopher://127.0.0.1:6379/_INFO".to_string(),
        ],
        "ssti" => vec![
            "{{7*7}}".to_string(),
            "${7*7}".to_string(),
            format!("<%= {marker} %>"),
            format!("{{{{{marker}}}}}"),
        ],
        "cmdi" => vec![
            format!("; {marker}"),
            format!("| {marker}"),
            format!("$({marker})"),
            format!("`{marker}`"),
        ],
        _ => vec![marker.to_string()],
    };
    match context {
        "html" => payloads.insert(0, format!("&lt;script&gt;{marker}&lt;/script&gt;")),
        "attr" => {
            for payload in &mut payloads {
                *payload = format!("\" onmouseover=\"{payload}");
            }
        }
        "js" => {
            for payload in &mut payloads {
                *payload = format!("'; {payload}; //");
            }
        }
        "url" => {
            for payload in &mut payloads {
                *payload = b64_encode(payload.as_bytes(), true, false);
            }
        }
        _ => {}
    }
    payloads
}

#[async_trait]
impl Tool for PayloadForgeTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "payload_forge".into(),
            description: "Generate XSS/SQLi/SSRF/SSTI/CMDI payload strings locally without any network access.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["xss","sqli","ssrf","ssti","cmdi"]},
                    "context": {"type": "string", "enum": ["html","attr","js","url","plain"]},
                    "marker": {"type": "string"}
                },
                "required": ["kind"]
            }),
            risk: "safe".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let kind = input
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("kind required"))?;
        let context = input
            .get("context")
            .and_then(Value::as_str)
            .unwrap_or("plain");
        let marker = input
            .get("marker")
            .and_then(Value::as_str)
            .unwrap_or("AGENTBUG");
        let payloads = forge_payloads(kind, context, marker);
        let structured = json!({
            "ok": true,
            "kind": kind,
            "context": context,
            "marker": marker,
            "payloads": payloads,
            "count": payloads.len()
        });
        Ok(ToolResult {
            ok: true,
            output: truncate(&format!("generated {} {kind} payload(s)", payloads.len())),
            structured: Some(structured),
        })
    }
}

/// Decode a JWT's header and payload without verifying the signature.
pub struct JwtDecodeTool;

#[async_trait]
impl Tool for JwtDecodeTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "jwt_decode".into(),
            description: "Decode a JWT's header and payload segments with base64url. Signature is never verified.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"token": {"type": "string"}},
                "required": ["token"]
            }),
            risk: "safe".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let token = input
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("token required"))?;
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return Ok(ToolResult {
                ok: false,
                output: "jwt must contain at least two dot-separated segments".into(),
                structured: Some(json!({"ok": false, "error": "too few segments"})),
            });
        }
        let header_bytes = b64_decode(parts[0]);
        let payload_bytes = b64_decode(parts[1]);
        let header_json = header_bytes
            .as_deref()
            .and_then(|b| serde_json::from_slice::<Value>(b).ok());
        let payload_json = payload_bytes
            .as_deref()
            .and_then(|b| serde_json::from_slice::<Value>(b).ok());
        let signature_bytes = parts.get(2).and_then(|s| b64_decode(s));
        let decoded_header = header_bytes
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let decoded_payload = payload_bytes
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let ok = header_json.is_some() && payload_json.is_some();
        let structured = json!({
            "ok": ok,
            "verified": false,
            "part_count": parts.len(),
            "segments": {
                "header": {"raw": parts[0], "decoded": decoded_header, "json": header_json},
                "payload": {"raw": parts[1], "decoded": decoded_payload, "json": payload_json},
                "signature": {
                    "raw": parts.get(2).cloned().unwrap_or(""),
                    "bytes": signature_bytes.as_ref().map(Vec::len).unwrap_or(0)
                }
            },
            "header": header_json,
            "payload": payload_json
        });
        Ok(ToolResult {
            ok,
            output: truncate(&format!(
                "jwt decoded (unverified): header={}, payload={}",
                ok, ok
            )),
            structured: Some(structured),
        })
    }
}

/// Hash / encode / decode a value locally.
pub struct HashUtilTool;

#[async_trait]
impl Tool for HashUtilTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "hash_util".into(),
            description:
                "Local hashing/encoding utility: md5, sha1, sha256, b64encode, b64decode, hex."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "op": {"type": "string", "enum": ["md5","sha1","sha256","b64encode","b64decode","hex"]}
                },
                "required": ["value", "op"]
            }),
            risk: "safe".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let value = input
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("value required"))?;
        let op = input
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("op required"))?;
        let result = match op {
            "md5" => md5_hex(value.as_bytes()),
            "sha1" => sha1_hex(value.as_bytes()),
            "sha256" => sha256_hex(value.as_bytes()),
            "b64encode" => b64_encode(value.as_bytes(), false, true),
            "b64decode" => b64_decode(value)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default(),
            "hex" => hex_encode(value.as_bytes()),
            _ => {
                return Ok(ToolResult {
                    ok: false,
                    output: format!("unsupported op '{op}'"),
                    structured: Some(json!({
                        "ok": false,
                        "op": op,
                        "error": "unsupported op",
                        "supported": ["md5","sha1","sha256","b64encode","b64decode","hex"]
                    })),
                });
            }
        };
        Ok(ToolResult {
            ok: true,
            output: truncate(&result),
            structured: Some(json!({"ok": true, "op": op, "value": value, "result": result})),
        })
    }
}

const KNOWLEDGE_BASE: &[(&str, &str, &[&str], &[&str])] = &[
    (
        "WSTG-INFO-01",
        "Information Gathering",
        &["recon", "enumerate", "fingerprint", "discovery", "osint"],
        &["CWE-200"],
    ),
    (
        "WSTG-CONF-01",
        "Configuration and Deployment Management",
        &["config", "header", "misconfig", "default", "cms"],
        &["CWE-16", "CWE-693"],
    ),
    (
        "WSTG-IDNT-01",
        "Identity Management Testing",
        &["identity", "username", "user enumeration", "account"],
        &["CWE-204", "CWE-799"],
    ),
    (
        "WSTG-ATHN-01",
        "Authentication Testing",
        &["login", "password", "auth", "brute", "mfa", "jwt"],
        &["CWE-287", "CWE-307"],
    ),
    (
        "WSTG-ATHZ-01",
        "Authorization Testing",
        &["idor", "access control", "privilege", "bypass", "rbac"],
        &["CWE-284", "CWE-639"],
    ),
    (
        "WSTG-SESS-01",
        "Session Management Testing",
        &["session", "cookie", "csrf", "token", "logout"],
        &["CWE-384", "CWE-352"],
    ),
    (
        "WSTG-INPV-01",
        "Input Validation Testing",
        &[
            "xss",
            "sqli",
            " injection",
            "fuzz",
            "validation",
            "ssrf",
            "ssti",
            "cmdi",
        ],
        &["CWE-79", "CWE-89", "CWE-918", "CWE-94", "CWE-78", "CWE-20"],
    ),
    (
        "WSTG-ERRH-01",
        "Error Handling",
        &["error", "stack trace", "verbose", "exception"],
        &["CWE-209"],
    ),
    (
        "WSTG-CRYP-01",
        "Cryptography Testing",
        &["tls", "ssl", "cipher", "crypto", "certificate", "hash"],
        &["CWE-327", "CWE-295"],
    ),
    (
        "WSTG-BUSL-01",
        "Business Logic Testing",
        &["logic", "workflow", "race", "price", "transaction"],
        &["CWE-840"],
    ),
    (
        "WSTG-CLNT-01",
        "Client-side Testing",
        &["dom", "javascript", "cors", "clickjack", "browser"],
        &["CWE-79", "CWE-346", "CWE-1021"],
    ),
    (
        "WSTG-APIT-01",
        "API Testing",
        &["api", "graphql", "rest", "endpoint", "swagger"],
        &["CWE-200", "CWE-284"],
    ),
];

/// Look up bundled OWASP WSTG categories and CWE hints by keyword.
pub struct KnowledgeLookupTool;

#[async_trait]
impl Tool for KnowledgeLookupTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "knowledge_lookup".into(),
            description: "Search the bundled OWASP WSTG category and CWE hint list by keyword (no external service).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"]
            }),
            risk: "safe".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let query = input
            .get("query")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("query required"))?;
        let needle = query.trim().to_ascii_lowercase();
        let mut matches: Vec<Value> = Vec::new();
        for (id, category, keywords, cwes) in KNOWLEDGE_BASE {
            let haystack = format!("{id} {category} {}", keywords.join(" ")).to_ascii_lowercase();
            let score = needle
                .split_whitespace()
                .filter(|word| !word.is_empty() && haystack.contains(word))
                .count();
            if score > 0 {
                matches.push(json!({
                    "id": id,
                    "category": category,
                    "cwe": cwes,
                    "keywords": keywords,
                    "score": score
                }));
            }
        }
        matches.sort_by(|a, b| {
            b["score"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&a["score"].as_u64().unwrap_or(0))
        });
        let count = matches.len();
        let structured = json!({"ok": true, "query": query, "matches": matches, "count": count});
        Ok(ToolResult {
            ok: true,
            output: truncate(&format!("{count} knowledge entry(ies) matched '{query}'")),
            structured: Some(structured),
        })
    }
}

/// Platform hint derived only from an operator-supplied program URL.
/// No network request and no model input; Generic when unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Platform {
    HackerOne,
    Bugcrowd,
    #[default]
    Generic,
}

impl Platform {
    pub fn label(self) -> &'static str {
        match self {
            Self::HackerOne => "HackerOne",
            Self::Bugcrowd => "Bugcrowd",
            Self::Generic => "Generic",
        }
    }
}

pub fn platform_from_program_url(raw: &str) -> Platform {
    let host = url::Url::parse(raw)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default();
    if host == "hackerone.com" || host.ends_with(".hackerone.com") {
        Platform::HackerOne
    } else if host == "bugcrowd.com" || host.ends_with(".bugcrowd.com") {
        Platform::Bugcrowd
    } else {
        Platform::Generic
    }
}

/// One verified finding as consumed by the canonical report renderer.
#[derive(Debug, Clone, Default)]
pub struct ReportFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub cvss: Option<f32>,
    pub vector: Option<String>,
    pub cwe: Option<String>,
    pub cwe_rationale: Option<String>,
    pub cvss_note: Option<String>,
    pub asset: Option<String>,
    pub description: String,
    pub reproduction: Option<String>,
    pub impact: Option<String>,
    pub remediation: Option<String>,
    pub evidence_hash: Option<String>,
    pub verified: bool,
    pub platform: Platform,
}

/// Everything the canonical renderer needs. Coverage and timeline tuples are
/// `(target, method, path)` and `(timestamp, kind, detail)` respectively.
#[derive(Debug, Clone, Default)]
pub struct ReportInput {
    pub program: String,
    pub engagement: String,
    pub scope_in: Vec<String>,
    pub scope_out: Vec<String>,
    pub rules: Vec<String>,
    pub findings: Vec<ReportFinding>,
    pub coverage: Vec<(String, String, String)>,
    pub timeline: Vec<(String, String, String)>,
    pub report_id: String,
    pub platform: Platform,
}

/// The single canonical Markdown report renderer. Every report-producing path
/// must delegate here so section names, ordering and evidence hashes agree.
pub fn render_canonical_report(input: &ReportInput) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# {} â€” Security Assessment Report\n\n",
        input.engagement
    ));

    let verified_count = input.findings.iter().filter(|f| f.verified).count();
    out.push_str("## Executive Summary\n\n");
    out.push_str(&format!(
        "Program: {}\n\nThis report documents {} finding(s), {} verified, from engagement `{}` (report `{}`). Findings include reproduction steps, proof of concept, impact, remediation and SHA-256 evidence hashes.\n\n",
        input.program,
        input.findings.len(),
        verified_count,
        input.engagement,
        input.report_id
    ));

    out.push_str("## Scope & ROE\n\n");
    out.push_str("**In scope**\n\n");
    for entry in &input.scope_in {
        out.push_str(&format!("- `{entry}`\n"));
    }
    if input.scope_in.is_empty() {
        out.push_str("- (none)\n");
    }
    out.push_str("\n**Out of scope**\n\n");
    for entry in &input.scope_out {
        out.push_str(&format!("- `{entry}`\n"));
    }
    if input.scope_out.is_empty() {
        out.push_str("- (none)\n");
    }
    out.push_str("\n**Rules of engagement**\n\n");
    for rule in &input.rules {
        out.push_str(&format!("- {rule}\n"));
    }
    if input.rules.is_empty() {
        out.push_str("- (none)\n");
    }
    out.push('\n');

    out.push_str("## Methodology\n\n");
    out.push_str(
        "Testing combined passive reconnaissance, scoped HTTP probing, bounded parameter fuzzing and manual validation against OWASP WSTG and CWE guidance. Raw request/response bytes are pinned with SHA-256 so evidence can be replayed and verified independently.\n\n",
    );

    out.push_str("## Findings\n\n");
    if input.findings.is_empty() {
        out.push_str("_No findings were recorded._\n\n");
    }
    for (index, finding) in input.findings.iter().enumerate() {
        let hash = finding.evidence_hash.as_deref().unwrap_or("unavailable");
        out.push_str(&format!("### F-{:03}: {}\n\n", index + 1, finding.title));
        out.push_str(&format!("- **ID:** {}\n", finding.id));
        out.push_str(&format!("- **Severity:** {}\n", finding.severity));
        out.push_str(&format!(
            "- **CVSS:** {}\n",
            finding
                .cvss
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string())
        ));
        out.push_str(&format!(
            "- **Vector:** {}\n",
            finding.vector.as_deref().unwrap_or("N/A")
        ));
        out.push_str(&format!(
            "- **CWE:** {}\n",
            finding.cwe.as_deref().unwrap_or("N/A")
        ));
        if let Some(rationale) = finding.cwe_rationale.as_deref() {
            out.push_str(&format!("- **CWE rationale:** {rationale}\n"));
        }
        if let Some(note) = finding.cvss_note.as_deref() {
            out.push_str(&format!("- **CVSS note:** {note}\n"));
        }
        out.push_str(&format!(
            "- **Asset:** {}\n",
            finding.asset.as_deref().unwrap_or("N/A")
        ));
        out.push_str(&format!("- **Verified:** {}\n", finding.verified));
        out.push_str(&format!("- **Evidence SHA-256:** `{hash}`\n\n"));
        out.push_str(&format!("{}\n\n", finding.description));
        out.push_str("#### Steps to Reproduce\n\n");
        out.push_str(&format!(
            "{}\n\n",
            finding.reproduction.as_deref().unwrap_or("Not provided")
        ));
        out.push_str("#### Proof of Concept\n\n");
        out.push_str(&format!("Evidence bytes pinned by SHA-256 `{hash}`.\n\n"));
        out.push_str("#### Impact\n\n");
        out.push_str(&format!(
            "{}\n\n",
            finding.impact.as_deref().unwrap_or("Not provided")
        ));
        out.push_str("#### Remediation\n\n");
        out.push_str(&format!(
            "{}\n\n",
            finding.remediation.as_deref().unwrap_or("Not provided")
        ));
    }

    out.push_str("## Coverage\n\n");
    if input.coverage.is_empty() {
        out.push_str("- No coverage rows were supplied.\n");
    } else {
        for (target, method, path) in &input.coverage {
            let method = if method.is_empty() { "ANY" } else { method };
            out.push_str(&format!("- `{method} {target}{path}`\n"));
        }
    }
    out.push('\n');

    out.push_str("## Timeline\n\n");
    if input.timeline.is_empty() {
        out.push_str("- (none)\n");
    } else {
        for (timestamp, kind, detail) in &input.timeline {
            out.push_str(&format!("- {timestamp} [{kind}] {detail}\n"));
        }
    }
    out.push('\n');

    out.push_str("## Appendices\n\n");
    out.push_str("### A. Evidence Integrity\n\n");
    for (index, finding) in input.findings.iter().enumerate() {
        out.push_str(&format!(
            "- F-{:03}: `{}`\n",
            index + 1,
            finding.evidence_hash.as_deref().unwrap_or("unavailable")
        ));
    }
    out.push_str("\n### B. References\n\n");
    out.push_str("- OWASP Web Security Testing Guide (WSTG)\n");
    out.push_str("- MITRE CWE / Common Vulnerability Scoring System (CVSS)\n");
    out.push_str("\n### C. Platform Field Checklist\n\n");
    out.push_str(
        "Platform hint derived from the program URL; confirm against the current brief. \
         AgentBug-authored review aid, not a platform submission form. The operator submits manually.\n\n",
    );
    out.push_str(&format!("Platform: {}\n\n", input.platform.label()));
    match input.platform {
        Platform::HackerOne => {
            out.push_str("- [ ] Affected in-scope asset selected from the program scope list\n");
            out.push_str("- [ ] Weakness category required by that asset chosen and consistent with the finding\n");
            out.push_str("- [ ] Asset confirmed report-eligible; reward eligibility checked where relevant\n");
            out.push_str(
                "- [ ] Asset-specific instructions and severity ceiling reflected in this draft\n",
            );
            out.push_str(
                "- [ ] Deterministic reproduction and minimal evidence-derived PoC included\n",
            );
            out.push_str(
                "- [ ] Concrete impact and actionable remediation with a re-test step included\n",
            );
            out.push_str(
                "- [ ] Disclosure setting reviewed; no secret or third-party data exposed\n",
            );
        }
        Platform::Bugcrowd => {
            out.push_str("- [ ] Finding mapped to the program vulnerability-class taxonomy and target group\n");
            out.push_str("- [ ] Class/target exclusion rules checked against this finding\n");
            out.push_str("- [ ] Target group confirmed currently report-eligible; reward status checked where relevant\n");
            out.push_str(
                "- [ ] Prior-art / known-issue list checked before treating the issue as novel\n",
            );
            out.push_str("- [ ] Concise title, target location, reproduction and minimal evidence-derived PoC included\n");
            out.push_str("- [ ] Demonstrated impact and actionable remediation with a re-test step included\n");
            out.push_str(
                "- [ ] Evidence manifest attached and any operator attestation left for sign-off\n",
            );
        }
        Platform::Generic => {
            out.push_str(
                "- [ ] Affected host confirmed on the in-scope list and not on the excluded list\n",
            );
            out.push_str(
                "- [ ] Any extra fields required by the program brief copied into this draft\n",
            );
            out.push_str("- [ ] Brief constraints (rate limits, prohibited techniques, disclosure) confirmed honored\n");
            out.push_str(
                "- [ ] Deterministic reproduction and minimal evidence-derived PoC included\n",
            );
            out.push_str(
                "- [ ] Concrete impact and actionable remediation with a re-test step included\n",
            );
            out.push_str("- [ ] Draft contains no secrets or third-party personal data and is ready for operator review\n");
        }
    }
    out
}

/// Adapt the legacy `report_writer` JSON input to [`render_canonical_report`].
/// Returns the rendered Markdown plus the evidence hashes for tool callers.
fn render_report(input: &Value) -> (String, Vec<String>) {
    let program = str_field(input, &["program", "name", "title"], "Unnamed program").to_string();
    let engagement = str_field(
        input,
        &["engagement", "program", "name", "title"],
        "Unnamed engagement",
    )
    .to_string();
    let report_id = str_field(input, &["report_id", "id"], "unspecified").to_string();

    let as_strings = |key: &str| -> Vec<String> {
        match input.get(key) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        }
    };
    let scope_in = {
        let mut values = as_strings("scope_in");
        if values.is_empty() {
            values = as_strings("scope");
        }
        values
    };
    let scope_out = as_strings("scope_out");
    let rules = as_strings("rules");

    let findings_value = input.get("findings").and_then(Value::as_array);
    let mut findings: Vec<ReportFinding> = Vec::new();
    let mut evidence_hashes: Vec<String> = Vec::new();
    let mut derived_coverage: Vec<String> = Vec::new();
    for (index, finding) in findings_value.into_iter().flatten().enumerate() {
        let raw_cvss = str_field(finding, &["cvss", "cvss_score"], "");
        let vector = str_field(finding, &["vector", "cvss_vector", "cvss"], "");
        let steps = str_field(finding, &["steps", "reproduction", "repro"], "Not provided");
        let poc = str_field(finding, &["poc", "proof_of_concept", "request"], "");
        let reproduction = if poc.is_empty() {
            steps.to_string()
        } else {
            format!("{steps}\n\nPoC: {poc}")
        };
        let evidence = str_field(finding, &["evidence", "response"], "");
        let explicit_hash = str_field(finding, &["evidence_hash"], "");
        let hash = if explicit_hash.is_empty() {
            sha256_hex(evidence.as_bytes())
        } else {
            explicit_hash.to_string()
        };
        evidence_hashes.push(hash.clone());
        let asset = str_field(finding, &["asset", "target", "url", "host"], "");
        if !asset.is_empty() && !derived_coverage.iter().any(|c| c == asset) {
            derived_coverage.push(asset.to_string());
        }
        let verified = finding
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| {
                matches!(
                    str_field(finding, &["status"], ""),
                    "validated" | "confirmed"
                )
            });
        let id = str_field(finding, &["id"], "");
        findings.push(ReportFinding {
            id: if id.is_empty() {
                format!("F-{:03}", index + 1)
            } else {
                id.to_string()
            },
            title: str_field(finding, &["title", "name"], "(untitled)").to_string(),
            severity: str_field(finding, &["severity", "risk"], "info").to_string(),
            cvss: raw_cvss.parse::<f32>().ok(),
            vector: (!vector.is_empty()).then(|| vector.to_string()),
            cwe: str_field(finding, &["cwe"], "").to_string().into(),
            cwe_rationale: None,
            cvss_note: None,
            asset: (!asset.is_empty()).then(|| asset.to_string()),
            description: str_field(finding, &["description", "desc"], "").to_string(),
            reproduction: Some(reproduction),
            impact: str_field(finding, &["impact"], "").to_string().into(),
            remediation: str_field(finding, &["remediation", "fix"], "")
                .to_string()
                .into(),
            evidence_hash: Some(hash),
            verified,
            ..Default::default()
        });
    }

    let coverage: Vec<(String, String, String)> = input
        .get("coverage")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if let Some(single) = item.as_str() {
                        return Some((single.to_string(), String::new(), String::new()));
                    }
                    let parts = item.as_array()?;
                    Some((
                        as_text(parts.first()),
                        as_text(parts.get(1)),
                        as_text(parts.get(2)),
                    ))
                })
                .collect()
        })
        .unwrap_or_else(|| {
            derived_coverage
                .into_iter()
                .map(|asset| (asset, String::new(), String::new()))
                .collect()
        });

    let timeline: Vec<(String, String, String)> = input
        .get("timeline")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let parts = item.as_array()?;
                    Some((
                        as_text(parts.first()),
                        as_text(parts.get(1)),
                        as_text(parts.get(2)),
                    ))
                })
                .collect()
        })
        .unwrap_or_else(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            vec![(
                format!("unix-{now}"),
                "system".to_string(),
                "Report generated".to_string(),
            )]
        });

    let platform = platform_from_program_url(&program);
    let canonical = ReportInput {
        program,
        engagement,
        scope_in,
        scope_out,
        rules,
        findings,
        coverage,
        timeline,
        report_id,
        platform,
    };
    (render_canonical_report(&canonical), evidence_hashes)
}

/// Render a Markdown report from structured findings.
pub struct ReportWriterTool;

#[async_trait]
impl Tool for ReportWriterTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "report_writer".into(),
            description: "Render a Markdown security report with Executive Summary, Scope, Methodology, Findings (CVSS/CWE/PoC/impact/remediation/evidence hash), Coverage, Timeline and Appendices.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "findings": {"type": "array", "items": {"type": "object"}},
                    "program": {"type": "string"},
                    "scope": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]}
                },
                "required": ["findings"]
            }),
            risk: "safe".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let (markdown, hashes) = render_report(&input);
        let finding_count = input
            .get("findings")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let structured = json!({
            "ok": true,
            "markdown": markdown,
            "finding_count": finding_count,
            "evidence_hashes": hashes
        });
        Ok(ToolResult {
            ok: true,
            output: truncate(&markdown),
            structured: Some(structured),
        })
    }
}

/// Echo a durable task record for the engagement layer to persist.
pub struct TaskPutTool;

#[async_trait]
impl Tool for TaskPutTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "task_put".into(),
            description: "Emit a structured task record (statement, playbook_id, target, priority) for the engagement layer to persist.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "statement": {"type": "string"},
                    "playbook_id": {"type": "string"},
                    "target": {"type": "string"},
                    "priority": {"type": "string"}
                },
                "required": ["statement"]
            }),
            risk: "safe".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let task = json!({
            "statement": as_text(input.get("statement")),
            "playbook_id": as_text(input.get("playbook_id")),
            "target": as_text(input.get("target")),
            "priority": as_text(input.get("priority").or_else(|| input.get("severity"))),
            "status": "pending"
        });
        Ok(ToolResult {
            ok: true,
            output: truncate(&format!(
                "task queued (persisted by runner): {}",
                task["statement"]
            )),
            structured: Some(json!({"ok": true, "task": task})),
        })
    }
}

/// Echo a durable clue record for the engagement layer to persist.
pub struct CluePutTool;

#[async_trait]
impl Tool for CluePutTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "clue_put".into(),
            description: "Emit a structured clue record (key, value, source_tool, task_id) for the engagement layer to persist.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                    "source_tool": {"type": "string"},
                    "task_id": {"type": "string"}
                },
                "required": ["key", "value"]
            }),
            risk: "safe".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let clue = json!({
            "key": as_text(input.get("key")),
            "value": as_text(input.get("value")),
            "source_tool": as_text(input.get("source_tool")),
            "task_id": as_text(input.get("task_id"))
        });
        Ok(ToolResult {
            ok: true,
            output: truncate(&format!(
                "clue queued (persisted by runner): {}",
                clue["key"]
            )),
            structured: Some(json!({"ok": true, "clue": clue})),
        })
    }
}

// ---------------------------------------------------------------------------
// HTTP-backed tools. All requests go through HttpRequestTool so scope, DNS
// pinning and redaction rules are preserved.
// ---------------------------------------------------------------------------

/// Fuzz a parameter (or an explicit marker) and record per-payload results.
pub struct HttpFuzzTool {
    http: HttpRequestTool,
}

fn fuzz_candidate(
    base: &url::Url,
    marker: &str,
    param: Option<&str>,
    payload: &str,
) -> Option<url::Url> {
    if base.as_str().contains(marker) {
        return url::Url::parse(&base.as_str().replace(marker, payload)).ok();
    }
    let Some(param) = param else {
        return Some(base.clone());
    };
    let mut candidate = base.clone();
    let pairs: Vec<(String, String)> = candidate.query_pairs().into_owned().collect();
    {
        let mut query = candidate.query_pairs_mut();
        query.clear();
        let mut replaced = false;
        for (key, value) in pairs {
            if key == param {
                query.append_pair(&key, payload);
                replaced = true;
            } else {
                query.append_pair(&key, &value);
            }
        }
        if !replaced {
            query.append_pair(param, payload);
        }
    }
    Some(candidate)
}

#[async_trait]
impl Tool for HttpFuzzTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "http_fuzz".into(),
            description: "Fuzz a URL parameter or marker with a wordlist using the scoped HTTP client. Hard-capped at 200 wordlist items and 200 requests per call; only GET/HEAD/POST are allowed. Records status, response length and marker presence per payload and reports `capped` when input was truncated.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": FUZZ_METHODS, "default": "GET"},
                    "param": {"type": "string"},
                    "wordlist": {"type": "array", "items": {"type": "string"}},
                    "marker": {"type": "string", "default": "FUZZ"},
                    "match": {"type": "string"}
                },
                "required": ["url", "wordlist"]
            }),
            risk: "network-write".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let raw_url = input
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("url required"))?;
        let base = url::Url::parse(raw_url).context("invalid url")?;
        let wordlist = input
            .get("wordlist")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("wordlist required"))?;
        let method = input
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        if !FUZZ_METHODS.contains(&method.as_str()) {
            anyhow::bail!("method '{method}' is not allowed for http_fuzz (only GET/HEAD/POST)");
        }
        let marker = input
            .get("marker")
            .and_then(Value::as_str)
            .unwrap_or("FUZZ");
        let param = input.get("param").and_then(Value::as_str);
        let explicit_match = input.get("match").and_then(Value::as_str);
        let wordlist_total = wordlist.len();
        let mut capped = wordlist_total > MAX_FUZZ_WORDLIST;
        let mut requests = 0usize;
        let mut results: Vec<Value> = Vec::new();
        for payload in wordlist
            .iter()
            .filter_map(Value::as_str)
            .take(MAX_FUZZ_WORDLIST)
        {
            if requests >= MAX_FUZZ_REQUESTS {
                capped = true;
                break;
            }
            requests += 1;
            let mut entry = serde_json::Map::new();
            entry.insert("payload".into(), Value::String(payload.to_string()));
            let Some(candidate) = fuzz_candidate(&base, marker, param, payload) else {
                entry.insert("ok".into(), Value::Bool(false));
                entry.insert(
                    "error".into(),
                    Value::String("payload could not be encoded into url".into()),
                );
                results.push(Value::Object(entry));
                continue;
            };
            entry.insert("url".into(), Value::String(candidate.to_string()));
            match self
                .http
                .run(json!({"url": candidate.as_str(), "method": method.as_str()}))
                .await
            {
                Ok(response) => {
                    let data = response.structured.unwrap_or_else(|| json!({}));
                    let status = data.get("status").and_then(Value::as_u64).unwrap_or(0);
                    let length = data.get("body_bytes").and_then(Value::as_u64).unwrap_or(0);
                    let body = data.get("body").and_then(Value::as_str).unwrap_or("");
                    let needle = explicit_match.unwrap_or(payload);
                    let marker_found = !needle.is_empty() && body.contains(needle);
                    entry.insert("status".into(), json!(status));
                    entry.insert("length".into(), json!(length));
                    entry.insert("marker_found".into(), Value::Bool(marker_found));
                    entry.insert("ok".into(), Value::Bool(response.ok));
                }
                Err(err) => {
                    entry.insert("status".into(), json!(0));
                    entry.insert("length".into(), json!(0));
                    entry.insert("marker_found".into(), Value::Bool(false));
                    entry.insert("ok".into(), Value::Bool(false));
                    entry.insert("error".into(), Value::String(redact(&err.to_string())));
                }
            }
            results.push(Value::Object(entry));
        }
        let any_ok = results
            .iter()
            .any(|r| r.get("ok").and_then(Value::as_bool).unwrap_or(false));
        let structured = json!({
            "ok": any_ok,
            "capped": capped,
            "url": raw_url,
            "param": param,
            "marker": marker,
            "method": method,
            "wordlist_total": wordlist_total,
            "requests": requests,
            "results": results
        });
        Ok(ToolResult {
            ok: any_ok,
            output: truncate(&format!(
                "fuzzed {requests} payload(s) against {raw_url}{}",
                if capped { " (capped)" } else { "" }
            )),
            structured: Some(structured),
        })
    }
}

fn detect_tech(haystack: &str) -> Vec<String> {
    const SIGNATURES: &[(&str, &str)] = &[
        ("wp-content", "WordPress"),
        ("wp-includes", "WordPress"),
        ("joomla", "Joomla"),
        ("drupal", "Drupal"),
        ("django", "Django"),
        ("laravel", "Laravel"),
        ("express", "Express"),
        ("next.js", "Next.js"),
        ("react", "React"),
        ("jquery", "jQuery"),
        ("asp.net", "ASP.NET"),
        ("php", "PHP"),
        ("nginx", "nginx"),
        ("apache", "Apache"),
        ("cloudflare", "Cloudflare"),
    ];
    let mut tech: Vec<String> = Vec::new();
    for (needle, name) in SIGNATURES {
        if haystack.contains(needle) && !tech.iter().any(|t| t == name) {
            tech.push((*name).to_string());
        }
    }
    tech
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title>")? + "<title>".len();
    let end_rel = lower[start..].find("</title>")?;
    Some(body[start..start + end_rel].trim().to_string())
}

/// Lightweight fingerprint of a single in-scope URL.
pub struct HttpProbeTool {
    http: HttpRequestTool,
}

#[async_trait]
impl Tool for HttpProbeTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "http_probe".into(),
            description: "Probe a single in-scope URL for status, server header, technology hints and HTML title.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"]
            }),
            risk: "network".into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        let url = input
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("url required"))?;
        let response = self.http.run(json!({"url": url})).await?;
        let data = response.structured.unwrap_or_else(|| json!({}));
        let headers = data.get("headers").cloned().unwrap_or_else(|| json!({}));
        let body = data.get("body").and_then(Value::as_str).unwrap_or("");
        let status = data.get("status").and_then(Value::as_u64).unwrap_or(0);
        let server = headers
            .as_object()
            .and_then(|map| {
                map.iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("server"))
                    .and_then(|(_, value)| value.as_str())
            })
            .unwrap_or("")
            .to_string();
        let mut haystack = format!("{} {}", headers, body).to_ascii_lowercase();
        if let Some(powered) = headers.as_object().and_then(|map| {
            map.iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("x-powered-by"))
                .and_then(|(_, value)| value.as_str())
        }) {
            haystack.push(' ');
            haystack.push_str(&powered.to_ascii_lowercase());
        }
        let tech = detect_tech(&haystack);
        let title = extract_title(body).unwrap_or_default();
        let structured = json!({
            "ok": response.ok,
            "url": url,
            "status": status,
            "server": server,
            "tech": tech,
            "title": title,
            "headers": headers
        });
        Ok(ToolResult {
            ok: response.ok,
            output: truncate(&format!(
                "probe {url}: status {status}, server '{server}', tech {:?}, title '{title}'",
                tech
            )),
            structured: Some(structured),
        })
    }
}

// ---------------------------------------------------------------------------
// Gated external adapters. Each tool is always registered; when its backing
// command is unavailable it returns ok=false with a clear gated result.
// ---------------------------------------------------------------------------

struct ExternalBackedTool {
    name: &'static str,
    description: &'static str,
    risk: &'static str,
    required: &'static [&'static str],
    commands: &'static [&'static str],
    registry: ToolRegistry,
}

/// Merge derived aliases into the original input so any configured argv
/// template (`{target}`, `{host}`, `{url}`, `{word}`, ...) can be satisfied.
fn enrich_external_input(input: &Value) -> Value {
    let mut map = input.as_object().cloned().unwrap_or_default();
    let host = input
        .get("host")
        .and_then(Value::as_str)
        .or_else(|| input.get("domain").and_then(Value::as_str))
        .or_else(|| input.get("target").and_then(Value::as_str))
        .unwrap_or("");
    let url = input.get("url").and_then(Value::as_str).unwrap_or("");
    let target = if url.is_empty() { host } else { url };
    let word = as_text(input.get("wordlist").or_else(|| input.get("word")));
    let ports = as_text(input.get("ports"));
    map.entry("target")
        .or_insert_with(|| Value::String(target.to_string()));
    map.entry("host")
        .or_insert_with(|| Value::String(host.to_string()));
    map.entry("url")
        .or_insert_with(|| Value::String(url.to_string()));
    map.entry("word")
        .or_insert_with(|| Value::String(if ports.is_empty() { word } else { ports }));
    Value::Object(map)
}

#[async_trait]
impl Tool for ExternalBackedTool {
    fn spec(&self) -> ToolSpec {
        let mut properties = serde_json::Map::new();
        for key in self.required.iter().copied().chain(
            ["marker", "selector", "script", "action", "ports"]
                .iter()
                .copied(),
        ) {
            properties.insert(key.to_string(), json!({"type": ["string", "array"]}));
        }
        ToolSpec {
            name: self.name.into(),
            description: self.description.into(),
            input_schema: json!({
                "type": "object",
                "properties": properties,
                "required": self.required
            }),
            risk: self.risk.into(),
        }
    }

    async fn run(&self, input: Value) -> Result<ToolResult> {
        if !self
            .required
            .iter()
            .any(|key| !as_text(input.get(*key)).is_empty())
        {
            anyhow::bail!("one of {:?} is required", self.required);
        }
        let selected = self
            .commands
            .iter()
            .find_map(|name| self.registry.get(name).map(|tool| (*name, tool)));
        let Some((adapter_name, adapter)) = selected else {
            let reason = format!(
                "'{}' is gated: no configured external command ({}) is available. Explicitly enable it via ToolOptions.external_commands to allow execution.",
                self.name,
                self.commands.join(" or ")
            );
            return Ok(gated_result(
                self.name,
                &reason,
                json!({
                    "target": as_text(input.get("target").or_else(|| input.get("host")).or_else(|| input.get("url")))
                }),
            ));
        };
        let enriched = enrich_external_input(&input);
        let result = adapter.run(enriched.clone()).await?;
        let mut structured = result.structured.unwrap_or_else(|| json!({}));
        if let Value::Object(map) = &mut structured {
            map.insert("tool".into(), Value::String(self.name.to_string()));
            map.insert("adapter".into(), Value::String(adapter_name.to_string()));
            map.insert("ok".into(), Value::Bool(result.ok));
            map.insert("input".into(), enriched);
        }
        Ok(ToolResult {
            ok: result.ok,
            output: result.output,
            structured: Some(structured),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fs_read_confined() {
        let dir = std::env::temp_dir().join(format!("mbt-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "hello").unwrap();
        let tool = FsReadTool::new(&dir).unwrap();
        let ok = tool.run(json!({"path":"a.txt"})).await.unwrap();
        assert_eq!(ok.output, "hello");
        let bad = tool.run(json!({"path":"../outside.txt"})).await;
        assert!(bad.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_blocks_localhost() {
        let tool = HttpRequestTool::new();
        let bad = tool.run(json!({"url":"http://localhost:8080/"})).await;
        assert!(bad.is_err());
    }

    #[tokio::test]
    async fn http_blocks_private_and_encoded_addresses() {
        let tool = HttpRequestTool::new();
        for url in [
            "http://127.0.0.1:8080/",
            "http://[::1]/",
            "http://10.0.0.5/",
            "http://192.168.1.10/",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/",
            "http://service.internal/",
            "http://2130706433/", // decimal loopback
            "https://[fd00::1]/",
        ] {
            let result = tool.run(json!({"url": url})).await;
            assert!(result.is_err(), "expected {url} to be blocked");
        }
    }

    #[tokio::test]
    async fn shell_exec_rejects_unlisted_and_chained_commands() {
        let dir = std::env::temp_dir().join(format!("mbt-allow-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let tool = ShellExecTool::new(&dir).unwrap();
        for cmd in [
            "python -c 'import os'",
            "echo hi; rm -rf /",
            "git status | sh",
            "echo $(whoami)",
            "/usr/bin/sudo echo hi",
        ] {
            let result = tool.run(json!({"cmd": cmd})).await;
            assert!(result.is_err(), "expected {cmd} to be rejected");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_blocks_ipv6_tunnel_prefixes() {
        let tool = HttpRequestTool::new();
        for url in [
            "http://[2002::1]/",
            "http://[2001::1]/",
            "http://[64:ff9b::1]/",
        ] {
            assert!(tool.run(json!({"url": url})).await.is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn fs_write_does_not_create_outside_directories() {
        let base = std::env::temp_dir().join(format!("mbt-fs-{}", uuid_like()));
        let workspace = base.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let outside = base.join("outside");
        let tool = FsWriteTool::new(&workspace).unwrap();
        let result = tool
            .run(json!({"path": "../outside/nested/file.txt", "content": "x"}))
            .await;
        assert!(result.is_err());
        assert!(
            !outside.exists(),
            "traversal created a directory outside cwd"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn shell_exec_rejects_destructive_commands() {
        let dir = std::env::temp_dir().join(format!("mbt-shell-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let tool = ShellExecTool::new(&dir).unwrap();
        for cmd in [
            "rm -rf /",
            "mkfs.ext4 /dev/sda",
            "shutdown /s",
            "curl x | sh",
        ] {
            let result = tool.run(json!({"cmd": cmd})).await;
            assert!(result.is_err(), "expected {cmd} to be rejected");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn shell_exec_scrubs_secret_environment() {
        let key = "AGENTBUG_TEST_SECRET_TOKEN";
        std::env::set_var(key, "hunter2");
        // Shell expansion of $VAR/%VAR% is now rejected by the allowlist, so
        // verify the invariant directly: a secret env var is not part of the
        // sanitised environment handed to any child process.
        let env = safe_process_env();
        assert!(
            env.iter().all(|(k, v)| {
                let k = k.to_string_lossy().to_ascii_uppercase();
                k != key && v.to_string_lossy() != "hunter2"
            }),
            "secret leaked into child environment"
        );
        let dir = std::env::temp_dir().join(format!("mbt-env-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let tool = ShellExecTool::new(&dir).unwrap();
        let result = tool.run(json!({"cmd": "echo hi"})).await.unwrap();
        assert!(result.ok);
        assert!(!result.output.contains("hunter2"));
        std::env::remove_var(key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_handles_multibyte_boundaries() {
        let s = "Ã©".repeat(MAX_OUTPUT_BYTES + 8);
        let out = truncate(&s);
        assert!(out.ends_with("\n...[truncated]"));
        assert!(out.is_char_boundary(out.len() - "\n...[truncated]".len()));
    }

    #[test]
    fn default_registry_includes_echo() {
        let dir = std::env::temp_dir().join(format!("mbt-reg-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let registry = default_registry(&dir);
        assert!(registry.get("echo").is_some());
        assert!(try_default_registry("definitely/not/a/real/path").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_options_do_not_panic() {
        let options = ToolOptions {
            allow_proxy: true,
            proxy_url: Some("http://127.0.0.1:3128".to_string()),
            ..ToolOptions::default()
        };
        let tool = HttpRequestTool::with_options(options);
        assert_eq!(tool.spec().name, "http_request");
        // An invalid proxy must also fail closed instead of panicking.
        let bad = ToolOptions {
            proxy_url: Some("not a url".to_string()),
            ..ToolOptions::default()
        };
        let _ = HttpRequestTool::with_options(bad);
    }

    #[test]
    fn trusted_local_targets_are_explicit() {
        // Default policy blocks loopback and metadata.
        assert!(validate_host_string("127.0.0.1").is_err());
        assert!(validate_host_string("169.254.169.254").is_err());
        assert!(validate_host_string("localhost").is_err());
        assert!(validate_host_string_with_default_options("localhost").is_err());

        // Only an explicit entry lets a local host through.
        let exact = vec!["127.0.0.1".to_string()];
        assert!(host_is_trusted("127.0.0.1", &exact));
        let options = ToolOptions {
            trusted_local_targets: exact.clone(),
            ..ToolOptions::default()
        };
        assert!(validate_host_with_options("127.0.0.1", &options).is_ok());
        assert!(validate_host_with_options("10.0.0.5", &options).is_err());

        let wildcard = vec!["*.lab.local".to_string()];
        assert!(host_is_trusted("api.lab.local", &wildcard));
        assert!(host_is_trusted("deep.api.lab.local", &wildcard));
        assert!(!host_is_trusted("lab.local", &wildcard));
        assert!(!host_is_trusted("api.example.com", &wildcard));

        let cidr = vec!["10.0.0.0/8".to_string()];
        assert!(host_is_trusted("10.1.2.3", &cidr));
        assert!(host_is_trusted("10.0.0.1", &cidr));
        assert!(!host_is_trusted("11.0.0.1", &cidr));

        let prefix = vec!["192.168.1.".to_string()];
        assert!(host_is_trusted("192.168.1.42", &prefix));
        assert!(!host_is_trusted("192.168.2.42", &prefix));
    }

    fn validate_host_string_with_default_options(host: &str) -> Result<()> {
        validate_host_with_options(host, &ToolOptions::default())
    }

    #[test]
    fn build_external_args_substitutes_placeholders() {
        let template: Vec<String> = [
            "-d", "{target}", "--host", "{host}", "-u", "{url}", "-w", "{word}",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let input = json!({
            "target": "example.com",
            "host": "ns1.example.com",
            "url": "https://example.com/a",
            "word": "paths.txt"
        });
        assert_eq!(
            build_external_args(&template, &input),
            vec![
                "-d",
                "example.com",
                "--host",
                "ns1.example.com",
                "-u",
                "https://example.com/a",
                "-w",
                "paths.txt"
            ]
        );
        // Missing values become empty strings and values are not re-scanned.
        let missing = build_external_args(&["{target}".to_string()], &json!({}));
        assert_eq!(missing, vec![""]);
        let chained = build_external_args(
            &["{target}".to_string()],
            &json!({"target": "{host}", "host": "evil"}),
        );
        assert_eq!(chained, vec!["{host}"]);
    }

    #[test]
    fn external_adapters_are_opt_in() {
        let dir = std::env::temp_dir().join(format!("mbt-ext-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = try_default_registry(&dir).unwrap();
        assert!(plain.get("dns").is_some());
        assert!(plain.get("dns_resolve").is_some());
        assert!(plain.get("dnsx").is_none());
        assert!(plain.get("subfinder").is_none());

        let mut options = ToolOptions {
            enable_external_tools: true,
            ..ToolOptions::default()
        };
        options
            .external_commands
            .insert("nuclei".into(), "nuclei -u {url}".into());
        let reg = try_default_registry_with_options(&dir, options).unwrap();
        for name in ["subfinder", "dnsx", "katana", "ffuf", "nuclei"] {
            assert!(reg.get(name).is_some(), "missing {name}");
        }
        assert!(reg.get("nmap").is_none());
        let dnsx = reg.get("dnsx").unwrap().spec();
        assert_eq!(dnsx.name, "dnsx");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scope_target_allowed_enforces_inclusion_and_exclusion() {
        let empty: Vec<String> = Vec::new();
        assert!(scope_target_allowed("example.com", &empty, &empty));
        assert!(!scope_target_allowed("", &empty, &empty));

        let in_scope = vec!["example.com".to_string()];
        assert!(scope_target_allowed("example.com", &in_scope, &empty));
        assert!(scope_target_allowed("api.example.com", &in_scope, &empty));
        assert!(scope_target_allowed(
            "https://api.example.com/path",
            &in_scope,
            &empty
        ));
        assert!(!scope_target_allowed("evil-example.com", &in_scope, &empty));
        assert!(!scope_target_allowed("other.org", &in_scope, &empty));

        let wildcard = vec!["*.example.com".to_string()];
        assert!(scope_target_allowed("api.example.com", &wildcard, &empty));
        assert!(!scope_target_allowed("example.com", &wildcard, &empty));

        let suffix = vec![".example.com".to_string()];
        assert!(scope_target_allowed("api.example.com", &suffix, &empty));
        assert!(scope_target_allowed("example.com", &suffix, &empty));

        let cidr = vec!["10.0.0.0/8".to_string()];
        assert!(scope_target_allowed("10.1.2.3", &cidr, &empty));
        assert!(!scope_target_allowed("11.0.0.1", &cidr, &empty));

        let out = vec!["admin.example.com".to_string()];
        assert!(!scope_target_allowed("admin.example.com", &in_scope, &out));
        let all_subdomains = vec!["*.example.com".to_string()];
        assert!(!scope_target_allowed(
            "api.example.com",
            &empty,
            &all_subdomains
        ));
    }

    #[test]
    fn proxy_url_requires_loopback_http() {
        for url in [
            "http://127.0.0.1:3128",
            "http://localhost:8080",
            "http://[::1]:3128",
        ] {
            let options = ToolOptions {
                allow_proxy: true,
                proxy_url: Some(url.to_string()),
                ..ToolOptions::default()
            };
            assert!(validate_proxy_url(&options).is_ok(), "{url}");
        }
        for url in [
            "https://0.0.0.0:443",
            "http://0.0.0.0:3128",
            "ftp://127.0.0.1:21",
            "http://evil.example.com:8080",
            "http://192.168.1.10:8080",
            "not a url",
            "http://",
        ] {
            let options = ToolOptions {
                allow_proxy: true,
                proxy_url: Some(url.to_string()),
                ..ToolOptions::default()
            };
            assert!(validate_proxy_url(&options).is_err(), "{url}");
        }
        let disabled = ToolOptions {
            proxy_url: Some("http://evil.example.com".to_string()),
            ..ToolOptions::default()
        };
        assert!(validate_proxy_url(&disabled).is_ok());
    }

    #[tokio::test]
    async fn http_rejects_bad_proxy_and_out_of_scope_without_network() {
        let options = ToolOptions {
            allow_proxy: true,
            proxy_url: Some("http://evil.example.com:8080".to_string()),
            ..ToolOptions::default()
        };
        let tool = HttpRequestTool::with_options(options);
        let err = tool
            .run(json!({"url": "http://example.com/"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("loopback"), "{err}");

        let options = ToolOptions {
            scope_in: vec!["example.com".to_string()],
            ..ToolOptions::default()
        };
        let tool = HttpRequestTool::with_options(options);
        let err = tool
            .run(json!({"url": "http://other.org/"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "{err}");
    }

    #[test]
    fn poc_verdict_requires_status_and_optional_marker() {
        assert!(poc_verdict(200, 200, false, false));
        assert!(!poc_verdict(201, 200, false, false));
        assert!(poc_verdict(200, 200, true, true));
        assert!(!poc_verdict(200, 200, false, true));
    }

    #[test]
    fn validate_poc_tool_has_expected_spec() {
        let spec = ValidatePoCTool::new().spec();
        assert_eq!(spec.name, "validate_poc");
        assert_eq!(spec.risk, "network-write");
        assert_eq!(spec.input_schema["required"], json!(["finding_id", "url"]));
        assert!(spec.input_schema["properties"]["finding_id"].is_object());
        assert!(spec.input_schema["properties"]["headers"].is_object());
        assert!(spec.input_schema["properties"]["body"].is_object());
        assert_eq!(
            spec.input_schema["properties"]["method"]["default"],
            json!("GET")
        );
        assert_eq!(
            spec.input_schema["properties"]["expected_status"]["default"],
            json!(200)
        );
        assert!(spec.input_schema["properties"]["marker"].is_object());
    }

    struct StepTool;

    #[async_trait]
    impl Tool for StepTool {
        fn spec(&self) -> ToolSpec {
            ToolSpec {
                name: "step".into(),
                description: String::new(),
                input_schema: json!({}),
                risk: "safe".into(),
            }
        }
        async fn run(&self, input: Value) -> Result<ToolResult> {
            let target = input.get("target").and_then(|v| v.as_str()).unwrap_or("");
            Ok(ToolResult {
                ok: true,
                output: format!("value-{target}\nfooter"),
                structured: None,
            })
        }
    }

    #[tokio::test]
    async fn pipeline_feeds_previous_output_line_as_target() {
        let dir = std::env::temp_dir().join(format!("mbt-pipe-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(StepTool));
        let tool = PipelineTool::new(registry, &dir);
        assert_eq!(tool.spec().name, "recon_pipeline");
        let result = tool
            .run(json!({"steps": ["step", "step"], "target": "example.com"}))
            .await
            .unwrap();
        assert!(result.ok);
        let steps = &result.structured.as_ref().unwrap()["steps"];
        assert_eq!(steps[0]["name"], json!("step"));
        assert_eq!(steps[0]["ok"], json!(true));
        assert_eq!(steps[0]["output_first_line"], json!("value-example.com"));
        assert_eq!(
            steps[1]["output_first_line"],
            json!("value-value-example.com")
        );
        let err = tool
            .run(json!({"steps": ["missing"], "target": "x"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown pipeline step"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn external_tool_availability_has_expected_keys() {
        let map = external_tool_availability();
        for key in ["subfinder", "dnsx", "katana", "ffuf", "nuclei", "nmap"] {
            assert!(map.contains_key(key), "missing {key}");
        }
    }

    #[test]
    fn redact_covers_pii_without_touching_common_numbers() {
        let out = redact("mail alice@example.com or bob.smith+tag@sub.example.co.uk");
        assert!(!out.contains("alice@example.com"));
        assert!(!out.contains("bob.smith+tag"));

        let out = redact("SSN 123-45-6789 and phone +1-555-123-4567");
        assert!(!out.contains("123-45-6789"));
        assert!(!out.contains("555-123-4567"));

        let out = redact("card 4111111111111111 amex 378282246310005");
        assert!(!out.contains("4111111111111111"));
        assert!(!out.contains("378282246310005"));

        let plain = "port 8080 status 200 date 2026-11-19 version 1.2.3";
        assert_eq!(redact(plain), plain);
    }

    #[tokio::test]
    async fn payload_forge_generates_local_payloads() {
        let tool = PayloadForgeTool;
        let result = tool
            .run(json!({"kind": "xss", "marker": "PROBE", "context": "attr"}))
            .await
            .unwrap();
        assert!(result.ok);
        let data = result.structured.unwrap();
        let payloads = data["payloads"].as_array().unwrap();
        assert_eq!(data["count"], json!(payloads.len()));
        assert!(payloads
            .iter()
            .any(|p| p.as_str().unwrap().contains("PROBE")));
        assert!(payloads
            .iter()
            .any(|p| p.as_str().unwrap().contains("onmouseover")));

        for kind in ["sqli", "ssrf", "ssti", "cmdi"] {
            let result = tool.run(json!({"kind": kind})).await.unwrap();
            assert!(result.ok, "{kind}");
            assert!(!result.structured.unwrap()["payloads"]
                .as_array()
                .unwrap()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn jwt_decode_decodes_segments_without_verifying() {
        let header = json!({"alg": "HS256", "typ": "JWT"}).to_string();
        let payload = json!({"sub": "1234567890", "admin": true}).to_string();
        let token = format!(
            "{}.{}.c2lnbmF0dXJl",
            b64_encode(header.as_bytes(), true, false),
            b64_encode(payload.as_bytes(), true, false)
        );
        let result = JwtDecodeTool.run(json!({"token": token})).await.unwrap();
        assert!(result.ok);
        let data = result.structured.unwrap();
        assert_eq!(data["verified"], json!(false));
        assert_eq!(data["header"]["alg"], json!("HS256"));
        assert_eq!(data["payload"]["sub"], json!("1234567890"));
        assert_eq!(data["payload"]["admin"], json!(true));
        assert_eq!(data["segments"]["signature"]["raw"], json!("c2lnbmF0dXJl"));

        let malformed = JwtDecodeTool.run(json!({"token": "abc"})).await.unwrap();
        assert!(!malformed.ok);
    }

    #[tokio::test]
    async fn hash_util_matches_known_vectors() {
        let tool = HashUtilTool;
        for (op, value, expected) in [
            ("md5", "", "d41d8cd98f00b204e9800998ecf8427e"),
            ("sha1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                "sha256",
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            ("b64encode", "hi", "aGk="),
            ("hex", "AB", "4142"),
        ] {
            let result = tool.run(json!({"op": op, "value": value})).await.unwrap();
            assert!(result.ok, "{op}");
            assert_eq!(
                result.structured.unwrap()["result"],
                json!(expected),
                "{op}"
            );
        }
        let decoded = tool
            .run(json!({"op": "b64decode", "value": "aGk="}))
            .await
            .unwrap();
        assert_eq!(decoded.structured.unwrap()["result"], json!("hi"));
        let bad = tool.run(json!({"op": "nope", "value": "x"})).await.unwrap();
        assert!(!bad.ok);
    }

    #[tokio::test]
    async fn knowledge_lookup_matches_wstg_and_cwe() {
        let result = KnowledgeLookupTool
            .run(json!({"query": "xss injection"}))
            .await
            .unwrap();
        assert!(result.ok);
        let data = result.structured.unwrap();
        let matches = data["matches"].as_array().unwrap();
        assert!(matches.iter().any(|m| m["id"] == json!("WSTG-INPV-01")));
        assert!(matches
            .iter()
            .any(|m| m["cwe"].as_array().unwrap().contains(&json!("CWE-79"))));
    }

    #[tokio::test]
    async fn report_writer_renders_required_markdown_sections() {
        let result = ReportWriterTool
            .run(json!({
                "program": "Acme Bug Bounty",
                "scope": ["example.com", "*.example.com"],
                "findings": [{
                    "title": "Reflected XSS",
                    "severity": "high",
                    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "cwe": "CWE-79",
                    "asset": "https://example.com/search",
                    "steps": "1. Visit /search?q=<script>...",
                    "poc": "GET /search?q=<script>alert(1)</script>",
                    "impact": "Script execution in victim browsers",
                    "remediation": "Encode output and add CSP",
                    "evidence": "HTTP/1.1 200 OK"
                }]
            }))
            .await
            .unwrap();
        assert!(result.ok);
        let data = result.structured.unwrap();
        let markdown = data["markdown"].as_str().unwrap();
        for section in [
            "Executive Summary",
            "Scope",
            "Methodology",
            "Findings",
            "CVSS",
            "CWE",
            "Steps to Reproduce",
            "Proof of Concept",
            "Impact",
            "Remediation",
            "Evidence SHA-256",
            "Coverage",
            "Timeline",
            "Appendices",
        ] {
            assert!(markdown.contains(section), "missing section: {section}");
        }
        assert!(markdown.contains("Acme Bug Bounty"));
        assert_eq!(data["finding_count"], json!(1));
        assert_eq!(
            data["evidence_hashes"][0],
            json!(sha256_hex(b"HTTP/1.1 200 OK"))
        );
    }

    #[test]
    fn new_tools_are_registered_and_gated_without_network() {
        let dir = std::env::temp_dir().join(format!("mbt-new-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let registry = default_registry(&dir);
        for name in [
            "http_fuzz",
            "http_probe",
            "subdomain_enum",
            "port_scan",
            "content_discovery",
            "vuln_scan",
            "browser",
            "payload_forge",
            "jwt_decode",
            "hash_util",
            "knowledge_lookup",
            "report_writer",
            "task_put",
            "clue_put",
        ] {
            assert!(registry.get(name).is_some(), "missing tool: {name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn gated_tools_return_ok_false_without_configured_commands() {
        let tool = ExternalBackedTool {
            name: "port_scan",
            description: "",
            risk: "intrusive",
            required: &["host"],
            commands: &["nmap", "naabu"],
            registry: ToolRegistry::new(),
        };
        let result = tool
            .run(json!({"host": "example.com", "ports": "80,443"}))
            .await
            .unwrap();
        assert!(!result.ok);
        let data = result.structured.unwrap();
        assert_eq!(data["gated"], json!(true));
        assert_eq!(data["ok"], json!(false));
        assert!(data["message"]
            .as_str()
            .unwrap()
            .contains("external_commands"));
    }

    #[test]
    fn canonical_report_contains_all_sections_and_f001() {
        let input = ReportInput {
            program: "Acme Bug Bounty".to_string(),
            engagement: "Acme Spring 2026".to_string(),
            scope_in: vec!["example.com".to_string()],
            scope_out: vec!["admin.example.com".to_string()],
            rules: vec!["Max 10 rps".to_string()],
            findings: vec![ReportFinding {
                id: "finding-1".to_string(),
                title: "Reflected XSS".to_string(),
                severity: "high".to_string(),
                cvss: Some(7.4),
                vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".to_string()),
                cwe: Some("CWE-79".to_string()),
                cwe_rationale: None,
                cvss_note: None,
                asset: Some("https://example.com/search".to_string()),
                description: "Reflected input reaches the DOM.".to_string(),
                reproduction: Some("1. Visit /search?q=<script>alert(1)</script>".to_string()),
                impact: Some("Session theft".to_string()),
                remediation: Some("Encode output".to_string()),
                evidence_hash: Some("a".repeat(64)),
                verified: true,
                ..Default::default()
            }],
            coverage: vec![(
                "https://example.com/search".to_string(),
                "GET".to_string(),
                String::new(),
            )],
            timeline: vec![(
                "2026-11-19T00:00:00Z".to_string(),
                "finding".to_string(),
                "XSS confirmed".to_string(),
            )],
            report_id: "report-1".to_string(),
            ..Default::default()
        };
        let markdown = render_canonical_report(&input);
        for section in [
            "# Acme Spring 2026 â€” Security Assessment Report",
            "## Executive Summary",
            "## Scope & ROE",
            "## Methodology",
            "## Findings",
            "### F-001",
            "CVSS",
            "CWE-79",
            "Steps to Reproduce",
            "Proof of Concept",
            "Impact",
            "Remediation",
            "Evidence SHA-256",
            "## Coverage",
            "## Timeline",
            "## Appendices",
        ] {
            assert!(markdown.contains(section), "missing section: {section}");
        }
        assert!(markdown.contains(&"a".repeat(64)));
        assert!(!markdown.contains("### F-1:"));
    }

    #[tokio::test]
    async fn http_fuzz_caps_wordlist_requests_and_methods() {
        let tool = HttpFuzzTool {
            http: HttpRequestTool::new(),
        };
        let wordlist: Vec<String> = (0..1000).map(|i| format!("w{i}")).collect();
        let result = tool
            .run(json!({"url": "http://localhost/FUZZ", "wordlist": wordlist}))
            .await
            .unwrap();
        let data = result.structured.unwrap();
        assert_eq!(data["capped"], json!(true));
        assert_eq!(data["wordlist_total"], json!(1000));
        assert_eq!(data["requests"], json!(MAX_FUZZ_REQUESTS));
        assert_eq!(data["results"].as_array().unwrap().len(), MAX_FUZZ_WORDLIST);

        for method in ["PUT", "DELETE", "PATCH"] {
            let err = tool
                .run(json!({"url": "http://localhost/FUZZ", "wordlist": ["a"], "method": method}))
                .await
                .unwrap_err();
            assert!(err.to_string().contains("not allowed"), "{err}");
        }
        for method in ["GET", "HEAD", "post"] {
            assert!(
                tool.run(
                    json!({"url": "http://localhost/FUZZ", "wordlist": ["a"], "method": method})
                )
                .await
                .is_ok(),
                "{method} should be accepted"
            );
        }
    }

    #[tokio::test]
    async fn external_command_tool_enforces_scope_before_spawn() {
        let dir = std::env::temp_dir().join(format!("mbt-scope-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(windows)]
        let (command, template) = (
            "cmd",
            vec!["/C".to_string(), "echo".to_string(), "{target}".to_string()],
        );
        #[cfg(not(windows))]
        let (command, template) = ("echo", vec!["{target}".to_string()]);
        let tool = ExternalCommandTool::new(
            "scoped",
            "scoped adapter",
            command,
            template,
            "network",
            &dir,
        )
        .with_scope(vec!["example.com".to_string()], Vec::new());

        let denied = tool.run(json!({"target": "evil.org"})).await.unwrap_err();
        assert!(denied.to_string().contains("scope policy"), "{denied}");
        let allowed = tool.run(json!({"target": "example.com"})).await.unwrap();
        assert!(allowed.ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- TC-1: shell allowlist / process environment -----------------------

    #[test]
    fn shell_allowlist_is_only_echo_and_whoami() {
        for cmd in [
            "git -c alias.x=!calc x",
            "cargo build",
            "cat C:\\Windows\\win.ini",
            "ls -la",
            "dir",
            "pwd",
            "echo hi > file",
            "echo a=b",
            "echo ..",
        ] {
            assert!(
                validate_shell_command(cmd).is_err(),
                "expected {cmd} to be rejected"
            );
        }
        assert!(validate_shell_command("echo hi").is_ok());
        assert!(validate_shell_command("whoami").is_ok());
    }

    #[tokio::test]
    async fn shell_exec_allows_echo_and_whoami() {
        let dir = std::env::temp_dir().join(format!("mbt-ok-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let tool = ShellExecTool::new(&dir).unwrap();
        let echo = tool.run(json!({"cmd": "echo hi"})).await.unwrap();
        assert!(echo.ok);
        assert!(echo.output.contains("hi"));
        let who = tool.run(json!({"cmd": "whoami"})).await.unwrap();
        assert!(who.ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_process_env_excludes_home_and_userprofile() {
        for (key, _) in safe_process_env() {
            let key = key.to_string_lossy().to_ascii_uppercase();
            assert!(
                !matches!(key.as_str(), "HOME" | "USERPROFILE"),
                "leaked {key} into child environment"
            );
        }
    }

    // ---- TC-5: capped streaming HTTP body ----------------------------------

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    async fn serve_once(body: String) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let header_end = loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break raw.len();
                }
                raw.extend_from_slice(&buf[..n]);
                if let Some(pos) = find_subslice(&raw, b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let head = String::from_utf8_lossy(&raw[..header_end]);
            let content_length = head
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
            while raw.len() < header_end + content_length {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&raw).into_owned()
        });
        (format!("http://{addr}/"), handle)
    }

    fn local_tool_options() -> ToolOptions {
        ToolOptions {
            trusted_local_targets: vec!["127.0.0.1".to_string()],
            ..ToolOptions::default()
        }
    }

    #[tokio::test]
    async fn http_body_is_capped_when_streamed() {
        let (url, server) = serve_once("x".repeat(64 * 1024)).await;
        let tool = HttpRequestTool::with_options(local_tool_options());
        let result = tool.run(json!({"url": url})).await.unwrap();
        let data = result.structured.unwrap();
        assert_eq!(data["body_truncated"], json!(true));
        let body_bytes = data["body_bytes"].as_u64().unwrap() as usize;
        assert!(body_bytes <= MAX_HTTP_BODY_BYTES + MAX_HTTP_BODY_SLACK);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_small_body_is_not_truncated() {
        let (url, server) = serve_once("hello".to_string()).await;
        let tool = HttpRequestTool::with_options(local_tool_options());
        let result = tool.run(json!({"url": url})).await.unwrap();
        let data = result.structured.unwrap();
        assert_eq!(data["body_truncated"], json!(false));
        assert_eq!(data["body"], json!("hello"));
        server.await.unwrap();
    }

    // ---- TC-6: redaction ----------------------------------------------------

    #[test]
    fn redact_covers_all_bearers_and_json_secrets() {
        let out = redact("Authorization: Bearer first and Bearer second");
        assert!(!out.contains("first"), "{out}");
        assert!(!out.contains("second"), "{out}");
        assert_eq!(out.matches("[REDACTED]").count(), 2);

        let input = r#"{"api_key":"plaintext","nested":{"token":"abc123"},"note":"Bearer leakme"}"#;
        let out = redact(input);
        assert!(!out.contains("plaintext"), "{out}");
        assert!(!out.contains("abc123"), "{out}");
        assert!(!out.contains("leakme"), "{out}");
    }

    // ---- TC-7: external command scope / timeout / redaction -----------------

    #[test]
    fn external_scope_values_covers_all_placeholders() {
        let template: Vec<String> = [
            "-d", "{target}", "--host", "{host}", "-u", "{url}", "-w", "{word}",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let input = json!({
            "target": "example.com",
            "host": "ns.example.com",
            "url": "https://example.com/a",
            "word": "wordlist.txt"
        });
        assert_eq!(
            external_scope_values(&template, &input),
            vec![
                "example.com",
                "ns.example.com",
                "https://example.com/a",
                "wordlist.txt"
            ]
        );
        // Empty values are skipped and a bare target is the fallback.
        assert!(external_scope_values(&["{host}".to_string()], &json!({"host": ""})).is_empty());
        assert_eq!(
            external_scope_values(&["plain".to_string()], &json!({"target": "t.example.com"})),
            vec!["t.example.com"]
        );
    }

    #[tokio::test]
    async fn external_command_checks_non_target_placeholders_against_scope() {
        let dir = std::env::temp_dir().join(format!("mbt-url-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        // "echo" never runs: the out-of-scope {url} value is rejected first.
        let tool = ExternalCommandTool::new(
            "scoped",
            "scoped",
            "echo",
            vec!["{url}".to_string()],
            "network",
            &dir,
        )
        .with_scope(vec!["example.com".to_string()], Vec::new());
        let err = tool
            .run(json!({"url": "https://evil.org/"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope policy"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn external_command_kills_child_on_timeout() {
        let dir = std::env::temp_dir().join(format!("mbt-kill-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(windows)]
        let (program, args) = (
            "ping",
            vec!["-n".to_string(), "30".to_string(), "127.0.0.1".to_string()],
        );
        #[cfg(not(windows))]
        let (program, args) = ("sleep", vec!["30".to_string()]);
        let tool = ExternalCommandTool::new("slow", "slow", program, args, "safe", &dir)
            .with_timeout(Duration::from_millis(200));
        let start = Instant::now();
        let err = tool.run(json!({})).await.unwrap_err();
        assert!(err.to_string().contains("timeout"), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "kill-on-timeout took too long: {:?}",
            start.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- TC-8: advisory PoC validation -------------------------------------

    #[tokio::test]
    async fn validate_poc_requires_finding_id() {
        let tool = ValidatePoCTool::new();
        let result = tool
            .run(json!({"url": "http://example.com/"}))
            .await
            .unwrap();
        assert!(!result.ok);
        let data = result.structured.unwrap();
        assert_eq!(data["valid"], json!(false));
        assert_eq!(data["error"], json!("finding_id required"));
    }

    #[tokio::test]
    async fn validate_poc_replay_is_advisory_and_includes_headers_body() {
        let (url, server) = serve_once("marker-here".to_string()).await;
        let tool = ValidatePoCTool::with_options(local_tool_options());
        let result = tool
            .run(json!({
                "finding_id": "f-1",
                "url": url,
                "method": "POST",
                "headers": {"X-Test": "abc123"},
                "body": "hello=world",
                "expected_status": 200,
                "marker": "marker-here"
            }))
            .await
            .unwrap();
        let data = result.structured.unwrap();
        assert_eq!(data["advisory"], json!(true));
        assert_eq!(data["finding_id"], json!("f-1"));
        assert_eq!(data["valid"], json!(true));
        let raw = server.await.unwrap().to_ascii_lowercase();
        assert!(
            raw.contains("x-test: abc123") || raw.contains("x-test:abc123"),
            "{raw}"
        );
        assert!(raw.contains("hello=world"), "{raw}");
    }

    // ---- B1: allowed_methods gate -------------------------------------------

    #[tokio::test]
    async fn allowed_methods_are_enforced_centrally_and_case_insensitively() {
        let options = ToolOptions {
            trusted_local_targets: vec!["127.0.0.1".to_string()],
            allowed_methods: Some(vec!["get".to_string(), "HEAD".to_string()]),
            ..ToolOptions::default()
        };
        let tool = HttpRequestTool::with_options(options);

        let denied = tool
            .run(json!({"url": "http://127.0.0.1:9/", "method": "POST"}))
            .await
            .unwrap();
        assert!(!denied.ok);
        let data = denied.structured.unwrap();
        assert_eq!(data["error"], json!("method_not_allowed"));
        assert_eq!(data["method"], json!("POST"));

        let (url, server) = serve_once("ok".to_string()).await;
        let allowed = tool
            .run(json!({"url": url, "method": "get"}))
            .await
            .unwrap();
        assert!(allowed.ok, "lowercase get should be accepted");
        server.await.unwrap();
    }

    // ---- B2: authoritative capture ------------------------------------------

    #[test]
    fn capture_from_structured_extracts_all_parts() {
        let value = json!({"capture": {"request": "r", "response": "s", "canary": "c"}});
        assert_eq!(
            capture_from_structured(&value).unwrap(),
            (String::from("r"), String::from("s"), String::from("c"))
        );
        assert_eq!(capture_from_structured(&json!({"capture": {}})), None);
        // The capture object itself is accepted too.
        let direct = json!({"request": "r", "response": "s", "canary": "c"});
        assert!(capture_from_structured(&direct).is_some());
    }

    #[tokio::test]
    async fn http_capture_records_request_response_and_canary() {
        let (url, server) = serve_once("body-marker".to_string()).await;
        let tool = HttpRequestTool::with_options(local_tool_options());
        let result = tool
            .run(json!({
                "url": url,
                "method": "POST",
                "headers": {"X-Trace": "abc"},
                "body": "k=v"
            }))
            .await
            .unwrap();
        assert!(result.ok);
        let structured = result.structured.unwrap();
        let (request, response, canary) = capture_from_structured(&structured).unwrap();
        assert!(canary.starts_with("agentbug-canary-"));
        assert_eq!(canary.len(), "agentbug-canary-".len() + 64);
        assert!(request.contains("POST / HTTP/1.1"), "{request}");
        assert!(request.contains("X-Trace: abc"), "{request}");
        assert!(request.contains("k=v"), "{request}");
        assert!(response.contains("HTTP/1.1 200"), "{response}");
        assert!(response.contains("body-marker"), "{response}");
        // The canary must stay out of the plaintext (LLM-visible) output.
        assert!(!result.output.contains(&canary));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_transport_error_still_carries_capture() {
        let tool = HttpRequestTool::with_options(local_tool_options());
        // Port 9 has no listener: the connection fails before any response.
        let result = tool
            .run(json!({"url": "http://127.0.0.1:9/"}))
            .await
            .unwrap();
        assert!(!result.ok);
        let structured = result.structured.unwrap();
        let (request, response, canary) = capture_from_structured(&structured).unwrap();
        assert!(request.contains("GET / HTTP/1.1"), "{request}");
        assert!(response.contains("(no response)"), "{response}");
        assert!(canary.starts_with("agentbug-canary-"));
    }

    // ---- B3/B4/B5: DNS, numeric hosts and trusted-target verification --------

    #[tokio::test]
    async fn dns_lookup_enforces_scope_and_rejects_blocked_addresses() {
        let scoped = DnsLookupTool::new_with_options(ToolOptions {
            scope_in: vec!["example.com".to_string()],
            ..ToolOptions::default()
        });
        let denied = scoped.run(json!({"host": "evil.org"})).await.unwrap();
        assert!(!denied.ok);
        assert_eq!(
            denied.structured.unwrap()["error"],
            json!("target_not_in_scope")
        );

        // A trusted hostname clears the syntactic block, but its loopback
        // address must still fail the independent IP check.
        let trusted = DnsLookupTool::new_with_options(ToolOptions {
            trusted_local_targets: vec!["localhost".to_string()],
            ..ToolOptions::default()
        });
        let blocked = trusted.run(json!({"host": "localhost"})).await.unwrap();
        assert!(!blocked.ok);
        let data = blocked.structured.unwrap();
        assert_eq!(data["error"], json!("blocked_ip"));
        assert!(data["blocked_ips"]
            .as_array()
            .unwrap()
            .iter()
            .any(|ip| ip == "127.0.0.1" || ip == "::1"));
    }

    #[test]
    fn numeric_host_forms_are_normalized_and_blocked() {
        for host in [
            "127.0.0.1",
            "2130706433",
            "0x7f000001",
            "0x7f.0x0.0x0.0x1",
            "0177.0.0.1",
            "127.1",
            "0.0.0.0",
            "0x0a0a0001", // 10.10.0.1
            "012.0.0.1",  // 10.0.0.1
        ] {
            assert!(validate_host_string(host).is_err(), "{host}");
            assert!(
                validate_host_with_options(host, &ToolOptions::default()).is_err(),
                "{host}"
            );
        }
        // Public forms, including hex, remain reachable.
        assert!(validate_host_string("8.8.8.8").is_ok());
        assert!(validate_host_string("0x8.8.8.8").is_ok());
        assert!(validate_host_string("example.com").is_ok());
    }

    #[tokio::test]
    async fn trusted_host_still_verifies_resolved_ips() {
        let options = ToolOptions {
            trusted_local_targets: vec!["localhost".to_string()],
            ..ToolOptions::default()
        };
        // A trusted name must not authorise the private IP DNS returns for it.
        assert!(resolve_trusted_host("localhost", &options).await.is_err());

        let ip_options = ToolOptions {
            trusted_local_targets: vec!["127.0.0.1".to_string()],
            ..ToolOptions::default()
        };
        assert!(validate_host_with_options("127.0.0.1", &ip_options).is_ok());
        assert!(validate_host_with_options("10.0.0.1", &ip_options).is_err());
        let resolved = resolve_trusted_host("127.0.0.1", &ip_options)
            .await
            .unwrap();
        assert_eq!(resolved.ip().to_string(), "127.0.0.1");
    }

    // ---- B7/B9: pipeline revalidation and PoC capture ------------------------

    #[tokio::test]
    async fn pipeline_revalidates_every_intermediate_target() {
        let dir = std::env::temp_dir().join(format!("mbt-pipe-scope-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(StepTool));
        let options = ToolOptions {
            scope_in: vec!["example.com".to_string()],
            ..ToolOptions::default()
        };
        let tool = PipelineTool::from_filtered_registry(registry, &dir, &options);
        // Step 1 receives the in-scope target; StepTool emits
        // "value-example.com", which is not under example.com and must be
        // rejected before step 2 spawns.
        let err = tool
            .run(json!({"steps": ["step", "step"], "target": "example.com"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope policy"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn validate_poc_forwards_capture_and_inherits_method_gate() {
        let options = ToolOptions {
            trusted_local_targets: vec!["127.0.0.1".to_string()],
            allowed_methods: Some(vec!["GET".to_string()]),
            ..ToolOptions::default()
        };
        let tool = ValidatePoCTool::with_options(options);
        let denied = tool
            .run(json!({
                "finding_id": "f-1",
                "url": "http://127.0.0.1:9/",
                "method": "POST"
            }))
            .await
            .unwrap();
        assert!(!denied.ok);
        assert_eq!(
            denied.structured.unwrap()["error"],
            json!("method_not_allowed")
        );

        let (url, server) = serve_once("marker".to_string()).await;
        let tool = ValidatePoCTool::with_options(local_tool_options());
        let result = tool
            .run(json!({
                "finding_id": "f-2",
                "url": url,
                "method": "GET",
                "expected_status": 200,
                "marker": "marker"
            }))
            .await
            .unwrap();
        let data = result.structured.unwrap();
        assert_eq!(data["valid"], json!(true));
        let (request, response, canary) = capture_from_structured(&data).unwrap();
        assert!(canary.starts_with("agentbug-canary-"));
        assert!(request.contains("GET /"));
        assert!(response.contains("marker"));
        server.await.unwrap();
    }

    fn uuid_like() -> String {
        format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }
}

// Type aliases for common names.
pub type DnsTool = DnsLookupTool;
pub type DnsResolveTool = DnsLookupTool;
pub type WriteFileTool = FsWriteTool;
pub type FsWrite = FsWriteTool;

fn apply_ranges(s: &mut String, mut ranges: Vec<(usize, usize)>) {
    if ranges.is_empty() {
        return;
    }
    ranges.sort_unstable_by_key(|r| r.0);
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start < last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    let original = std::mem::take(s);
    let mut out = String::with_capacity(original.len());
    let mut cursor = 0;
    for (start, end) in merged {
        if start < cursor {
            continue;
        }
        out.push_str(&original[cursor..start]);
        out.push_str("[REDACTED]");
        cursor = end;
    }
    out.push_str(&original[cursor..]);
    *s = out;
}

fn is_email_local(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-' | b'\'')
}

fn is_email_domain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

fn email_ranges(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'@' {
            let mut start = i;
            while start > 0 && is_email_local(b[start - 1]) {
                start -= 1;
            }
            let mut end = i + 1;
            while end < b.len() && is_email_domain(b[end]) {
                end += 1;
            }
            while end > i + 1 && b[end - 1] == b'.' {
                end -= 1;
            }
            let local = &s[start..i];
            let domain = &s[i + 1..end];
            let tld = domain.rsplit('.').next().unwrap_or("");
            if !local.is_empty()
                && domain.contains('.')
                && tld.len() >= 2
                && tld.bytes().all(|c| c.is_ascii_alphabetic())
            {
                ranges.push((start, end));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    ranges
}

fn ssn_ranges(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i + 11 <= b.len() {
        let shape = b[i..i + 3].iter().all(|c| c.is_ascii_digit())
            && b[i + 3] == b'-'
            && b[i + 4..i + 6].iter().all(|c| c.is_ascii_digit())
            && b[i + 6] == b'-'
            && b[i + 7..i + 11].iter().all(|c| c.is_ascii_digit());
        let bounded = (i == 0 || !(b[i - 1].is_ascii_digit() || b[i - 1] == b'-'))
            && (i + 11 == b.len() || !(b[i + 11].is_ascii_digit() || b[i + 11] == b'-'));
        if shape && bounded {
            ranges.push((i, i + 11));
            i += 11;
        } else {
            i += 1;
        }
    }
    ranges
}

fn is_numeric_span_byte(b: u8) -> bool {
    b.is_ascii_digit() || matches!(b, b' ' | b'-' | b'(' | b')' | b'+')
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@')
}

/// Contiguous runs of digits with optional phone/card separators. Returns the
/// byte span and the number of digits it contains.
fn numeric_spans(s: &str) -> Vec<(usize, usize, usize)> {
    let b = s.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() || b[i] == b'+' || b[i] == b'(' {
            let start = i;
            let mut end = i;
            while end < b.len() && is_numeric_span_byte(b[end]) {
                end += 1;
            }
            while end > start && !b[end - 1].is_ascii_digit() {
                end -= 1;
            }
            let digits = b[start..end].iter().filter(|c| c.is_ascii_digit()).count();
            let bounded = (start == 0 || !is_token_byte(b[start - 1]))
                && (end == b.len() || !is_token_byte(b[end]));
            if digits > 0 && bounded {
                spans.push((start, end, digits));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    spans
}

/// Skip epoch-millisecond and compact timestamp values so common numeric
/// identifiers are not mistaken for payment cards.
fn looks_like_timestamp(digits: &str) -> bool {
    let b = digits.as_bytes();
    if b.len() == 13 && b[0] == b'1' {
        return true;
    }
    if b.len() == 14 {
        let year = &digits[..4];
        let month: u32 = digits[4..6].parse().unwrap_or(0);
        if (year.starts_with("19") || year.starts_with("20")) && (1..=12).contains(&month) {
            return true;
        }
    }
    false
}

fn redact_pii(out: &mut String) {
    apply_ranges(out, email_ranges(out));
    apply_ranges(out, ssn_ranges(out));
    let mut numeric = Vec::new();
    for (start, end, digits) in numeric_spans(out) {
        let is_card = (13..=19).contains(&digits) && !looks_like_timestamp(&out[start..end]);
        let is_phone = (10..=12).contains(&digits);
        let bytes = out.as_bytes();
        let bounded = (start == 0 || !bytes[start - 1].is_ascii_alphanumeric())
            && (end >= bytes.len() || !bytes[end].is_ascii_alphanumeric());
        if (is_card || is_phone) && bounded {
            numeric.push((start, end));
        }
    }
    apply_ranges(out, numeric);
}

/// Keys whose values are credentials and must never appear in tool output.
const SENSITIVE_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "token",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

fn is_sensitive_key(key: &str) -> bool {
    let k = key.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| k == *sensitive || k.contains(sensitive))
}

/// Redact credential values in structured JSON, including nested objects and
/// arrays, so an LLM-supplied `api_key`/`token`/`secret` cannot leak verbatim.
fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *child = Value::String("[REDACTED]".into());
                } else {
                    redact_json_value(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        _ => {}
    }
}

/// Redact likely secrets from free text.
pub fn redact(input: &str) -> String {
    let mut out = if let Ok(mut value) = serde_json::from_str::<Value>(input) {
        if value.is_object() || value.is_array() {
            redact_json_value(&mut value);
            value.to_string()
        } else {
            input.to_string()
        }
    } else {
        input.to_string()
    };
    // Bearer tokens: replace every occurrence, not just the first one.
    loop {
        let Some(idx) = out.to_ascii_lowercase().find("bearer ") else {
            break;
        };
        let end = out[idx + "bearer ".len()..]
            .find(char::is_whitespace)
            .map(|n| idx + "bearer ".len() + n)
            .unwrap_or(out.len());
        out.replace_range(idx..end, "[REDACTED]");
    }
    // key=value style secrets
    for key in SENSITIVE_KEYS {
        let lower = out.to_ascii_lowercase();
        let mut search_from = 0;
        while let Some(pos) = lower[search_from..].find(key) {
            let abs = search_from + pos;
            // find '=' or ':' after key
            let after = abs + key.len();
            if after < out.len() {
                let bytes = out.as_bytes();
                let mut sep = after;
                while sep < bytes.len() && (bytes[sep] as char).is_whitespace() {
                    sep += 1;
                }
                if sep < bytes.len() && (bytes[sep] == b'=' || bytes[sep] == b':') {
                    sep += 1;
                    while sep < bytes.len() && (bytes[sep] as char).is_whitespace() {
                        sep += 1;
                    }
                    let val_start = sep;
                    let val_end = out[val_start..]
                        .find(|c: char| c.is_whitespace() || c == '&' || c == '"' || c == '\'')
                        .map(|n| val_start + n)
                        .unwrap_or(out.len());
                    if val_end > val_start {
                        out.replace_range(val_start..val_end, "[REDACTED]");
                    }
                }
            }
            search_from = abs + key.len();
            if search_from >= out.len() {
                break;
            }
        }
    }
    // Common secret prefixes
    for prefix in ["sk-", "ghp_", "gho_", "xoxb-", "xoxp-"] {
        let mut i = 0;
        while let Some(pos) = out[i..].find(prefix) {
            let start = i + pos;
            let end = out[start..]
                .find(|c: char| c.is_whitespace())
                .map(|n| start + n)
                .unwrap_or(out.len());
            if end > start + prefix.len() {
                out.replace_range(start..end, "[REDACTED]");
                i = start + 10;
            } else {
                i = start + prefix.len();
            }
            if i >= out.len() {
                break;
            }
        }
    }
    redact_pii(&mut out);
    out
}
pub fn redact_sensitive(input: &str) -> String {
    redact(input)
}
pub fn redact_secrets(input: &str) -> String {
    redact(input)
}
pub fn redact_text(input: &str) -> String {
    redact(input)
}

#[cfg(test)]
mod host_risk_tests {
    use super::*;

    #[test]
    fn registry_host_risk_is_frozen_at_registration() {
        struct Forged;
        #[async_trait]
        impl Tool for Forged {
            fn spec(&self) -> ToolSpec {
                ToolSpec {
                    name: "forged".to_string(),
                    description: String::new(),
                    input_schema: json!({"type":"object"}),
                    risk: "safe".to_string(),
                }
            }
            async fn run(&self, _input: Value) -> Result<ToolResult> {
                Ok(ToolResult {
                    ok: true,
                    output: "ok".to_string(),
                    structured: None,
                })
            }
        }

        let mut registry = ToolRegistry::new();
        registry.register_with_host_risk(Arc::new(Forged), "network-write");
        assert_eq!(registry.host_risk("forged"), "network-write");
        assert_eq!(registry.specs()[0].risk, "safe");
    }
}

#[cfg(test)]
mod platform_tests {
    use super::*;

    #[test]
    fn platform_detection_uses_host_without_network() {
        assert_eq!(
            platform_from_program_url("https://hackerone.com/acme"),
            Platform::HackerOne
        );
        assert_eq!(
            platform_from_program_url("https://www.hackerone.com/x"),
            Platform::HackerOne
        );
        assert_eq!(
            platform_from_program_url("https://bugcrowd.com/acme"),
            Platform::Bugcrowd
        );
        assert_eq!(
            platform_from_program_url("https://portal.bugcrowd.com/x"),
            Platform::Bugcrowd
        );
        assert_eq!(
            platform_from_program_url("https://HACKERONE.COM:443/x"),
            Platform::HackerOne
        );
        assert_eq!(
            platform_from_program_url("https://hackerone.com.evil.example/x"),
            Platform::Generic
        );
        assert_eq!(platform_from_program_url("not a url"), Platform::Generic);
    }

    #[test]
    fn platform_appendix_is_rendered_without_changing_eval_headings() {
        for platform in [Platform::HackerOne, Platform::Bugcrowd, Platform::Generic] {
            let input = ReportInput {
                program: "program".to_string(),
                engagement: "engagement".to_string(),
                report_id: "r1".to_string(),
                platform,
                ..Default::default()
            };
            let markdown = render_canonical_report(&input);
            assert!(markdown.contains("### C. Platform Field Checklist"));
            assert!(markdown.contains(&format!("Platform: {}", platform.label())));
            for heading in [
                "## Executive Summary",
                "## Scope & ROE",
                "## Methodology",
                "## Findings",
                "## Coverage",
                "## Timeline",
                "## Appendices",
            ] {
                assert!(markdown.contains(heading), "missing {heading}");
            }
        }
        let h1 = render_canonical_report(&ReportInput {
            platform: Platform::HackerOne,
            ..Default::default()
        });
        let bc = render_canonical_report(&ReportInput {
            platform: Platform::Bugcrowd,
            ..Default::default()
        });
        assert!(h1.contains("report-eligible"));
        assert!(!h1.contains("Prior-art"));
        assert!(bc.contains("Prior-art"));
        assert!(!bc.contains("severity ceiling"));
    }
}
