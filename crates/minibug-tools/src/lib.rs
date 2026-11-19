// Public type aliases/redaction helpers intentionally live below the test module.
#![allow(clippy::items_after_test_module)]

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

const MAX_OUTPUT_BYTES: usize = 8 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 16 * 1024;
const MAX_READ_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub risk: String, // read|write|destructive|network
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub ok: bool,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn spec(&self) -> ToolSpec;
    async fn run(&self, input: Value) -> Result<ToolResult>;
}

#[derive(Default, Clone)]
pub struct ToolRegistry {
    tools: BTreeMap<String, Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
        }
    }
    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        self.tools.insert(tool.spec().name.clone(), tool);
    }
    pub fn register_alias(&mut self, name: impl Into<String>, tool: Arc<dyn Tool>) {
        let name = name.into();
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

/// Only a small set of local, non-network commands may be spawned by the agent.
/// Network-capable recon must go through `http_request`/`dns_lookup`, which
/// enforce scope and egress rules.
fn validate_shell_command(cmd: &str) -> Result<()> {
    const ALLOWED: &[&str] = &["echo", "git", "cargo", "ls", "dir", "cat", "pwd", "whoami"];
    let first = cmd.split_whitespace().next().unwrap_or("");
    let exe = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !ALLOWED.contains(&exe.as_str()) {
        anyhow::bail!("command '{exe}' is not in the shell allowlist");
    }
    for ch in ['|', ';', '&', '`', '>', '<', '\n', '\r'] {
        if cmd.contains(ch) {
            anyhow::bail!("shell metacharacter '{ch}' is not allowed");
        }
    }
    if cmd.contains("$(") {
        anyhow::bail!("command substitution is not allowed");
    }
    Ok(())
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

/// String-level checks that do not need DNS. Fail closed on anything ambiguous.
fn validate_host_string(host: &str) -> Result<()> {
    let h = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if h.is_empty() {
        anyhow::bail!("url has no host");
    }
    if h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
    {
        anyhow::bail!("local/metadata targets are not allowed");
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            anyhow::bail!("private/reserved target address is not allowed: {ip}");
        }
        return Ok(());
    }
    // Decimal IP notation (e.g. 2130706433) bypasses naive string checks.
    if h.chars().all(|c| c.is_ascii_digit() || c == '.') {
        if let Ok(n) = h.replace('.', "").parse::<u32>() {
            let ip = IpAddr::V4(Ipv4Addr::from(n));
            if is_blocked_ip(ip) {
                anyhow::bail!("encoded private/reserved target address is not allowed: {ip}");
            }
        }
    }
    Ok(())
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
            description: "Execute a shell command in the workspace cwd (30s timeout, 8KB output cap). Intended for safe local recon/build/test commands as allowed by policy.".into(),
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
        // Pass only what a shell/process needs to start; never inherit secrets
        // such as DATABASE_URL or program API tokens.
        let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os()
            .filter(|(k, _)| {
                let key = k.to_string_lossy().to_ascii_uppercase();
                [
                    "PATH",
                    "PATHEXT",
                    "SYSTEMROOT",
                    "COMSPEC",
                    "TEMP",
                    "TMP",
                    "HOME",
                    "USERPROFILE",
                    "LANG",
                    "LC_ALL",
                ]
                .iter()
                .any(|allowed| *allowed == key)
            })
            .collect();
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
}
impl Default for HttpRequestTool {
    fn default() -> Self {
        Self::new()
    }
}
impl HttpRequestTool {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            // Redirects are disabled: following one could land on an internal
            // address that passed validation only for the original target.
            .redirect(reqwest::redirect::Policy::none())
            // A system proxy would resolve the hostname itself and bypass our
            // validated DNS pin; egress must go directly to the pinned IP.
            .no_proxy()
            .user_agent("minibug/0.1")
            .build()
            .expect("http client");
        Self { client }
    }
}
#[async_trait]
impl Tool for HttpRequestTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "http_request".into(),
            description: "Perform an HTTP request to an in-scope target for reconnaissance/validation. Returns status, selected headers, and truncated body. Localhost/.local/metadata targets are blocked; engagement scope/policy is enforced by the agent.".into(),
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
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("url has no host"))?;
        validate_host_string(host)?;
        let pinned_ip = if host.parse::<IpAddr>().is_ok() {
            None
        } else {
            Some(resolve_public_ip(host).await?)
        };
        // Pin the connection to the IP we validated; the TLS SNI and Host header
        // still use the original hostname.
        let client = if let Some(ip) = pinned_ip {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .user_agent("minibug/0.1")
                .resolve(host, ip)
                .build()
                .context("build pinned http client")?
        } else {
            self.client.clone()
        };
        let method = input
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_uppercase();
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
            _ => anyhow::bail!("unsupported method"),
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
        let resp = timeout(Duration::from_millis(timeout_ms), req.send())
            .await
            .context("http timeout")??;
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
        let bytes = timeout(Duration::from_millis(timeout_ms), resp.bytes())
            .await
            .context("read body timeout")??;
        let truncated = bytes.len() > MAX_HTTP_BODY_BYTES;
        let slice = &bytes[..bytes.len().min(MAX_HTTP_BODY_BYTES)];
        let body_text = redact(&String::from_utf8_lossy(slice));
        let out = json!({
            "ok": (200..400).contains(&status),
            "url": parsed.to_string(),
            "status": status,
            "headers": headers,
            "body": body_text,
            "body_truncated": truncated,
            "body_bytes": bytes.len()
        });
        Ok(ToolResult {
            ok: (200..400).contains(&status),
            output: truncate(&out.to_string()),
            structured: Some(out),
        })
    }
}

pub struct DnsLookupTool {
    timeout_ms: u64,
}
impl DnsLookupTool {
    pub fn new() -> Self {
        Self { timeout_ms: 10000 }
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
        let target = format!(
            "{}:0",
            host.trim_start_matches("http://")
                .trim_start_matches("https://")
        );
        let fut = tokio::net::lookup_host(&target);
        let addrs = tokio::time::timeout(std::time::Duration::from_millis(self.timeout_ms), fut)
            .await
            .context("dns timeout")??;
        let mut ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
        ips.sort();
        ips.dedup();
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
                    "evidence":{"type":"string"}
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
                "finding recorded (pending persist): [{sev}] {title}"
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
            output: truncate(&format!("asset recorded (pending persist): {kind}={value}")),
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

/// Non-panicking registry constructor for untrusted CLI input.
pub fn try_default_registry(cwd: impl AsRef<Path>) -> Result<ToolRegistry> {
    let cwd = cwd.as_ref();
    let mut reg = ToolRegistry::new();
    reg.register(Arc::new(FsReadTool::new(cwd)?));
    reg.register(Arc::new(FsWriteTool::new(cwd)?));
    reg.register(Arc::new(ShellExecTool::new(cwd)?));
    reg.register(Arc::new(HttpRequestTool::new()));
    reg.register(Arc::new(DnsLookupTool::new()));
    reg.register(Arc::new(SaveFindingTool));
    reg.register(Arc::new(RecordAssetTool));
    reg.register(Arc::new(SaveArtifactTool::new(cwd)?));
    reg.register(Arc::new(EchoTool));
    // Aliases for convenience / common tool names.
    let fs_read = Arc::new(FsReadTool::new(cwd)?);
    let fs_write = Arc::new(FsWriteTool::new(cwd)?);
    let dns = Arc::new(DnsLookupTool::new());
    reg.register_alias("read_file", fs_read.clone());
    reg.register_alias("read", fs_read);
    reg.register_alias("fs_write", fs_write.clone());
    reg.register_alias("write_file", fs_write.clone());
    reg.register_alias("write", fs_write);
    reg.register_alias("dns", dns.clone());
    reg.register_alias("dns_lookup", dns.clone());
    reg.register_alias("dns_resolve", dns.clone());
    reg.register_alias("dnsx", dns);
    Ok(reg)
}

/// Compatibility wrapper. Prefer [`try_default_registry`] for user-supplied paths.
pub fn default_registry(cwd: impl AsRef<Path>) -> ToolRegistry {
    try_default_registry(cwd).expect("invalid workspace cwd")
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
        let key = "MINIBUG_TEST_SECRET_TOKEN";
        std::env::set_var(key, "hunter2");
        let dir = std::env::temp_dir().join(format!("mbt-env-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let tool = ShellExecTool::new(&dir).unwrap();
        #[cfg(windows)]
        let cmd = format!("echo %{key}%");
        #[cfg(not(windows))]
        let cmd = format!("echo ${key}");
        let result = tool.run(json!({"cmd": cmd})).await.unwrap();
        assert!(result.ok);
        assert!(!result.output.contains("hunter2"));
        std::env::remove_var(key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_handles_multibyte_boundaries() {
        let s = "é".repeat(MAX_OUTPUT_BYTES + 8);
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

/// Redact likely secrets from free text.
pub fn redact(input: &str) -> String {
    let mut out = input.to_string();
    // Bearer tokens
    if let Some(idx) = out.to_ascii_lowercase().find("bearer ") {
        // redact rest of token-like chunk
        let start = idx + "bearer ".len();
        let end = out[start..]
            .find(|c: char| c.is_whitespace())
            .map(|n| start + n)
            .unwrap_or(out.len());
        out.replace_range(start..end, "[REDACTED]");
    }
    // key=value style secrets
    for key in [
        "api_key",
        "apikey",
        "token",
        "secret",
        "password",
        "passwd",
        "authorization",
    ] {
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
