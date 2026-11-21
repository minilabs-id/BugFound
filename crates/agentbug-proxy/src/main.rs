//! Bounded, deterministic HTTP intercepting proxy.
//!
//! This is the headless analogue of Burp's Proxy interception decision: every
//! request is either forwarded or dropped by an explicit deterministic gate.
//! With `--require-ack` the operator must approve each request on stdin, and
//! anything other than an explicit `y` is a fail-closed drop. There is no LLM
//! in this path and no auto-approval.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;

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
    /// Hard cap on total processed requests.
    #[arg(long, default_value_t = 100)]
    max_requests: usize,
    /// JSONL history output.
    #[arg(long, default_value = "proxy-history.jsonl")]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.scope_in.is_empty() && args.scope_out.is_empty() {
        return Err(anyhow!(
            "at least one --scope-in or --scope-out entry is required (fail-closed)"
        ));
    }
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;
    let history_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.out)
        .with_context(|| format!("open {}", args.out.display()))?;
    let history = Arc::new(tokio::sync::Mutex::new(history_file));
    let mut processed = 0usize;
    eprintln!(
        "agentbug-proxy listening on {} (require_ack={}, max_requests={})",
        args.listen, args.require_ack, args.max_requests
    );

    while processed < args.max_requests {
        let (stream, _peer) = listener.accept().await?;
        handle(stream, &args, &history, processed).await;
        processed += 1;
    }

    eprintln!("wrote history to {}", args.out.display());
    Ok(())
}

async fn handle(
    mut stream: TcpStream,
    args: &Args,
    history: &Arc<tokio::sync::Mutex<std::fs::File>>,
    index: usize,
) {
    let record = match process(&mut stream, args).await {
        Ok(record) => record,
        Err(error) => json!({"index": index, "decision": "error", "reason": error.to_string()}),
    };
    {
        let mut file = history.lock().await;
        let _ = writeln!(file, "{}", record);
        let _ = file.flush();
    }
    let _ = stream.shutdown().await;
}

async fn read_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>)> {
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

async fn process(stream: &mut TcpStream, args: &Args) -> Result<Value> {
    let (header, raw) = read_request(stream).await?;
    let request_line = header.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("").to_string();
    let parsed = url::Url::parse(&target).context("request target is not an absolute URL")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!("unsupported scheme"));
    }
    let host = parsed.host_str().unwrap_or_default().to_string();
    let allowed = agentbug_tools::scope_target_allowed(&host, &args.scope_in, &args.scope_out);
    let mut record = json!({
        "method": method,
        "url": agentbug_tools::redact(&target),
        "host": host,
        "scope_allowed": allowed
    });

    if !allowed {
        let body = b"{\"error\":\"out of scope\"}";
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(body).await?;
        record["decision"] = json!("drop");
        record["reason"] = json!("out_of_scope");
        return Ok(record);
    }

    if args.require_ack {
        println!(
            "INTERCEPT {} {} -> approve? [y/N]",
            agentbug_tools::redact(&method),
            agentbug_tools::redact(&target)
        );
        let answer = tokio::task::spawn_blocking(|| {
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer).map(|_| answer)
        })
        .await??;
        if !answer.trim().eq_ignore_ascii_case("y") {
            let body = b"{\"error\":\"operator declined\"}";
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            stream.write_all(body).await?;
            record["decision"] = json!("drop");
            record["reason"] = json!("operator_declined");
            return Ok(record);
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
    Ok(record)
}
