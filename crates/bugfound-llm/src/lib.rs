use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use reqwest::header::{CONTENT_TYPE, RETRY_AFTER};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedSender;

pub mod error;

pub use error::{LlmError, LlmErrorKind, Recovery};

/// Token counts reported by the provider (when the response includes `usage`).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub base_url: String,
    pub api_key: String,
    #[serde(default)]
    pub default_model: Option<String>,
    /// Ordered alternate model ids tried when the primary is retired or unknown.
    #[serde(default)]
    pub fallback_models: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    60000
}

/// Hard ceilings for streamed responses. A single provider frame, a single
/// content stream or a single tool-call argument blob may never grow without
/// bound, regardless of what the peer sends.
const MAX_SSE_BUFFER: usize = 2 * 1024 * 1024;
const MAX_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_TOOL_ARGS: usize = 1024 * 1024;
const MAX_TOOL_CALLS: usize = 128;

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.openai.com".into(),
            api_key: String::new(),
            default_model: None,
            fallback_models: Vec::new(),
            timeout_ms: default_timeout(),
        }
    }
}

/// Validate that a configured base URL is an absolute http/https URL with a host.
pub fn validate_base_url(raw: &str) -> Result<()> {
    let parsed = url::Url::parse(raw.trim())
        .with_context(|| format!("base_url '{raw}' is not a valid absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!(
            "base_url '{raw}' must use the http or https scheme"
        ));
    }
    if parsed.host_str().unwrap_or_default().is_empty() {
        return Err(anyhow!("base_url '{raw}' must include a host"));
    }
    Ok(())
}

/// Remove credentials and query/fragment data before a URL is put in an error
/// message or an event. Authentication material must never be echoed back.
fn sanitize_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut parsed) => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string()
        }
        Err(_) => raw.to_string(),
    }
}

/// Strip a URL from arbitrary error text (reqwest embeds the request URL in
/// some transport errors), so credentials in the URL cannot leak verbatim.
fn sanitize_error_text(raw_url: &str, text: &str) -> String {
    text.replace(raw_url, &sanitize_url(raw_url))
}

/// Read at most `cap` bytes from a response body. Used where the body is only
/// needed to make sure the connection is drained; never buffer unbounded text.
async fn read_bounded_body(mut response: reqwest::Response, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < cap {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let take = chunk.len().min(cap - out.len());
                out.extend_from_slice(&chunk[..take]);
            }
            _ => break,
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default)]
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

/// Canonical tool descriptor, re-exported from `bugfound-tools` so provider
/// adapters and tool registries share one lossless type.
pub use bugfound_tools::ToolSpec;

/// Compatibility alias for the old provider-side name.
#[deprecated(note = "use bugfound_llm::ToolSpec / bugfound_tools::ToolSpec")]
pub type LlmToolSpec = ToolSpec;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub model: String,
}

/// Response plus provider-reported usage. Usage is carried in the response
/// instead of a shared side channel, so concurrent calls cannot steal each
/// other's token counts.
#[derive(Debug, Clone)]
pub struct ChatResponseWithUsage {
    pub response: ChatResponse,
    pub usage: Option<TokenUsage>,
}

impl std::ops::Deref for ChatResponseWithUsage {
    type Target = ChatResponse;

    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

/// Provider-advertised capabilities. All flags are conservative by default;
/// a missing declaration never unlocks a feature.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCapabilities {
    pub tool_calling: bool,
    pub parallel_tool_calls: bool,
    pub streaming: bool,
    pub native_compaction: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ModelDescriptor {
    pub id: String,
    pub capabilities: ModelCapabilities,
    pub context_window: Option<u64>,
}

#[async_trait]
pub trait Llm: Send + Sync {
    async fn resolve_model(&self) -> Result<String>;

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities::default()
    }

    async fn model_info(&self) -> Result<ModelDescriptor> {
        Ok(ModelDescriptor {
            id: self.resolve_model().await?,
            capabilities: self.capabilities(),
            ..Default::default()
        })
    }

    async fn supported_models(&self) -> Vec<String> {
        Vec::new()
    }

    async fn chat(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<ChatResponse>;

    /// Preferred entry point: response and usage travel together. The default
    /// implementation keeps every existing `Llm` implementation source-compatible.
    async fn chat_full(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<ChatResponseWithUsage> {
        Ok(ChatResponseWithUsage {
            response: self.chat(model, messages, tools).await?,
            usage: None,
        })
    }

    /// Stream content deltas to `delta_tx` and return the same final response
    /// and usage as `chat_full`. Implementations without streaming emit one
    /// delta containing the full content, so existing mocks stay unchanged.
    async fn chat_stream_full(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
        delta_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    ) -> Result<ChatResponseWithUsage> {
        let full = self.chat_full(model, messages, tools).await?;
        if let (Some(tx), Some(content)) = (delta_tx, full.response.content.clone()) {
            let _ = tx.send(content);
        }
        Ok(full)
    }

    /// Compatibility shim. Prefer `chat_full` in new code.
    async fn chat_with_usage(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<(ChatResponse, Option<TokenUsage>)> {
        let full = self.chat_full(model, messages, tools).await?;
        Ok((full.response, full.usage))
    }
}

#[derive(Clone)]
pub struct LlmClient {
    cfg: LlmConfig,
    http: Client,
}

impl LlmClient {
    pub fn new(cfg: LlmConfig) -> Result<Self> {
        if cfg.api_key.trim().is_empty() {
            return Err(anyhow!(
                "api_key is required (set [llm].api_key or env:VAR in config)"
            ));
        }
        if cfg.base_url.trim().is_empty() {
            return Err(anyhow!("base_url is required"));
        }
        validate_base_url(&cfg.base_url)?;
        let http = Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(1000)))
            .build()?;
        Ok(Self { cfg, http })
    }

    fn api_base(&self) -> String {
        let b = self.cfg.base_url.trim().trim_end_matches('/').to_string();
        if b.ends_with("/v1") {
            b
        } else {
            format!("{b}/v1")
        }
    }

    pub async fn discover_models(&self) -> Result<Vec<String>> {
        let base = self.cfg.base_url.trim().trim_end_matches('/').to_string();
        let candidates = if base.ends_with("/v1") {
            vec![
                format!("{base}/models"),
                format!("{}/models", base.trim_end_matches("/v1")),
            ]
        } else {
            vec![format!("{base}/v1/models"), format!("{base}/models")]
        };
        let mut last_err: Option<anyhow::Error> = None;
        for url in candidates {
            for attempt in 0..2 {
                let res = self
                    .http
                    .get(&url)
                    .bearer_auth(self.cfg.api_key.trim())
                    .send()
                    .await;
                let res = match res {
                    Ok(r) => r,
                    Err(e) => {
                        let detail = sanitize_error_text(&url, &e.to_string());
                        last_err = Some(anyhow!("GET {} failed: {}", sanitize_url(&url), detail));
                        if attempt == 0 {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            continue;
                        }
                        break;
                    }
                };
                if !res.status().is_success() {
                    let status = res.status();
                    // Drain only a bounded number of bytes; the body may carry
                    // tokens/credentials and is deliberately omitted from errors.
                    let _ = read_bounded_body(res, 4096).await;
                    last_err = Some(anyhow!(
                        "models discovery failed at {}: {status}",
                        sanitize_url(&url)
                    ));
                    break;
                }
                let v: serde_json::Value = match res.json().await {
                    Ok(v) => v,
                    Err(_) => {
                        // serde errors echo the offending body fragment — omit it.
                        last_err = Some(anyhow!("invalid models json at {}", sanitize_url(&url)));
                        break;
                    }
                };
                let mut ids = vec![];
                if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
                    for item in arr {
                        if let Some(id) = item.get("id").and_then(|x| x.as_str()) {
                            if !id.trim().is_empty() {
                                ids.push(id.to_string());
                            }
                        }
                    }
                } else if let Some(arr) = v.as_array() {
                    for item in arr {
                        if let Some(id) = item
                            .get("id")
                            .and_then(|x| x.as_str())
                            .or_else(|| item.as_str())
                        {
                            if !id.trim().is_empty() {
                                ids.push(id.to_string());
                            }
                        }
                    }
                }
                if !ids.is_empty() {
                    return Ok(ids);
                }
                last_err = Some(anyhow!("no models found at {}", sanitize_url(&url)));
                break;
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("model discovery failed")))
    }

    async fn consume_chat_sse(
        &self,
        response: reqwest::Response,
        fallback_model: &str,
        delta_tx: Option<&UnboundedSender<String>>,
    ) -> Result<ChatResponseWithUsage> {
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        // A trailing '\r' may be split from its '\n' across two chunks.
        let mut carry_cr = false;
        let mut content = String::new();
        let mut usage = None;
        let mut model = fallback_model.to_string();
        let mut parts: BTreeMap<usize, (String, String, String)> = BTreeMap::new();
        let mut finished = false;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("chat stream read failed")?;
            // Normalize CRLF to LF before frame splitting, carrying a lone
            // trailing '\r' over to the next chunk.
            let mut normalized: Vec<u8> = Vec::with_capacity(chunk.len() + 1);
            let mut i = 0;
            if carry_cr {
                carry_cr = false;
                if chunk.first() == Some(&b'\n') {
                    normalized.push(b'\n');
                    i = 1;
                } else {
                    normalized.push(b'\r');
                }
            }
            while i < chunk.len() {
                match chunk[i] {
                    b'\r' if i + 1 == chunk.len() => {
                        carry_cr = true;
                        i += 1;
                    }
                    b'\r' if chunk[i + 1] == b'\n' => {
                        normalized.push(b'\n');
                        i += 2;
                    }
                    byte => {
                        normalized.push(byte);
                        i += 1;
                    }
                }
            }
            buffer.push_str(&String::from_utf8_lossy(&normalized));
            if buffer.len() > MAX_SSE_BUFFER {
                return Err(anyhow!(
                    "chat stream buffer exceeded {MAX_SSE_BUFFER} bytes; refusing to buffer unbounded SSE data"
                ));
            }
            while let Some(index) = buffer.find("\n\n") {
                let frame: String = buffer.drain(..index + 2).collect();
                for line in frame.lines() {
                    let Some(data) = line.strip_prefix("data:") else {
                        continue;
                    };
                    let data = data.trim();
                    if data == "[DONE]" {
                        finished = true;
                        break;
                    }
                    if data.is_empty() {
                        continue;
                    }
                    let value: serde_json::Value = match serde_json::from_str(data) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    // A streamed frame can terminate the completion early,
                    // exactly like a non-streamed `finish_reason`.
                    if let Some(reason) = value
                        .get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|c| c.first())
                        .and_then(|c| c.get("finish_reason"))
                        .and_then(|f| f.as_str())
                    {
                        if reason == "length" || reason == "content_filter" {
                            reject_truncated(reason)?;
                        }
                    }
                    if let Some(u) = value.get("usage") {
                        usage = Some(TokenUsage {
                            prompt_tokens: u
                                .get("prompt_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            completion_tokens: u
                                .get("completion_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                        });
                    }
                    if let Some(m) = value.get("model").and_then(|m| m.as_str()) {
                        if !m.is_empty() {
                            model = m.to_string();
                        }
                    }
                    let Some(delta) = value
                        .get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|c| c.first())
                        .and_then(|c| c.get("delta"))
                    else {
                        continue;
                    };
                    if let Some(text) = delta.get("content").and_then(|c| c.as_str()) {
                        if !text.is_empty() {
                            if content.len().saturating_add(text.len()) > MAX_CONTENT_BYTES {
                                return Err(anyhow!(
                                    "chat stream content exceeded {MAX_CONTENT_BYTES} bytes"
                                ));
                            }
                            content.push_str(text);
                            if let Some(tx) = delta_tx {
                                tx.send(text.to_string()).map_err(|_| {
                                    anyhow!("chat stream delta receiver was dropped")
                                })?;
                            }
                        }
                    }
                    if let Some(calls) = delta.get("tool_calls").and_then(|c| c.as_array()) {
                        for call in calls {
                            let index =
                                call.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                            if !parts.contains_key(&index) && parts.len() >= MAX_TOOL_CALLS {
                                return Err(anyhow!(
                                    "chat stream exceeded {MAX_TOOL_CALLS} tool calls"
                                ));
                            }
                            let entry = parts
                                .entry(index)
                                .or_insert_with(|| (String::new(), String::new(), String::new()));
                            if let Some(id) = call.get("id").and_then(|i| i.as_str()) {
                                if !id.is_empty() {
                                    entry.0 = id.to_string();
                                }
                            }
                            if let Some(function) = call.get("function") {
                                if let Some(name) = function.get("name").and_then(|n| n.as_str()) {
                                    entry.1.push_str(name);
                                }
                                if let Some(arguments) =
                                    function.get("arguments").and_then(|a| a.as_str())
                                {
                                    if entry.2.len().saturating_add(arguments.len()) > MAX_TOOL_ARGS
                                    {
                                        return Err(anyhow!(
                                            "streamed arguments for tool call {index} exceeded {MAX_TOOL_ARGS} bytes"
                                        ));
                                    }
                                    entry.2.push_str(arguments);
                                }
                            }
                        }
                    }
                }
                if finished {
                    break;
                }
            }
            if finished {
                break;
            }
        }

        let mut tool_calls = Vec::new();
        for (index, (id, name, arguments)) in parts {
            if name.is_empty() {
                continue;
            }
            let parsed: serde_json::Value = serde_json::from_str(&arguments)
                .with_context(|| format!("invalid streamed tool arguments for {name}"))?;
            tool_calls.push(ToolCall {
                id: if id.is_empty() {
                    format!("call_{index}")
                } else {
                    id
                },
                name,
                arguments: parsed,
            });
        }
        Ok(ChatResponseWithUsage {
            response: ChatResponse {
                content: if content.is_empty() {
                    None
                } else {
                    Some(content)
                },
                tool_calls,
                model,
            },
            usage,
        })
    }

    fn chat_request_body(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> serde_json::Value {
        let mut msgs: Vec<serde_json::Value> = Vec::new();
        for m in messages {
            let mut obj = serde_json::json!({"role": m.role});
            if !m.content.is_empty() || m.role == "tool" {
                obj["content"] = serde_json::json!(m.content);
            } else {
                obj["content"] = serde_json::json!(null);
            }
            if let Some(id) = &m.tool_call_id {
                obj["tool_call_id"] = serde_json::json!(id);
            }
            if let Some(name) = &m.name {
                obj["name"] = serde_json::json!(name);
            }
            if let Some(tc) = &m.tool_calls {
                let tcs: Vec<serde_json::Value> = tc
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "id": t.id,
                            "type": "function",
                            "function": {
                                "name": t.name,
                                "arguments": t.arguments.to_string()
                            }
                        })
                    })
                    .collect();
                obj["tool_calls"] = serde_json::json!(tcs);
            }
            msgs.push(obj);
        }
        let mut body = serde_json::json!({
            "model": model,
            "messages": msgs,
        });
        if !tools.is_empty() {
            let t: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {"name": t.name, "description": t.description, "parameters": t.input_schema}
                    })
                })
                .collect();
            body["tools"] = serde_json::Value::Array(t);
        }
        body
    }
}

#[async_trait]
impl Llm for LlmClient {
    async fn resolve_model(&self) -> Result<String> {
        if let Some(m) = &self.cfg.default_model {
            let m = m.trim();
            if !m.is_empty() {
                return Ok(m.to_string());
            }
        }
        let models = self.discover_models().await?;
        models
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no model discovered; set [llm].default_model"))
    }

    async fn chat_full(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<ChatResponseWithUsage> {
        let url = format!("{}/chat/completions", self.api_base());
        let mut body = self.chat_request_body(model, messages, tools);

        let mut candidates = vec![model.to_string()];
        for extra in &self.cfg.fallback_models {
            if extra != model {
                candidates.push(extra.clone());
            }
        }
        let mut fallback_error: Option<anyhow::Error> = None;
        for candidate in &candidates {
            body["model"] = serde_json::json!(candidate);
            let mut last_err: Option<anyhow::Error> = None;
            for attempt in 0..3u32 {
                let res = self
                    .http
                    .post(&url)
                    .bearer_auth(self.cfg.api_key.trim())
                    .json(&body)
                    .send()
                    .await;
                match res {
                    Ok(r) => {
                        if r.status().is_success() {
                            let v: serde_json::Value =
                                r.json().await.context("invalid chat json")?;
                            let usage = v.get("usage").map(|usage| TokenUsage {
                                prompt_tokens: usage
                                    .get("prompt_tokens")
                                    .and_then(|value| value.as_u64())
                                    .unwrap_or(0),
                                completion_tokens: usage
                                    .get("completion_tokens")
                                    .and_then(|value| value.as_u64())
                                    .unwrap_or(0),
                            });
                            let response = parse_chat_response(&v, model)?;
                            return Ok(ChatResponseWithUsage { response, usage });
                        }
                        let status = r.status().as_u16();
                        let retry_after = r
                            .headers()
                            .get(RETRY_AFTER)
                            .and_then(|v| v.to_str().ok())
                            .and_then(parse_retry_after)
                            .map(|d| d.min(Duration::from_secs(10)));
                        let text = r.text().await.unwrap_or_default();
                        let kind = LlmErrorKind::from_status(status, &text);
                        if kind.retryable() {
                            if attempt == 2 {
                                return Err(LlmError {
                                    kind,
                                    message: format!("chat failed {status}: {text}"),
                                    status: Some(status),
                                    retry_after,
                                    model: Some(model.to_string()),
                                }
                                .into());
                            }
                            let fallback = Duration::from_millis(500 * (1u64 << attempt));
                            let delay = retry_after.unwrap_or(fallback);
                            last_err = Some(
                                LlmError {
                                    kind,
                                    message: format!(
                                        "chat failed {status}: {text} (retrying in {}s)",
                                        delay.as_secs()
                                    ),
                                    status: Some(status),
                                    retry_after,
                                    model: Some(model.to_string()),
                                }
                                .into(),
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        let err = LlmError {
                            kind,
                            message: format!("chat failed {status}: {text}"),
                            status: Some(status),
                            retry_after,
                            model: Some(model.to_string()),
                        };
                        if err.kind == LlmErrorKind::ModelNotFound {
                            last_err = Some(err.into());
                            break;
                        }
                        return Err(err.into());
                    }
                    Err(e) => {
                        let kind = if e.is_timeout() {
                            LlmErrorKind::Timeout
                        } else {
                            LlmErrorKind::Transport
                        };
                        last_err = Some(
                            LlmError {
                                kind,
                                message: format!("POST {url} failed: {e}"),
                                status: e.status().map(|s| s.as_u16()),
                                retry_after: None,
                                model: Some(model.to_string()),
                            }
                            .into(),
                        );
                        if attempt < 2 {
                            tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt)))
                                .await;
                            continue;
                        }
                        break;
                    }
                }
            }
            let err = last_err.unwrap_or_else(|| anyhow!("chat failed"));
            let kind = err
                .downcast_ref::<LlmError>()
                .map(|e| e.kind)
                .unwrap_or_else(|| LlmErrorKind::from_message(&err.to_string()));
            if kind == LlmErrorKind::ModelNotFound {
                fallback_error = Some(err);
                continue;
            }
            return Err(err);
        }
        Err(fallback_error.unwrap_or_else(|| anyhow!("chat failed")))
    }

    async fn chat_stream_full(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
        delta_tx: Option<UnboundedSender<String>>,
    ) -> Result<ChatResponseWithUsage> {
        let url = format!("{}/chat/completions", self.api_base());
        let mut body = self.chat_request_body(model, messages, tools);
        body["stream"] = serde_json::json!(true);
        body["stream_options"] = serde_json::json!({ "include_usage": true });

        let mut candidates = vec![model.to_string()];
        for extra in &self.cfg.fallback_models {
            if extra != model {
                candidates.push(extra.clone());
            }
        }
        let mut fallback_error: Option<anyhow::Error> = None;
        for candidate in &candidates {
            body["model"] = serde_json::json!(candidate);
            let mut last_err: Option<anyhow::Error> = None;
            for attempt in 0..3u32 {
                let response = self
                    .http
                    .post(&url)
                    .bearer_auth(self.cfg.api_key.trim())
                    .json(&body)
                    .send()
                    .await;
                match response {
                    Ok(r) if r.status().is_success() => {
                        let is_json = r
                            .headers()
                            .get(CONTENT_TYPE)
                            .and_then(|v| v.to_str().ok())
                            .map(|v| v.contains("json"))
                            .unwrap_or(false);
                        if is_json {
                            let value: serde_json::Value =
                                r.json().await.context("invalid chat json")?;
                            let usage = value.get("usage").map(|u| TokenUsage {
                                prompt_tokens: u
                                    .get("prompt_tokens")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0),
                                completion_tokens: u
                                    .get("completion_tokens")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0),
                            });
                            let parsed = parse_chat_response(&value, model)?;
                            if let (Some(tx), Some(content)) = (&delta_tx, &parsed.content) {
                                tx.send(content.clone()).map_err(|_| {
                                    anyhow!("chat stream delta receiver was dropped")
                                })?;
                            }
                            return Ok(ChatResponseWithUsage {
                                response: parsed,
                                usage,
                            });
                        }
                        return self.consume_chat_sse(r, model, delta_tx.as_ref()).await;
                    }
                    Ok(r) => {
                        let status = r.status().as_u16();
                        let retry_after = r
                            .headers()
                            .get(RETRY_AFTER)
                            .and_then(|v| v.to_str().ok())
                            .and_then(parse_retry_after)
                            .map(|d| d.min(Duration::from_secs(10)));
                        // Keep the body bounded: it is only diagnostic text and
                        // may contain provider-supplied secrets.
                        let bytes = read_bounded_body(r, 4096).await;
                        let text = String::from_utf8_lossy(&bytes);
                        let kind = LlmErrorKind::from_status(status, &text);
                        if kind.retryable() {
                            if attempt == 2 {
                                return Err(LlmError {
                                    kind,
                                    message: format!("chat stream failed {status}: {text}"),
                                    status: Some(status),
                                    retry_after,
                                    model: Some(model.to_string()),
                                }
                                .into());
                            }
                            let fallback = Duration::from_millis(500 * (1u64 << attempt));
                            let delay = retry_after.unwrap_or(fallback);
                            last_err = Some(
                                LlmError {
                                    kind,
                                    message: format!(
                                        "chat stream failed {status}: {text} (retrying in {}s)",
                                        delay.as_secs()
                                    ),
                                    status: Some(status),
                                    retry_after,
                                    model: Some(model.to_string()),
                                }
                                .into(),
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        let err = LlmError {
                            kind,
                            message: format!("chat stream failed {status}: {text}"),
                            status: Some(status),
                            retry_after,
                            model: Some(model.to_string()),
                        };
                        if kind == LlmErrorKind::ModelNotFound {
                            last_err = Some(err.into());
                            break;
                        }
                        return Err(err.into());
                    }
                    Err(e) => {
                        let kind = if e.is_timeout() {
                            LlmErrorKind::Timeout
                        } else {
                            LlmErrorKind::Transport
                        };
                        last_err = Some(
                            LlmError {
                                kind,
                                message: format!("chat stream transport error: {e}"),
                                status: None,
                                retry_after: None,
                                model: Some(model.to_string()),
                            }
                            .into(),
                        );
                        if attempt < 2 {
                            tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt)))
                                .await;
                            continue;
                        }
                        break;
                    }
                }
            }
            let err = last_err.unwrap_or_else(|| anyhow!("chat stream failed"));
            let kind = err
                .downcast_ref::<LlmError>()
                .map(|e| e.kind)
                .unwrap_or_else(|| LlmErrorKind::from_message(&err.to_string()));
            if kind == LlmErrorKind::ModelNotFound {
                fallback_error = Some(err);
                continue;
            }
            return Err(err);
        }
        Err(fallback_error.unwrap_or_else(|| anyhow!("chat stream failed")))
    }

    async fn chat(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<ChatResponse> {
        Ok(self.chat_full(model, messages, tools).await?.response)
    }
}

/// Single source of truth for the rejection text used by both streamed and
/// non-streamed responses, so a truncated stream cannot be treated as complete.
fn reject_truncated(reason: &str) -> Result<()> {
    Err(anyhow!(
        "chat response was cut short (finish_reason={reason}); refusing to treat truncated output as complete"
    ))
}

/// Validate and decode a chat-completions response body.
///
/// Kept separate from the HTTP loop so the shape checks (including truncated
/// responses and malformed tool arguments) can be exercised without a network.
fn parse_chat_response(v: &serde_json::Value, fallback_model: &str) -> Result<ChatResponse> {
    let choices = v
        .get("choices")
        .and_then(|c| c.as_array())
        .filter(|arr| !arr.is_empty())
        .ok_or_else(|| anyhow!("invalid chat response: missing or empty 'choices' array"))?;
    let choice = &choices[0];
    let msg = choice
        .get("message")
        .and_then(|m| m.as_object())
        .ok_or_else(|| {
            anyhow!("invalid chat response: choices[0].message is missing or not an object")
        })?;

    let finish_reason = choice
        .get("finish_reason")
        .and_then(|f| f.as_str())
        .unwrap_or_default();
    if finish_reason == "length" || finish_reason == "content_filter" {
        reject_truncated(finish_reason)?;
    }

    let content = msg
        .get("content")
        .and_then(|c| c.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let mut tool_calls = vec![];
    if let Some(arr) = msg.get("tool_calls").and_then(|x| x.as_array()) {
        for (i, tc) in arr.iter().enumerate() {
            let function = tc.get("function").and_then(|f| f.as_object());
            let name = function
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let args_str = function
                .and_then(|f| f.get("arguments"))
                .and_then(|a| a.as_str())
                .unwrap_or("{}");
            let arguments: serde_json::Value =
                serde_json::from_str(args_str).with_context(|| {
                    format!("invalid JSON in tool arguments for '{name}' (tool call index {i})")
                })?;
            let id = tc
                .get("id")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("call_{i}"));
            tool_calls.push(ToolCall {
                id,
                name,
                arguments,
            });
        }
    }

    let used_model = v
        .get("model")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_model)
        .to_string();
    Ok(ChatResponse {
        content,
        tool_calls,
        model: used_model,
    })
}

/// Parse a Retry-After value (delta-seconds or a simple IMF-fixdate HTTP-date).
fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    // IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT". Other date formats fall
    // back to the caller's exponential backoff.
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 6 || !parts[5].eq_ignore_ascii_case("GMT") {
        return None;
    }
    let months = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let month = parts[2].to_ascii_lowercase();
    let m = months
        .iter()
        .position(|name| *name == month.as_str())
        .map(|i| i as i64 + 1)?;
    let day: i64 = parts[1].parse().ok()?;
    let year: i64 = parts[3].parse().ok()?;
    let clock: Vec<i64> = parts[4]
        .split(':')
        .map(|p| p.parse::<i64>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    if clock.len() != 3
        || !(1..=31).contains(&day)
        || clock[0] > 23
        || clock[1] > 59
        || clock[2] > 59
    {
        return None;
    }
    let days = days_from_civil(year, m, day);
    let secs = days * 86400 + clock[0] * 3600 + clock[1] * 60 + clock[2];
    let target = UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64);
    Some(target.duration_since(SystemTime::now()).unwrap_or_default())
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("test JSON should parse")
    }

    #[test]
    fn parses_valid_response_and_uses_fallback_model() {
        let v = body(
            r#"{"choices":[{"message":{"content":"hello","tool_calls":[]},"finish_reason":"stop"}]}"#,
        );
        let resp = parse_chat_response(&v, "fallback-model").unwrap();
        assert_eq!(resp.content.as_deref(), Some("hello"));
        assert!(resp.tool_calls.is_empty());
        assert_eq!(resp.model, "fallback-model");
    }

    #[test]
    fn uses_response_model_when_present() {
        let v = body(
            r#"{"model":"gpt-4o","choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}"#,
        );
        let resp = parse_chat_response(&v, "fallback").unwrap();
        assert_eq!(resp.model, "gpt-4o");
    }

    #[test]
    fn rejects_missing_empty_or_malformed_choices() {
        for raw in [
            r#"{}"#,
            r#"{"choices":[]}"#,
            r#"{"choices":"nope"}"#,
            r#"{"choices":[5]}"#,
            r#"{"choices":[{"finish_reason":"stop"}]}"#,
            r#"{"choices":[{"message":"not-an-object"}]}"#,
        ] {
            let v = body(raw);
            let err = parse_chat_response(&v, "m").unwrap_err().to_string();
            assert!(
                err.contains("choices") || err.contains("message"),
                "unexpected error for {raw}: {err}"
            );
        }
    }

    #[test]
    fn rejects_truncated_finish_reasons() {
        for reason in ["length", "content_filter"] {
            let raw = format!(
                r#"{{"choices":[{{"message":{{"content":"partial"}},"finish_reason":"{reason}"}}]}}"#
            );
            let v = body(&raw);
            let err = parse_chat_response(&v, "m").unwrap_err().to_string();
            assert!(err.contains("cut short"), "unexpected error: {err}");
            assert!(err.contains(reason), "error should name the reason: {err}");
        }
        let ok = body(r#"{"choices":[{"message":{"content":"x"},"finish_reason":"tool_calls"}]}"#);
        assert!(parse_chat_response(&ok, "m").is_ok());
    }

    #[test]
    fn parses_well_formed_tool_arguments() {
        let v = body(
            r#"{"choices":[{"message":{"content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"fs_read","arguments":"{\"path\":\"a.txt\"}"}}]},"finish_reason":"tool_calls"}]}"#,
        );
        let resp = parse_chat_response(&v, "m").unwrap();
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].name, "fs_read");
        assert_eq!(resp.tool_calls[0].arguments["path"], "a.txt");
        assert_eq!(resp.tool_calls[0].id, "c1");
    }

    #[test]
    fn rejects_malformed_tool_arguments_instead_of_raw_substitute() {
        let v = body(
            r#"{"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"fs_read","arguments":"{not json"}}]},"finish_reason":"tool_calls"}]}"#,
        );
        let err = parse_chat_response(&v, "m").unwrap_err().to_string();
        assert!(
            err.contains("invalid JSON in tool arguments"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn retry_after_seconds_and_cap() {
        assert_eq!(parse_retry_after("7"), Some(Duration::from_secs(7)));
        assert_eq!(parse_retry_after(" 3 "), Some(Duration::from_secs(3)));
        assert_eq!(
            parse_retry_after(" Sun, 06 Nov 1994 08:49:37 GMT "),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("not-a-date"), None);
    }

    #[test]
    fn validates_base_urls() {
        assert!(validate_base_url("https://api.openai.com").is_ok());
        assert!(validate_base_url("http://127.0.0.1:8080/v1").is_ok());
        assert!(validate_base_url("ftp://example.com").is_err());
        assert!(validate_base_url("not a url").is_err());
        assert!(validate_base_url("http://").is_err());
    }

    struct ChatOnly;

    #[async_trait]
    impl Llm for ChatOnly {
        async fn resolve_model(&self) -> Result<String> {
            Ok("m".to_string())
        }

        async fn chat(
            &self,
            _model: &str,
            _messages: &[ChatMessage],
            _tools: &[ToolSpec],
        ) -> Result<ChatResponse> {
            Ok(ChatResponse {
                content: Some("hi".to_string()),
                tool_calls: Vec::new(),
                model: "m".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn chat_full_default_preserves_response_and_none_usage() {
        let full = ChatOnly.chat_full("m", &[], &[]).await.unwrap();
        assert_eq!(full.response.content.as_deref(), Some("hi"));
        assert!(full.usage.is_none());
        let (response, usage) = ChatOnly.chat_with_usage("m", &[], &[]).await.unwrap();
        assert_eq!(response.content.as_deref(), Some("hi"));
        assert!(usage.is_none());
    }

    fn serve(
        responses: Vec<(u16, &'static str, Option<&'static str>)>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for (status, body, retry_after) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut buf = vec![0u8; 8192];
                let mut raw = Vec::new();
                loop {
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                        let text = String::from_utf8_lossy(&raw);
                        if let Some(line) = text
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                        {
                            let expected: usize = line
                                .split(':')
                                .nth(1)
                                .unwrap_or("0")
                                .trim()
                                .parse()
                                .unwrap_or(0);
                            let head = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                            if raw.len() >= head + expected {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
                seen.push(String::from_utf8_lossy(&raw).to_string());
                let retry = retry_after
                    .map(|value| format!("Retry-After: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{retry}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
            seen
        });
        (format!("http://{addr}"), handle)
    }

    fn fallback_client(base: &str, fallbacks: &[&str]) -> LlmClient {
        LlmClient::new(LlmConfig {
            base_url: base.to_string(),
            api_key: "k".to_string(),
            default_model: Some("m-a".to_string()),
            fallback_models: fallbacks.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        })
        .unwrap()
    }

    #[tokio::test]
    async fn model_not_found_falls_back_to_second_model() {
        let (base, server) = serve(vec![
            (404, r#"{"error":{"code":"model_not_found"}}"#, None),
            (
                200,
                r#"{"choices":[{"message":{"content":"ok","tool_calls":[]},"finish_reason":"stop"}],"model":"m-b","usage":{"prompt_tokens":2,"completion_tokens":3}}"#,
                None,
            ),
        ]);
        let client = fallback_client(&base, &["m-b"]);
        let full = client.chat_full("m-a", &[], &[]).await.unwrap();
        assert_eq!(full.response.content.as_deref(), Some("ok"));
        assert_eq!(full.response.model, "m-b");
        assert_eq!(full.usage.unwrap().prompt_tokens, 2);
        let seen = server.join().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].contains(r#""model":"m-a""#));
        assert!(seen[1].contains(r#""model":"m-b""#));
    }

    #[tokio::test]
    async fn auth_error_never_falls_back() {
        let (base, server) = serve(vec![(401, "unauthorized", None)]);
        let client = fallback_client(&base, &["m-b"]);
        let err = client.chat_full("m-a", &[], &[]).await.unwrap_err();
        assert_eq!(err.to_string(), "chat failed 401: unauthorized");
        assert_eq!(
            err.downcast_ref::<LlmError>().unwrap().kind,
            LlmErrorKind::Auth
        );
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fallback_exhaustion_returns_last_error_verbatim() {
        let (base, server) = serve(vec![
            (
                404,
                r#"{"error":{"code":"model_not_found","message":"model a missing"}}"#,
                None,
            ),
            (
                404,
                r#"{"error":{"code":"model_not_found","message":"model b missing"}}"#,
                None,
            ),
        ]);
        let client = fallback_client(&base, &["m-b"]);
        let err = client.chat_full("m-a", &[], &[]).await.unwrap_err();
        assert!(err.to_string().contains("model b missing"));
        assert_eq!(
            err.downcast_ref::<LlmError>().unwrap().kind,
            LlmErrorKind::ModelNotFound
        );
        assert_eq!(server.join().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn generic_404_is_not_a_fallback_trigger() {
        let (base, server) = serve(vec![(404, r#"{"error":{"code":"unknown"}}"#, None)]);
        let client = fallback_client(&base, &["m-b"]);
        let err = client.chat_full("m-a", &[], &[]).await.unwrap_err();
        assert_eq!(
            err.downcast_ref::<LlmError>().unwrap().kind,
            LlmErrorKind::InvalidRequest
        );
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn capabilities_default_to_conservative() {
        let caps = ChatOnly.capabilities();
        assert!(!caps.tool_calling);
        assert!(!caps.streaming);
        let info = ChatOnly.model_info().await.unwrap();
        assert_eq!(info.id, "m");
        assert_eq!(info.capabilities, caps);
    }

    #[tokio::test]
    async fn stream_full_emits_deltas_and_assembles_tools_and_usage() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).unwrap();
            let body = concat!(
                "data: {\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
                "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
                "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"echo\",\"arguments\":\"{\\\"x\\\":\"}}]}}]}\n\n",
                "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"1}\"}}]}}]}\n\n",
                "data: {\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":5},\"choices\":[]}\n\n",
                "data: [DONE]\n\n",
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let client = LlmClient::new(LlmConfig {
            base_url: format!("http://{addr}"),
            api_key: "k".into(),
            default_model: Some("m".into()),
            ..Default::default()
        })
        .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let full = client
            .chat_stream_full("m", &[], &[], Some(tx))
            .await
            .unwrap();
        let mut deltas = Vec::new();
        while let Ok(delta) = rx.try_recv() {
            deltas.push(delta);
        }
        assert_eq!(deltas, vec!["Hel", "lo"]);
        assert_eq!(full.response.content.as_deref(), Some("Hello"));
        assert_eq!(full.response.tool_calls.len(), 1);
        assert_eq!(full.response.tool_calls[0].name, "echo");
        assert_eq!(full.response.tool_calls[0].arguments["x"], 1);
        assert_eq!(full.usage.unwrap().completion_tokens, 5);
        server.join().unwrap();
    }

    #[test]
    fn client_new_rejects_bad_base_url() {
        let err = LlmClient::new(LlmConfig {
            base_url: "ftp://example.com".into(),
            api_key: "k".into(),
            ..Default::default()
        })
        .err()
        .expect("ftp base_url must be rejected")
        .to_string();
        assert!(err.contains("http or https"), "{err}");
        assert!(LlmClient::new(LlmConfig {
            base_url: "not a url".into(),
            api_key: "k".into(),
            ..Default::default()
        })
        .is_err());
    }

    #[tokio::test]
    async fn discovery_error_omits_credentials_and_body() {
        let secret_body = "SUPERSECRET_BODY_MARKER";
        let (base, server) = serve(vec![(401, secret_body, None), (401, secret_body, None)]);
        let host = base.trim_start_matches("http://");
        let client = LlmClient::new(LlmConfig {
            base_url: format!("http://user:s3cr3t@{host}/v1?token=QUERYSECRET"),
            api_key: "k".into(),
            ..Default::default()
        })
        .unwrap();
        let err = client.discover_models().await.unwrap_err().to_string();
        assert!(!err.contains("s3cr3t"), "userinfo leaked: {err}");
        assert!(!err.contains("QUERYSECRET"), "query leaked: {err}");
        assert!(!err.contains(secret_body), "body leaked: {err}");
        assert!(err.contains("127.0.0.1"), "host should survive: {err}");
        server.join().unwrap();
    }

    /// Serve an SSE body in explicit chunks, flushing between each so the
    /// client really observes the requested chunk boundaries.
    fn serve_sse_chunks(chunks: Vec<String>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let total: usize = chunks.iter().map(|chunk| chunk.len()).sum();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.flush();
            for chunk in chunks {
                let _ = stream.write_all(chunk.as_bytes());
                let _ = stream.flush();
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        });
        (format!("http://{addr}"), handle)
    }

    async fn stream_from(body: String) -> Result<ChatResponseWithUsage> {
        let (base, server) = serve_sse_chunks(vec![body]);
        let client = LlmClient::new(LlmConfig {
            base_url: base,
            api_key: "k".into(),
            default_model: Some("m".into()),
            ..Default::default()
        })
        .unwrap();
        let result = client.chat_stream_full("m", &[], &[], None).await;
        server.join().unwrap();
        result
    }

    #[tokio::test]
    async fn streaming_rejects_length_finish_reason() {
        let err = stream_from(
            "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":\"length\"}]}\n\ndata: [DONE]\n\n"
                .to_string(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("cut short"), "{err}");
        assert!(err.contains("length"), "{err}");
        // Same text as the non-streaming parser.
        let v = body(r#"{"choices":[{"message":{"content":"partial"},"finish_reason":"length"}]}"#);
        assert_eq!(err, parse_chat_response(&v, "m").unwrap_err().to_string());
    }

    #[tokio::test]
    async fn streaming_rejects_content_filter() {
        let err = stream_from(
            "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":\"content_filter\"}]}\n\ndata: [DONE]\n\n"
                .to_string(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("cut short"), "{err}");
        assert!(err.contains("content_filter"), "{err}");
        let v = body(
            r#"{"choices":[{"message":{"content":"partial"},"finish_reason":"content_filter"}]}"#,
        );
        assert_eq!(err, parse_chat_response(&v, "m").unwrap_err().to_string());
    }

    #[tokio::test]
    async fn streaming_crlf_sse_frames_assembled() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"A\"}}]}\r\n\r\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"B\"}}]}\r\n\r\n",
            "data: [DONE]\r\n\r\n",
        );
        let full = stream_from(body.to_string()).await.unwrap();
        assert_eq!(full.response.content.as_deref(), Some("AB"));
    }

    #[tokio::test]
    async fn crlf_split_across_chunks() {
        let first = "data: {\"choices\":[{\"delta\":{\"content\":\"A\"}}]}\r\n\r\n";
        let rest = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"B\"}}]}\r\n\r\n",
            "data: [DONE]\r\n\r\n",
        );
        let all = format!("{first}{rest}");
        let split = first.len() - 1; // ends on the trailing '\r' of the frame
        let chunks = vec![all[..split].to_string(), all[split..].to_string()];
        let (base, server) = serve_sse_chunks(chunks);
        let client = LlmClient::new(LlmConfig {
            base_url: base,
            api_key: "k".into(),
            default_model: Some("m".into()),
            ..Default::default()
        })
        .unwrap();
        let full = client.chat_stream_full("m", &[], &[], None).await.unwrap();
        assert_eq!(full.response.content.as_deref(), Some("AB"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn sse_buffer_cap_rejects_oversized_frame() {
        let frame = format!("data: {}\n\n", "x".repeat(MAX_SSE_BUFFER + 100));
        let err = stream_from(frame).await.unwrap_err().to_string();
        assert!(err.contains("buffer exceeded"), "{err}");
    }

    #[tokio::test]
    async fn streamed_arguments_cap_rejects_huge_partial_call() {
        let arguments = "x".repeat(MAX_TOOL_ARGS + 100);
        let frame = serde_json::json!({
            "choices": [{
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "id": "c1",
                        "function": { "name": "echo", "arguments": arguments }
                    }]
                }
            }]
        })
        .to_string();
        let err = stream_from(format!("data: {frame}\n\ndata: [DONE]\n\n"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("streamed arguments"), "{err}");
    }

    #[tokio::test]
    async fn stream_429_retries_with_retry_after() {
        let ok = r#"{"choices":[{"message":{"content":"ok","tool_calls":[]},"finish_reason":"stop"}],"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
        let (base, server) = serve(vec![
            (429, r#"{"error":"slow down"}"#, Some("0")),
            (200, ok, None),
        ]);
        let client = fallback_client(&base, &[]);
        let full = client
            .chat_stream_full("m-a", &[], &[], None)
            .await
            .unwrap();
        assert_eq!(full.response.content.as_deref(), Some("ok"));
        assert_eq!(server.join().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn stream_model_not_found_falls_back() {
        let ok = r#"{"choices":[{"message":{"content":"from-b","tool_calls":[]},"finish_reason":"stop"}],"model":"m-b"}"#;
        let (base, server) = serve(vec![
            (404, r#"{"error":{"code":"model_not_found"}}"#, None),
            (200, ok, None),
        ]);
        let client = fallback_client(&base, &["m-b"]);
        let full = client
            .chat_stream_full("m-a", &[], &[], None)
            .await
            .unwrap();
        assert_eq!(full.response.content.as_deref(), Some("from-b"));
        let seen = server.join().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].contains(r#""model":"m-a""#));
        assert!(seen[1].contains(r#""model":"m-b""#));
    }

    #[tokio::test]
    async fn stream_transport_error_retries() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut seen = 0;
            {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = stream.read(&mut buf).unwrap();
                seen += 1;
                // Drop without responding: reqwest surfaces a Transport error.
            }
            {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = stream.read(&mut buf).unwrap();
                seen += 1;
                let body = r#"{"choices":[{"message":{"content":"recovered"},"finish_reason":"stop"}],"model":"m"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
            seen
        });
        let client = fallback_client(&format!("http://{addr}"), &[]);
        let full = client.chat_stream_full("m", &[], &[], None).await.unwrap();
        assert_eq!(full.response.content.as_deref(), Some("recovered"));
        assert_eq!(server.join().unwrap(), 2);
    }
}
