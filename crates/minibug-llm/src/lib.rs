use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use reqwest::header::RETRY_AFTER;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub base_url: String,
    pub api_key: String,
    #[serde(default)]
    pub default_model: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    60000
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.openai.com".into(),
            api_key: String::new(),
            default_model: None,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

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

#[async_trait]
pub trait Llm: Send + Sync {
    async fn resolve_model(&self) -> Result<String>;
    async fn chat(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<ChatResponse>;
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
                        last_err = Some(anyhow!("GET {url} failed: {e}"));
                        if attempt == 0 {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            continue;
                        }
                        break;
                    }
                };
                if !res.status().is_success() {
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    last_err = Some(anyhow!("models discovery failed at {url}: {status} {body}"));
                    break;
                }
                let v: serde_json::Value = match res.json().await {
                    Ok(v) => v,
                    Err(e) => {
                        last_err = Some(anyhow!("invalid models json at {url}: {e}"));
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
                last_err = Some(anyhow!("no models found at {url}"));
                break;
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("model discovery failed")))
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

    async fn chat(
        &self,
        model: &str,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<ChatResponse> {
        let url = format!("{}/chat/completions", self.api_base());
        let mut msgs: Vec<serde_json::Value> = Vec::new();
        for m in messages {
            let mut obj = serde_json::json!({"role": m.role});
            // For tool messages, content must be present (can be empty string)
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
                        "function": {"name": t.name, "description": t.description, "parameters": t.parameters}
                    })
                })
                .collect();
            body["tools"] = serde_json::Value::Array(t);
        }

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
                        let v: serde_json::Value = r.json().await.context("invalid chat json")?;
                        return parse_chat_response(&v, model);
                    }
                    let status = r.status();
                    let retry_after = r
                        .headers()
                        .get(RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let text = r.text().await.unwrap_or_default();
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
                    {
                        if attempt == 2 {
                            last_err = Some(anyhow!("chat failed {status}: {text}"));
                            break;
                        }
                        let fallback = Duration::from_millis(500 * (1u64 << attempt));
                        let delay = retry_after
                            .as_deref()
                            .and_then(parse_retry_after)
                            .unwrap_or(fallback)
                            .min(Duration::from_secs(10));
                        last_err = Some(anyhow!(
                            "chat failed {status}: {text} (retrying in {}s)",
                            delay.as_secs()
                        ));
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Err(anyhow!("chat failed {status}: {text}"));
                }
                Err(e) => {
                    last_err = Some(anyhow!("POST {url} failed: {e}"));
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
                        continue;
                    }
                    break;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("chat failed")))
    }
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
        return Err(anyhow!(
            "chat response was cut short (finish_reason={finish_reason}); refusing to treat truncated output as complete"
        ));
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
}
