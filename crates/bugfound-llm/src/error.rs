//! Typed provider errors. Message text stays byte-compatible with the legacy
//! `anyhow!` strings so existing events and tests are unchanged.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// True only when the text names an HTTP status with an explicit token such as
/// `status 429` or `HTTP 429`. Bare digits inside ids, bodies or free-form text
/// must never be treated as a status code.
fn names_status(message: &str, status: u16) -> bool {
    let lower = message.to_ascii_lowercase();
    let digits = status.to_string();
    for prefix in ["status ", "http ", "status:", "http:"] {
        let mut from = 0;
        while let Some(offset) = lower[from..].find(prefix) {
            let at = from + offset + prefix.len();
            let tail = &lower[at..];
            if tail.starts_with(&digits)
                && !tail[digits.len()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
            {
                return true;
            }
            from = at;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlmErrorKind {
    Auth,
    RateLimited,
    ContextOverflow,
    PayloadTooLarge,
    ContentPolicy,
    InvalidRequest,
    Server,
    Timeout,
    Transport,
    ModelNotFound,
    Truncated,
    InvalidResponse,
    Config,
    Cancelled,
    Unknown,
}

impl LlmErrorKind {
    /// Legacy classification for foreign `Llm` implementations that only
    /// return `anyhow::Error`. New code should map at the HTTP boundary.
    pub fn from_message(message: &str) -> Self {
        let lower = message.to_ascii_lowercase();
        if lower.contains("context length")
            || lower.contains("context window")
            || lower.contains("too many tokens")
            || lower.contains("token limit")
        {
            Self::ContextOverflow
        } else if lower.contains("content filter")
            || lower.contains("moderation")
            || lower.contains("safety")
        {
            Self::ContentPolicy
        } else if lower.contains("rate limit") || names_status(message, 429) {
            Self::RateLimited
        } else if lower.contains("model not found")
            || lower.contains("model_not_found")
            || lower.contains("unknown model")
            || lower.contains("does not exist")
        {
            Self::ModelNotFound
        } else if lower.contains("finish_reason=length") || lower.contains("cut short") {
            Self::Truncated
        } else if lower.contains("api_key") || lower.contains("base_url") {
            Self::Config
        } else if names_status(message, 401)
            || names_status(message, 403)
            || lower.contains("unauthorized")
        {
            Self::Auth
        } else if lower.contains("timeout") || lower.contains("timed out") {
            Self::Timeout
        } else if lower.contains("invalid json") || lower.contains("missing choices") {
            Self::InvalidResponse
        } else {
            Self::Unknown
        }
    }

    /// Deterministic mapping from an HTTP status and response body.
    pub fn from_status(status: u16, body: &str) -> Self {
        match status {
            401 | 403 => Self::Auth,
            408 | 425 => Self::Timeout,
            413 => Self::PayloadTooLarge,
            429 => Self::RateLimited,
            404 => {
                let lower = body.to_ascii_lowercase();
                if lower.contains("model_not_found")
                    || lower.contains("model not found")
                    || lower.contains("unknown model")
                    || lower.contains("does not exist")
                {
                    Self::ModelNotFound
                } else {
                    Self::InvalidRequest
                }
            }
            // 501/505 describe an unsupported request (method or HTTP version),
            // not a transient server failure — never retry them.
            501 | 505 => Self::InvalidRequest,
            500..=599 => Self::Server,
            400 | 422 => {
                let lower = body.to_ascii_lowercase();
                if lower.contains("context_length_exceeded")
                    || lower.contains("maximum_context_length")
                    || lower.contains("context length")
                    || lower.contains("too many tokens")
                    || lower.contains("token limit")
                {
                    Self::ContextOverflow
                } else if lower.contains("content_policy_violation")
                    || lower.contains("content_filter")
                    || lower.contains("content filter")
                    || lower.contains("moderation")
                {
                    Self::ContentPolicy
                } else if lower.contains("rate_limit_exceeded") {
                    Self::RateLimited
                } else {
                    Self::InvalidRequest
                }
            }
            _ if (400..=499).contains(&status) => Self::InvalidRequest,
            _ => Self::Unknown,
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::Server | Self::Timeout | Self::Transport
        )
    }

    pub fn recovery(&self) -> Recovery {
        match self {
            Self::RateLimited | Self::Server | Self::Timeout | Self::Transport => Recovery::Retry,
            Self::ContextOverflow | Self::PayloadTooLarge | Self::Truncated => {
                Recovery::CompactAndRetry
            }
            Self::ModelNotFound => Recovery::Fallback,
            Self::Auth
            | Self::ContentPolicy
            | Self::InvalidRequest
            | Self::InvalidResponse
            | Self::Config
            | Self::Cancelled
            | Self::Unknown => Recovery::Fail,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::RateLimited => "rate_limited",
            Self::ContextOverflow => "context_overflow",
            Self::PayloadTooLarge => "payload_too_large",
            Self::ContentPolicy => "content_policy",
            Self::InvalidRequest => "invalid_request",
            Self::Server => "server",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::ModelNotFound => "model_not_found",
            Self::Truncated => "truncated",
            Self::InvalidResponse => "invalid_response",
            Self::Config => "config",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    Retry,
    CompactAndRetry,
    Fallback,
    Fail,
}

#[derive(Debug)]
pub struct LlmError {
    pub kind: LlmErrorKind,
    pub message: String,
    pub status: Option<u16>,
    pub retry_after: Option<Duration>,
    pub model: Option<String>,
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LlmError {}

impl LlmError {
    pub fn new(kind: LlmErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            status: None,
            retry_after: None,
            model: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_is_deterministic() {
        assert_eq!(LlmErrorKind::from_status(401, ""), LlmErrorKind::Auth);
        assert_eq!(
            LlmErrorKind::from_status(429, ""),
            LlmErrorKind::RateLimited
        );
        assert_eq!(LlmErrorKind::from_status(503, ""), LlmErrorKind::Server);
        assert_eq!(LlmErrorKind::from_status(408, ""), LlmErrorKind::Timeout);
        assert_eq!(
            LlmErrorKind::from_status(413, ""),
            LlmErrorKind::PayloadTooLarge
        );
        assert_eq!(
            LlmErrorKind::from_status(400, r#"{"error":{"code":"context_length_exceeded"}}"#),
            LlmErrorKind::ContextOverflow
        );
        assert_eq!(
            LlmErrorKind::from_status(400, r#"{"error":{"message":"content filter"}}"#),
            LlmErrorKind::ContentPolicy
        );
        assert_eq!(
            LlmErrorKind::from_status(404, r#"{"error":{"code":"unknown"}}"#),
            LlmErrorKind::InvalidRequest
        );
        assert_eq!(
            LlmErrorKind::from_status(404, r#"{"error":{"code":"model_not_found"}}"#),
            LlmErrorKind::ModelNotFound
        );
        assert_eq!(LlmErrorKind::ModelNotFound.recovery(), Recovery::Fallback);
        assert!(!LlmErrorKind::ModelNotFound.retryable());
        assert_eq!(LlmErrorKind::from_status(500, "boom"), LlmErrorKind::Server);
    }

    #[test]
    fn status_501_is_not_retryable() {
        for status in [501, 505] {
            let kind = LlmErrorKind::from_status(status, "unsupported");
            assert_eq!(kind, LlmErrorKind::InvalidRequest, "status {status}");
            assert!(!kind.retryable(), "status {status} must not be retried");
            assert_eq!(kind.recovery(), Recovery::Fail);
        }
    }

    #[test]
    fn body_containing_401_is_not_auth() {
        // Bare digits in a body/id are not status tokens.
        assert_ne!(
            LlmErrorKind::from_message("item 401 was skipped"),
            LlmErrorKind::Auth
        );
        assert_eq!(
            LlmErrorKind::from_message("item 401 was skipped"),
            LlmErrorKind::Unknown
        );
        assert_eq!(
            LlmErrorKind::from_message("HTTP 401 unauthorized"),
            LlmErrorKind::Auth
        );
        assert_eq!(
            LlmErrorKind::from_message("status 403 forbidden"),
            LlmErrorKind::Auth
        );
        // Longer numbers that merely start with a status are not matches.
        assert_ne!(
            LlmErrorKind::from_message("status 4291 is a request id"),
            LlmErrorKind::RateLimited
        );
    }

    #[test]
    fn legacy_message_classification_covers_common_failures() {
        assert_eq!(
            LlmErrorKind::from_message("chat failed status 429: slow down"),
            LlmErrorKind::RateLimited
        );
        assert_eq!(
            LlmErrorKind::from_message("chat failed HTTP 429: slow down"),
            LlmErrorKind::RateLimited
        );
        assert_eq!(
            LlmErrorKind::from_message("chat response was cut short (finish_reason=length)"),
            LlmErrorKind::Truncated
        );
        assert_eq!(
            LlmErrorKind::from_message("simulated llm outage"),
            LlmErrorKind::Unknown
        );
        assert_eq!(
            LlmErrorKind::from_message("api_key is required"),
            LlmErrorKind::Config
        );
    }

    #[test]
    fn recovery_table_is_total() {
        for kind in [
            LlmErrorKind::RateLimited,
            LlmErrorKind::Server,
            LlmErrorKind::Timeout,
            LlmErrorKind::Transport,
        ] {
            assert_eq!(kind.recovery(), Recovery::Retry);
            assert!(kind.retryable());
        }
        for kind in [
            LlmErrorKind::ContextOverflow,
            LlmErrorKind::PayloadTooLarge,
            LlmErrorKind::Truncated,
        ] {
            assert_eq!(kind.recovery(), Recovery::CompactAndRetry);
            assert!(!kind.retryable());
        }
        for kind in [
            LlmErrorKind::Auth,
            LlmErrorKind::ContentPolicy,
            LlmErrorKind::InvalidRequest,
            LlmErrorKind::InvalidResponse,
            LlmErrorKind::Config,
            LlmErrorKind::Cancelled,
            LlmErrorKind::Unknown,
        ] {
            assert_eq!(kind.recovery(), Recovery::Fail);
            assert!(!kind.retryable());
        }
    }

    #[test]
    fn display_preserves_legacy_text_and_downcasts() {
        let err = LlmError::new(LlmErrorKind::Server, "chat failed 500: boom");
        assert_eq!(err.to_string(), "chat failed 500: boom");
        let wrapped = anyhow::Error::new(err);
        assert!(wrapped.downcast_ref::<LlmError>().is_some());
    }
}
