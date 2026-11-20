//! Typed provider errors. Message text stays byte-compatible with the legacy
//! `anyhow!` strings so existing events and tests are unchanged.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

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
        } else if lower.contains("rate limit") || lower.contains("429") {
            Self::RateLimited
        } else if lower.contains("finish_reason=length") || lower.contains("cut short") {
            Self::Truncated
        } else if lower.contains("api_key") || lower.contains("base_url") {
            Self::Config
        } else if lower.contains("403") || lower.contains("401") || lower.contains("unauthorized") {
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
            500..=599 => Self::Server,
            400 | 404 | 422 => {
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
            Self::RateLimited | Self::Server | Self::Timeout | Self::Transport | Self::Unknown
        )
    }

    pub fn recovery(&self) -> Recovery {
        match self {
            Self::RateLimited | Self::Server | Self::Timeout | Self::Transport | Self::Unknown => {
                Recovery::Retry
            }
            Self::ContextOverflow | Self::PayloadTooLarge | Self::Truncated => {
                Recovery::CompactAndRetry
            }
            Self::Auth
            | Self::ContentPolicy
            | Self::InvalidRequest
            | Self::InvalidResponse
            | Self::Config
            | Self::Cancelled => Recovery::Fail,
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
    }

    #[test]
    fn legacy_message_classification_covers_common_failures() {
        assert_eq!(
            LlmErrorKind::from_message("chat failed 429: slow down"),
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
            LlmErrorKind::Unknown,
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
