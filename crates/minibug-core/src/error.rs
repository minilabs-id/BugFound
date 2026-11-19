//! Typed agent errors with best-effort classification of free-form messages.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    Retryable(String),
    Blocked(String),
    Declined(String),
    Corrected(String),
    Fatal(String),
    Interrupted(String),
}

impl AgentError {
    pub fn message(&self) -> &str {
        match self {
            Self::Retryable(message)
            | Self::Blocked(message)
            | Self::Declined(message)
            | Self::Corrected(message)
            | Self::Fatal(message)
            | Self::Interrupted(message) => message,
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::Retryable(_) => "retryable",
            Self::Blocked(_) => "blocked",
            Self::Declined(_) => "declined",
            Self::Corrected(_) => "corrected",
            Self::Fatal(_) => "fatal",
            Self::Interrupted(_) => "interrupted",
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }

    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Fatal(_))
    }

    pub fn is_interrupted(&self) -> bool {
        matches!(self, Self::Interrupted(_))
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.category(), self.message())
    }
}

impl std::error::Error for AgentError {}

impl From<String> for AgentError {
    fn from(value: String) -> Self {
        classify(&value)
    }
}

impl From<&str> for AgentError {
    fn from(value: &str) -> Self {
        classify(value)
    }
}

impl From<anyhow::Error> for AgentError {
    fn from(error: anyhow::Error) -> Self {
        classify(&error.to_string())
    }
}

/// Classify a free-form message into the most specific agent error variant.
pub fn classify(message: &str) -> AgentError {
    let lower = message.to_ascii_lowercase();
    let has = |needle: &str| lower.contains(needle);

    if has("interrupt") || has("cancel") || has("aborted") || has("shutdown") {
        AgentError::Interrupted(message.to_string())
    } else if has("denied") || has("declined") || has("rejected") || has("user said no") {
        AgentError::Declined(message.to_string())
    } else if has("blocked")
        || has("forbidden")
        || has("permission")
        || has("not allowed")
        || has("policy")
        || has("out of scope")
    {
        AgentError::Blocked(message.to_string())
    } else if has("correct") || has("fix ") || has("invalid") || has("malformed") {
        AgentError::Corrected(message.to_string())
    } else if has("retry")
        || has("temporar")
        || has("rate limit")
        || has("429")
        || has("timeout")
        || has("timed out")
        || has("connection")
        || has("unavailable")
    {
        AgentError::Retryable(message.to_string())
    } else {
        AgentError::Fatal(message.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognizes_each_category() {
        assert_eq!(
            classify("session interrupted by user"),
            AgentError::Interrupted("session interrupted by user".into())
        );
        assert!(matches!(
            classify("user declined the tool"),
            AgentError::Declined(_)
        ));
        assert!(matches!(
            classify("blocked by policy"),
            AgentError::Blocked(_)
        ));
        assert!(matches!(
            classify("invalid arguments; correct them"),
            AgentError::Corrected(_)
        ));
        assert!(matches!(
            classify("429 rate limited, retry soon"),
            AgentError::Retryable(_)
        ));
        assert!(matches!(classify("unexpected panic"), AgentError::Fatal(_)));
    }

    #[test]
    fn display_and_conversions() {
        let err: AgentError = anyhow::anyhow!("temporary network failure").into();
        assert!(err.is_retryable());
        assert!(err.to_string().contains("retryable"));
        assert_eq!(err.category(), "retryable");
        let owned: AgentError = String::from("fatal boom").into();
        assert!(owned.is_fatal());
    }
}
