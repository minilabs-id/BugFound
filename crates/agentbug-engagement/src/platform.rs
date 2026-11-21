//! Read-only program-brief adapters for bug-bounty platforms.
//!
//! This module only ever performs an HTTP GET to *read* a public or
//! token-gated program brief. It has no submission, report-publishing, or any
//! other write path by design. Scope and ROE still come from the fetched text
//! and are enforced fail-closed by the engagement; a receipt or adapter flag
//! can never become permission to act.
//!
//! ## API contract caveat
//!
//! Public platform API shapes and authentication schemes change between API
//! versions and can be program-specific. The header name and schemes below are
//! isolated constants so an operator can adapt them. Verify the exact contract
//! for the program you are reading before relying on a token-gated fetch:
//! an unexpected response is treated as an error, never as an empty/empty-scope
//! brief that would silently bypass a check.

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use regex::Regex;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

/// Header used to carry the platform API token. Centralised because providers
/// occasionally document a different name; changing it here changes every
/// adapter. This is an *Authorization* header only, never a submission header.
pub const AUTHORIZATION_HEADER: &str = "Authorization";

/// HackerOne documents API-token auth as HTTP Basic with the token as the
/// username and an empty password. Kept configurable for API-version drift.
pub const HACKERONE_AUTH_SCHEME: &str = "Basic";
/// Bugcrowd commonly documents `Authorization: Token <token>`.
pub const BUGCROWD_AUTH_SCHEME: &str = "Token";
/// Intigriti commonly documents `Authorization: Bearer <token>`.
pub const INTIGRITI_AUTH_SCHEME: &str = "Bearer";

/// Maximum bytes buffered from an adapter response before extraction.
pub const MAX_RAW_BYTES: usize = 1024 * 1024;
/// Maximum bytes of extracted text handed to the scope/ROE parser.
pub const MAX_TEXT_BYTES: usize = 256 * 1024;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Supported brief sources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Platform {
    /// Unauthenticated public page; handled by the engagement's plain fetch.
    #[default]
    Generic,
    HackerOne,
    Bugcrowd,
    Intigriti,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::HackerOne => "hackerone",
            Self::Bugcrowd => "bugcrowd",
            Self::Intigriti => "intigriti",
        }
    }

    /// All non-generic adapters require a token; no anonymous fallback exists.
    pub fn requires_api_key(self) -> bool {
        !matches!(self, Self::Generic)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Clap-friendly parser (the error is a plain `String`). Aliases with `-` and
/// `_` are normalised so `hacker-one` and `hacker_one` both work from scripts.
impl FromStr for Platform {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let normalised = value.trim().to_ascii_lowercase().replace(['-', '_'], "");
        match normalised.as_str() {
            "generic" => Ok(Self::Generic),
            "hackerone" | "hacker1" => Ok(Self::HackerOne),
            "bugcrowd" => Ok(Self::Bugcrowd),
            "intigriti" => Ok(Self::Intigriti),
            other => Err(format!(
                "unknown platform '{other}'; expected generic, hackerone, bugcrowd, or intigriti"
            )),
        }
    }
}

/// Read-only result of a platform brief fetch.
#[derive(Debug, Clone)]
pub struct ProgramBrief {
    pub title: String,
    pub text: String,
    pub platform: Platform,
}

/// Fetch a program brief over READ-ONLY HTTP GET.
///
/// - only `http`/`https`, no redirects, private/non-public hosts rejected;
/// - token-bearing platforms require `api_key` and fail clearly without it;
/// - response body and extracted text are bounded;
/// - `Generic` is deliberately *not* handled here: the caller must use the
///   engagement's existing plain `fetch_brief` path, which keeps the public-page
///   safety checks in one place.
///
/// There is no parameter for a submission endpoint, finding body, or HTTP
/// method; this function cannot write to a platform.
pub async fn fetch_platform_brief(
    platform: Platform,
    url: &str,
    api_key: Option<&str>,
) -> Result<ProgramBrief> {
    if platform == Platform::Generic {
        return Err(anyhow!(
            "generic briefs use the engagement's plain public-page fetch; no platform adapter is needed"
        ));
    }

    let parsed = url::Url::parse(url).context("invalid program brief URL")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!(
            "program brief URL must use http or https (got '{}'); refusing to engage",
            parsed.scheme()
        ));
    }
    if parsed.host_str().unwrap_or_default().is_empty() {
        return Err(anyhow!(
            "program brief URL has no host; refusing to engage (fail-closed)"
        ));
    }

    let key = api_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "platform '{platform}' requires an API token; refusing unauthenticated brief fetch"
            )
        })?;
    let authorization = authorization_value(platform, key);

    crate::reject_private_brief_host(url).await?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("build platform brief HTTP client")?;
    let response = client
        .get(parsed.clone())
        .header(AUTHORIZATION_HEADER, authorization)
        .header(
            "accept",
            "text/html,application/json;q=0.9,text/plain;q=0.8",
        )
        .header("user-agent", "agentbug-readonly-brief/1.0")
        .send()
        .await
        .with_context(|| format!("fetch read-only brief from {platform}"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "platform '{platform}' brief request returned HTTP {}; refusing to engage (fail-closed)",
            response.status()
        ));
    }
    if crate::is_login_page(url, response.url().as_str()) {
        return Err(anyhow!(
            "platform '{platform}' brief request redirected to a login endpoint; refusing to engage (fail-closed)"
        ));
    }

    let body = response
        .bytes()
        .await
        .context("stream platform brief body")?;
    let end = body.len().min(MAX_RAW_BYTES);
    let raw = String::from_utf8_lossy(&body[..end]);
    let text = bounded_text(crate::html_to_text(&raw));
    if text.trim().is_empty() {
        return Err(anyhow!(
            "platform '{platform}' brief contains no readable text; refusing to engage (fail-closed)"
        ));
    }
    let title = bounded_text(extract_title(&raw))
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    Ok(ProgramBrief {
        title,
        text,
        platform,
    })
}

fn authorization_value(platform: Platform, key: &str) -> String {
    match platform {
        Platform::HackerOne => format!(
            "{} {}",
            HACKERONE_AUTH_SCHEME,
            base64::engine::general_purpose::STANDARD.encode(format!("{key}:"))
        ),
        Platform::Bugcrowd => format!("{BUGCROWD_AUTH_SCHEME} {key}"),
        Platform::Intigriti => format!("{INTIGRITI_AUTH_SCHEME} {key}"),
        Platform::Generic => String::new(),
    }
}

fn extract_title(raw: &str) -> String {
    let pattern = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("valid title regex");
    pattern
        .captures(raw)
        .and_then(|captures| captures.get(1))
        .map(|capture| crate::decode_entities(capture.as_str()))
        .unwrap_or_default()
}

fn bounded_text(text: String) -> String {
    if text.len() <= MAX_TEXT_BYTES {
        return text;
    }
    let mut end = MAX_TEXT_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_parsing_is_clap_friendly() {
        assert_eq!("generic".parse::<Platform>().unwrap(), Platform::Generic);
        assert_eq!(
            "HackerOne".parse::<Platform>().unwrap(),
            Platform::HackerOne
        );
        assert_eq!(
            "hacker-one".parse::<Platform>().unwrap(),
            Platform::HackerOne
        );
        assert_eq!("bugcrowd".parse::<Platform>().unwrap(), Platform::Bugcrowd);
        assert_eq!(
            "intigriti".parse::<Platform>().unwrap(),
            Platform::Intigriti
        );
        assert!("unknown".parse::<Platform>().is_err());
        assert!(!Platform::Generic.requires_api_key());
        assert!(Platform::HackerOne.requires_api_key());
        assert_eq!(Platform::Bugcrowd.to_string(), "bugcrowd");
    }

    #[tokio::test]
    async fn token_bearing_platforms_never_fall_back_to_anonymous_access() {
        for platform in [Platform::HackerOne, Platform::Bugcrowd, Platform::Intigriti] {
            let error = fetch_platform_brief(platform, "https://example.test/program", None)
                .await
                .expect_err("missing token must fail closed");
            assert!(error.to_string().contains("API token"), "{error:#}");
        }
        let error = fetch_platform_brief(
            Platform::HackerOne,
            "https://example.test/program",
            Some("   "),
        )
        .await
        .expect_err("blank token must fail closed");
        assert!(error.to_string().contains("API token"), "{error:#}");
    }

    #[tokio::test]
    async fn rejects_non_http_urls_and_generic_adapter_calls() {
        for url in ["file:///tmp/brief", "ftp://example.test/brief"] {
            let error = fetch_platform_brief(Platform::Bugcrowd, url, Some("token"))
                .await
                .expect_err("non-http URL must be rejected");
            assert!(error.to_string().contains("http or https"), "{error:#}");
        }
        let error = fetch_platform_brief(Platform::Generic, "https://example.test", Some("token"))
            .await
            .expect_err("generic must use the plain fetch path");
        assert!(error.to_string().contains("plain public-page fetch"));
    }

    #[test]
    fn text_is_bounded_and_common_entities_are_decoded() {
        let long = "x".repeat(MAX_TEXT_BYTES + 100);
        assert_eq!(bounded_text(long).len(), MAX_TEXT_BYTES);
        assert_eq!(
            extract_title("<html><title>A &amp; B</title></html>"),
            "A & B"
        );
        assert!(authorization_value(Platform::Bugcrowd, "secret").starts_with("Token "));
        assert!(authorization_value(Platform::Bugcrowd, "secret").contains("secret"));
    }
}
