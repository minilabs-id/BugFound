//! Program-brief adapters for bug-bounty platforms. The adapters issue HTTP GET
//! requests and return text; there is no submission or report-publishing path in
//! this module. Scope and ROE are taken from the returned text and checked by
//! the engagement layer. A receipt or adapter flag does not grant permission to
//! act on a target.
//!
//! ## API contract caveat
//!
//! Platform API shapes and authentication schemes vary by version and program.
//! The header name and schemes are constants so an operator can adjust them.
//! Check the current contract for the program before using a token-gated fetch.
//! An unexpected response is returned as an error rather than an empty brief.

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use regex::Regex;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

/// Header used to carry the platform API token. Centralised because providers
/// occasionally document a different name; changing it here changes every
/// adapter. This is an `Authorization` header.
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

    // Resolve and validate the host ONCE, then pin every vetted address into
    // the client. reqwest would otherwise resolve the hostname again while
    // connecting, letting a changed DNS answer deliver the token to a private
    // or metadata endpoint (DNS rebinding).
    let client = pinned_platform_client(&parsed).await?;
    let authorization = reqwest::header::HeaderValue::from_str(&authorization).map_err(|_| {
        anyhow!(
            "platform '{platform}' API token is not a valid HTTP header value; refusing to engage (fail-closed)"
        )
    })?;
    let response = client
        .get(parsed.clone())
        .header(AUTHORIZATION_HEADER, authorization)
        .header(
            "accept",
            "text/html,application/json;q=0.9,text/plain;q=0.8",
        )
        .header("user-agent", "bugfound-readonly-brief/1.0")
        .send()
        .await
        // Never surface a transport error verbatim: it could echo request
        // details, including the token-bearing header.
        .map_err(|_| {
            anyhow!("platform '{platform}' brief request failed; refusing to engage (fail-closed)")
        })?;
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

    let body = read_bounded_body(response, platform).await?;
    let raw = String::from_utf8_lossy(&body);
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

/// Resolve the brief host a single time and pin every vetted address into the
/// HTTP client. reqwest resolves a hostname again at connect time; without
/// these overrides a hostile DNS answer could pass validation with a public IP
/// and then hand the token-bearing request to a private/metadata endpoint.
async fn pinned_platform_client(parsed: &url::Url) -> Result<reqwest::Client> {
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("program brief URL has no host; refusing to engage (fail-closed)"))?
        .trim()
        .to_ascii_lowercase();
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return Err(anyhow!(
            "program brief host '{host}' is not publicly routable; refusing to engage (fail-closed)"
        ));
    }

    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT);

    // url::Url serialises IPv6 literals with brackets; strip them for the IP
    // parse. A literal is never resolved a second time, so there is nothing to
    // rebind, but it must still pass the project's private/reserved check.
    let ip_literal = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(&host);
    if let Ok(ip) = ip_literal.parse::<IpAddr>() {
        if crate::is_non_public_ip(ip) {
            return Err(anyhow!(
                "program brief host '{host}' resolves to a private address; refusing to engage (fail-closed)"
            ));
        }
    } else {
        let port = parsed.port_or_known_default().unwrap_or(443);
        let target = (host.clone(), port);
        let addrs = tokio::task::spawn_blocking(move || {
            target
                .to_socket_addrs()
                .map(|addresses| addresses.collect::<Vec<SocketAddr>>())
        })
        .await
        .context("resolve program brief host")?
        .with_context(|| format!("resolve program brief host {host}"))?;
        validate_resolved_addrs(&host, &addrs)?;
        // Pin ALL validated addresses in one call: reqwest's `resolve` replaces
        // the override vector, so repeated calls would keep only the last one.
        builder = builder.resolve_to_addrs(&host, &addrs);
    }
    builder.build().context("build platform brief HTTP client")
}

/// Every DNS answer must be publicly routable: a single private/reserved answer
/// means the host is untrusted even if all the other answers look public.
fn validate_resolved_addrs(host: &str, addrs: &[SocketAddr]) -> Result<()> {
    if addrs.is_empty() {
        return Err(anyhow!(
            "program brief host '{host}' resolves to no addresses; refusing to engage (fail-closed)"
        ));
    }
    if addrs.iter().any(|addr| crate::is_non_public_ip(addr.ip())) {
        return Err(anyhow!(
            "program brief host '{host}' resolves to a private or reserved address; refusing to engage (fail-closed)"
        ));
    }
    Ok(())
}

/// Consume the response body incrementally and stop at the cap. `chunk` yields
/// the underlying body stream piece by piece, so an oversized response is
/// rejected as soon as the cap is crossed instead of being buffered in full.
/// The running byte count is checked *before* appending each chunk.
async fn read_bounded_body(mut response: reqwest::Response, platform: Platform) -> Result<Vec<u8>> {
    let cap = crate::MAX_BRIEF_BYTES.min(MAX_RAW_BYTES);
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("stream platform brief body")?
    {
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(anyhow!(
                "platform '{platform}' brief body exceeds {cap} bytes; refusing to engage (fail-closed)"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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
    use std::io::{Read, Write};
    use std::sync::mpsc::{channel, Receiver};

    /// Tiny offline loopback HTTP server. Returns its URL, socket address and a
    /// receiver holding the bytes it actually saw (empty when no connection
    /// arrived within the wait window).
    fn spawn_loopback_server(
        response_body: Option<Vec<u8>>,
    ) -> (String, SocketAddr, Receiver<Vec<u8>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
        let addr = listener.local_addr().expect("loopback address");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            let mut received = Vec::new();
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                        let mut buf = [0u8; 4096];
                        while let Ok(count) = stream.read(&mut buf) {
                            if count == 0 {
                                break;
                            }
                            received.extend_from_slice(&buf[..count]);
                            if received
                                .windows(4)
                                .any(|window| window == b"\r\n\r\n".as_slice())
                            {
                                break;
                            }
                        }
                        if let Some(body) = &response_body {
                            let header = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(header.as_bytes());
                            let _ = stream.write_all(body);
                            let _ = stream.flush();
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(received);
        });
        (format!("http://127.0.0.1:{}/brief", addr.port()), addr, rx)
    }

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

    #[tokio::test]
    async fn dns_answer_changing_to_loopback_cannot_leak_token() {
        const TOKEN: &str = "leak-me-platform-token";
        let (url, loopback, received) = spawn_loopback_server(None);

        // Simulate validation seeing a public address while the connection
        // would be handed the loopback address: one bad answer poisons the set.
        let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let error = validate_resolved_addrs("brief.example.test", &[public, loopback])
            .expect_err("one private answer must fail the whole resolution set");
        assert!(
            error.to_string().contains("private or reserved"),
            "{error:#}"
        );

        // Even a URL that points straight at a loopback listener never gets a
        // token-bearing request: validation fails before the client connects.
        let error = fetch_platform_brief(Platform::Bugcrowd, &url, Some(TOKEN))
            .await
            .expect_err("loopback host must fail closed");
        assert!(error.to_string().contains("private"), "{error:#}");
        assert!(
            !format!("{error:#}").contains(TOKEN),
            "error leaked the token"
        );

        let seen = received
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default();
        assert!(
            seen.is_empty(),
            "unexpected request reached loopback: {seen:?}"
        );
        assert!(!seen.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    }

    #[test]
    fn resolution_set_validation_fails_closed_on_empty_or_private_answers() {
        let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert!(validate_resolved_addrs("brief.example.test", &[public]).is_ok());
        let error = validate_resolved_addrs("brief.example.test", &[])
            .expect_err("an empty answer set must fail closed");
        assert!(error.to_string().contains("no addresses"), "{error:#}");
        let error = validate_resolved_addrs(
            "brief.example.test",
            &[public, "169.254.169.254:80".parse().unwrap()],
        )
        .expect_err("a metadata address must fail closed");
        assert!(
            error.to_string().contains("private or reserved"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn oversized_streamed_body_is_rejected_at_the_cap() {
        let cap = crate::MAX_BRIEF_BYTES.min(MAX_RAW_BYTES);
        let (url, _addr, received) = spawn_loopback_server(Some(vec![b'x'; cap + 1024]));
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("build test client");
        let response = client.get(&url).send().await.expect("mock server response");
        let error = read_bounded_body(response, Platform::Bugcrowd)
            .await
            .expect_err("body above the cap must be rejected");
        assert!(error.to_string().contains("exceeds"), "{error:#}");
        let _ = received.recv_timeout(Duration::from_secs(2));
    }

    #[tokio::test]
    async fn streamed_body_at_the_cap_is_accepted() {
        let cap = crate::MAX_BRIEF_BYTES.min(MAX_RAW_BYTES);
        let (url, _addr, received) = spawn_loopback_server(Some(vec![b'a'; cap]));
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("build test client");
        let response = client.get(&url).send().await.expect("mock server response");
        let body = read_bounded_body(response, Platform::Bugcrowd)
            .await
            .expect("body at the cap is allowed");
        assert_eq!(body.len(), cap);
        let _ = received.recv_timeout(Duration::from_secs(2));
    }
}
