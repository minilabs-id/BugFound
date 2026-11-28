//! Shared, dependency-light redaction primitives.
//!
//! This is a leaf crate on purpose: `tools`, `store` and `collaborator` all
//! need the same secret/PII/canary rules, while `store -> kernel-traits` is
//! already a dependency (the reverse would be a cycle) and `collaborator` is
//! intentionally free of internal dependencies except this one.
//!
//! Raw capture bytes are never routed through these helpers — redaction is for
//! model-visible views only. Hash/evidence code must keep the original bytes.

use serde_json::Value;

/// Canary tokens minted by the tools layer are prefixed with this string.
pub const CANARY_PREFIX: &str = "bugfound-canary-";
/// Inert placeholder written wherever a canary was found. Kept verbatim for
/// compatibility with existing report/tool assertions.
pub const REDACTED_CANARY: &str = "<redacted-canary>";
/// Standard marker for redacted secret/PII values.
pub const REDACTED: &str = "[REDACTED]";

/// Keys whose values are credentials and must never appear in model-visible
/// text. The union of the three historical implementations lives here.
pub const SENSITIVE_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "x-api-key",
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
    "session",
    "connection_string",
    "database_url",
    "dsn",
    "private_key",
    "credential",
];

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
}

fn is_sensitive_key(key: &str) -> bool {
    let k = key.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| k == *sensitive || k.contains(sensitive))
}

// ---------------------------------------------------------------------------
// Range helpers
// ---------------------------------------------------------------------------

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
        out.push_str(REDACTED);
        cursor = end;
    }
    out.push_str(&original[cursor..]);
    *s = out;
}

// ---------------------------------------------------------------------------
// Bearer / Basic credentials
// ---------------------------------------------------------------------------

/// Replace every `Bearer <token>` occurrence, case-insensitively.
fn redact_bearer(out: &mut String) {
    let mut i = 0;
    while i + 6 <= out.len() {
        let bytes = out.as_bytes();
        if bytes[i..i + 6].eq_ignore_ascii_case(b"bearer")
            && (i == 0 || !is_token_byte(bytes[i - 1]))
            && i + 6 < bytes.len()
            && bytes[i + 6].is_ascii_whitespace()
        {
            let mut end = i + 6;
            while end < bytes.len() && bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            let value_start = end;
            while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            if end > value_start {
                out.replace_range(i..end, REDACTED);
                i += REDACTED.len();
                continue;
            }
        }
        i += 1;
    }
}

fn is_b64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

/// Minimal base64 decoder used only to tell a real `Basic` credential from the
/// ordinary English word "Basic". No extra dependency is needed.
fn decode_b64(token: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in token.bytes() {
        if b == b'=' {
            break;
        }
        let value = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits) - 1;
        }
    }
    Some(out)
}

fn looks_like_basic_credential(token: &str) -> bool {
    if token.len() < 8 {
        return false;
    }
    if decode_b64(token).is_some_and(|decoded| decoded.contains(&b':')) {
        return true;
    }
    // Padded or long mixed-case/digit tokens are still credential-shaped even
    // when the decoded bytes do not contain a colon.
    token.ends_with('=')
        || (token.len() >= 16
            && token.bytes().any(|b| b.is_ascii_uppercase())
            && token.bytes().any(|b| b.is_ascii_lowercase())
            && token.bytes().any(|b| b.is_ascii_digit()))
}

/// Replace `Basic <base64>` credentials. The English word "Basic" followed by
/// ordinary prose is deliberately left untouched.
fn redact_basic(out: &mut String) {
    let mut i = 0;
    while i + 5 <= out.len() {
        let bytes = out.as_bytes();
        if bytes[i..i + 5].eq_ignore_ascii_case(b"basic")
            && (i == 0 || !is_token_byte(bytes[i - 1]))
            && i + 5 < bytes.len()
            && bytes[i + 5].is_ascii_whitespace()
        {
            let mut value_start = i + 5;
            while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
                value_start += 1;
            }
            let mut end = value_start;
            while end < bytes.len() && is_b64_byte(bytes[end]) {
                end += 1;
            }
            if looks_like_basic_credential(&out[value_start..end]) {
                out.replace_range(i..end, REDACTED);
                i += REDACTED.len();
                continue;
            }
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// key: "value" / key=value pairs
// ---------------------------------------------------------------------------

/// Redact values following sensitive keys in free text. Values stop at cookie
/// attribute boundaries (`;`), whitespace, quotes and JSON punctuation so a
/// `Cookie: session=abc; Path=/` cannot lose its harmless attributes.
fn redact_text_pairs(out: &mut String) {
    // Longest first so `set-cookie` wins over `cookie`, `x-api-key` over `key`.
    let mut keys = SENSITIVE_KEYS.to_vec();
    keys.sort_unstable_by_key(|key| std::cmp::Reverse(key.len()));
    for key in keys {
        let mut search = 0usize;
        loop {
            let lower = out.to_ascii_lowercase();
            let Some(rel) = lower[search..].find(key) else {
                break;
            };
            let start = search + rel;
            let end = start + key.len();
            let bytes = out.as_bytes();
            let bounded = (start == 0 || !is_token_byte(bytes[start - 1]))
                && (end >= bytes.len() || !is_token_byte(bytes[end]));
            if !bounded {
                search = end;
                if search >= out.len() {
                    break;
                }
                continue;
            }
            let mut i = end;
            while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
                i += 1;
            }
            // Tolerate `"key":` (raw JSON text) before the separator.
            if i < bytes.len() && matches!(bytes[i], b'"' | b'\'') {
                i += 1;
                while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
                    i += 1;
                }
            }
            if i >= bytes.len() || !matches!(bytes[i], b'=' | b':') {
                search = end;
                if search >= out.len() {
                    break;
                }
                continue;
            }
            i += 1;
            while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
                i += 1;
            }
            let quoted = i < bytes.len() && matches!(bytes[i], b'"' | b'\'');
            if quoted {
                i += 1;
            }
            let value_start = i;
            while i < bytes.len() {
                let c = bytes[i];
                if (c as char).is_ascii_whitespace()
                    || matches!(c, b'"' | b'\'' | b'&' | b',' | b';' | b'}' | b']')
                {
                    break;
                }
                i += 1;
            }
            if i > value_start {
                out.replace_range(value_start..i, REDACTED);
                search = value_start + REDACTED.len();
            } else {
                search = end;
            }
            if search >= out.len() {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Well-known token prefixes
// ---------------------------------------------------------------------------

fn redact_prefixes(out: &mut String) {
    const PREFIXES: &[&str] = &["sk-", "ghp_", "gho_", "glpat-", "AKIA", "xoxb-", "xoxp-"];
    for prefix in PREFIXES {
        let mut search = 0usize;
        loop {
            let Some(rel) = out[search..].find(prefix) else {
                break;
            };
            let start = search + rel;
            let bytes = out.as_bytes();
            if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
                search = start + prefix.len();
                if search >= out.len() {
                    break;
                }
                continue;
            }
            let mut end = start + prefix.len();
            while end < bytes.len() && is_token_byte(bytes[end]) {
                end += 1;
            }
            if end > start + prefix.len() {
                out.replace_range(start..end, REDACTED);
                search = start + REDACTED.len();
            } else {
                search = end;
            }
            if search >= out.len() {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PII: email, SSN, phone, payment cards
// ---------------------------------------------------------------------------

fn is_email_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '\'')
}

fn is_email_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-')
}

fn redact_emails(out: &mut String) {
    let mut search = 0usize;
    while let Some(rel) = out[search..].find('@') {
        let at = search + rel;
        let mut start = at;
        while let Some(c) = out[..start].chars().next_back() {
            if is_email_local_char(c) {
                start -= c.len_utf8();
            } else {
                break;
            }
        }
        let mut end = at + 1;
        while end < out.len() {
            let c = out[end..].chars().next().unwrap();
            if is_email_domain_char(c) {
                end += c.len_utf8();
            } else {
                break;
            }
        }
        let local = &out[start..at];
        let domain = &out[at + 1..end];
        let (label, tld) = domain.rsplit_once('.').unwrap_or(("", ""));
        let looks_email = !local.is_empty()
            && !label.is_empty()
            && tld.len() >= 2
            && tld.bytes().all(|byte| byte.is_ascii_alphabetic());
        if looks_email {
            out.replace_range(start..end, REDACTED);
            search = start + REDACTED.len();
        } else {
            search = at + 1;
        }
    }
}

/// `ddd-dd-dddd` with digit/punctuation boundaries on both sides.
fn ssn_ranges(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i + 11 <= b.len() {
        let shape = b[i..i + 3].iter().all(u8::is_ascii_digit)
            && b[i + 3] == b'-'
            && b[i + 4..i + 6].iter().all(u8::is_ascii_digit)
            && b[i + 6] == b'-'
            && b[i + 7..i + 11].iter().all(u8::is_ascii_digit);
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

fn redact_ssn(out: &mut String) {
    let ranges = ssn_ranges(out);
    apply_ranges(out, ranges);
}

fn is_number_separator(c: char) -> bool {
    matches!(c, ' ' | '-' | '(' | ')')
}

/// Year-first groups such as `2026-11-19 10` are timestamps, not phone numbers.
fn looks_like_date(chunks: &[usize], digits: &str) -> bool {
    chunks.len() >= 3
        && chunks[0] == 4
        && (digits.starts_with("19") || digits.starts_with("20"))
        && chunks[1..].iter().all(|&n| n <= 2)
}

/// Millisecond epochs and compact `YYYYMMDDHHMMSS` stamps must not be treated
/// as 13-19 digit payment cards.
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

fn is_phone_chunks(chunks: &[usize], first_digit: char) -> bool {
    match chunks {
        [3, 3, 4] => true,
        [1, 3, 3, 4] => first_digit == '1',
        _ => false,
    }
}

fn is_card_chunks(chunks: &[usize]) -> bool {
    chunks.len() >= 2
        && chunks[..chunks.len() - 1].iter().all(|&n| n == 4)
        && (1..=4).contains(chunks.last().unwrap())
}

/// Redact phone numbers, payment cards and SSNs while leaving short numbers,
/// dates, epochs and hashes alone.
fn redact_pii_numbers(out: &mut String) {
    let mut search = 0usize;
    loop {
        let bytes = out.as_bytes();
        let mut candidate = None;
        let mut j = search;
        while j < bytes.len() {
            let c = bytes[j] as char;
            if c.is_ascii_digit()
                || ((c == '+' || c == '(')
                    && j + 1 < bytes.len()
                    && (bytes[j + 1] as char).is_ascii_digit())
            {
                candidate = Some(j);
                break;
            }
            j += 1;
        }
        let Some(start) = candidate else {
            break;
        };

        let mut i = start;
        if bytes[i] == b'+' || bytes[i] == b'(' {
            i += 1;
        }
        let mut chunks = Vec::new();
        let mut current = 0usize;
        let mut digits = String::new();
        let mut end = i;
        while end < bytes.len() {
            let c = bytes[end] as char;
            if c.is_ascii_digit() {
                digits.push(c);
                current += 1;
                end += 1;
            } else if is_number_separator(c) {
                let mut k = end;
                while k < bytes.len() && is_number_separator(bytes[k] as char) {
                    k += 1;
                }
                if k < bytes.len() && (bytes[k] as char).is_ascii_digit() {
                    if current > 0 {
                        chunks.push(current);
                        current = 0;
                    }
                    end = k;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        if current > 0 {
            chunks.push(current);
        }

        let total: usize = chunks.iter().sum();
        let first_digit = digits.chars().next().unwrap_or_default();
        let is_ssn = chunks.as_slice() == [3, 2, 4];
        let is_card = (13..=19).contains(&total)
            && (chunks.len() == 1 || is_card_chunks(&chunks))
            && !looks_like_timestamp(&digits);
        let is_phone = if chunks.len() == 1 {
            total == 10 || (total == 11 && first_digit == '1')
        } else {
            is_phone_chunks(&chunks, first_digit)
        };
        let bounded = (start == 0 || !out.as_bytes()[start - 1].is_ascii_alphanumeric())
            && (end >= out.len() || !out.as_bytes()[end].is_ascii_alphanumeric());
        let should_redact =
            (is_card || is_ssn || is_phone) && !looks_like_date(&chunks, &digits) && bounded;

        if should_redact {
            out.replace_range(start..end, REDACTED);
            search = start + REDACTED.len();
        } else {
            search = end.max(start + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Redact likely secrets and PII from free text.
///
/// Structured JSON objects/arrays are redacted field by field first so a
/// sensitive key never survives a serialize/parse round trip; every string
/// leaf (and plain prose) then runs the shared text pipeline.
pub fn redact(input: &str) -> String {
    let mut out = match serde_json::from_str::<Value>(input) {
        Ok(mut value) if value.is_object() || value.is_array() => {
            redact_json(&mut value);
            value.to_string()
        }
        _ => input.to_string(),
    };
    redact_bearer(&mut out);
    redact_basic(&mut out);
    redact_text_pairs(&mut out);
    redact_prefixes(&mut out);
    redact_emails(&mut out);
    redact_ssn(&mut out);
    redact_pii_numbers(&mut out);
    out
}

/// Recursively redact a structured `Value` in place. Sensitive keys lose their
/// value entirely; every other string leaf runs the text pipeline.
pub fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *child = Value::String(REDACTED.to_string());
                } else {
                    redact_json(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json(item);
            }
        }
        Value::String(text) => {
            *text = redact(text.as_str());
        }
        _ => {}
    }
}

/// Alias kept for the historical store-internal helper name.
pub fn redact_json_value(value: &mut Value) {
    redact_json(value);
}

/// Clone-and-redact convenience wrapper around [`redact_json`].
pub fn redacted_json(value: &Value) -> Value {
    let mut value = value.clone();
    redact_json(&mut value);
    value
}

/// Replace every tool-minted canary token with [`REDACTED_CANARY`].
pub fn redact_canary_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(CANARY_PREFIX) {
        out.push_str(&rest[..index]);
        let tail = &rest[index + CANARY_PREFIX.len()..];
        let token_len = tail
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
            .count();
        out.push_str(REDACTED_CANARY);
        rest = &tail[token_len..];
    }
    out.push_str(rest);
    out
}

/// Recursively scrub canaries from a model-visible `Value`. A `canary` key is
/// replaced wholesale even when its value is not prefix-shaped.
pub fn scrub_canaries(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    let value = if key.eq_ignore_ascii_case("canary") {
                        Value::String(REDACTED_CANARY.to_string())
                    } else {
                        scrub_canaries(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(scrub_canaries).collect()),
        Value::String(text) => Value::String(redact_canary_text(text)),
        _ => value.clone(),
    }
}

/// Historical alias for [`scrub_canaries`].
pub fn redact_canaries(value: &Value) -> Value {
    scrub_canaries(value)
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
