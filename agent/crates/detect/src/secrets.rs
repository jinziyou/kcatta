//! Secret / credential-leak detection: plaintext private keys, cloud keys, and
//! provider tokens left on the host, emitted as host-attributed `source="secret"`
//! [`Vulnerability`]s.
//!
//! **Deterministic, low false positive, no regex** (so no ReDoS): every rule is an
//! anchored literal prefix (matched with `aho-corasick`, linear time) plus a
//! hand-written length / charclass / proximity / denylist check. High-FP detector
//! classes (generic high-entropy strings, JWTs, DB connection strings, `.env`
//! key=value) are deliberately NOT implemented.
//!
//! **Hard privacy invariant (collect-only):** the plaintext secret MUST NEVER
//! leave the host. The only upload-bound strings are `vuln_id` (rule type +
//! relative path + line) and `evidence` (rule type + path + line + a *non-reversible*
//! fingerprint or a masked prefix). Raw secret bytes are read at most into a local
//! window for validation and dropped — never formatted into any field.

use std::fs;
use std::path::{Path, PathBuf};

use aho_corasick::AhoCorasick;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use agent_contract::{Severity, Vulnerability};
use agent_detect_malware::{is_media_file, should_skip_entry, PSEUDO_FS, SKIP_DIR_NAMES};

/// Source label written into every secret [`Vulnerability`].
pub const SOURCE: &str = "secret";

/// Secrets live in small files; cap reads tight (saves IO vs malware's 32 MiB).
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Bytes sniffed for a NUL to classify a file as binary (skip content rules).
const BINARY_SNIFF: usize = 8192;
const MAX_DEPTH: usize = 64;

/// Path components that overwhelmingly hold benign fixtures / sample keys /
/// placeholders. A real secret legitimately committed here is skipped — an
/// accepted false-negative for a much larger false-positive reduction.
const EXCLUDE_COMPONENTS: &[&str] = &[
    "docs",
    "doc",
    "documentation",
    "example",
    "examples",
    "sample",
    "samples",
    "demo",
    "demos",
    "test",
    "tests",
    "testdata",
    "fixtures",
    "__fixtures__",
    "__tests__",
    "spec",
    "specs",
    "mock",
    "mocks",
    "testing",
    "guide",
    "guides",
    "tutorial",
    "tutorials",
];

/// Documentation file stems (basename up to first dot) — README.md, SECURITY.rst,
/// etc. routinely paste example / revoked credential forms in prose or code fences.
const DOC_STEMS: &[&str] = &[
    "readme",
    "contributing",
    "security",
    "changelog",
    "changes",
    "history",
    "code_of_conduct",
    "authors",
    "maintainers",
    "notice",
    "license",
];

/// Collect all secret-leak findings under `scan_root`, host-attributed to `host_id`.
pub fn collect(scan_root: &Path, host_id: &str) -> Vec<Vulnerability> {
    let root = scan_root;
    let excludes: Vec<PathBuf> = PSEUDO_FS.iter().map(|d| root.join(d)).collect();
    let skip_dirs: Vec<String> = SKIP_DIR_NAMES.iter().map(|s| s.to_string()).collect();
    let ac = AhoCorasick::new(CONTENT_PREFIXES.iter().map(|(p, _)| *p))
        .expect("static content prefixes compile");

    let mut out = Vec::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .max_depth(MAX_DEPTH)
        .into_iter()
        .filter_entry(|e| !should_skip_entry(e.path(), root, &excludes, &skip_dirs));
    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_excluded_path(&rel) {
            continue;
        }
        // Filename-only rules first (zero content read for keystores).
        scan_filename_rules(path, &rel, &mut out);
        scan_content_rules(&ac, path, &rel, &mut out);
    }

    for v in &mut out {
        v.affected_asset_id = host_id.to_string();
    }
    // Sort + dedup on (vuln_id, evidence): two DISTINCT secrets on the same line
    // share a vuln_id (which carries only path#line), but their evidence carries
    // distinct fingerprints — so keying on evidence too keeps both while still
    // collapsing a genuine exact duplicate.
    out.sort_by(|a, b| (&a.vuln_id, &a.evidence).cmp(&(&b.vuln_id, &b.evidence)));
    out.dedup_by(|a, b| a.vuln_id == b.vuln_id && a.evidence == b.evidence);
    out
}

fn finding(vuln_id: String, severity: Severity, evidence: String) -> Vulnerability {
    Vulnerability {
        vuln_id,
        severity,
        cvss_score: None,
        affected_asset_id: String::new(),
        parent_asset_id: None,
        source: SOURCE.to_string(),
        evidence: Some(evidence),
        references: Vec::new(),
    }
}

/// Path/filename heuristics that mark a file as fixture/doc/placeholder.
fn is_excluded_path(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    if lower.split('/').any(|c| EXCLUDE_COMPONENTS.contains(&c)) {
        return true;
    }
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    // Documentation files (by stem or doc extension) are doc-class — accepted FN,
    // mirrors the docs/ directory exclusion.
    let stem = base.split('.').next().unwrap_or(base);
    if DOC_STEMS.contains(&stem)
        || matches!(
            base.rsplit('.').next(),
            Some("md" | "markdown" | "rst" | "adoc" | "asciidoc")
        )
    {
        return true;
    }
    base.ends_with(".example")
        || base.ends_with(".sample")
        || base.ends_with(".template")
        || base.ends_with(".dist")
        || base.contains(".example.")
        || base.contains(".sample.")
}

// ----------------------------------------------------------------- helpers

/// Non-reversible short fingerprint of matched bytes (never the secret itself).
fn fp12(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize()
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn line_of(text: &str, byte_off: usize) -> usize {
    text.as_bytes()[..byte_off.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// Count of distinct ASCII chars — a cheap diversity floor to reject low-entropy
/// placeholders like `xxxxxxxx…` / `00000000…` without a full entropy model.
fn distinct_ascii(s: &str) -> usize {
    let mut seen = [false; 128];
    let mut n = 0;
    for &b in s.as_bytes() {
        let i = b as usize;
        if i < 128 && !seen[i] {
            seen[i] = true;
            n += 1;
        }
    }
    n
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True if the char immediately before `start` is not a word byte (so a prefix
/// like `AKIA` isn't matched mid-identifier).
fn left_boundary_ok(text: &str, start: usize) -> bool {
    start == 0 || !is_word_byte(text.as_bytes()[start - 1])
}

/// Take the run of bytes at `from` matching `pred`, up to `max` chars.
fn take_run(text: &str, from: usize, max: usize, pred: fn(u8) -> bool) -> &str {
    let b = text.as_bytes();
    let mut end = from;
    while end < b.len() && end - from < max && pred(b[end]) {
        end += 1;
    }
    &text[from..end]
}

fn contains_placeholder(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("example")
        || l.contains("xxxx")
        || l.contains("placeholder")
        || l.contains("your")
        || l.contains("redacted")
        || l.contains("dummy")
        || l.contains("changeme")
        || l.contains("notreal")
}

// ----------------------------------------------------------- content rules

#[derive(Clone, Copy)]
enum ContentRule {
    Pem,
    Aws,
    Github,
    Slack,
    Stripe,
}

/// Anchored literal prefixes → rule. PEM headers carry `PRIVATE KEY`, so public
/// keys / certificates simply never match.
const CONTENT_PREFIXES: &[(&str, ContentRule)] = &[
    ("-----BEGIN RSA PRIVATE KEY-----", ContentRule::Pem),
    ("-----BEGIN EC PRIVATE KEY-----", ContentRule::Pem),
    ("-----BEGIN DSA PRIVATE KEY-----", ContentRule::Pem),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", ContentRule::Pem),
    ("-----BEGIN PGP PRIVATE KEY BLOCK-----", ContentRule::Pem),
    ("-----BEGIN PRIVATE KEY-----", ContentRule::Pem),
    ("-----BEGIN ENCRYPTED PRIVATE KEY-----", ContentRule::Pem),
    ("AKIA", ContentRule::Aws),
    ("ASIA", ContentRule::Aws),
    ("ghp_", ContentRule::Github),
    ("gho_", ContentRule::Github),
    ("ghu_", ContentRule::Github),
    ("ghs_", ContentRule::Github),
    ("ghr_", ContentRule::Github),
    ("github_pat_", ContentRule::Github),
    ("xoxb-", ContentRule::Slack),
    ("xoxa-", ContentRule::Slack),
    ("xoxp-", ContentRule::Slack),
    ("xoxr-", ContentRule::Slack),
    ("xoxs-", ContentRule::Slack),
    ("xoxe-", ContentRule::Slack),
    ("sk_live_", ContentRule::Stripe),
    ("rk_live_", ContentRule::Stripe),
];

/// AWS published example keys (must never alert).
const AWS_EXAMPLE_IDS: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
];
/// Stripe canonical example key bodies.
const STRIPE_EXAMPLE_BODIES: &[&str] = &["4eC39HqLyjWDarjtT1zdp7dc", "TYooMQauvdEDq54NiTphI7jx"];

fn scan_content_rules(ac: &AhoCorasick, path: &Path, rel: &str, out: &mut Vec<Vulnerability>) {
    let Ok(meta) = fs::metadata(path) else { return };
    if meta.len() == 0 || meta.len() > MAX_FILE_BYTES {
        return;
    }
    if is_media_file(path) {
        return;
    }
    let Ok(bytes) = fs::read(path) else { return };
    if bytes.iter().take(BINARY_SNIFF).any(|&b| b == 0) {
        return; // binary
    }
    let text = String::from_utf8_lossy(&bytes);

    for m in ac.find_iter(text.as_ref()) {
        let (prefix, rule) = CONTENT_PREFIXES[m.pattern().as_usize()];
        let start = m.start();
        if !left_boundary_ok(&text, start) {
            continue;
        }
        let f = match rule {
            ContentRule::Pem => validate_pem(&text, start, prefix, rel),
            ContentRule::Aws => validate_aws(&text, start, rel),
            ContentRule::Github => validate_github(&text, start, prefix, rel),
            ContentRule::Slack => validate_slack(&text, start, prefix, rel),
            ContentRule::Stripe => validate_stripe(&text, start, prefix, rel),
        };
        if let Some(v) = f {
            out.push(v);
        }
    }
}

fn validate_pem(text: &str, start: usize, header: &str, rel: &str) -> Option<Vulnerability> {
    // Require a matching END within a bounded window (guards a bare header snippet).
    // Walk the end down to a char boundary — a UTF-8-lossy haystack can place a
    // multi-byte char across the 16 KiB mark, and slicing mid-char would panic and
    // abort the whole host scan.
    let mut window_end = (start + 16_384).min(text.len());
    while window_end > start && !text.is_char_boundary(window_end) {
        window_end -= 1;
    }
    let body = &text[start..window_end];
    if !body.contains("-----END") {
        return None;
    }
    let kind = if header.contains("RSA") {
        "RSA"
    } else if header.contains("EC ") {
        "EC"
    } else if header.contains("DSA") {
        "DSA"
    } else if header.contains("OPENSSH") {
        "OPENSSH"
    } else if header.contains("PGP") {
        "PGP"
    } else {
        "PKCS8"
    };
    let encrypted = header.contains("ENCRYPTED")
        || body
            .get(..256)
            .is_some_and(|h| h.contains("Proc-Type: 4,ENCRYPTED"));
    let line = line_of(text, start);
    let dev = {
        let l = rel.to_ascii_lowercase();
        l.contains("snakeoil")
            || l.contains("localhost")
            || l.contains("mkcert")
            || l.contains("self-signed")
    };
    let severity = if dev {
        Severity::Low
    } else if encrypted {
        Severity::High
    } else {
        Severity::Critical
    };
    Some(finding(
        format!("SECRET-PRIVATE-KEY-PEM::{rel}#{line}"),
        severity,
        format!("type=private-key kind={kind} encrypted={encrypted} path={rel} line={line}"),
    ))
}

fn validate_aws(text: &str, start: usize, rel: &str) -> Option<Vulnerability> {
    let id = take_run(text, start, 20, |b| {
        b.is_ascii_uppercase() || b.is_ascii_digit()
    });
    if id.len() != 20 {
        return None;
    }
    // right boundary
    if text
        .as_bytes()
        .get(start + 20)
        .is_some_and(|&b| is_word_byte(b))
    {
        return None;
    }
    if AWS_EXAMPLE_IDS.contains(&id) || id.contains("EXAMPLE") {
        return None;
    }
    // MANDATORY proximity: a 40-char high-entropy secret nearby (else a bare ID,
    // which is non-secret and common in ARNs/docs).
    if !has_aws_secret_nearby(text, start) {
        return None;
    }
    let line = line_of(text, start);
    let masked = format!("{}****{}", &id[..4], &id[16..]);
    Some(finding(
        format!("SECRET-AWS-ACCESS-KEY::{rel}#{line}"),
        Severity::Critical,
        format!("type=aws-access-key id={masked} paired_secret=present path={rel} line={line}"),
    ))
}

fn has_aws_secret_nearby(text: &str, center: usize) -> bool {
    let lo = center.saturating_sub(512);
    let hi = (center + 512).min(text.len());
    let b = &text.as_bytes()[lo..hi];
    let is_sec = |c: u8| c.is_ascii_alphanumeric() || c == b'/' || c == b'+';
    let mut run_start = 0usize;
    let mut i = 0usize;
    while i <= b.len() {
        let in_run = i < b.len() && is_sec(b[i]);
        if in_run && (i == 0 || !is_sec(b[i - 1])) {
            run_start = i;
        }
        if !in_run && i > 0 && is_sec(b[i - 1]) {
            let run = &b[run_start..i];
            if run.len() >= 40 {
                let s = std::str::from_utf8(run).unwrap_or("");
                // >=17 distinct excludes any pure-hex 40-char run (git SHA / md5 /
                // sha1 have <=16 distinct symbols) while still matching a real
                // base64 AWS secret access key.
                if distinct_ascii(s) >= 17 && !contains_placeholder(s) {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

fn validate_github(text: &str, start: usize, prefix: &str, rel: &str) -> Option<Vulnerability> {
    let body_start = start + prefix.len();
    let body = take_run(text, body_start, 90, |b| {
        b.is_ascii_alphanumeric() || b == b'_'
    });
    let ok = if prefix == "github_pat_" {
        body.len() >= 70 && body.contains('_')
    } else {
        body.len() == 36
    };
    if !ok {
        return None;
    }
    if text
        .as_bytes()
        .get(body_start + body.len())
        .is_some_and(|&b| is_word_byte(b))
    {
        return None;
    }
    // No CRC32 (matches gitleaks/trufflehog); reject low-diversity placeholders +
    // published-sample tokens via the path/placeholder exclusions already applied.
    if contains_placeholder(body) || distinct_ascii(body) < 12 {
        return None;
    }
    let line = line_of(text, start);
    let token = &text[start..body_start + body.len()];
    Some(finding(
        format!("SECRET-GITHUB-TOKEN::{rel}#{line}"),
        Severity::Critical,
        format!(
            "type=github-token prefix={prefix} fp={} path={rel} line={line}",
            fp12(token.as_bytes())
        ),
    ))
}

fn validate_slack(text: &str, start: usize, prefix: &str, rel: &str) -> Option<Vulnerability> {
    let body_start = start + prefix.len();
    let rest = take_run(text, body_start, 120, |b| {
        b.is_ascii_alphanumeric() || b == b'-'
    });
    // Real Slack tokens: a leading numeric segment then '-'-joined fields.
    let segs: Vec<&str> = rest.split('-').collect();
    let first_numeric = segs
        .first()
        .is_some_and(|s| s.len() >= 6 && s.bytes().all(|b| b.is_ascii_digit()));
    if !(segs.len() >= 2 && first_numeric && rest.len() >= 20) {
        return None;
    }
    if contains_placeholder(rest) {
        return None;
    }
    let line = line_of(text, start);
    let token = &text[start..body_start + rest.len()];
    Some(finding(
        format!("SECRET-SLACK-TOKEN::{rel}#{line}"),
        Severity::High,
        format!(
            "type=slack-token prefix={prefix} fp={} path={rel} line={line}",
            fp12(token.as_bytes())
        ),
    ))
}

fn validate_stripe(text: &str, start: usize, prefix: &str, rel: &str) -> Option<Vulnerability> {
    if !(prefix == "sk_live_" || prefix == "rk_live_") {
        return None; // the xoxe- alignment entry is inert
    }
    let body_start = start + prefix.len();
    let body = take_run(text, body_start, 99, |b| b.is_ascii_alphanumeric());
    if body.len() < 24 {
        return None;
    }
    if text
        .as_bytes()
        .get(body_start + body.len())
        .is_some_and(|&b| is_word_byte(b))
    {
        return None;
    }
    if STRIPE_EXAMPLE_BODIES.iter().any(|e| body.starts_with(e)) || contains_placeholder(body) {
        return None;
    }
    let line = line_of(text, start);
    let token = &text[start..body_start + body.len()];
    Some(finding(
        format!("SECRET-STRIPE-LIVE-KEY::{rel}#{line}"),
        Severity::Critical,
        format!(
            "type=stripe-live-key prefix={prefix} fp={} path={rel} line={line}",
            fp12(token.as_bytes())
        ),
    ))
}

// ---------------------------------------------------------- filename rules

const KEYSTORE_EXTS: &[(&str, Severity)] = &[
    ("p12", Severity::Medium),
    ("pfx", Severity::Medium),
    ("ppk", Severity::Medium),
    ("jks", Severity::Low),
    ("keystore", Severity::Low),
];

fn scan_filename_rules(path: &Path, rel: &str, out: &mut Vec<Vulnerability>) {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let base_lc = base.to_ascii_lowercase();
    // Keystore / identity-container files: report by existence, NEVER read bytes.
    if let Some(ext) = base_lc.rsplit('.').next() {
        if let Some(&(_, sev)) = KEYSTORE_EXTS.iter().find(|(e, _)| *e == ext) {
            // Known non-secret keystores.
            let benign =
                base_lc == "debug.keystore" || base_lc == "cacerts" || base_lc == ".keystore";
            let cert = base_lc.contains("truststore")
                || base_lc.contains("cacert")
                || base_lc.contains("ca-cert")
                || base_lc.contains("ca-bundle")
                || base_lc.contains("ca_bundle")
                || base_lc.contains("roots")
                || base_lc.starts_with("ca.")
                || base_lc.contains("public");
            let size_ok = fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false);
            if !benign && !cert && size_ok {
                out.push(finding(
                    format!("SECRET-KEYSTORE-FILE::{rel}"),
                    sev,
                    format!("type=keystore-file ext={ext} path={rel}"),
                ));
            }
        }
    }
    // Known credential files: confirm a plaintext (non-interpolated) secret marker.
    scan_credential_file(path, rel, &base_lc, out);
}

fn scan_credential_file(path: &Path, rel: &str, base_lc: &str, out: &mut Vec<Vulnerability>) {
    let rel_lc = rel.to_ascii_lowercase();
    let kind = if rel_lc.ends_with(".aws/credentials") {
        "aws-credentials"
    } else if base_lc == ".npmrc" {
        "npmrc"
    } else if base_lc == ".git-credentials" {
        "git-credentials"
    } else if base_lc == ".pypirc" {
        "pypirc"
    } else {
        return;
    };
    let Ok(meta) = fs::metadata(path) else { return };
    if meta.len() == 0 || meta.len() > MAX_FILE_BYTES {
        return;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue; // commented-out credential (.npmrc/.pypirc use ; and #)
        }
        let hit = match kind {
            "aws-credentials" => credential_rhs(line, "aws_secret_access_key")
                .is_some_and(|v| v.len() >= 16 && !rhs_is_placeholder(v)),
            "npmrc" => credential_rhs(line, "_authtoken")
                .is_some_and(|v| v.len() >= 16 && !rhs_is_placeholder(v)),
            "pypirc" => credential_rhs(line, "password")
                .is_some_and(|v| v.len() >= 6 && !rhs_is_placeholder(v)),
            "git-credentials" => git_credentials_has_password(line),
            _ => false,
        };
        if hit {
            out.push(finding(
                format!("SECRET-CREDENTIAL-FILE::{rel}#{}", i + 1),
                Severity::High,
                format!("type=credential-file file={kind} path={rel} line={}", i + 1),
            ));
        }
    }
}

/// `key = value` / `key value` / `key:value` RHS, case-insensitive key match.
fn credential_rhs<'a>(line: &'a str, key_lc: &str) -> Option<&'a str> {
    let lower = line.to_ascii_lowercase();
    let pos = lower.find(key_lc)?;
    let after = line[pos + key_lc.len()..].trim_start();
    let rhs = after
        .strip_prefix('=')
        .or_else(|| after.strip_prefix(':'))
        .unwrap_or(after)
        .trim();
    if rhs.is_empty() {
        None
    } else {
        Some(rhs)
    }
}

fn rhs_is_placeholder(rhs: &str) -> bool {
    rhs.starts_with("${")
        || rhs.starts_with("$(")
        || rhs.starts_with("$%")
        || rhs.contains("${")
        || contains_placeholder(rhs)
}

/// A `scheme://user:password@host` *or* the very common `scheme://<token>@host`
/// (a PAT stored as the username) with a non-placeholder secret segment.
fn git_credentials_has_password(line: &str) -> bool {
    let Some(scheme) = line.find("://") else {
        return false;
    };
    let after = &line[scheme + 3..];
    let Some(at) = after.find('@') else {
        return false;
    };
    let userinfo = &after[..at];
    let candidate = match userinfo.find(':') {
        Some(colon) => &userinfo[colon + 1..], // user:password
        None => userinfo,                      // token-as-username
    };
    if candidate.is_empty() || rhs_is_placeholder(candidate) {
        return false;
    }
    // A known token prefix, or a strong length+diversity floor — so a plain
    // `https://git@host` username isn't mistaken for a leaked credential.
    let known_token = [
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "github_pat_",
        "glpat-",
        "xoxb-",
    ]
    .iter()
    .any(|p| candidate.starts_with(p));
    known_token || (candidate.len() >= 16 && distinct_ascii(candidate) >= 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }
    fn write(r: &Path, rel: &str, content: &str) {
        let p = r.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }
    fn run(r: &Path) -> Vec<Vulnerability> {
        collect(r, "h-1")
    }
    fn ids(v: &[Vulnerability]) -> Vec<String> {
        v.iter().map(|x| x.vuln_id.clone()).collect()
    }
    fn has(v: &[Vulnerability], prefix: &str) -> bool {
        ids(v).iter().any(|i| i.starts_with(prefix))
    }

    const RSA_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
        MIIEpAIBAAKCAQEA0987654321zyxwvutsrqponmlkjihgfedcba0987654321ab\n\
        -----END RSA PRIVATE KEY-----\n";

    // Synthetic test tokens. The provider prefix is split with `concat!` so the
    // full token never appears contiguously in source — otherwise GitHub push
    // protection (the very thing this feature mirrors) blocks the push. `concat!`
    // joins at compile time, so the validators still see the complete token.
    const GH_A: &str = concat!("ghp", "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    const GH_B: &str = concat!("ghp", "_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2");
    const GH_PLACEHOLDER: &str = concat!("ghp", "_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    const AWS_ID: &str = concat!("AKIA", "Z7XK39QPLMNV2WC4");
    const AWS_SECRET: &str = "aZ4xK9pQ2mWvN8rT1yB7cE3uH6jL0sD5fG2hJ4kP";
    const AWS_EX_ID: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");
    const AWS_EX_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const SLACK_TOK: &str = concat!("xox", "b-123456789012-1234567890123-aBcDeFgHiJkLmNoPqRsTuV");
    const STRIPE_LIVE: &str = concat!("sk", "_live_0a1B2c3D4e5F6g7H8i9J0kLm");
    const STRIPE_EX: &str = concat!("sk", "_live_4eC39HqLyjWDarjtT1zdp7dc");
    const STRIPE_TEST: &str = concat!("sk", "_test_0a1B2c3D4e5F6g7H8i9J0kLm");
    const GLPAT: &str = concat!("glpat", "-AbCdEf1234567890XyZw");

    #[test]
    fn pem_private_key_flagged_public_and_cert_not() {
        let r = root();
        write(r.path(), "etc/ssl/host.key", RSA_KEY);
        write(
            r.path(),
            "etc/ssl/host.pub",
            "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
        );
        write(
            r.path(),
            "etc/ssl/host.crt",
            "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----\n",
        );
        let v = run(r.path());
        assert!(has(&v, "SECRET-PRIVATE-KEY-PEM::etc/ssl/host.key"));
        assert_eq!(
            v.iter()
                .filter(|x| x.vuln_id.starts_with("SECRET-PRIVATE-KEY"))
                .count(),
            1
        );
        let f = v
            .iter()
            .find(|x| x.vuln_id.starts_with("SECRET-PRIVATE-KEY"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.source, "secret");
        assert_eq!(f.affected_asset_id, "h-1");
        // Redaction: evidence carries no base64 key body.
        assert!(!f.evidence.as_ref().unwrap().contains("0987654321zyxw"));
    }

    #[test]
    fn aws_key_needs_nearby_secret_and_excludes_example() {
        let r = root();
        // Real-ish: AKIA id + a 40-char high-entropy secret nearby.
        write(
            r.path(),
            "app/config.yaml",
            &format!("aws_access_key_id: {AWS_ID}\naws_secret_access_key: {AWS_SECRET}\n"),
        );
        // A bare AKIA id with no nearby secret -> not a finding.
        write(r.path(), "app/arn.txt", &format!("user {AWS_ID} done\n"));
        // AWS published example -> never.
        write(
            r.path(),
            "app/ex.txt",
            &format!("{AWS_EX_ID} {AWS_EX_SECRET}\n"),
        );
        let v = run(r.path());
        assert!(has(&v, "SECRET-AWS-ACCESS-KEY::app/config.yaml"));
        assert_eq!(
            v.iter()
                .filter(|x| x.vuln_id.starts_with("SECRET-AWS"))
                .count(),
            1,
            "only the paired one"
        );
        let f = v
            .iter()
            .find(|x| x.vuln_id.starts_with("SECRET-AWS"))
            .unwrap();
        // Redaction: neither the full 20-char id nor the 40-char secret appears.
        let ev = f.evidence.as_ref().unwrap();
        assert!(!ev.contains(AWS_ID));
        assert!(!ev.contains(AWS_SECRET));
        assert!(ev.contains("AKIA****"));
    }

    #[test]
    fn github_token_flagged_placeholder_not() {
        let r = root();
        write(r.path(), "src/app.js", &format!("const t = '{GH_A}'\n"));
        write(r.path(), "src/ph.js", &format!("{GH_PLACEHOLDER}\n"));
        let v = run(r.path());
        assert!(has(&v, "SECRET-GITHUB-TOKEN::src/app.js"));
        assert!(
            !ids(&v).iter().any(|i| i.contains("ph.js")),
            "placeholder not flagged"
        );
        let f = v
            .iter()
            .find(|x| x.vuln_id.starts_with("SECRET-GITHUB"))
            .unwrap();
        assert!(!f.evidence.as_ref().unwrap().contains(GH_A));
    }

    #[test]
    fn slack_and_stripe_live_flagged() {
        let r = root();
        write(r.path(), "a/s.txt", &format!("token={SLACK_TOK}\n"));
        write(r.path(), "a/stripe.txt", &format!("{STRIPE_LIVE}\n"));
        write(r.path(), "a/stripe_ex.txt", &format!("{STRIPE_EX}\n"));
        write(r.path(), "a/test.txt", &format!("{STRIPE_TEST}\n"));
        let v = run(r.path());
        assert!(has(&v, "SECRET-SLACK-TOKEN::a/s.txt"));
        assert!(has(&v, "SECRET-STRIPE-LIVE-KEY::a/stripe.txt"));
        assert!(
            !ids(&v).iter().any(|i| i.contains("stripe_ex")),
            "stripe example excluded"
        );
        assert!(
            !ids(&v).iter().any(|i| i.contains("test.txt")),
            "sk_test_ not matched"
        );
    }

    #[test]
    fn keystore_file_by_name_only() {
        let r = root();
        write(r.path(), "opt/app/identity.p12", "\x00\x01binary-pkcs12");
        write(r.path(), "opt/app/debug.keystore", "android-debug");
        let v = run(r.path());
        assert!(has(&v, "SECRET-KEYSTORE-FILE::opt/app/identity.p12"));
        assert!(
            !ids(&v).iter().any(|i| i.contains("debug.keystore")),
            "android debug keystore excluded"
        );
    }

    #[test]
    fn credential_file_plaintext_not_interpolated() {
        let r = root();
        write(
            r.path(),
            "root/.npmrc",
            "//registry.npmjs.org/:_authToken=abc123def456ghi789jkl\n",
        );
        write(
            r.path(),
            "home/u/.npmrc",
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
        );
        let v = run(r.path());
        assert!(has(&v, "SECRET-CREDENTIAL-FILE::root/.npmrc"));
        assert!(
            !ids(&v).iter().any(|i| i.contains("home/u/.npmrc")),
            "interpolated token not flagged"
        );
    }

    #[test]
    fn binary_file_is_skipped() {
        let r = root();
        // PEM header but with an embedded NUL -> classified binary -> skipped.
        write(
            r.path(),
            "blob.bin",
            "-----BEGIN RSA PRIVATE KEY-----\x00\nMIIE\n-----END RSA PRIVATE KEY-----\n",
        );
        assert!(run(r.path()).is_empty());
    }

    #[test]
    fn excluded_paths_are_skipped() {
        let r = root();
        write(r.path(), "tests/fixtures/id_rsa", RSA_KEY);
        write(r.path(), "docs/example.key", RSA_KEY);
        write(r.path(), "src/key.example", RSA_KEY);
        assert!(
            run(r.path()).is_empty(),
            "fixtures/docs/.example are excluded"
        );
    }

    #[test]
    fn probe_fp_reattack_guide_md() {
        let r = root();
        write(
            r.path(),
            "guide/aws-setup.md",
            "aws_access_key_id = AKIAZ7XK39QPLMNV2WC4\n\
             aws_secret_access_key = aZ4xK9pQ2mWvN8rT1yB7cE3uH6jL0sD5fG2hJ4kP\n",
        );
        // CI-template forms claimed to NOT fire.
        write(
            r.path(),
            "guide/ci.yaml",
            "aws_access_key_id = AKIAZ7XK39QPLMNV2WC4\n\
             aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}\n",
        );
        write(
            r.path(),
            "guide/gha.yaml",
            "aws_access_key_id = AKIAZ7XK39QPLMNV2WC4\n\
             aws_secret_access_key = ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n",
        );
        let v = run(r.path());
        for x in &v {
            eprintln!(
                "PROBE_HIT {} sev={:?} ev={:?}",
                x.vuln_id, x.severity, x.evidence
            );
        }
        eprintln!("PROBE_COUNT {}", v.len());
        eprintln!(
            "PROBE_GUIDE_MD_FIRES {}",
            has(&v, "SECRET-AWS-ACCESS-KEY::guide/aws-setup.md")
        );
        eprintln!(
            "PROBE_CI_FIRES {}",
            ids(&v).iter().any(|i| i.contains("ci.yaml"))
        );
        eprintln!(
            "PROBE_GHA_FIRES {}",
            ids(&v).iter().any(|i| i.contains("gha.yaml"))
        );
    }

    #[test]
    fn no_findings_on_clean_tree() {
        let r = root();
        write(r.path(), "etc/hosts", "127.0.0.1 localhost\n");
        write(r.path(), "src/main.rs", "fn main() { println!(\"hi\"); }\n");
        assert!(run(r.path()).is_empty());
    }

    // ---- regressions from the implementation review ----

    #[test]
    fn documentation_files_are_excluded() {
        let r = root();
        write(
            r.path(),
            "README.md",
            &format!("Example: export GH_TOKEN={GH_A}\n"),
        );
        write(
            r.path(),
            "SECURITY.md",
            &format!("The revoked token {GH_A} was rotated.\n"),
        );
        write(r.path(), "docs/guide.txt", &format!("use {GH_A}\n"));
        assert!(
            run(r.path()).is_empty(),
            "README/SECURITY/docs are doc-class, excluded"
        );
    }

    #[test]
    fn two_distinct_secrets_on_one_line_both_reported() {
        let r = root();
        write(
            r.path(),
            "src/cfg.json",
            &format!("{{\"a\":\"{GH_A}\",\"b\":\"{GH_B}\"}}\n"),
        );
        let v = run(r.path());
        let n = v
            .iter()
            .filter(|x| x.vuln_id.starts_with("SECRET-GITHUB"))
            .count();
        assert_eq!(n, 2, "co-located distinct tokens must not be deduped away");
    }

    #[test]
    fn pem_window_at_multibyte_boundary_does_not_panic() {
        let r = root();
        // Many 3-byte chars so the 16 KiB window end lands mid-character.
        let filler = "中".repeat(6000);
        write(
            r.path(),
            "etc/big.key",
            &format!("-----BEGIN RSA PRIVATE KEY-----\n{filler}\n-----END RSA PRIVATE KEY-----\n"),
        );
        let _ = run(r.path()); // must not panic
    }

    #[test]
    fn ca_truststore_keystores_not_flagged() {
        let r = root();
        write(r.path(), "etc/ssl/ca-bundle.p12", "x");
        write(r.path(), "etc/pki/roots.jks", "x");
        write(r.path(), "opt/app/identity.p12", "x");
        let v = run(r.path());
        assert!(!ids(&v)
            .iter()
            .any(|i| i.contains("ca-bundle") || i.contains("roots")));
        assert!(has(&v, "SECRET-KEYSTORE-FILE::opt/app/identity.p12"));
    }

    #[test]
    fn commented_credential_lines_not_flagged() {
        let r = root();
        write(
            r.path(),
            "root/.npmrc",
            "#//registry.npmjs.org/:_authToken=abc123def456ghi789jkl\n",
        );
        write(
            r.path(),
            "home/u/.pypirc",
            "; password=supersecretvalue123\n",
        );
        assert!(
            run(r.path()).is_empty(),
            "commented-out credentials are skipped"
        );
    }

    #[test]
    fn git_credentials_token_as_username_flagged() {
        let r = root();
        // PAT stored as the username (no colon) — the most common real form.
        write(
            r.path(),
            "root/.git-credentials",
            &format!("https://{GLPAT}@gitlab.com\n"),
        );
        // A plain username with no secret must NOT be flagged.
        write(
            r.path(),
            "home/u/.git-credentials",
            "https://git@github.com\n",
        );
        let v = run(r.path());
        assert!(has(&v, "SECRET-CREDENTIAL-FILE::root/.git-credentials"));
        assert!(
            !ids(&v).iter().any(|i| i.contains("home/u")),
            "plain username not a finding"
        );
    }

    #[test]
    fn aws_id_with_only_hex_sha_nearby_is_not_paired() {
        let r = root();
        // The only 40-char run near the AKIA id is a hex git SHA (<=16 distinct).
        write(
            r.path(),
            "app/log.txt",
            "key AKIAZ7XK39QPLMNV2WC4 at commit a1b2c3d4e5f6789012345678901234567890abcd done\n",
        );
        assert!(
            !has(&run(r.path()), "SECRET-AWS"),
            "a hex SHA is not a paired AWS secret"
        );
    }
}
