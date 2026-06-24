//! Host security-posture misconfiguration findings: `sshd_config`, `/etc/shadow`,
//! and SUID/SGID binaries — emitted as host-attributed contract [`Vulnerability`]s
//! (`source = "posture"`).
//!
//! Deliberately **low false positive** (a blue-team tool that cries wolf buries
//! real findings): only *explicit* risky values are flagged — never a missing
//! directive whose modern default is safe — modern hardening idioms are excluded,
//! locked/system accounts are filtered out, and only world-writable or
//! GTFOBins-class SUID binaries are reported (never the large standard SUID set).
//!
//! Every read degrades to zero findings when the file is missing or unreadable
//! (e.g. `/etc/shadow` under an unprivileged scan): never an error that aborts the
//! scan, never a fabricated "secure" negative.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use agent_contract::{Severity, Vulnerability};

use crate::root::{join_root, resolve_under_root};
use crate::ScanContext;

/// Source label written into every posture [`Vulnerability`].
pub const SOURCE: &str = "posture";

/// Collect all posture findings under `ctx.scan_root`, host-attributed to `host_id`.
pub fn collect(ctx: &ScanContext, host_id: &str) -> Vec<Vulnerability> {
    let (mut out, permit_empty_passwords) = sshd::evaluate(ctx);
    out.extend(shadow::evaluate(ctx, permit_empty_passwords));
    out.extend(suid::evaluate(ctx));
    for v in &mut out {
        v.affected_asset_id = host_id.to_string();
    }
    // Deterministic, idempotent across re-scans (vuln_id carries the subject).
    out.sort_by(|a, b| a.vuln_id.cmp(&b.vuln_id));
    out
}

/// Build a posture [`Vulnerability`]. `affected_asset_id` is filled in by
/// [`collect`] with the host id.
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

// ============================================================ sshd_config

mod sshd {
    use super::*;

    const MAX_INCLUDE_DEPTH: usize = 8;

    /// One effective global directive (pre-first-`Match`), with provenance.
    struct Directive {
        source: String, // "etc/ssh/sshd_config:12" (relative to scan_root)
        keyword_lc: String,
        raw: String,   // original trimmed line, for evidence
        value: String, // first whitespace token of the argument, lower-cased
    }

    /// Evaluate the effective global sshd config. Returns `(findings,
    /// permit_empty_passwords)` — the bool lets the shadow rule corroborate a
    /// network-reachable empty-password path.
    pub(super) fn evaluate(ctx: &ScanContext) -> (Vec<Vulnerability>, bool) {
        let top = join_root(ctx, "etc/ssh/sshd_config");
        if !top.exists() {
            return (Vec::new(), false); // no sshd configured -> nothing to say
        }
        let mut directives = Vec::new();
        flatten_file(ctx, &top, 0, &mut directives);

        // First-occurrence-wins (man sshd_config): the FIRST value per keyword in
        // the flattened pre-Match stream is authoritative; later dupes are dead.
        let mut first: HashMap<&str, &Directive> = HashMap::new();
        for d in &directives {
            first.entry(d.keyword_lc.as_str()).or_insert(d);
        }

        let mut out = Vec::new();
        let mut permit_empty = false;

        if let Some(d) = first.get("permitrootlogin") {
            if d.value == "yes" {
                out.push(finding(
                    "POSTURE-SSHD-PERMIT-ROOT-LOGIN-YES".to_string(),
                    Severity::High,
                    format!(
                        "{}: `{}` — permits direct root login over SSH via any auth \
                         method including password (modern default is prohibit-password)",
                        d.source, d.raw
                    ),
                ));
            }
        }

        if let Some(d) = first.get("permitemptypasswords") {
            if d.value == "yes" {
                permit_empty = true;
                out.push(finding(
                    "POSTURE-SSHD-PERMIT-EMPTY-PASSWORDS".to_string(),
                    Severity::Critical,
                    format!(
                        "{}: `{}` — SSH accepts accounts with an empty password hash \
                         (default is no; corroborated by the shadow empty-password rule)",
                        d.source, d.raw
                    ),
                ));
            }
        }

        // Weak MAC: flag only an ADDITIVE list (plain replace, or `+`/`^`) that
        // names an MD5 MAC. A leading `-` (remove) list is hardening — never flag.
        // Use `value` (the first whitespace token) — the MACs argument is a single
        // comma-list, so any trailing inline text (e.g. a `# md5 removed` note) is
        // not part of it and must not trip the substring check.
        if let Some(d) = first.get("macs") {
            let list = d.value.as_str();
            let stripped = list
                .strip_prefix('+')
                .or_else(|| list.strip_prefix('^'))
                .unwrap_or(list);
            let is_removal = list.starts_with('-');
            if !is_removal
                && stripped
                    .split(',')
                    .any(|t| t.trim().to_ascii_lowercase().contains("md5"))
            {
                out.push(finding(
                    "POSTURE-SSHD-WEAK-MACS".to_string(),
                    Severity::Medium,
                    format!(
                        "{}: `{}` — additively enables an MD5-based MAC, weakening SSH \
                         transport integrity with no modern interop rationale",
                        d.source, d.raw
                    ),
                ));
            }
        }

        (out, permit_empty)
    }

    /// Append `file`'s global-scope directives to `out`, splicing `Include`d files
    /// in lexical order at their inclusion point. A `Match` ends the global scope
    /// of **this file only** (per `man sshd_config`): we `return`, which stops this
    /// file but lets the including file resume in its own global scope — a `Match`
    /// in an included drop-in must NOT mask the base config body that follows the
    /// `Include`. Missing/unreadable files contribute nothing (never an error).
    fn flatten_file(ctx: &ScanContext, file: &Path, depth: usize, out: &mut Vec<Directive>) {
        if depth > MAX_INCLUDE_DEPTH {
            return;
        }
        let Ok(text) = fs::read_to_string(file) else {
            return;
        };
        let rel = file
            .strip_prefix(&ctx.scan_root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");

        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // keyword ends at the first whitespace or '=' (sshd allows `Key=Value`).
            let kw_end = trimmed
                .find(|c: char| c.is_whitespace() || c == '=')
                .unwrap_or(trimmed.len());
            let keyword_lc = trimmed[..kw_end].to_ascii_lowercase();
            let args = trimmed[kw_end..]
                .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
                .trim();

            if keyword_lc == "match" {
                return; // ends THIS file's global scope only
            }
            if keyword_lc == "include" {
                for pattern in args.split_whitespace() {
                    for included in resolve_includes(ctx, pattern) {
                        flatten_file(ctx, &included, depth + 1, out);
                    }
                }
                continue;
            }

            let value = args
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            out.push(Directive {
                source: format!("{rel}:{}", i + 1),
                keyword_lc,
                raw: trimmed.to_string(),
                value,
            });
        }
    }

    /// Resolve a (possibly globbed) `Include` pattern to existing files under
    /// `scan_root`, sorted lexically. A relative pattern is taken relative to
    /// `/etc/ssh` (sshd semantics); paths are contained under `scan_root`.
    ///
    /// Only the trailing (basename) component may be globbed — the common
    /// `sshd_config.d/*.conf` drop-in idiom. A wildcard in a *directory* component
    /// is not expanded (it would just not match, a conservative false negative).
    fn resolve_includes(ctx: &ScanContext, pattern: &str) -> Vec<std::path::PathBuf> {
        let logical = if pattern.starts_with('/') {
            pattern.to_string()
        } else {
            format!("etc/ssh/{pattern}")
        };
        let resolved = resolve_under_root(&ctx.scan_root, &logical);
        let (Some(parent), Some(name)) = (resolved.parent(), resolved.file_name()) else {
            return Vec::new();
        };
        let name = name.to_string_lossy();
        if !name.contains('*') {
            return if resolved.is_file() {
                vec![resolved]
            } else {
                Vec::new()
            };
        }
        let Ok(entries) = fs::read_dir(parent) else {
            return Vec::new();
        };
        let mut matched: Vec<std::path::PathBuf> = entries
            .flatten()
            .filter(|e| e.path().is_file())
            .filter(|e| glob_match(&name, &e.file_name().to_string_lossy()))
            .map(|e| e.path())
            .collect();
        matched.sort();
        matched
    }

    /// Minimal `*`-wildcard glob (no `?`/`[]`) — covers `*.conf`, `50-*.conf`, …
    fn glob_match(pattern: &str, name: &str) -> bool {
        fn go(p: &[u8], n: &[u8]) -> bool {
            match p.first() {
                None => n.is_empty(),
                Some(b'*') => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
                Some(&c) => !n.is_empty() && n[0] == c && go(&p[1..], &n[1..]),
            }
        }
        go(pattern.as_bytes(), name.as_bytes())
    }
}

// ================================================================ shadow

mod shadow {
    use super::*;

    /// Basenames of shells that mean "cannot interactively log in".
    const NOLOGIN_SHELLS: &[&str] = &["nologin", "false", "sync", "shutdown", "halt", "poweroff"];

    struct PasswdEntry {
        uid: Option<u32>,
        shell: String,
    }

    pub(super) fn evaluate(ctx: &ScanContext, permit_empty_passwords: bool) -> Vec<Vulnerability> {
        let Ok(shadow_text) = fs::read_to_string(join_root(ctx, "etc/shadow")) else {
            return Vec::new(); // unreadable (unprivileged) or absent -> say nothing
        };
        let passwd = fs::read_to_string(join_root(ctx, "etc/passwd")).unwrap_or_default();
        let passwd_map = parse_passwd(&passwd);
        let now_days = now_days();

        let mut out = Vec::new();
        for line in shadow_text.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 2 {
                continue;
            }
            let user = fields[0];
            if user.is_empty() {
                continue;
            }
            let hash = fields[1]; // NOT trimmed: a single space is a real value
            let expire = fields.get(7).copied().unwrap_or("");
            let pw = classify_hash(hash);
            let entry = passwd_map.get(user);
            let login_capable = entry.is_none_or(|e| is_login_capable(&e.shell));
            let uid = entry.and_then(|e| e.uid);

            match pw {
                HashState::Empty if login_capable => {
                    // Reachable auth path => critical, else (system/root on a bare
                    // image with no SSH empty-password) => medium.
                    let reachable = matches!(uid, Some(u) if u >= 1000) || (permit_empty_passwords);
                    let sev = if reachable {
                        Severity::Critical
                    } else {
                        Severity::Medium
                    };
                    out.push(finding(
                        format!("POSTURE-SHADOW-EMPTY-PASSWORD::{user}"),
                        sev,
                        format!(
                            "account '{user}'{} has an EMPTY password field in /etc/shadow — \
                             login with no password",
                            uid.map(|u| format!(" (uid {u})")).unwrap_or_default()
                        ),
                    ));
                }
                HashState::Weak(algo) => {
                    // Weak hash matters only on a login-capable, non-expired,
                    // human/root account (uid 0 or >=1000). Skip system daemons.
                    let human = matches!(uid, Some(0)) || matches!(uid, Some(u) if u >= 1000);
                    if login_capable && human && !is_expired(expire, now_days) {
                        out.push(finding(
                            format!("POSTURE-SHADOW-WEAK-HASH::{user}"),
                            Severity::Medium,
                            format!(
                                "account '{user}'{} password is stored with legacy {algo} in \
                                 /etc/shadow — cheap to brute-force offline if the file leaks; \
                                 upgrade to yescrypt/sha512",
                                uid.map(|u| format!(" (uid {u})")).unwrap_or_default()
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }
        out
    }

    enum HashState {
        Empty,
        Locked,
        Strong,
        Weak(&'static str),
    }

    /// Classify a shadow hash field. Locked (`*`/`!`/`!!`/prefixed real hash) and
    /// strong (`$5/$6/$7/$y/$gy/$2*`) are NOT findings.
    fn classify_hash(hash: &str) -> HashState {
        if hash.is_empty() {
            return HashState::Empty;
        }
        // Disabled / locked markers, and locked-but-has-hash (`!`/`*` prefix).
        if hash.starts_with('!') || hash.starts_with('*') {
            return HashState::Locked;
        }
        if hash.starts_with("$1$") {
            return HashState::Weak("MD5-crypt ($1$)");
        }
        if hash.starts_with('$') {
            // $2*/$5$/$6$/$7$/$y$/$gy$/... — modern algorithms.
            return HashState::Strong;
        }
        // No `$`: a 13-char [./0-9A-Za-z] string is classic DES crypt.
        if hash.len() == 13
            && hash
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
        {
            return HashState::Weak("DES crypt");
        }
        // Anything else with no `$` and wrong length is not a usable hash -> locked.
        HashState::Locked
    }

    fn parse_passwd(text: &str) -> HashMap<String, PasswdEntry> {
        let mut map = HashMap::new();
        for line in text.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split(':').collect();
            // Keep any line that carries a username + uid; a malformed/truncated
            // line with an absent shell still maps (absent shell => login-capable),
            // so a present account is never dropped (which would silently downgrade
            // its empty-password severity).
            if f.len() < 3 || f[0].is_empty() {
                continue;
            }
            map.insert(
                f[0].to_string(),
                PasswdEntry {
                    uid: f[2].parse().ok(),
                    shell: f.get(6).map(|s| s.trim().to_string()).unwrap_or_default(),
                },
            );
        }
        map
    }

    fn is_login_capable(shell: &str) -> bool {
        if shell.is_empty() {
            return true; // empty shell defaults to /bin/sh -> login-capable
        }
        let base = shell.rsplit('/').next().unwrap_or(shell);
        !NOLOGIN_SHELLS.contains(&base)
    }

    /// Days since the Unix epoch, or `None` if the clock is unavailable.
    fn now_days() -> Option<i64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| (d.as_secs() / 86_400) as i64)
    }

    /// True if the shadow `expire` field (days-since-epoch) is in the past.
    fn is_expired(expire: &str, now_days: Option<i64>) -> bool {
        match (expire.trim().parse::<i64>(), now_days) {
            (Ok(e), Some(now)) if e >= 0 => e < now,
            _ => false,
        }
    }
}

// ================================================================== SUID

mod suid {
    use super::*;

    /// Standard top-level binary directories we enumerate for SUID/SGID bits.
    /// Scoping to these (shallow) keeps the walk cheap AND naturally excludes
    /// container/image layer storage (var/lib/docker, …), whose binaries are NOT
    /// under these host paths — so they are never mis-attributed to the host.
    const BIN_DIRS: &[&str] = &[
        "usr/bin",
        "bin",
        "usr/sbin",
        "sbin",
        "usr/local/bin",
        "usr/local/sbin",
    ];

    const MAX_DEPTH: usize = 2;

    /// GTFOBins-class binaries that are NEVER legitimately SUID/SGID on a stock
    /// distro — setuid on any of these is a direct privilege-escalation primitive.
    /// Deliberately EXCLUDES the standard SUID set (sudo/su/passwd/mount/ping/…)
    /// and SGID `man`/`mandb` (6755/2755 by default), which would be false alarms.
    const DANGEROUS: &[&str] = &[
        // shells (`busybox` deliberately omitted — some embedded/legacy systems
        // ship it SUID by design; a malicious one is still caught world-writable)
        "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "ash", // interpreters
        "python", "python2", "python3", "perl", "ruby", "php", "lua", "node", "nodejs", "tclsh",
        "expect", // editors / pagers with shell escapes
        "vim", "vi", "view", "nano", "ed", "emacs", "less", "more",
        // file/text tools that are GTFOBins SUID escalators
        "find", "awk", "gawk", "mawk", "sed", "env", "tar", "make", "nmap", "gdb", "socat", "dd",
    ];

    #[cfg(unix)]
    pub(super) fn evaluate(ctx: &ScanContext) -> Vec<Vulnerability> {
        use std::os::unix::fs::MetadataExt;

        let mut out = Vec::new();
        for dir in BIN_DIRS {
            walk(
                &join_root(ctx, dir),
                &ctx.scan_root,
                0,
                &mut |path, meta| {
                    let mode = meta.mode();
                    let suid_or_sgid = mode & 0o4000 != 0 || mode & 0o2000 != 0;
                    if !suid_or_sgid {
                        return;
                    }
                    let rel = path
                        .strip_prefix(&ctx.scan_root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    let octal = format!("{:o}", mode & 0o7777);

                    if mode & 0o002 != 0 {
                        out.push(finding(
                            format!("POSTURE-SUID-WORLD-WRITABLE::{rel}"),
                            Severity::Critical,
                            format!(
                            "world-writable SUID/SGID binary: /{rel} (mode {octal}, owner uid {}) \
                             — any local user can overwrite its bytes and run code as the owner",
                            meta.uid()
                        ),
                        ));
                    }
                    let base = rel.rsplit('/').next().unwrap_or(&rel);
                    if DANGEROUS.contains(&base) {
                        out.push(finding(
                            format!("POSTURE-SUID-DANGEROUS-BINARY::{rel}"),
                            Severity::High,
                            format!(
                                "SUID/SGID set on {base}: /{rel} (mode {octal}, owner uid {}) — \
                             GTFOBins documents this as a direct root-escalation primitive and it \
                             is not part of any standard SUID set",
                                meta.uid()
                            ),
                        ));
                    }
                },
            );
        }
        out
    }

    #[cfg(not(unix))]
    pub(super) fn evaluate(_ctx: &ScanContext) -> Vec<Vulnerability> {
        Vec::new() // SUID/SGID is a Unix permission concept
    }

    /// Shallow walk (regular files only, never following symlinks) invoking `f`
    /// for each file with its metadata.
    #[cfg(unix)]
    fn walk(
        dir: &Path,
        _scan_root: &Path,
        depth: usize,
        f: &mut dyn FnMut(&Path, &std::fs::Metadata),
    ) {
        if depth > MAX_DEPTH {
            return;
        }
        // Skip a bin-dir ROOT that is itself a symlink: on merged-/usr systems
        // `/bin -> /usr/bin` and `/sbin -> /usr/sbin`, so walking both would
        // double-count every SUID binary. The real target is enumerated via its
        // canonical path (usr/bin, usr/sbin), which is also in BIN_DIRS.
        if depth == 0 && fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
            return;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // lstat semantics: never follow a symlink (a symlink carries no SUID,
            // and following one could escape the scan root).
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            let ft = meta.file_type();
            if ft.is_dir() {
                walk(&path, _scan_root, depth + 1, f);
            } else if ft.is_file() {
                f(&path, &meta);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    fn run(root: &Path) -> Vec<Vulnerability> {
        collect(&ScanContext::at(root), "host-1")
    }

    fn ids(v: &[Vulnerability]) -> Vec<&str> {
        v.iter().map(|x| x.vuln_id.as_str()).collect()
    }

    // -------------------------------------------------------------- sshd

    #[test]
    fn missing_sshd_config_yields_nothing() {
        let r = root();
        assert!(run(r.path()).is_empty());
    }

    #[test]
    fn insecure_sshd_flags_root_login_and_empty_passwords() {
        let r = root();
        write(
            r.path(),
            "etc/ssh/sshd_config",
            "PermitRootLogin yes\nPermitEmptyPasswords yes\n",
        );
        let v = run(r.path());
        let got = ids(&v);
        assert!(got.contains(&"POSTURE-SSHD-PERMIT-ROOT-LOGIN-YES"));
        assert!(got.contains(&"POSTURE-SSHD-PERMIT-EMPTY-PASSWORDS"));
        assert!(v
            .iter()
            .all(|x| x.source == "posture" && x.affected_asset_id == "host-1"));
        assert!(v.iter().all(|x| x.parent_asset_id.is_none()));
    }

    #[test]
    fn hardened_and_benign_sshd_yields_zero_findings() {
        // The FP matrix: every line here is a standard/safe config.
        let r = root();
        write(
            r.path(),
            "etc/ssh/sshd_config",
            "PermitRootLogin prohibit-password\n\
             #PermitRootLogin yes\n\
             PasswordAuthentication yes\n\
             X11Forwarding yes\n\
             Ciphers +aes128-cbc\n\
             MACs hmac-sha2-512,hmac-ripemd160\n\
             Match Address 10.0.0.0/8\n\
             PermitRootLogin yes\n",
        );
        assert!(
            run(r.path()).is_empty(),
            "no rule should fire on a hardened/benign config"
        );
    }

    #[test]
    fn dropin_hardening_wins_over_insecure_base_first_occurrence() {
        // Include at the top -> drop-in is processed first -> first-occurrence-wins
        // makes prohibit-password authoritative; the later base `yes` is dead.
        let r = root();
        write(
            r.path(),
            "etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
        );
        write(
            r.path(),
            "etc/ssh/sshd_config.d/50-harden.conf",
            "PermitRootLogin prohibit-password\n",
        );
        assert!(
            run(r.path()).is_empty(),
            "a drop-in that hardens the base must suppress the finding (no false positive)"
        );
    }

    #[test]
    fn match_in_dropin_does_not_mask_base_body() {
        // Stock Ubuntu/Debian layout: `Include` at the TOP, real body below. A
        // drop-in with its own `Match` block must NOT mask the base config body —
        // a `Match` ends global scope for its own file only. (Regression: a shared
        // hit_match flag used to unwind the whole include stack -> silent FNs.)
        let r = root();
        write(
            r.path(),
            "etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\n\
             PermitRootLogin yes\n\
             PermitEmptyPasswords yes\n",
        );
        write(
            r.path(),
            "etc/ssh/sshd_config.d/20-sftp.conf",
            "Match Group sftponly\n    ChrootDirectory /srv/sftp\n    ForceCommand internal-sftp\n",
        );
        let v = run(r.path());
        let got = ids(&v);
        assert!(
            got.contains(&"POSTURE-SSHD-PERMIT-ROOT-LOGIN-YES"),
            "base body after Include must still be read"
        );
        assert!(got.contains(&"POSTURE-SSHD-PERMIT-EMPTY-PASSWORDS"));
    }

    #[test]
    fn inline_comment_with_md5_does_not_trip_weak_mac() {
        let r = root();
        write(
            r.path(),
            "etc/ssh/sshd_config",
            "MACs hmac-sha2-512,hmac-sha2-256 # legacy md5 macs removed\n",
        );
        assert!(
            run(r.path()).is_empty(),
            "md5 only in a trailing comment must not flag the MAC list"
        );
    }

    #[test]
    fn weak_mac_additive_flags_but_removal_does_not() {
        let r = root();
        write(r.path(), "etc/ssh/sshd_config", "MACs +hmac-md5\n");
        assert!(ids(&run(r.path())).contains(&"POSTURE-SSHD-WEAK-MACS"));

        let r2 = root();
        write(
            r2.path(),
            "etc/ssh/sshd_config",
            "MACs -hmac-md5,hmac-md5-96\n",
        );
        assert!(
            run(r2.path()).is_empty(),
            "a `-` remove list is hardening, never a finding"
        );
    }

    // ------------------------------------------------------------ shadow

    fn passwd_login(user: &str, uid: u32) -> String {
        format!("{user}:x:{uid}:{uid}::/home/{user}:/bin/bash\n")
    }

    #[test]
    fn empty_password_login_user_is_critical() {
        let r = root();
        write(r.path(), "etc/passwd", &passwd_login("app", 1000));
        write(r.path(), "etc/shadow", "app::19000:0:99999:7:::\n");
        let v = run(r.path());
        let f = v
            .iter()
            .find(|x| x.vuln_id == "POSTURE-SHADOW-EMPTY-PASSWORD::app")
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn empty_password_system_root_is_medium_without_ssh_corroboration() {
        let r = root();
        write(r.path(), "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
        write(r.path(), "etc/shadow", "root::19000:0:99999:7:::\n");
        let v = run(r.path());
        let f = v
            .iter()
            .find(|x| x.vuln_id == "POSTURE-SHADOW-EMPTY-PASSWORD::root")
            .unwrap();
        assert_eq!(
            f.severity,
            Severity::Medium,
            "no reachable auth path -> medium"
        );
    }

    #[test]
    fn empty_password_root_is_critical_when_sshd_permits_empty() {
        let r = root();
        write(
            r.path(),
            "etc/ssh/sshd_config",
            "PermitEmptyPasswords yes\n",
        );
        write(r.path(), "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
        write(r.path(), "etc/shadow", "root::19000:0:99999:7:::\n");
        let v = run(r.path());
        let f = v
            .iter()
            .find(|x| x.vuln_id == "POSTURE-SHADOW-EMPTY-PASSWORD::root")
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn locked_and_nologin_accounts_are_not_flagged() {
        let r = root();
        write(
            r.path(),
            "etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             cloud:x:1000:1000::/home/cloud:/bin/bash\n",
        );
        // root locked (*), daemon empty-but-nologin, cloud has a strong $6$ hash.
        write(
            r.path(),
            "etc/shadow",
            "root:*:19000:0:99999:7:::\n\
             daemon::19000:0:99999:7:::\n\
             cloud:$6$abcd$xyz:19000:0:99999:7:::\n",
        );
        assert!(
            run(r.path()).is_empty(),
            "locked / nologin / strong-hash accounts are not findings"
        );
    }

    #[test]
    fn weak_hash_flagged_on_human_accounts_only() {
        let r = root();
        write(
            r.path(),
            "etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n\
             svc:x:140:140::/var/svc:/usr/sbin/nologin\n\
             user:x:1001:1001::/home/user:/bin/bash\n",
        );
        write(
            r.path(),
            "etc/shadow",
            "root:$1$salt$hash:19000:0:99999:7:::\n\
             svc:$1$salt$hash:19000:0:99999:7:::\n\
             user:0123456789abc:19000:0:99999:7:::\n",
        );
        let v = run(r.path());
        let got = ids(&v);
        assert!(got.contains(&"POSTURE-SHADOW-WEAK-HASH::root"), "root MD5");
        assert!(
            got.contains(&"POSTURE-SHADOW-WEAK-HASH::user"),
            "uid>=1000 DES"
        );
        assert!(
            !got.contains(&"POSTURE-SHADOW-WEAK-HASH::svc"),
            "system nologin daemon skipped"
        );
    }

    #[test]
    fn short_passwd_line_does_not_downgrade_empty_password_severity() {
        // A truncated 6-field passwd line (no shell) must still map the account so
        // its empty-password finding stays Critical (uid>=1000), not downgraded to
        // Medium by treating the user as unknown.
        let r = root();
        write(r.path(), "etc/passwd", "app:x:1000:1000::/home/app\n");
        write(r.path(), "etc/shadow", "app::19000:0:99999:7:::\n");
        let v = run(r.path());
        let f = v
            .iter()
            .find(|x| x.vuln_id == "POSTURE-SHADOW-EMPTY-PASSWORD::app")
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn unreadable_or_absent_shadow_is_silent() {
        let r = root();
        // passwd present, shadow absent -> no panic, no findings.
        write(r.path(), "etc/passwd", &passwd_login("app", 1000));
        assert!(run(r.path()).is_empty());
    }

    #[test]
    fn two_empty_password_accounts_produce_two_distinct_findings() {
        let r = root();
        write(
            r.path(),
            "etc/passwd",
            &(passwd_login("a", 1000) + &passwd_login("b", 1001)),
        );
        write(r.path(), "etc/shadow", "a::1::::::\nb::1::::::\n");
        let v = run(r.path());
        let got = ids(&v);
        assert!(got.contains(&"POSTURE-SHADOW-EMPTY-PASSWORD::a"));
        assert!(got.contains(&"POSTURE-SHADOW-EMPTY-PASSWORD::b"));
    }

    // -------------------------------------------------------------- SUID

    #[cfg(unix)]
    fn chmod(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn flags_world_writable_and_dangerous_suid_but_not_standard() {
        let r = root();
        // dangerous SUID (bash) - high
        write(r.path(), "usr/bin/bash", "x");
        chmod(&r.path().join("usr/bin/bash"), 0o4755);
        // world-writable SUID (any name) - critical
        write(r.path(), "usr/bin/weird", "x");
        chmod(&r.path().join("usr/bin/weird"), 0o4777);
        // standard SUID (sudo) - NOT flagged
        write(r.path(), "usr/bin/sudo", "x");
        chmod(&r.path().join("usr/bin/sudo"), 0o4755);
        // SGID man - NOT flagged (excluded from dangerous list)
        write(r.path(), "usr/bin/man", "x");
        chmod(&r.path().join("usr/bin/man"), 0o2755);
        // a container layer's SUID bash must NOT be reached (not under a bin dir)
        write(
            r.path(),
            "var/lib/docker/overlay2/x/merged/usr/bin/bash",
            "x",
        );
        chmod(
            &r.path()
                .join("var/lib/docker/overlay2/x/merged/usr/bin/bash"),
            0o4755,
        );

        let v = run(r.path());
        let got = ids(&v);
        assert!(got.contains(&"POSTURE-SUID-DANGEROUS-BINARY::usr/bin/bash"));
        assert!(got.contains(&"POSTURE-SUID-WORLD-WRITABLE::usr/bin/weird"));
        assert!(
            !got.iter().any(|i| i.contains("sudo")),
            "standard SUID not flagged"
        );
        assert!(
            !got.iter().any(|i| i.contains("man")),
            "SGID man not flagged"
        );
        assert!(
            !got.iter().any(|i| i.contains("docker")),
            "container-layer SUID must not be attributed to the host"
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_merged_usr_symlinked_bindir() {
        use std::os::unix::fs::symlink;
        let r = root();
        // Physical layout: single usr/bin/find 4755
        write(r.path(), "usr/bin/find", "x");
        chmod(&r.path().join("usr/bin/find"), 0o4755);
        write(r.path(), "usr/sbin/find", "x");
        chmod(&r.path().join("usr/sbin/find"), 0o4755);
        // Merged-/usr: top-level bin/sbin are SYMLINKS to usr/bin, usr/sbin.
        symlink("usr/bin", r.path().join("bin")).unwrap();
        symlink("usr/sbin", r.path().join("sbin")).unwrap();

        let v = run(r.path());
        let got = ids(&v);
        eprintln!("PROBE_IDS={got:?}");
        let dupes: Vec<_> = got.iter().filter(|i| i.contains("find")).collect();
        eprintln!("PROBE_FIND_COUNT={}", dupes.len());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_bin_dir_is_not_double_walked() {
        // merged-/usr: `bin -> usr/bin`. A dangerous SUID must be reported ONCE
        // (via usr/bin), not duplicated through the `bin` symlink.
        let r = root();
        write(r.path(), "usr/bin/bash", "x");
        chmod(&r.path().join("usr/bin/bash"), 0o4755);
        std::os::unix::fs::symlink("usr/bin", r.path().join("bin")).unwrap();

        let v = run(r.path());
        let hits: Vec<&str> = ids(&v)
            .into_iter()
            .filter(|i| i.contains("DANGEROUS-BINARY"))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "exactly one finding, not duplicated via the bin symlink"
        );
        assert_eq!(hits[0], "POSTURE-SUID-DANGEROUS-BINARY::usr/bin/bash");
    }

    #[cfg(unix)]
    #[test]
    fn non_suid_binaries_are_not_flagged() {
        let r = root();
        write(r.path(), "usr/bin/bash", "x");
        chmod(&r.path().join("usr/bin/bash"), 0o0755); // SUID bit NOT set
        assert!(run(r.path()).is_empty());
    }
}
