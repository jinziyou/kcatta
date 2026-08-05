//! Linux local accounts from `etc/passwd`.

use std::fs;

use crate::ScanContext;
use agent_contract::{Account, Asset};

use crate::root::join_root;

/// Local accounts as contract [`Asset`]s.
#[allow(dead_code)] // Compatibility wrapper for existing collector callers.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    collect_with_coverage(ctx).0
}

/// Same-pass diagnostics for the local account source.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AccountCoverage {
    source_incomplete: bool,
}

impl AccountCoverage {
    pub(crate) fn source_incomplete(self) -> bool {
        self.source_incomplete
    }

    pub(crate) fn incomplete() -> Self {
        Self {
            source_incomplete: true,
        }
    }
}

/// Local accounts plus read and parse diagnostics from the same pass.
pub(crate) fn collect_with_coverage(ctx: &ScanContext) -> (Vec<Asset>, AccountCoverage) {
    let mut coverage = AccountCoverage::default();
    let path = join_root(ctx, "etc/passwd");
    let Ok(text) = fs::read_to_string(&path) else {
        coverage.source_incomplete = true;
        return (Vec::new(), coverage);
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 || fields[0].is_empty() {
            coverage.source_incomplete = true;
            continue;
        }
        if fields[2].parse::<i64>().is_err() {
            coverage.source_incomplete = true;
        }
        let Some(account) = parse_passwd_line(line) else {
            coverage.source_incomplete = true;
            continue;
        };
        out.push(Asset::Account(account));
    }
    (out, coverage)
}

fn parse_passwd_line(line: &str) -> Option<Account> {
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() < 7 {
        return None;
    }
    let username = fields[0].to_string();
    if username.is_empty() {
        return None;
    }
    let uid = fields[2].parse().ok();
    let shell = {
        let sh = fields[6].trim();
        if sh.is_empty() {
            None
        } else {
            Some(sh.to_string())
        }
    };
    Some(Account {
        asset_id: format!("acct-{username}"),
        parent_asset_id: None,
        username,
        uid,
        shell,
        last_login: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;

    #[test]
    fn parses_passwd_entries() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\n\
             nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
             app:x:1000:1000::/home/app:/bin/sh\n",
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 3);
        match &assets[2] {
            Asset::Account(a) => {
                assert_eq!(a.username, "app");
                assert_eq!(a.uid, Some(1000));
                assert_eq!(a.shell.as_deref(), Some("/bin/sh"));
            }
            other => panic!("expected account, got {other:?}"),
        }
    }

    #[test]
    fn coverage_marks_passwd_read_and_parse_failures() {
        let unreadable = tempfile::tempdir().unwrap();
        fs::create_dir_all(unreadable.path().join("etc/passwd")).unwrap();
        let (assets, coverage) = collect_with_coverage(&ScanContext::at(unreadable.path()));
        assert!(assets.is_empty());
        assert!(coverage.source_incomplete());

        let malformed = tempfile::tempdir().unwrap();
        fs::create_dir_all(malformed.path().join("etc")).unwrap();
        fs::write(malformed.path().join("etc/passwd"), "broken-entry\n").unwrap();
        let (assets, coverage) = collect_with_coverage(&ScanContext::at(malformed.path()));
        assert!(assets.is_empty());
        assert!(coverage.source_incomplete());
    }
}
