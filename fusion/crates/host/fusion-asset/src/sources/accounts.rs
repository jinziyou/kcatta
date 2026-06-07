//! Linux local accounts from `etc/passwd`.

use std::fs;

use fusion_contract::{Account, Asset};
use fusion_runtime::ScanContext;

use crate::root::join_root;

/// Local accounts as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let path = join_root(ctx, "etc/passwd");
    let Ok(text) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(account) = parse_passwd_line(line) else {
            continue;
        };
        out.push(Asset::Account(account));
    }
    out
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
        username,
        uid,
        shell,
        last_login: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fusion_runtime::ScanContext;

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
}
