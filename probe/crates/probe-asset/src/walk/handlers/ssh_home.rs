//! SSH credential discovery under user home / profile directories.

use probe_contract::Asset;
use probe_runtime::ScanContext;

use crate::platform::windows::{first_existing_dir, users_dir};
use crate::root::join_root;
use crate::sources::credentials;

/// Scan `home/*/.ssh` on Linux mounts.
pub fn scan_linux_homes(ctx: &ScanContext, out: &mut Vec<Asset>) {
    let home = join_root(ctx, "home");
    let Ok(entries) = std::fs::read_dir(&home) else {
        return;
    };
    for entry in entries.flatten() {
        let user = entry.file_name().to_string_lossy().into_owned();
        let ssh = entry.path().join(".ssh");
        credentials::scan_ssh_dir(ctx, &ssh, Some(user.as_str()), out);
        credentials::scan_authorized_keys(
            ctx,
            &ssh.join("authorized_keys"),
            Some(user.as_str()),
            out,
        );
    }
}

/// Scan Windows `ProgramData/ssh` and `Users/*/.ssh`.
pub fn scan_windows_profiles(ctx: &ScanContext, out: &mut Vec<Asset>) {
    if let Some(admin_ssh) = first_existing_dir(&ctx.scan_root, &[&["ProgramData", "ssh"]]) {
        credentials::scan_ssh_dir(ctx, &admin_ssh, Some("Administrators"), out);
        credentials::scan_authorized_keys(
            ctx,
            &admin_ssh.join("administrators_authorized_keys"),
            Some("Administrators"),
            out,
        );
    }
    let Some(users) = users_dir(ctx) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(&users) else {
        return;
    };
    for entry in entries.flatten() {
        let user = entry.file_name().to_string_lossy().into_owned();
        if is_skipped_windows_profile(&user) {
            continue;
        }
        let ssh = entry.path().join(".ssh");
        credentials::scan_ssh_dir(ctx, &ssh, Some(user.as_str()), out);
        credentials::scan_authorized_keys(
            ctx,
            &ssh.join("authorized_keys"),
            Some(user.as_str()),
            out,
        );
    }
}

fn is_skipped_windows_profile(name: &str) -> bool {
    name.eq_ignore_ascii_case("Public")
        || name.eq_ignore_ascii_case("Default")
        || name.eq_ignore_ascii_case("Default User")
        || name.eq_ignore_ascii_case("All Users")
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe_contract::{Asset, CredentialKind};
    use std::fs;

    const TEST_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsURFqkM+K0OqYj2o/MHmDP test@host";

    #[test]
    fn scan_linux_homes_finds_authorized_keys() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let ssh = root.join("home/alice/.ssh");
        fs::create_dir_all(&ssh).unwrap();
        fs::write(ssh.join("authorized_keys"), format!("{TEST_PUB}\n")).unwrap();

        let ctx = ScanContext::at(root);
        let mut out = Vec::new();
        scan_linux_homes(&ctx, &mut out);
        assert_eq!(out.len(), 1);
        match &out[0] {
            Asset::Credential(c) => {
                assert_eq!(c.owner.as_deref(), Some("alice"));
            }
            other => panic!("expected credential, got {other:?}"),
        }
    }

    #[test]
    fn scan_windows_profiles_skips_system_accounts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("Users/alice/.ssh")).unwrap();
        fs::write(
            root.join("Users/alice/.ssh/authorized_keys"),
            format!("{TEST_PUB}\n"),
        )
        .unwrap();
        fs::create_dir_all(root.join("Users/Public/.ssh")).unwrap();
        fs::write(
            root.join("Users/Public/.ssh/authorized_keys"),
            format!("{TEST_PUB}\n"),
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let mut out = Vec::new();
        scan_windows_profiles(&ctx, &mut out);
        assert_eq!(out.len(), 1);
        match &out[0] {
            Asset::Credential(c) => {
                assert_eq!(c.credential_kind, CredentialKind::SshKey);
                assert_eq!(c.owner.as_deref(), Some("alice"));
            }
            other => panic!("expected credential, got {other:?}"),
        }
    }
}
