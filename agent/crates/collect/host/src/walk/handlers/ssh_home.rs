//! SSH credential discovery under user home / profile directories.

use crate::ScanContext;
use agent_contract::Asset;
use std::io;

use crate::platform::windows::{first_existing_dir, users_dir};
use crate::root::join_root;
use crate::sources::credentials;

/// Scan `home/*/.ssh` on Linux mounts.
#[allow(dead_code)] // Compatibility wrapper for callers without diagnostics.
pub fn scan_linux_homes(ctx: &ScanContext, out: &mut Vec<Asset>) {
    let mut coverage = credentials::CredentialCoverage::default();
    scan_linux_homes_with_coverage(ctx, out, &mut coverage);
}

/// Scan Linux homes while preserving traversal and credential read failures.
pub(crate) fn scan_linux_homes_with_coverage(
    ctx: &ScanContext,
    out: &mut Vec<Asset>,
    coverage: &mut credentials::CredentialCoverage,
) {
    let home = join_root(ctx, "home");
    let entries = match std::fs::read_dir(&home) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(_) => {
            coverage.mark_incomplete();
            return;
        }
    };
    for item in entries {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                coverage.mark_incomplete();
                continue;
            }
        };
        let Some(user) = entry.file_name().to_str().map(str::to_string) else {
            coverage.mark_incomplete();
            continue;
        };
        let ssh = entry.path().join(".ssh");
        credentials::scan_ssh_dir_with_coverage(ctx, &ssh, Some(user.as_str()), out, coverage);
        credentials::scan_authorized_keys_with_coverage(
            ctx,
            &ssh.join("authorized_keys"),
            Some(user.as_str()),
            out,
            coverage,
        );
    }
}

/// Scan Windows `ProgramData/ssh` and `Users/*/.ssh`.
#[allow(dead_code)] // Compatibility wrapper for callers without diagnostics.
pub fn scan_windows_profiles(ctx: &ScanContext, out: &mut Vec<Asset>) {
    let mut coverage = credentials::CredentialCoverage::default();
    scan_windows_profiles_with_coverage(ctx, out, &mut coverage);
}

/// Scan Windows profiles while preserving traversal and credential read failures.
pub(crate) fn scan_windows_profiles_with_coverage(
    ctx: &ScanContext,
    out: &mut Vec<Asset>,
    coverage: &mut credentials::CredentialCoverage,
) {
    if let Some(admin_ssh) = first_existing_dir(&ctx.scan_root, &[&["ProgramData", "ssh"]]) {
        credentials::scan_ssh_dir_with_coverage(
            ctx,
            &admin_ssh,
            Some("Administrators"),
            out,
            coverage,
        );
        credentials::scan_authorized_keys_with_coverage(
            ctx,
            &admin_ssh.join("administrators_authorized_keys"),
            Some("Administrators"),
            out,
            coverage,
        );
    }
    let Some(users) = users_dir(ctx) else {
        return;
    };
    let entries = match std::fs::read_dir(&users) {
        Ok(entries) => entries,
        Err(_) => {
            coverage.mark_incomplete();
            return;
        }
    };
    for item in entries {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                coverage.mark_incomplete();
                continue;
            }
        };
        let Some(user) = entry.file_name().to_str().map(str::to_string) else {
            coverage.mark_incomplete();
            continue;
        };
        if is_skipped_windows_profile(&user) {
            continue;
        }
        let ssh = entry.path().join(".ssh");
        credentials::scan_ssh_dir_with_coverage(ctx, &ssh, Some(user.as_str()), out, coverage);
        credentials::scan_authorized_keys_with_coverage(
            ctx,
            &ssh.join("authorized_keys"),
            Some(user.as_str()),
            out,
            coverage,
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
    use agent_contract::{Asset, CredentialKind};
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
