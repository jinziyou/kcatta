//! SSH credential collector (Linux fixed paths or Windows user profiles).

use crate::{Collector, CollectorOutput, ScanContext};
use agent_contract::Asset;

use crate::platform::{self, OsFamily};
use crate::sources::credentials;
use crate::walk::handlers::ssh_home;

/// Collects SSH public key and `authorized_keys` fingerprints (no private key material).
pub struct CredentialsCollector;

impl Collector for CredentialsCollector {
    fn id(&self) -> &'static str {
        "credentials"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "credentials")?;
        Ok(CollectorOutput::Assets(collect(ctx)))
    }
}

/// SSH credentials as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    if platform::detect(&ctx.scan_root) == OsFamily::Windows {
        let mut out = Vec::new();
        ssh_home::scan_windows_profiles(ctx, &mut out);
        out.sort_by(|a, b| credential_fingerprint(a).cmp(credential_fingerprint(b)));
        return out;
    }
    credentials::collect(ctx)
}

fn credential_fingerprint(asset: &Asset) -> &str {
    match asset {
        agent_contract::Asset::Credential(c) => &c.fingerprint,
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;
    use agent_contract::{Asset, CredentialKind};
    use std::fs;

    const TEST_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsURFqkM+K0OqYj2o/MHmDP test@host";

    #[test]
    fn collects_authorized_keys_without_secret_material() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let ssh = root.join("home/alice/.ssh");
        fs::create_dir_all(&ssh).unwrap();
        fs::write(ssh.join("authorized_keys"), format!("{TEST_PUB}\n")).unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Credential(c) => {
                assert_eq!(c.credential_kind, CredentialKind::SshKey);
                assert_eq!(c.owner.as_deref(), Some("alice"));
                assert!(c.path.as_ref().unwrap().contains("authorized_keys"));
            }
            other => panic!("expected credential, got {other:?}"),
        }
    }
}
