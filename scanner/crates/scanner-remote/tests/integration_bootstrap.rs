//! Integration test against a real SSH target. **Ignored by default.**
//!
//! Run:
//! ```sh
//! SCDR_TEST_TARGET=user@host \
//! SCDR_SSH_PASSWORD=... \
//! cargo test --package scanner-remote --test integration_bootstrap -- \
//!     --ignored --nocapture
//! ```
//!
//! Side effect: appends a managed ed25519 public key to the remote
//! `~/.ssh/authorized_keys` if not already present. Idempotent.

use scanner_remote::bootstrap::ensure_key_auth;

#[test]
#[ignore]
fn bootstrap_against_real_target() {
    let target = std::env::var("SCDR_TEST_TARGET")
        .expect("set SCDR_TEST_TARGET=user@host");
    let port: u16 = std::env::var("SCDR_TEST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);
    let password = std::env::var("SCDR_SSH_PASSWORD").ok();

    let key =
        ensure_key_auth(&target, port, None, password.as_deref()).expect("ensure_key_auth");
    eprintln!("OK: key auth verified against {target}:{port}");
    eprintln!("    private key: {}", key.display());
    eprintln!("    public  key: {}", key.with_extension("pub").display());
}
