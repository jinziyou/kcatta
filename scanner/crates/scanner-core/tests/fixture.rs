//! Minimal filesystem tree for contract tests (avoids scanning live `/`).

use std::fs;
use std::path::Path;

pub fn write_minimal_scan_root(root: &Path) {
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(root.join("etc/hostname"), "contract-test-host\n").unwrap();
    fs::write(
        root.join("etc/os-release"),
        "ID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04\"\n",
    )
    .unwrap();

    fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
    fs::write(
        root.join("var/lib/dpkg/status"),
        "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.2-0ubuntu1.18\n\n",
    )
    .unwrap();
}
