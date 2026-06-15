//! Compiles the `trace-ebpf` kernel programs to bpf bytecode and embeds them,
//! but ONLY when the `ebpf` feature is enabled — so default `cargo build` / tests
//! stay lean (no aya-build, no nightly, no bpf-linker required).
//!
//! Build-time requirements when `ebpf` IS on: a `nightly` toolchain with
//! `rust-src`, and `bpf-linker` on PATH (`cargo install bpf-linker`). This
//! replicates the invocation aya-build performs, using only `std`.
//!
//! If that toolchain is missing (e.g. a CI runner doing `--all-features` without
//! the eBPF prerequisites), the build DOES NOT fail: it emits an empty stub and a
//! warning, and the `ebpf` backend returns a clear error at runtime instead. Real
//! eBPF builds (with the toolchain) embed the genuine object.

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EBPF");
    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return; // eBPF backend not requested.
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set"));
    let dst = out_dir.join("trace-ebpf");

    match build_ebpf(&out_dir) {
        Ok(artifact) => {
            fs::copy(&artifact, &dst)
                .unwrap_or_else(|e| panic!("copy bpf object {artifact:?} -> {dst:?}: {e}"));
        }
        Err(e) => {
            // Degrade gracefully: embed an empty object so the crate still compiles;
            // `aya::Ebpf::load` then fails at runtime with an actionable message.
            println!(
                "cargo:warning=trace-ebpf not built ({e}); the `ebpf` backend will error at \
                 runtime. Install a nightly toolchain + rust-src and `cargo install bpf-linker` \
                 to enable it."
            );
            fs::write(&dst, []).expect("write empty eBPF stub");
        }
    }
}

/// Build `trace-ebpf` for the bpf target and return the produced object path.
fn build_ebpf(out_dir: &std::path::Path) -> Result<PathBuf, String> {
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"));
    let ebpf_dir = manifest.join("../ebpf");
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("Cargo.toml").display()
    );

    // The bpf programs are arch-neutral, but aya passes the host arch through as a
    // cfg so aya-ebpf can select the right register bindings.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
    let target_arch = if target_arch.starts_with("riscv64") {
        "riscv64".to_string()
    } else {
        target_arch
    };

    // Separate target dir so the nested cargo doesn't deadlock on the outer lock.
    let build_dir = out_dir.join("ebpf-build");
    const SEP: &str = "\x1f";
    let rustflags =
        format!("--cfg=bpf_target_arch=\"{target_arch}\"{SEP}-Cdebuginfo=2{SEP}-Clink-arg=--btf");

    let mut cmd = Command::new("rustup");
    cmd.args([
        "run",
        "nightly",
        "cargo",
        "build",
        "--package",
        "agent-ebpf",
        "--bin",
        "trace-ebpf",
        "--features",
        "ebpf",
        "-Z",
        "build-std=core",
        "--release",
        "--target",
        "bpfel-unknown-none",
    ]);
    cmd.arg("--target-dir").arg(&build_dir);
    cmd.env("CARGO_ENCODED_RUSTFLAGS", rustflags);
    // The outer build wraps rustc; the nested bpf build must use the plain nightly.
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");

    let status = cmd
        .status()
        .map_err(|e| format!("spawn `rustup run nightly cargo build`: {e}"))?;
    if !status.success() {
        return Err(format!("bpf build exited {status}"));
    }

    let artifact = build_dir.join("bpfel-unknown-none/release/trace-ebpf");
    if !artifact.exists() {
        return Err(format!("bpf object not found at {artifact:?}"));
    }
    Ok(artifact)
}
