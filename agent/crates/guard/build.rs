//! Compiles the `guard-ebpf` cgroup-connect blocker to bpf bytecode and embeds
//! it, but ONLY when the `ebpf` feature is enabled — so default builds/tests stay
//! lean. Mirrors `agent-trace`'s build.rs; see there for the full rationale.
//!
//! Requires (when `ebpf` is on) a `nightly` toolchain + `rust-src` and
//! `bpf-linker` on PATH. If absent, it emits an empty stub + warning so CI
//! `--all-features` stays green; the eBPF backend then errors at runtime.

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EBPF");
    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set"));
    let dst = out_dir.join("guard-ebpf");

    match build_ebpf(&out_dir) {
        Ok(artifact) => {
            fs::copy(&artifact, &dst)
                .unwrap_or_else(|e| panic!("copy bpf object {artifact:?} -> {dst:?}: {e}"));
        }
        Err(e) => {
            println!(
                "cargo:warning=guard-ebpf not built ({e}); the `ebpf` netblock backend will error \
                 at runtime. Install a nightly toolchain + rust-src and `cargo install bpf-linker` \
                 to enable it."
            );
            fs::write(&dst, []).expect("write empty eBPF stub");
        }
    }
}

fn build_ebpf(out_dir: &std::path::Path) -> Result<PathBuf, String> {
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"));
    let ebpf_dir = manifest.join("../guard-ebpf");
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("Cargo.toml").display()
    );

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
    let target_arch = if target_arch.starts_with("riscv64") {
        "riscv64".to_string()
    } else {
        target_arch
    };

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
        "guard-ebpf",
        "-Z",
        "build-std=core",
        "--bins",
        "--release",
        "--target",
        "bpfel-unknown-none",
    ]);
    cmd.arg("--target-dir").arg(&build_dir);
    cmd.env("CARGO_ENCODED_RUSTFLAGS", rustflags);
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");

    let status = cmd
        .status()
        .map_err(|e| format!("spawn `rustup run nightly cargo build`: {e}"))?;
    if !status.success() {
        return Err(format!("bpf build exited {status}"));
    }

    let artifact = build_dir.join("bpfel-unknown-none/release/guard-ebpf");
    if !artifact.exists() {
        return Err(format!("bpf object not found at {artifact:?}"));
    }
    Ok(artifact)
}
