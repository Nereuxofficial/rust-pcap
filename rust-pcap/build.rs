use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "rust-pcap-ebpf")
        .ok_or_else(|| anyhow!("rust-pcap-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let root_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?;

    // In a workspace the eBPF package is a member; in Cargo's extracted
    // publish-verification package it is a registry build-dependency. Build
    // from its own root so `cargo build --package rust-pcap-ebpf` works in
    // both layouts.
    std::env::set_current_dir(root_dir).context("set current directory to rust-pcap-ebpf")?;

    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: root_dir.as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf(
        [aya_build::Package {
            features: &["ebpf"],
            ..ebpf_package
        }],
        Toolchain::default(),
    )
}
