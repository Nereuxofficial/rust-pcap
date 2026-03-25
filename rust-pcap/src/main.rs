use std::{env, process::exit};

use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <output.pcap>",
            args.get(0).unwrap_or(&"rust-pcap".to_string())
        );
        exit(1);
    }
    let filename = &args[1];

    let ebpf_bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/rust-pcap"));

    tokio::spawn(async move {
        let ctrl_c = signal::ctrl_c();
        println!("Waiting for Ctrl-C...");
        ctrl_c.await.unwrap();
        println!("Exiting...");
        exit(0);
    });

    println!("Starting capture, writing to {}", filename);
    rust_pcap::run_capture(filename, ebpf_bytes).await?;

    Ok(())
}
