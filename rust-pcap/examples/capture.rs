use std::process::exit;

use tokio::signal;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <output.pcap> [interface]",
            args.first().unwrap_or(&"rust-pcap".to_string())
        );
        exit(1);
    }
    let filename = &args[1];
    let device = match args.get(2) {
        Some(iface) => rust_pcap::device::Device::lookup(iface)
            .map_err(|e| anyhow::anyhow!("unknown interface '{}': {e}", iface))?,
        None => rust_pcap::device::Device::any(),
    };

    println!("Capturing on {} → {}", device, filename);

    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        println!("Exiting...");
        exit(0);
    });

    rust_pcap::capture::Capture::from_device(device)
        .start(filename)
        .await?;

    Ok(())
}
