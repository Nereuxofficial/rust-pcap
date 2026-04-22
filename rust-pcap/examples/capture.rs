use std::process::exit;

use rust_pcap::pcap_writer::PcapWriter;
use tokio::{fs::File, signal};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <output.pcap> [interface]", args[0]);
        exit(1);
    }

    let filename = &args[1];
    let device = match args.get(2) {
        Some(iface) => rust_pcap::device::Device::lookup(iface)
            .map_err(|e| anyhow::anyhow!("unknown interface '{iface}': {e}"))?,
        None => rust_pcap::device::Device::any(),
    };

    println!("Capturing on {device} to {filename}");

    let file = File::create(filename).await?;
    let mut writer = PcapWriter::new(file).await?;
    let mut capture = rust_pcap::capture::Capture::from_device(device)
        .start()
        .await?;

    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        println!("Exiting...");
        exit(0);
    });

    loop {
        let packet = capture.next_packet().await?;
        writer.write(&packet).await?;
    }
}
