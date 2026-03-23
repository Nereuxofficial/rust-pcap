use tokio::io::AsyncWriteExt;

use crate::packet::Packet;

pub struct PcapWriter {
    file: tokio::fs::File,
}

impl PcapWriter {
    pub async fn new(path: impl AsRef<std::path::Path>) -> Result<Self, std::io::Error> {
        let mut file = tokio::fs::File::create(path).await?;
        // Write header to file, fields will be big endian.
        file.write_u32(0xa1b2c3d4).await?;
        // Major and minor version
        file.write_u16(2).await?;
        file.write_u16(4).await?;
        // GMT offset in seconds(for now 0)
        file.write_u32(0).await?;
        // Timestamp precision
        file.write_u32(0).await?;
        // Snaplen
        file.write_u32(u32::MAX).await?;
        // Link type. 1 for ethernet
        file.write_u32(1).await?;
        Ok(Self { file })
    }
    pub async fn write(&mut self, packet: &Packet) -> Result<(), std::io::Error> {
        packet.write(&mut self.file).await?;
        self.file.flush().await?;
        Ok(())
    }
}
