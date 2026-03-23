use tokio::io::AsyncWriteExt;

use crate::packet::Packet;

pub struct PcapWriter {
    file: tokio::fs::File,
}

impl PcapWriter {
    pub async fn new(path: impl AsRef<std::path::Path>) -> Result<Self, std::io::Error> {
        let mut file = tokio::fs::File::create(path).await?;
        // Write header to file, fields will be little endian.
        file.write_u32_le(0xa1b2c3d4).await?;
        // Major and minor version
        file.write_u16_le(2).await?;
        file.write_u16_le(4).await?;
        // GMT offset in seconds(for now 0)
        file.write_u32_le(0).await?;
        // Timestamp precision
        file.write_u32_le(0).await?;
        // Snaplen
        file.write_u32_le(u32::MAX).await?;
        // Link type. 113 for Linux SLL
        file.write_u32_le(113).await?;
        Ok(Self { file })
    }
    pub async fn write(&mut self, packet: &Packet) -> Result<(), std::io::Error> {
        packet.write(&mut self.file).await?;
        self.file.flush().await?;
        Ok(())
    }
}
