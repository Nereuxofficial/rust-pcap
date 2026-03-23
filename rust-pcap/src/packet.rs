use tokio::io::AsyncWriteExt;

pub struct Packet {
    pub ts_sec: u32,
    pub ts_usec: u32,
    // For our purposes these should always be the same as we include every packet fully
    pub incl_len: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

impl Packet {
    pub async fn write<T: AsyncWriteExt + std::marker::Unpin>(
        &self,
        writer: &mut T,
    ) -> std::io::Result<()> {
        writer.write_all(&self.ts_sec.to_le_bytes()).await?;
        writer.write_all(&self.ts_usec.to_le_bytes()).await?;
        writer.write_all(&self.incl_len.to_le_bytes()).await?;
        writer.write_all(&self.orig_len.to_le_bytes()).await?;
        writer.write_all(&self.data).await?;
        Ok(())
    }
}
