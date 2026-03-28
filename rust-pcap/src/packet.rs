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

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    async fn write_packet_to_bytes(packet: &Packet) -> Vec<u8> {
        let (mut write_end, mut read_end) = tokio::io::duplex(65536);
        packet.write(&mut write_end).await.unwrap();
        drop(write_end);
        let mut bytes = Vec::new();
        read_end.read_to_end(&mut bytes).await.unwrap();
        bytes
    }

    #[tokio::test]
    async fn packet_write_field_layout() {
        let packet = Packet {
            ts_sec: 1,
            ts_usec: 500_000,
            incl_len: 3,
            orig_len: 3,
            data: vec![0xAA, 0xBB, 0xCC],
        };
        let bytes = write_packet_to_bytes(&packet).await;

        assert_eq!(bytes.len(), 16 + 3);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 500_000);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 3);
        assert_eq!(&bytes[16..], &[0xAA, 0xBB, 0xCC]);
    }

    #[tokio::test]
    async fn packet_write_all_fields_little_endian() {
        let packet = Packet {
            ts_sec: 0x01020304,
            ts_usec: 0x05060708,
            incl_len: 0x09000000,
            orig_len: 0x0A000000,
            data: vec![],
        };
        let bytes = write_packet_to_bytes(&packet).await;

        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[0..4], &[0x04, 0x03, 0x02, 0x01]); // little-endian ts_sec
        assert_eq!(&bytes[4..8], &[0x08, 0x07, 0x06, 0x05]); // little-endian ts_usec
    }

    #[tokio::test]
    async fn packet_write_empty_data() {
        let packet = Packet { ts_sec: 0, ts_usec: 0, incl_len: 0, orig_len: 0, data: vec![] };
        let bytes = write_packet_to_bytes(&packet).await;
        assert_eq!(bytes.len(), 16);
    }
}
