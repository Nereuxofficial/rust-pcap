use tokio::io::AsyncWriteExt;

use crate::packet::Packet;

pub struct PcapWriter<W> {
    writer: W,
}

impl<W: AsyncWriteExt + Unpin> PcapWriter<W> {
    pub async fn new(mut writer: W) -> Result<Self, std::io::Error> {
        // Write global header, all fields little-endian.
        writer.write_u32_le(0xa1b2c3d4).await?; // magic
        writer.write_u16_le(2).await?; // major version
        writer.write_u16_le(4).await?; // minor version
        writer.write_u32_le(0).await?; // GMT offset
        writer.write_u32_le(0).await?; // timestamp precision
        writer.write_u32_le(u32::MAX).await?; // snaplen
        writer.write_u32_le(113).await?; // link type: Linux SLL
        writer.flush().await?;
        Ok(Self { writer })
    }

    pub async fn write(&mut self, packet: &Packet) -> Result<(), std::io::Error> {
        packet.write(&mut self.writer).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    async fn capture_bytes(packets: &[Packet]) -> Vec<u8> {
        let (write_end, mut read_end) = tokio::io::duplex(65536);
        let mut writer = PcapWriter::new(write_end).await.unwrap();
        for p in packets {
            writer.write(p).await.unwrap();
        }
        drop(writer); // closes write_end, signals EOF to read_end
        let mut bytes = Vec::new();
        read_end.read_to_end(&mut bytes).await.unwrap();
        bytes
    }

    #[tokio::test]
    async fn pcap_global_header_magic_and_version() {
        let bytes = capture_bytes(&[]).await;

        assert_eq!(bytes.len(), 24, "global header must be 24 bytes");
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 0xa1b2c3d4);
        assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), 2); // major
        assert_eq!(u16::from_le_bytes(bytes[6..8].try_into().unwrap()), 4); // minor
    }

    #[tokio::test]
    async fn pcap_global_header_link_type_linux_sll() {
        let bytes = capture_bytes(&[]).await;

        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 113);
    }

    #[tokio::test]
    async fn pcap_packet_record_begins_at_byte_24() {
        let packets =
            [Packet { ts_sec: 1, ts_usec: 0, incl_len: 2, orig_len: 2, data: vec![0x45, 0x00] }];
        let bytes = capture_bytes(&packets).await;

        assert_eq!(bytes.len(), 24 + 16 + 2);
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 1); // ts_sec
        assert_eq!(u32::from_le_bytes(bytes[28..32].try_into().unwrap()), 0); // ts_usec
        assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 2); // incl_len
        assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), 2); // orig_len
        assert_eq!(&bytes[40..42], &[0x45, 0x00]);
    }

    #[tokio::test]
    async fn pcap_multiple_packets_written_sequentially() {
        let packets = [
            Packet { ts_sec: 1, ts_usec: 0, incl_len: 1, orig_len: 1, data: vec![0x01] },
            Packet { ts_sec: 2, ts_usec: 0, incl_len: 1, orig_len: 1, data: vec![0x02] },
        ];
        let bytes = capture_bytes(&packets).await;

        // 24 byte global header + 2 × (16 byte record header + 1 byte data)
        assert_eq!(bytes.len(), 24 + 17 + 17);

        let p1_ts = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let p2_ts = u32::from_le_bytes(bytes[41..45].try_into().unwrap());
        assert_eq!(p1_ts, 1);
        assert_eq!(p2_ts, 2);
        assert_eq!(bytes[40], 0x01);
        assert_eq!(bytes[57], 0x02);
    }
}
