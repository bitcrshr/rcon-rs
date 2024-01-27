use crate::errors::{Error, Result};

pub type PacketType = i32;

/// Typically the first packet sent by the client. Used to Authenticate
/// the connection with the RCON server.
pub const SERVERDATA_AUTH: PacketType = 3;

/// A notification of the connections auth status. This immediately
/// follows an empty `SERVERDATA_RESPONSE_VALUE`.
pub const SERVERDATA_AUTH_RESPONSE: PacketType = 2;

/// Represents a command issued to the server from the client.
pub const SERVERDATA_EXECCOMMAND: PacketType = 2;

/// A response to a `SERVERDATA_EXECCOMMAND` request.
pub const SERVERDATA_RESPONSE_VALUE: PacketType = 0;

/// The id we use for auth requests.
pub const SERVERDATA_AUTH_ID: i32 = 0;

pub const PACKET_PADDING_SIZE: i32 = 2;
pub const PACKET_HEADER_SIZE: i32 = 8;

pub const MIN_PACKET_SIZE: i32 = PACKET_PADDING_SIZE + PACKET_HEADER_SIZE;
pub const MAX_PACKET_SIZE: i32 = 4096 + MIN_PACKET_SIZE;

#[derive(Debug, PartialEq, Eq)]
pub struct Packet {
    size: i32,
    id: i32,
    type_: PacketType,
    body: String,
}

impl Packet {
    pub fn new(packet_type: PacketType, packet_id: i32, body: &str) -> Self {
        let size = body.len() as i32 + PACKET_HEADER_SIZE + PACKET_PADDING_SIZE;

        Self {
            size,
            type_: packet_type,
            id: packet_id,
            body: String::from(body),
        }
    }

    pub fn read_from(r: &mut dyn std::io::Read) -> Result<Self> {
        let mut size_buf = [0; 4];

        r.read_exact(&mut size_buf)?;

        let size = i32::from_le_bytes(size_buf);

        if size < MIN_PACKET_SIZE {
            return Err(Error::ResponseTooSmall);
        }

        let mut id_buf = [0; 4];
        let mut type_buf = [0; 4];

        r.read_exact(&mut id_buf)?;
        r.read_exact(&mut type_buf)?;

        let id = i32::from_le_bytes(id_buf);
        let type_ = i32::from_le_bytes(type_buf);

        println!(
            "header has been read. size: {}, id: {}, type: {}",
            size, id, type_
        );

        let mut body_buf = vec![0; (size - PACKET_HEADER_SIZE) as usize];
        let mut total_read = 0;

        while total_read < body_buf.len() {
            match r.read(&mut body_buf[total_read..]) {
                Ok(0) => break,
                Ok(n) => {
                    total_read += n;
                    println!("read {} bytes into body", n);
                }
                Err(e) => return Err(e.into()),
            }
        }

        println!("body_buf: {:#?}", body_buf);

        body_buf.truncate(total_read);

        println!("truncated body_buf: {:#?}", body_buf);

        Ok(Self {
            size,
            type_,
            id,
            body: String::from_utf8(body_buf[0..body_buf.len() - 2].to_vec())?,
        })
    }

    pub fn get_size(&self) -> i32 {
        self.size
    }

    pub fn get_id(&self) -> i32 {
        self.id
    }

    pub fn get_type(&self) -> PacketType {
        self.type_
    }

    pub fn get_body(&self) -> String {
        self.body.clone()
    }

    pub fn write_to(&self, w: &mut dyn std::io::Write) -> Result<()> {
        let mut buf = Vec::with_capacity(self.size as usize + 4);

        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.id.to_le_bytes());
        buf.extend_from_slice(&<PacketType as Into<i32>>::into(self.type_).to_le_bytes());
        buf.extend_from_slice(self.body.as_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);

        w.write_all(&buf)?;

        w.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valid_auth_serde() {
        let packet = Packet::new(SERVERDATA_AUTH, 1, "mypassword");

        let mut actual_bytes: Vec<u8> = vec![
            0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x6d, 0x79,
            0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, 0x00,
        ];

        let mut buf: Vec<u8> = vec![];

        packet.write_to(&mut buf).unwrap();

        assert_eq!(buf, actual_bytes);

        let actual_packet = Packet::read_from(&mut buf.as_slice()).unwrap();

        assert_eq!(packet, actual_packet);
    }
}
