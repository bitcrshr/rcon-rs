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

    pub fn from_bytes(buf: Vec<u8>) -> Result<Self> {
        let size = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if size < MIN_PACKET_SIZE {
            return Err(Error::ResponseTooSmall);
        }

        let id = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

        let type_ = i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        match type_ {
            0 | 3 | 2 => (),
            _ => return Err(Error::InvalidPacketType),
        }

        let body = String::from_utf8(Vec::from(&buf[12..buf.len() - 2]))?;

        if buf[buf.len() - 2] != 0x00 || buf[buf.len() - 1] != 0x00 {
            return Err(Error::InvalidPacketPadding);
        }

        Ok(Self {
            size,
            id,
            type_,
            body,
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size as usize + 4);

        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.id.to_le_bytes());
        buf.extend_from_slice(&<PacketType as Into<i32>>::into(self.type_).to_le_bytes());
        buf.extend_from_slice(self.body.as_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);

        buf
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valid_auth_serde() {
        let packet = Packet::new(SERVERDATA_AUTH, 1, "mypassword");

        let actual_bytes: Vec<u8> = vec![
            0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x6d, 0x79,
            0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, 0x00,
        ];

        assert_eq!(packet.to_bytes(), actual_bytes);

        let actual_packet = Packet::from_bytes(actual_bytes).unwrap();

        assert_eq!(packet, actual_packet);
    }
}
