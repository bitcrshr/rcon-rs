use std::{
    io::Read,
    io::Write,
    net::{AddrParseError, SocketAddr, TcpStream},
    time::Duration,
};

use crate::packet::{
    Packet, PacketType, PACKET_HEADER_SIZE, SERVERDATA_AUTH, SERVERDATA_AUTH_ID,
    SERVERDATA_AUTH_RESPONSE, SERVERDATA_EXECCOMMAND, SERVERDATA_RESPONSE_VALUE,
};

const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);
const MAX_COMMAND_LEN: i32 = 1000;

const SERVERDATA_EXECCOMMAND_ID: i32 = 0;

pub type Result<T> = std::result::Result<T, Error>;

pub enum Error {
    BadAddress(String),
    IoError(String),
    BadResponse(String),
    AuthFailed,
    CommandEmpty,
    CommandTooLong(usize),
}

impl From<AddrParseError> for Error {
    fn from(value: AddrParseError) -> Self {
        Self::BadAddress(value.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value.to_string())
    }
}

impl From<super::packet::Error> for Error {
    fn from(value: super::packet::Error) -> Self {
        Self::BadResponse(value.to_string())
    }
}

pub struct Conn {
    conn: TcpStream,
}

impl Conn {
    pub fn dial(address: &str, password: &str) -> Result<Self> {
        let addr: SocketAddr = address.parse()?;

        let stream = TcpStream::connect_timeout(&addr, DEFAULT_DIAL_TIMEOUT)?;
        stream.set_read_timeout(Some(DEFAULT_DEADLINE))?;
        stream.set_write_timeout(Some(DEFAULT_DEADLINE))?;

        let mut conn = Self { conn: stream };

        conn.auth(password)?;

        Ok(conn)
    }

    pub fn execute(&mut self, command: &str) -> Result<String> {
        if command.is_empty() {
            return Err(Error::CommandEmpty);
        }

        if command.len() > MAX_COMMAND_LEN as usize {
            return Err(Error::CommandTooLong(command.len()));
        }

        self.write(SERVERDATA_EXECCOMMAND, SERVERDATA_EXECCOMMAND_ID, command)?;

        let packet = self.read()?;

        if packet.get_id() != SERVERDATA_EXECCOMMAND_ID {
            return Err(Error::BadResponse(String::from("invalid exec command id")));
        }

        Ok(packet.get_body())
    }

    fn auth(&mut self, password: &str) -> Result<()> {
        self.write(SERVERDATA_AUTH, SERVERDATA_AUTH_ID, password)?;

        let mut header = self.read_header()?;

        let size = header.0 - PACKET_HEADER_SIZE;
        if size < 0 {
            return Err(Error::BadResponse(String::from(
                "packet header had invalid size",
            )));
        }

        // When the server receives an auth request, it will respond with an empty
        // SERVERDATA_RESPONSE_VALUE, followed immediately by a SERVERDATA_AUTH_RESPONSE
        // indicating whether authentication succeeded or failed.
        // Some servers doesn't send an empty SERVERDATA_RESPONSE_VALUE packet, so we
        // do this case optional.
        if header.2 == SERVERDATA_RESPONSE_VALUE {
            // Discard empty SERVERDATA_RESPONSE_VALUE from authentication response.
            let mut tmp = Vec::with_capacity(size as usize);
            let _ = self.conn.read(&mut tmp);
            header = self.read_header()?;
        }

        // must read the response body
        let mut buf = Vec::with_capacity(size as usize);
        self.conn.read_exact(&mut buf)?;

        if header.2 != SERVERDATA_AUTH_RESPONSE {
            return Err(Error::BadResponse(String::from("invalid auth response")));
        }

        if header.1 == -1 {
            return Err(Error::AuthFailed);
        }

        if header.1 != SERVERDATA_AUTH_ID {
            return Err(Error::BadResponse(String::from("invalid auth packet id")));
        }

        Ok(())
    }

    fn write(&mut self, packet_type: PacketType, packet_id: i32, command: &str) -> Result<()> {
        let buf = Packet::new(packet_type, packet_id, command).to_bytes();

        self.conn.write_all(&buf)?;

        Ok(())
    }

    fn read(&mut self) -> Result<Packet> {
        let mut buf: Vec<u8> = vec![];

        self.conn.read_to_end(&mut buf)?;

        let packet = Packet::from_bytes(buf)?;

        Ok(packet)
    }

    fn read_header(&mut self) -> Result<(i32, i32, PacketType)> {
        let mut size_buf = [0; 4];
        let mut id_buf = [0; 4];
        let mut type_buf = [0; 4];

        self.conn.read_exact(&mut size_buf)?;
        self.conn.read_exact(&mut id_buf)?;
        self.conn.read_exact(&mut type_buf)?;

        Ok((
            i32::from_le_bytes(size_buf),
            i32::from_le_bytes(id_buf),
            i32::from_le_bytes(type_buf),
        ))
    }
}
