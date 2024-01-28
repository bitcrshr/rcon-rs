use std::{io::Read, net::TcpStream, time::Duration};

use r2d2::ManageConnection;

use crate::packet::{
    Packet, PacketType, PACKET_HEADER_SIZE, SERVERDATA_AUTH, SERVERDATA_AUTH_ID,
    SERVERDATA_AUTH_RESPONSE, SERVERDATA_EXECCOMMAND, SERVERDATA_RESPONSE_VALUE,
};

use crate::errors::{Error, Result};

/// How long to wait for bytes to be read from / written to
/// the stream.
const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);

/// Arbitrary value, but should be plenty, one would hope.
const MAX_COMMAND_LEN: i32 = 1000;

const SERVERDATA_EXECCOMMAND_ID: i32 = 0;

/// Recommended for general use. Supports pooling.
#[derive(Debug)]
pub struct ConnectionManager {
    addr: String,
    password: String,
}

impl ConnectionManager {
    pub fn new(addr: &str, password: &str) -> Result<Self> {
        Ok(Self {
            addr: String::from(addr),
            password: String::from(password),
        })
    }
}

impl ManageConnection for ConnectionManager {
    type Connection = RCONStream;

    type Error = Error;

    fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        RCONStream::dial(&self.addr.to_string(), &self.password)
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
        let res = conn.execute("ping")?;

        if res.to_lowercase() != "pong" {
            return Err(Error::BadPing(res));
        }

        Ok(())
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct RCONStream {
    stream: TcpStream,
}

impl RCONStream {
    /// Execute a single command and close. Builds and tears down
    /// a TCP stream every time it's called, so for hot code paths,
    /// using ConnectionManager is recommended.
    pub fn oneoff(addr: &str, password: &str, cmd: &str) -> Result<String> {
        let mut conn: Self = Self::dial(addr, password)?;

        conn.execute(cmd)
    }

    /// Creates the TCP stream and attempts to auth with it.
    fn dial(addr: &str, password: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(DEFAULT_DEADLINE))?;
        stream.set_write_timeout(Some(DEFAULT_DEADLINE))?;
        stream.set_nonblocking(false)?;

        let mut conn = Self { stream };

        conn.auth(password)?;

        Ok(conn)
    }

    /// Executes a command and returns its result.
    pub fn execute(&mut self, command: &str) -> Result<String> {
        if command.is_empty() {
            return Err(Error::CommandEmpty);
        }

        if command.len() > MAX_COMMAND_LEN as usize {
            return Err(Error::CommandTooLong);
        }

        let id = crate::util::random_pos_i32();
        let packet = Packet::new(SERVERDATA_EXECCOMMAND, id, command);

        self.write(packet)?;

        let packet = self.read()?;

        if packet.get_id() != SERVERDATA_EXECCOMMAND_ID {
            return Err(Error::InvalidPacketId);
        }

        Ok(packet.get_body())
    }

    /// Authenticates with the server over an active TCP connection.
    fn auth(&mut self, password: &str) -> Result<()> {
        let packet = Packet::new(SERVERDATA_AUTH, SERVERDATA_AUTH_ID, password);

        self.write(packet)?;

        let mut header = self.read_header()?;

        let size = header.0 - PACKET_HEADER_SIZE;
        if size < 0 {
            return Err(Error::InvalidPacketSize);
        }

        // When the server receives an auth request, it will respond with an empty
        // SERVERDATA_RESPONSE_VALUE, followed immediately by a SERVERDATA_AUTH_RESPONSE
        // indicating whether authentication succeeded or failed.
        // Some servers doesn't send an empty SERVERDATA_RESPONSE_VALUE packet, so we
        // do this case optional.
        if header.2 == SERVERDATA_RESPONSE_VALUE {
            // Discard empty SERVERDATA_RESPONSE_VALUE from authentication response.
            let mut tmp = vec![0; size as usize];
            let _ = self.stream.read(&mut tmp);
            header = self.read_header()?;
        }

        // must read the response body
        let mut buf = vec![0; size as usize];
        self.stream.read_exact(&mut buf)?;

        if header.2 != SERVERDATA_AUTH_RESPONSE {
            return Err(Error::InvalidAuthResponse);
        }

        if header.1 == -1 {
            return Err(Error::AuthFailed);
        }

        if header.1 != SERVERDATA_AUTH_ID {
            return Err(Error::InvalidAuthResponse);
        }

        Ok(())
    }

    /// Writes a packet to the TCP stream.
    fn write(&mut self, packet: Packet) -> Result<()> {
        packet.write_to(&mut self.stream)?;

        Ok(())
    }

    /// Reads a packet from the TCP stream.
    fn read(&mut self) -> Result<Packet> {
        Packet::read_from(&mut self.stream)
    }

    /// Reads (and consumes) a packet header from the TCP stream
    fn read_header(&mut self) -> Result<(i32, i32, PacketType)> {
        let mut size_buf = [0; 4];
        let mut id_buf = [0; 4];
        let mut type_buf = [0; 4];

        self.stream.read_exact(&mut size_buf)?;
        self.stream.read_exact(&mut id_buf)?;
        self.stream.read_exact(&mut type_buf)?;

        Ok((
            i32::from_le_bytes(size_buf),
            i32::from_le_bytes(id_buf),
            i32::from_le_bytes(type_buf),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_connects() {
        let addr_res = std::env::var("RCON_SERVER_ADDR");
        let password_res = std::env::var("RCON_SERVER_PASSWORD");

        if addr_res.is_err() {
            panic!("RCON_SERVER_ADDR not present in env; cannot test RCON connection");
        }

        if password_res.is_err() {
            panic!("RCON_SERVER_PASSWORD not present in env; cannot test RCON connection");
        }

        let addr = addr_res.unwrap();
        let password = password_res.unwrap();

        let conn = RCONStream::dial(&addr, &password);
        if conn.is_err() {
            panic!("failed to auth: {:#?}", conn.unwrap_err());
        }

        assert!(conn.is_ok());
    }

    #[test]
    fn it_pings() {
        let addr_res = std::env::var("RCON_SERVER_ADDR");
        let password_res = std::env::var("RCON_SERVER_PASSWORD");

        if addr_res.is_err() {
            panic!("RCON_SERVER_ADDR not present in env; cannot test RCON connection");
        }

        if password_res.is_err() {
            panic!("RCON_SERVER_PASSWORD not present in env; cannot test RCON connection");
        }

        let addr = addr_res.unwrap();
        let password = password_res.unwrap();

        let mut conn = RCONStream::dial(&addr, &password).expect("must connect");

        match conn.execute("ping") {
            Err(e) => {
                panic!("failed to ping: {:#?}", e);
            }
            Ok(res) => {
                assert_eq!(res.to_lowercase(), "pong\n");
            }
        }
    }

    #[test]
    fn it_pools() {
        let addr_res = std::env::var("RCON_SERVER_ADDR");
        let password_res = std::env::var("RCON_SERVER_PASSWORD");

        if addr_res.is_err() {
            panic!("RCON_SERVER_ADDR not present in env; cannot test RCON connection");
        }

        if password_res.is_err() {
            panic!("RCON_SERVER_PASSWORD not present in env; cannot test RCON connection");
        }

        let addr = addr_res.unwrap();
        let password = password_res.unwrap();

        let mgr = ConnectionManager::new(&addr, &password).expect("failed to create manager!");

        let mut pool = vec![];

        for _ in 0..10 {
            pool.push(mgr.connect().expect("failed to connect!"));
        }

        for mut c in pool {
            c.execute("ping").expect("failed to ping!");
        }
    }
}
