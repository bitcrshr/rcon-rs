use std::{io::Read, net::TcpStream, time::Duration};

use r2d2::ManageConnection;

use crate::packet::{
    Packet, PacketType, PACKET_HEADER_SIZE, SERVERDATA_AUTH, SERVERDATA_AUTH_ID,
    SERVERDATA_AUTH_RESPONSE, SERVERDATA_EXECCOMMAND, SERVERDATA_RESPONSE_VALUE,
};

use crate::errors::{Error, Result};

const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);
const MAX_COMMAND_LEN: i32 = 1000;

const SERVERDATA_EXECCOMMAND_ID: i32 = 0;

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
    fn dial(addr: &str, password: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(DEFAULT_DEADLINE))?;
        stream.set_write_timeout(Some(DEFAULT_DEADLINE))?;
        stream.set_nonblocking(false)?;

        let mut conn = Self { stream };

        conn.auth(password)?;

        Ok(conn)
    }

    pub fn execute(&mut self, command: &str) -> Result<String> {
        if command.is_empty() {
            return Err(Error::CommandEmpty);
        }

        if command.len() > MAX_COMMAND_LEN as usize {
            return Err(Error::CommandTooLong);
        }

        self.write(SERVERDATA_EXECCOMMAND, SERVERDATA_EXECCOMMAND_ID, command)?;

        println!("parsing reponse...");
        let packet = self.read()?;
        println!("response parsed. packet: {:#?}", packet);

        if packet.get_id() != SERVERDATA_EXECCOMMAND_ID {
            return Err(Error::InvalidPacketId);
        }

        Ok(packet.get_body())
    }

    fn auth(&mut self, password: &str) -> Result<()> {
        self.write(SERVERDATA_AUTH, SERVERDATA_AUTH_ID, password)?;

        let mut header = self.read_header()?;

        println!("got auth header: {:#?}", header);

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
            println!("got SERVERDATA_RESPONSE_VALUE, eating body and reading header again");
            // Discard empty SERVERDATA_RESPONSE_VALUE from authentication response.
            let mut tmp = vec![0; size as usize];
            let _ = self.stream.read(&mut tmp);
            header = self.read_header()?;

            println!("new header: {:#?}", header);
        }

        // must read the response body
        let mut buf = vec![0; size as usize];
        self.stream.read_exact(&mut buf)?;

        println!("got response body: {:#?}", buf);

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

    fn write(&mut self, packet_type: PacketType, packet_id: i32, command: &str) -> Result<()> {
        let packet = Packet::new(packet_type, packet_id, command);

        println!("writing bytes to stream...");
        packet.write_to(&mut self.stream)?;
        println!("wrote bytes to stream.");

        Ok(())
    }

    fn read(&mut self) -> Result<Packet> {
        Packet::read_from(&mut self.stream)
    }

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
    use std::net::Shutdown;

    use super::*;

    #[test]
    fn it_connects() {
        let conn = RCONStream::dial("palworld-server:25575", "boogerbean36");
        if conn.is_err() {
            panic!("failed to auth: {:#?}", conn.unwrap_err());
        }

        assert!(conn.is_ok());

        conn.unwrap().stream.shutdown(Shutdown::Both).unwrap();
    }

    #[test]
    fn it_pings() {
        let mut conn =
            RCONStream::dial("palworld-server:25575", "boogerbean36").expect("must connect");

        match conn.execute("ping") {
            Err(e) => {
                panic!("failed to ping: {:#?}", e);
            }
            Ok(res) => {
                assert_eq!(res.to_lowercase(), "pong\n");
            }
        }
    }
}
