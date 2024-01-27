use std::string::FromUtf8Error;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("authentication failed")]
    AuthFailed,

    #[error("received invalid response while trying to auth with server")]
    InvalidAuthResponse,

    #[error("received packet with invalid size")]
    InvalidPacketSize,

    #[error("received packet with invalid id")]
    InvalidPacketId,

    #[error("received packet with invalid type")]
    InvalidPacketType,

    #[error("received packet with invalid padding")]
    InvalidPacketPadding,

    #[error("received response that was too small")]
    ResponseTooSmall,

    #[error("received response that was too large")]
    ResponseTooLarge,

    #[error("refusing to send empty command")]
    CommandEmpty,

    #[error("command was too long")]
    CommandTooLong,

    #[error("invalid address supplied")]
    InvalidAddress(#[from] std::net::AddrParseError),

    #[error("an io error occurred with the socket")]
    SocketError(#[from] std::io::Error),

    #[error("failed to parse body")]
    BodyParseError(#[from] FromUtf8Error),
}
