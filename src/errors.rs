#[derive(Debug)]
pub enum Errors {
    NetworkError(minecraft_net::Errors),
    IOError(std::io::Error),
    InvalidPacketError(String),
    EncryptionError(openssl::error::ErrorStack),
    Disconnected(String),
    ValueError(String),
    AuthenticationRequestError(reqwest::Error),
    AuthenticationError(String),
    Moved,
}
pub type Result<T> = core::result::Result<T, Errors>;