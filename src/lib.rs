pub mod errors;
mod ping;
mod login;
mod net;
pub mod configure;

use std::fmt::Debug;
use crate::errors::Errors;
use crate::login::functions::login;
use crate::net::{receive_unknown, send_packet};
pub use crate::ping::{get_status, ping};
use logging::Logger;
use minecraft_net::packets::handshake::upstream::Handshake;
use minecraft_net::{packets, Packet, Stream};
use minecraft_net::packets::login::downstream::LoginSuccess;
use minecraft_net::UnknownPacket;
use std::net::TcpStream;
use crate::configure::ConfigurationTarget;
use crate::configure::function::configure;

pub struct Client<C: ConfigurationTarget> {
    server_url: String,
    server_port: u16,
    token: Option<String>,
    uuid: u128,
    name: String,
    compression_threshold: Option<usize>,
    stream: Option<Box<dyn Stream>>,
    login_success: Option<LoginSuccess>,
    logger: Logger,
    pub config_handler: C,
}
impl<C: ConfigurationTarget> Client<C> {
    pub fn new(url: impl ToString, port: u16, uuid: u128, name: String, configuration_target: C) -> Self {
        Self {
            server_url: url.to_string(),
            server_port: port,
            token: None,
            uuid,
            name,
            compression_threshold: None,
            stream: None,
            login_success: None,
            logger: Logger::new("Minecraft.Client"),
            config_handler: configuration_target,
        }
    }
    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }
    pub fn connect(&mut self) -> Result<(), Errors> {
        self.logger.debug("initializing");
        let conn = TcpStream::connect(format!("{}:{}", self.server_url, self.server_port)).map_err(|e| Errors::IOError(e))?;
        self.stream = Some(Box::new(conn.try_clone().unwrap()));
        self.logger.info("logging in");
        self.handshake(2)?;
        self.login(conn)?;
        self.logger.success("logged in");
        self.configure()?;
        self.logger.success("configured successfully");
        Ok(())
    }
    fn handshake(&mut self, next_state: i32) -> Result<(), Errors> {
        self.send_packet(Handshake::new(self.server_url.clone(), self.server_port, next_state))
    }
    fn configure(&mut self) -> Result<(), Errors> {
        configure(self)
    }
}
// login protocol
impl<C: ConfigurationTarget> Client<C> {
    fn login(&mut self, mut tcp_stream: TcpStream) -> Result<(), Errors> {
        let res = login(self, &mut tcp_stream)?;
        self.login_success = Some(res);
        self.logger.debug("acknowledging login");
        self.ack_login()?;
        Ok(())
    }
    fn ack_login(&mut self) -> Result<(), Errors> {
        self.send_packet(packets::login::upstream::LoginAcknowledged::new())
    }
    pub(crate) fn receive_unknown(&mut self) -> Result<UnknownPacket, Errors> {
        let stream = self.stream.as_mut().unwrap();
        receive_unknown(stream, self.compression_threshold.is_some())
    }
    pub(crate) fn send_packet<T: Packet + Debug>(&mut self, packet: T) -> Result<(), Errors> {
        send_packet(self.stream.as_mut().unwrap(), packet, self.compression_threshold)
    }
}