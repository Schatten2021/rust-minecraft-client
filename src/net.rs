use std::fmt::Debug;
use lazy_static::lazy_static;
use logging::Logger;
use crate::errors::{Errors, Result};
use minecraft_net::{Packet, Stream, UnknownPacket};

lazy_static!{
    static ref logger: Logger = {
        Logger::new("Minecraft.client.net")
    };
}

pub fn receive_unknown(stream: impl Stream, with_compression: bool) -> Result<UnknownPacket> {
    let packet = minecraft_net::receive_unknown_packet(stream, with_compression).map_err(|e| Errors::NetworkError(e))?;
    logger.debug(format!("received unknown packet with id {} and data {:?}", packet.id, packet.reader.get_rest()));
    Ok(packet)
}
pub fn receive_packet<T: Packet + Debug>(stream: impl Stream, compression_enabled: bool) -> Result<T> {
    let packet = minecraft_net::receive_packet(stream, compression_enabled).map_err(|e| Errors::NetworkError(e))?;
    logger.debug(format!("received packet {:?}", packet));
    Ok(packet)
}
pub fn send_packet<T: Packet + Debug>(stream: impl Stream, packet: T, compression_threshold: Option<usize>) -> Result<()> {
    logger.debug(format!("sending packet {:?} with data {:?}", packet, packet.to_bytes()));
    minecraft_net::send_packet(packet, stream, compression_threshold).map_err(|e| Errors::NetworkError(e))
}
pub fn into<T: Packet + Debug>(mut src: UnknownPacket) -> Result<T> {
    if src.id != T::ID {
        return Err(Errors::InvalidPacketError(format!("expected packet with id {} but got packet with id {}", T::ID, src.id)))
    }
    let data = src.reader.get_rest();
    let packet = T::from_reader(&mut src.reader).map_err(|e| Errors::NetworkError(e))?;
    if src.reader.len() != 0 {
        return Err(Errors::InvalidPacketError("Packet not read to end. Invalid length".into()))
    }
    logger.debug(format!("parsed packet {:?} from {:?}", packet, data));
    Ok(packet)
}