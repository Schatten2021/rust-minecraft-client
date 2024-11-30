use crate::errors::Errors;
use minecraft_net::packets::handshake::upstream::Handshake;
use minecraft_net::packets::status::upstream::{PingRequest, StatusRequest};
use minecraft_net::{Packet, PacketReader};
use std::io::Read;
use std::net::TcpStream;
use std::time::SystemTime;
use minecraft_net::packets::status::downstream::StatusResponse;
use minecraft_net::fields::read_var_int_from_stream;
use minecraft_net::send_packet;

pub fn ping(server_addr: impl ToString, server_port: u16) -> Result<u128, Errors> {
    let server_addr = server_addr.to_string();
    let addr = format!("{}:{}", server_addr, server_port);
    let mut conn = TcpStream::connect(addr).map_err(|e| Errors::IOError(e))?;
    let handshake = Handshake::new(server_addr, server_port, 1);
    send_packet(handshake, &conn, None).map_err(|e| Errors::NetworkError(e))?;
    let packet = PingRequest::now();
    send_packet(packet, &conn, None).map_err(|e| Errors::NetworkError(e))?;
    let request_time = SystemTime::now();
    conn.read(&mut *vec![0]).map_err(|e| Errors::IOError(e))?;
    let diff = SystemTime::now().duration_since(request_time).expect("Somehow time moves backwards?").as_millis();
    Ok(diff)
}
pub fn get_status(server_addr: impl ToString, server_port: u16) -> Result<String, Errors> {
    let server_addr = server_addr.to_string();
    let addr = format!("{}:{}", server_addr, server_port);
    let mut conn = TcpStream::connect(addr).map_err(|e| Errors::IOError(e))?;
    let handshake = Handshake::new(server_addr, server_port, 1);
    send_packet(handshake, &conn, None).map_err(|e| Errors::NetworkError(e))?;
    send_packet(StatusRequest::new(), &conn, None).map_err(|e| Errors::NetworkError(e))?;
    let response_len = read_var_int_from_stream(&mut conn).map_err(|e| Errors::NetworkError(e))?;
    let mut buff = vec![0; response_len as usize];
    conn.read(&mut buff).map_err(|e| Errors::IOError(e))?;
    let packet = StatusResponse::from_reader(&mut PacketReader::new(buff)).map_err(|e| Errors::NetworkError(e))?;
    Ok(packet.status)
}