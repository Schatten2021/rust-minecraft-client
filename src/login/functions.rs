use crate::errors::{Errors, Result};
use crate::net::{into, receive_packet, receive_unknown, send_packet};
use crate::Client;
use minecraft_net::packets::login::*;
use minecraft_net::{EncryptedTcp, Packet, Stream, UnknownPacket};
use num_bigint::BigInt;
use openssl::pkey::Public;
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::sha::Sha1;
use reqwest::StatusCode;
use serde::Serialize;
use std::net::TcpStream;
use crate::configure::ConfigurationTarget;

pub fn login<C: ConfigurationTarget>(client: &mut Client<C>, stream: &mut TcpStream) -> Result<downstream::LoginSuccess> {
    client.logger.debug("starting login sequence");
    login_start(client, stream.try_clone().map_err(|e| Errors::IOError(e))?)?;
    client.logger.info("started login sequence");
    login_main(client, stream)
}
fn login_start<C: ConfigurationTarget>(client: &Client<C>, stream: impl Stream) -> Result<()> {
    send_packet(stream, upstream::LoginStart::new(client.name.clone(), client.uuid), None)
}
fn login_main<C: ConfigurationTarget>(client: &mut Client<C>, stream: &mut TcpStream) -> Result<downstream::LoginSuccess> {
    let packet = receive_unknown(stream.try_clone().unwrap(), false)?;
    match packet.id {
        downstream::LoginSuccess::ID => Ok(into(packet)?),
        downstream::Disconnect::ID => Err(Errors::Disconnected(into::<downstream::Disconnect>(packet)?.reason)),
        downstream::SetCompression::ID => enable_compression(client, packet, stream),
        downstream::EncryptionRequest::ID => enable_encryption(client, packet, stream),
        id => Err(Errors::InvalidPacketError(format!("Unknown Packet with id {}", id))),
    }
}
fn enable_compression<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket, stream: impl Stream) -> Result<downstream::LoginSuccess> {
    client.logger.info("enabling compression");
    let packet: downstream::SetCompression = into(packet)?;
    if packet.threshold > 0 {
        client.logger.debug(format!("enabled compression with threshold {}", packet.threshold));
        client.compression_threshold = Some(packet.threshold as usize)
    }
    let login_success = receive_packet(stream, client.compression_threshold.is_some())?;
    Ok(login_success)
}
//TODO: somethings broken with the encryption (I think), but I don't know what.
fn enable_encryption<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket, stream: &mut TcpStream) -> Result<downstream::LoginSuccess> {
    let packet: downstream::EncryptionRequest = into(packet)?;

    let secret = generate_aes_key()?;
    let server_key = openssl::rsa::Rsa::public_key_from_der(&*packet.public_key)
        .map_err(|e| Errors::EncryptionError(e))?;
    
    if packet.should_authenticate {
        client.logger.info("authenticating");
        let token = client.token.clone().ok_or(Errors::ValueError("authentication token required for client".into()))?;
        authenticate(packet.server_id, secret.clone(), packet.public_key, token, client.uuid)?;
    }

    client.logger.info("enabling encryption");
    let encrypted_token = rsa_encrypt(&server_key, packet.verify_token)?;
    let encrypted_secret = rsa_encrypt(&server_key, secret.clone())?;
    let encryption_response_packet = upstream::EncryptionResponse::new(encrypted_secret, encrypted_token);

    send_packet(stream.try_clone().unwrap(), encryption_response_packet, None)?;

    client.stream = Some(Box::new(EncryptedTcp::new(stream.try_clone().unwrap(), secret).map_err(|e| Errors::NetworkError(e))?));

    client.logger.debug("encryption enabled");

    let packet = client.receive_unknown()?;
    match packet.id {
        downstream::LoginSuccess::ID => into(packet),
        downstream::Disconnect::ID => Err(Errors::Disconnected(into::<downstream::Disconnect>(packet)?.reason)),
        downstream::SetCompression::ID => enable_compression(client, packet, stream),
        id => Err(Errors::InvalidPacketError(format!("Unknown Packet with id {}", id)))
    }
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct AuthenticationRequest {
    accessToken: String,
    selectedProfile: String,
    serverId: String,
}
fn authenticate(server_id: String, secret: Vec<u8>, public_key: Vec<u8>, access_token: String, uuid: u128) -> Result<()> {
    let mut hash = Sha1::new();
    if !server_id.is_ascii() {
        return Err(Errors::ValueError("Server id must be a string".into()));
    }
    hash.update(server_id.as_bytes());
    hash.update(&*secret);
    hash.update(&*public_key);
    let result = hash.finish();
    let hex = BigInt::from_signed_bytes_be(result.as_ref());
    let body = AuthenticationRequest {
        accessToken: access_token,
        selectedProfile: format!("{:X}", uuid),
        serverId: hex.to_str_radix(16),
    };
    let request = reqwest::blocking::Client::new()
        .post("https://sessionserver.mojang.com/session/minecraft/join")
        .json(&body)
        .send();
    match request {
        Err(e) => Err(Errors::AuthenticationRequestError(e)),
        Ok(resp) => match resp.status() {
            StatusCode::NO_CONTENT => Ok(()),
            _other => Err(Errors::AuthenticationError(resp.text().unwrap())),
        }
    }?;
    let logger = logging::Logger::new("Minecraft.client.login.thread");
    logger.debug("finished request");
    // sender.send(request).expect("couldn't send back result of request");
    Ok(())
}

fn generate_aes_key() -> Result<Vec<u8>> {
    let mut buff = vec![0; 16];
    rand_bytes(&mut *buff).map_err(|e| Errors::EncryptionError(e))?;
    Ok(buff)
}
fn rsa_encrypt(key: &Rsa<Public>, data: Vec<u8>) -> Result<Vec<u8>> {
    let mut encrypted = vec![0; key.size() as usize];
    let encrypted_len = key.public_encrypt(&*data, &mut *encrypted, Padding::PKCS1)
        .map_err(|e| Errors::EncryptionError(e))?;
    encrypted.resize(encrypted_len, 0);
    assert_eq!(encrypted_len, 128);
    Ok(encrypted)
}