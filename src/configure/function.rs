use crate::errors::Errors;
use crate::net::into;
use crate::Client;
use lazy_static::lazy_static;
use logging::Logger;
use minecraft_net::{Packet, UnknownPacket};
use minecraft_net::packets::configuration::*;
use crate::configure::ConfigurationTarget;

lazy_static!{
    static ref logger: Logger = {
        Logger::new("Minecraft.client.configure")
    };
}

pub fn configure<C: ConfigurationTarget>(client: &mut Client<C>) -> Result<(), Errors> {
    let client_information = upstream::ClientInformation::new(
        "de_DE".into(), 8, 0, false, 1, 1, false, true,
    );
    client.send_packet(client_information)?;
    while read_configuration_packet(client)? {}
    Ok(())
}
fn read_configuration_packet<C: ConfigurationTarget>(client: &mut Client<C>) -> Result<bool, Errors> {
    let packet = client.receive_unknown()?;
    match packet.id {
        downstream::CookieRequest::ID => handle_cookie_request(client, packet)?,
        downstream::ClientboundPluginMessage::ID => handle_plugin_message(client, packet)?,
        downstream::Disconnect::ID => handle_disconnect(client, packet)?,
        downstream::FinishConfiguration::ID => { handle_finish_configuration(client, packet)?; return Ok(false) },
        downstream::ClientBoundKeepAlive::ID => handle_keep_alive(client, packet)?,
        downstream::Ping::ID => handle_ping(client, packet)?,
        downstream::ResetChat::ID => handle_reset_chat(client, packet)?,
        downstream::RegistryData::ID => handle_registry_data(client, packet)?,
        downstream::RemoveResourcePack::ID => handle_remove_resource_pack(client, packet)?,
        downstream::AddResourcePack::ID => handle_add_resource_pack(client, packet)?,
        downstream::StoreCookie::ID => handle_store_cookie(client, packet)?,
        downstream::Transfer::ID => handle_transfer(client, packet)?,
        downstream::FeatureFlags::ID => handle_feature_flags(client, packet)?,
        downstream::UpdateTags::ID => handle_update_tags(client, packet)?,
        downstream::ClientBoundKnownPacks::ID => handle_known_packs(client, packet)?,
        downstream::ServerLinks::ID => handle_server_links(client, packet)?,
        _ => return Err(Errors::InvalidPacketError("Invalid packet id during configuration phase".into())),
    };
    Ok(true)
}
fn handle_cookie_request<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::CookieRequest>(packet)?;
    logger.debug(format!("received request for cookie \"{}\"", packet.key));
    let data = client.config_handler.cookie_request(packet.key.clone());
    let response = upstream::CookieResponse::new(packet.key.clone(), data);
    client.send_packet(response)?;
    logger.debug(format!("told server that we don't know anything about cookie \"{}\"", packet.key));
    Ok(())
}
fn handle_plugin_message<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::ClientboundPluginMessage>(packet)?;
    logger.debug(format!("received plugin message {:?}", packet));
    client.config_handler.plugin_message(packet.channel, packet.data);
    Ok(())
}
fn handle_disconnect<C: ConfigurationTarget>(_client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::Disconnect>(packet)?;
    logger.error(format!("disconnected due to {:?}", packet.reason));
    Err(Errors::Disconnected(packet.reason))
}
fn handle_finish_configuration<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let _packet = into::<downstream::FinishConfiguration>(packet)?;
    logger.success("received Finish Configuration packet!");
    client.send_packet(upstream::AcknowledgeFinishConfiguration::new())
}
fn handle_keep_alive<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::ClientBoundKeepAlive>(packet)?;
    client.send_packet(upstream::ServerBoundKeepAlive::new(packet.id))
}
fn handle_ping<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::Ping>(packet)?;
    client.send_packet(upstream::Pong::new(packet.id))
}
fn handle_reset_chat<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let _packet = into::<downstream::ResetChat>(packet)?;
    logger.debug("received resset chat");
    client.config_handler.reset_chat();
    Ok(())
}
fn handle_registry_data<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::RegistryData>(packet)?;
    logger.debug(format!("received registry data: {:?}", packet));
    client.config_handler.registry_data(packet.registry_id, packet.entries);
    Ok(())
}
fn handle_remove_resource_pack<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::RemoveResourcePack>(packet)?;
    logger.debug(format!("received request to remove resource pack {:?}", packet));
    match packet.uuid {
        Some(uuid) => client.config_handler.remove_resource_pack(uuid),
        None => client.config_handler.remove_all_resource_packs(),
    }
    Ok(())
}
fn handle_add_resource_pack<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::AddResourcePack>(packet)?;
    let result = client.config_handler.add_resource_pack(packet.uuid, packet.url, packet.hash, packet.forced, packet.prompt_message);
    let response = upstream::ResourcePackResponse::new(packet.uuid, result.into());
    client.send_packet(response)
}
fn handle_store_cookie<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::StoreCookie>(packet)?;
    logger.debug(format!("received request to store a cookie {:?}", packet));
    client.config_handler.store_cookie(packet.key, packet.payload);
    Ok(())
}
fn handle_transfer<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::Transfer>(packet)?;
    client.server_url = packet.host;
    client.server_port = packet.port as u16;
    Err(Errors::Moved)
}
fn handle_feature_flags<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::FeatureFlags>(packet)?;
    logger.debug(format!("received feature flags: {:?}", packet));
    client.config_handler.feature_flags(packet.feature_flags);
    Ok(())
}
fn handle_update_tags<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::UpdateTags>(packet)?;
    logger.debug(format!("received request to update tags: {:?}", packet));
    client.config_handler.update_tags(packet.arr);
    Ok(())
}
fn handle_known_packs<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::ClientBoundKnownPacks>(packet)?;
    logger.debug(format!("known packs by the server: {:?}", packet));
    let known_packs = client.config_handler.known_packs(packet.known_packs);
    let response = upstream::ServerBoundKnownPacks::new(known_packs);
    client.send_packet(response)?;
    logger.debug("informed the server that the client does not know any packs besides the core one.");
    Ok(())
}
fn handle_server_links<C: ConfigurationTarget>(client: &mut Client<C>, packet: UnknownPacket) -> Result<(), Errors> {
    let packet = into::<downstream::ServerLinks>(packet)?;
    logger.debug(format!("received server links: {:?}", packet));
    client.config_handler.server_links(packet.links);
    Ok(())
}