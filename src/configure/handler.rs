use minecraft_net::packets::configuration::KnownPack;
use minecraft_net::packets::configuration::downstream::registry_data::Entry;
use minecraft_net::packets::configuration::downstream::server_links::Link;
use minecraft_net::packets::configuration::downstream::update_tags::Tags;

pub trait ConfigurationTarget {
    fn cookie_request(&mut self, id: String) -> Option<Vec<u8>>;
    fn plugin_message(&mut self, channel: String, data: Vec<u8>);
    fn disconnect(&mut self, reason: String);
    fn reset_chat(&mut self);
    fn registry_data(&mut self, id: String, entries: Vec<Entry>);
    fn remove_resource_pack(&mut self, uuid: u128);
    fn remove_all_resource_packs(&mut self);
    fn add_resource_pack(&mut self, uuid: u128, url: String, hash: String, forced: bool, prompt_message: Option<String>) -> AddResourcePackResult;
    fn store_cookie(&mut self, name: String, value: Vec<u8>);
    fn feature_flags(&mut self, features: Vec<String>);
    fn update_tags(&mut self, tags: Vec<Tags>);
    fn known_packs(&mut self, packs: Vec<KnownPack>) -> Vec<KnownPack>;
    fn server_links(&mut self, links: Vec<Link>);
}
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Hash)]
pub enum AddResourcePackResult {
    #[default]
    Success = 0,
    Declined = 1,
    FailedToDownload = 2,
    Accepted = 3,
    Downloaded = 4,
    InvalidURL = 5,
    FailedToReload = 6,
    Discarded = 7,
}
impl From<AddResourcePackResult> for i32 {
    fn from(v: AddResourcePackResult) -> Self {
        match v {
            AddResourcePackResult::Success => 0, 
            AddResourcePackResult::Declined => 1,
            AddResourcePackResult::FailedToDownload => 2,
            AddResourcePackResult::Accepted => 3,
            AddResourcePackResult::Downloaded => 4,
            AddResourcePackResult::InvalidURL => 5,
            AddResourcePackResult::FailedToReload => 6,
            AddResourcePackResult::Discarded => 7,
        }
    }
}