use crate::error::CoreError;
use nostr_mcp_types::metadata::{
    MetadataResult, ProfileGetArgs, ProfileGetResult, SetMetadataArgs,
};
use nostr_mcp_types::settings::ProfileMetadata;
use nostr_sdk::prelude::*;

pub struct ProfileService;

impl ProfileService {
    pub fn from_args(args: &SetMetadataArgs) -> ProfileMetadata {
        crate::metadata::args_to_profile(args)
    }

    pub async fn publish(
        client: &Client,
        profile: &ProfileMetadata,
    ) -> Result<MetadataResult, CoreError> {
        crate::metadata::publish_metadata(client, profile).await
    }

    pub async fn fetch_metadata(
        client: &Client,
        pubkey: &PublicKey,
    ) -> Result<Option<Metadata>, CoreError> {
        crate::metadata::fetch_metadata(client, pubkey).await
    }

    pub async fn fetch_profile(
        client: &Client,
        args: ProfileGetArgs,
    ) -> Result<ProfileGetResult, CoreError> {
        crate::metadata::fetch_profile(client, args).await
    }
}

#[cfg(test)]
mod tests;
