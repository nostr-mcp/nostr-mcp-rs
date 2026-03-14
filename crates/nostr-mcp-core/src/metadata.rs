use crate::error::CoreError;
use nostr_mcp_types::metadata::{
    MetadataResult, ProfileGetArgs, ProfileGetResult, SetMetadataArgs,
};
use nostr_mcp_types::settings::ProfileMetadata;
use nostr_sdk::prelude::*;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedMetadataOutput {
    event_id: String,
    success_relays: Vec<String>,
    failed_relays: HashMap<String, String>,
}

pub fn profile_to_nostr_metadata(profile: &ProfileMetadata) -> Result<Metadata, CoreError> {
    let mut metadata = Metadata::new();

    if let Some(name) = &profile.name {
        metadata = metadata.name(name);
    }
    if let Some(display_name) = &profile.display_name {
        metadata = metadata.display_name(display_name);
    }
    if let Some(about) = &profile.about {
        metadata = metadata.about(about);
    }
    if let Some(picture) = &profile.picture {
        let url = Url::parse(picture)
            .map_err(|e| CoreError::invalid_input(format!("invalid picture url: {e}")))?;
        metadata = metadata.picture(url);
    }
    if let Some(banner) = &profile.banner {
        let url = Url::parse(banner)
            .map_err(|e| CoreError::invalid_input(format!("invalid banner url: {e}")))?;
        metadata = metadata.banner(url);
    }
    if let Some(nip05) = &profile.nip05 {
        metadata = metadata.nip05(nip05);
    }
    if let Some(lud06) = &profile.lud06 {
        metadata = metadata.lud06(lud06);
    }
    if let Some(lud16) = &profile.lud16 {
        metadata = metadata.lud16(lud16);
    }
    if let Some(website) = &profile.website {
        let url = Url::parse(website)
            .map_err(|e| CoreError::invalid_input(format!("invalid website url: {e}")))?;
        metadata = metadata.website(url);
    }

    Ok(metadata)
}

pub fn args_to_profile(args: &SetMetadataArgs) -> ProfileMetadata {
    ProfileMetadata {
        name: args.name.clone(),
        display_name: args.display_name.clone(),
        about: args.about.clone(),
        picture: args.picture.clone(),
        banner: args.banner.clone(),
        nip05: args.nip05.clone(),
        lud06: args.lud06.clone(),
        lud16: args.lud16.clone(),
        website: args.website.clone(),
    }
}

fn published_metadata_output(out: Output<EventId>) -> PublishedMetadataOutput {
    PublishedMetadataOutput {
        event_id: out.id().to_string(),
        success_relays: out.success.into_iter().map(|u| u.to_string()).collect(),
        failed_relays: out
            .failed
            .into_iter()
            .map(|(u, e)| (u.to_string(), e.to_string()))
            .collect(),
    }
}

fn publish_metadata_result(output: PublishedMetadataOutput, pubkey: String) -> MetadataResult {
    MetadataResult {
        saved: true,
        published: true,
        event_id: Some(output.event_id),
        pubkey: Some(pubkey),
        success_relays: output.success_relays,
        failed_relays: output.failed_relays,
    }
}

fn parse_metadata_content(content: &str) -> Result<Metadata, CoreError> {
    Metadata::from_json(content).map_err(|e| CoreError::operation(format!("parse metadata: {e}")))
}

fn metadata_from_events<T>(events: T) -> Result<Option<Metadata>, CoreError>
where
    T: IntoIterator<Item = Event>,
{
    if let Some(event) = events.into_iter().next() {
        parse_metadata_content(&event.content).map(Some)
    } else {
        Ok(None)
    }
}

fn collect_metadata_events(events: Events) -> Vec<Event> {
    events.into_iter().collect()
}

pub async fn publish_metadata(
    client: &Client,
    profile: &ProfileMetadata,
) -> Result<MetadataResult, CoreError> {
    let metadata = match profile_to_nostr_metadata(profile) {
        Ok(metadata) => metadata,
        Err(err) => return Err(err),
    };
    let builder = EventBuilder::metadata(&metadata);
    let signer = client
        .signer()
        .await
        .map_err(|e| CoreError::operation(format!("get signer: {e}")))?;
    let pubkey = signer
        .get_public_key()
        .await
        .map_err(|e| CoreError::operation(format!("get signer pubkey: {e}")))?
        .to_hex();
    let output = client
        .send_event_builder(builder)
        .await
        .map_err(|e| CoreError::operation(format!("publish metadata: {e}")))?;

    Ok(publish_metadata_result(
        published_metadata_output(output),
        pubkey,
    ))
}

pub async fn fetch_metadata(
    client: &Client,
    pubkey: &PublicKey,
) -> Result<Option<Metadata>, CoreError> {
    fetch_metadata_with_timeout(client, pubkey, 10).await
}

pub async fn fetch_metadata_with_timeout(
    client: &Client,
    pubkey: &PublicKey,
    timeout_secs: u64,
) -> Result<Option<Metadata>, CoreError> {
    let filter = Filter::new().author(*pubkey).kind(Kind::Metadata).limit(1);

    let events = client
        .fetch_events(filter, std::time::Duration::from_secs(timeout_secs))
        .await
        .map(collect_metadata_events)
        .map_err(|e| CoreError::operation(format!("fetch metadata: {e}")))?;

    metadata_from_events(events)
}

pub async fn fetch_profile(
    client: &Client,
    args: ProfileGetArgs,
) -> Result<ProfileGetResult, CoreError> {
    let pubkey = parse_pubkey(&args.pubkey)?;
    let metadata = match fetch_metadata_with_timeout(client, &pubkey, args.timeout()).await {
        Ok(metadata) => metadata,
        Err(err) => return Err(err),
    };
    let pubkey_bech32 = match pubkey.to_bech32() {
        Ok(value) => value,
        Err(err) => match err {},
    };

    Ok(ProfileGetResult {
        pubkey: pubkey_bech32,
        metadata,
    })
}

fn parse_pubkey(value: &str) -> Result<PublicKey, CoreError> {
    let value = value.trim();
    if value.starts_with("npub1") {
        PublicKey::from_bech32(value)
            .map_err(|e| CoreError::invalid_input(format!("invalid npub: {e}")))
    } else if value.len() == 64 {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(value, &mut bytes)
            .map_err(|e| CoreError::invalid_input(format!("invalid hex pubkey: {e}")))?;
        Ok(PublicKey::from_byte_array(bytes))
    } else {
        Err(CoreError::invalid_input(
            "invalid pubkey format; expected npub1... or 64-character hex",
        ))
    }
}

#[cfg(test)]
mod tests;
