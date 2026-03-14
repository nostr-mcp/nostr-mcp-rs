use super::ProfileService;
use nostr_mcp_types::metadata::{ProfileGetArgs, SetMetadataArgs};
use nostr_mcp_types::settings::ProfileMetadata;
use nostr_sdk::prelude::*;

#[test]
fn service_maps_metadata_args_to_profile() {
    let profile = ProfileService::from_args(&SetMetadataArgs {
        name: Some("name".to_string()),
        display_name: Some("display".to_string()),
        about: Some("about".to_string()),
        picture: None,
        banner: None,
        nip05: None,
        lud06: None,
        lud16: None,
        website: None,
        publish: None,
    });

    assert_eq!(profile.name.as_deref(), Some("name"));
    assert_eq!(profile.display_name.as_deref(), Some("display"));
    assert_eq!(profile.about.as_deref(), Some("about"));
}

#[tokio::test]
async fn service_publish_propagates_publish_errors() {
    let client = Client::new(Keys::generate());
    let err = ProfileService::publish(&client, &ProfileMetadata::default())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("publish metadata"));
}

#[tokio::test]
async fn service_fetch_metadata_propagates_fetch_errors() {
    let client = Client::new(Keys::generate());
    let err = ProfileService::fetch_metadata(&client, &Keys::generate().public_key())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("fetch metadata"));
}

#[tokio::test]
async fn service_fetch_profile_propagates_invalid_pubkey_errors() {
    let client = Client::new(Keys::generate());
    let err = ProfileService::fetch_profile(
        &client,
        ProfileGetArgs {
            pubkey: "not-a-pubkey".to_string(),
            timeout_secs: None,
        },
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("invalid pubkey format"));
}
