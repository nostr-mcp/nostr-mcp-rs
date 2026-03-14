use super::{
    args_to_profile, collect_metadata_events, fetch_metadata, fetch_metadata_with_timeout,
    fetch_profile, metadata_from_events, parse_metadata_content, parse_pubkey,
    profile_to_nostr_metadata, publish_metadata, publish_metadata_result,
    published_metadata_output,
};
use nostr_mcp_types::metadata::{ProfileGetArgs, SetMetadataArgs};
use nostr_mcp_types::settings::ProfileMetadata;
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::future::ready;

fn profile_with_all_fields() -> ProfileMetadata {
    ProfileMetadata {
        name: Some("name".to_string()),
        display_name: Some("display".to_string()),
        about: Some("about".to_string()),
        picture: Some("https://example.com/picture.png".to_string()),
        banner: Some("https://example.com/banner.png".to_string()),
        nip05: Some("name@example.com".to_string()),
        lud06: Some("lnurl1example".to_string()),
        lud16: Some("name@lightning.example.com".to_string()),
        website: Some("https://example.com".to_string()),
    }
}

fn metadata_event(keys: &Keys, metadata: &Metadata) -> Event {
    EventBuilder::metadata(metadata)
        .sign_with_keys(keys)
        .unwrap()
}

fn invalid_metadata_event(keys: &Keys, content: &str) -> Event {
    EventBuilder::new(Kind::Metadata, content)
        .sign_with_keys(keys)
        .unwrap()
}

async fn connected_client(keys: Keys, url: &RelayUrl) -> Client {
    let client = Client::new(keys);
    client.add_relay(url).await.unwrap();
    client.connect().await;
    client
}

async fn seed_metadata(url: RelayUrl, keys: &Keys, metadata: &Metadata) {
    let client = connected_client(keys.clone(), &url).await;
    let builder = EventBuilder::metadata(metadata).custom_created_at(Timestamp::now());
    client.send_event_builder(builder).await.unwrap();
}

#[derive(Debug, Clone)]
struct PublicKeyErrorSigner(Keys);

impl NostrSigner for PublicKeyErrorSigner {
    fn backend(&self) -> SignerBackend<'_> {
        SignerBackend::Custom(Cow::Borrowed("public-key-error"))
    }

    fn get_public_key(&self) -> BoxedFuture<'_, Result<PublicKey, SignerError>> {
        Box::pin(ready(Err(SignerError::from("public key boom"))))
    }

    fn sign_event(&self, unsigned: UnsignedEvent) -> BoxedFuture<'_, Result<Event, SignerError>> {
        self.0.sign_event(unsigned)
    }

    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        self.0.nip04_encrypt(public_key, content)
    }

    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        encrypted_content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        self.0.nip04_decrypt(public_key, encrypted_content)
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        self.0.nip44_encrypt(public_key, content)
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> BoxedFuture<'a, Result<String, SignerError>> {
        self.0.nip44_decrypt(public_key, payload)
    }
}

#[test]
fn args_to_profile_maps_all_fields() {
    let args = SetMetadataArgs {
        name: Some("name".to_string()),
        display_name: Some("display".to_string()),
        about: Some("about".to_string()),
        picture: Some("https://example.com/picture.png".to_string()),
        banner: Some("https://example.com/banner.png".to_string()),
        nip05: Some("name@example.com".to_string()),
        lud06: Some("lnurl1example".to_string()),
        lud16: Some("name@lightning.example.com".to_string()),
        website: Some("https://example.com".to_string()),
        publish: Some(true),
    };

    let profile = args_to_profile(&args);

    assert_eq!(profile, profile_with_all_fields());
}

#[test]
fn profile_to_nostr_metadata_maps_all_fields() {
    let metadata = profile_to_nostr_metadata(&profile_with_all_fields()).unwrap();

    assert_eq!(metadata.name.as_deref(), Some("name"));
    assert_eq!(metadata.display_name.as_deref(), Some("display"));
    assert_eq!(metadata.about.as_deref(), Some("about"));
    assert_eq!(
        metadata.picture.as_deref(),
        Some("https://example.com/picture.png")
    );
    assert_eq!(
        metadata.banner.as_deref(),
        Some("https://example.com/banner.png")
    );
    assert_eq!(metadata.nip05.as_deref(), Some("name@example.com"));
    assert_eq!(metadata.lud06.as_deref(), Some("lnurl1example"));
    assert_eq!(
        metadata.lud16.as_deref(),
        Some("name@lightning.example.com")
    );
    assert_eq!(metadata.website.as_deref(), Some("https://example.com/"));
}

#[test]
fn profile_to_nostr_metadata_accepts_empty_profile() {
    let metadata = profile_to_nostr_metadata(&ProfileMetadata::default()).unwrap();

    assert_eq!(metadata, Metadata::new());
}

#[test]
fn profile_to_nostr_metadata_rejects_bad_picture_url() {
    let err = profile_to_nostr_metadata(&ProfileMetadata {
        picture: Some("not a url".to_string()),
        ..ProfileMetadata::default()
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid picture url"));
}

#[test]
fn profile_to_nostr_metadata_rejects_bad_banner_url() {
    let err = profile_to_nostr_metadata(&ProfileMetadata {
        banner: Some("not a url".to_string()),
        ..ProfileMetadata::default()
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid banner url"));
}

#[test]
fn profile_to_nostr_metadata_rejects_bad_website_url() {
    let err = profile_to_nostr_metadata(&ProfileMetadata {
        website: Some("not a url".to_string()),
        ..ProfileMetadata::default()
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid website url"));
}

#[test]
fn published_metadata_output_and_result_map_sdk_output() {
    let relay = RelayUrl::parse("wss://relay.example").unwrap();
    let failed_relay = RelayUrl::parse("wss://relay.fail").unwrap();
    let output = Output {
        val: EventId::all_zeros(),
        success: HashSet::from([relay]),
        failed: HashMap::from([(failed_relay, "timeout".to_string())]),
    };

    let published = published_metadata_output(output);
    let result = publish_metadata_result(published.clone(), "pubkey".to_string());

    assert_eq!(published.event_id, EventId::all_zeros().to_string());
    assert_eq!(published.success_relays, vec!["wss://relay.example"]);
    assert_eq!(
        published.failed_relays,
        HashMap::from([("wss://relay.fail".to_string(), "timeout".to_string())])
    );
    assert!(result.saved);
    assert!(result.published);
    assert_eq!(result.pubkey.as_deref(), Some("pubkey"));
    assert_eq!(
        result.event_id.as_deref(),
        Some(EventId::all_zeros().to_hex().as_str())
    );
    assert_eq!(result.success_relays, vec!["wss://relay.example"]);
    assert_eq!(
        result.failed_relays,
        HashMap::from([("wss://relay.fail".to_string(), "timeout".to_string())])
    );
}

#[test]
fn parse_metadata_content_decodes_metadata_json() {
    let metadata = Metadata::new()
        .name("name")
        .display_name("display")
        .about("about")
        .picture(Url::parse("https://example.com/picture.png").unwrap());

    let parsed = parse_metadata_content(&serde_json::to_string(&metadata).unwrap()).unwrap();

    assert_eq!(parsed.name.as_deref(), Some("name"));
    assert_eq!(parsed.display_name.as_deref(), Some("display"));
    assert_eq!(parsed.about.as_deref(), Some("about"));
    assert_eq!(
        parsed.picture.as_deref(),
        Some("https://example.com/picture.png")
    );
}

#[test]
fn parse_metadata_content_reports_parse_errors() {
    let err = parse_metadata_content("{not-json").unwrap_err();

    assert!(err.to_string().contains("parse metadata"));
}

#[test]
fn metadata_from_events_returns_first_metadata_event() {
    let first_metadata = Metadata::new().name("first");
    let second_metadata = Metadata::new().name("second");
    let first = metadata_event(&Keys::generate(), &first_metadata);
    let second = metadata_event(&Keys::generate(), &second_metadata);

    let metadata = metadata_from_events(vec![first, second]).unwrap().unwrap();

    assert_eq!(metadata.name.as_deref(), Some("first"));
}

#[test]
fn metadata_from_events_returns_none_when_empty() {
    let metadata = metadata_from_events(Vec::<Event>::new()).unwrap();

    assert!(metadata.is_none());
}

#[test]
fn metadata_from_events_reports_parse_errors() {
    let err = metadata_from_events(vec![invalid_metadata_event(&Keys::generate(), "{broken")])
        .unwrap_err();

    assert!(err.to_string().contains("parse metadata"));
}

#[test]
fn collect_metadata_events_accepts_events_collection() {
    let first = metadata_event(&Keys::generate(), &Metadata::new().name("first"));
    let second = metadata_event(&Keys::generate(), &Metadata::new().name("second"));
    let expected = HashSet::from([first.id, second.id]);
    let events = vec![first, second].into_iter().collect::<Events>();

    let collected = collect_metadata_events(events)
        .into_iter()
        .map(|event| event.id)
        .collect::<HashSet<_>>();

    assert_eq!(collected, expected);
}

#[test]
fn parse_pubkey_accepts_npub_and_hex() {
    let keys = Keys::generate();
    let npub = keys.public_key().to_bech32().unwrap();
    let hex = keys.public_key().to_hex();

    assert_eq!(parse_pubkey(&npub).unwrap(), keys.public_key());
    assert_eq!(parse_pubkey(&hex).unwrap(), keys.public_key());
}

#[test]
fn parse_pubkey_accepts_trimmed_npub() {
    let keys = Keys::generate();
    let npub = format!("  {}  ", keys.public_key().to_bech32().unwrap());

    assert_eq!(parse_pubkey(&npub).unwrap(), keys.public_key());
}

#[test]
fn parse_pubkey_accepts_raw_64_hex_value() {
    assert_eq!(
        parse_pubkey(&"f".repeat(64)).unwrap().to_hex(),
        "f".repeat(64)
    );
}

#[test]
fn parse_pubkey_rejects_invalid_format() {
    let err = parse_pubkey("not-a-pubkey").unwrap_err();

    assert!(err.to_string().contains("invalid pubkey format"));
}

#[test]
fn parse_pubkey_rejects_non_hex_64_char_input() {
    let err = parse_pubkey(&"g".repeat(64)).unwrap_err();

    assert!(err.to_string().contains("invalid hex pubkey"));
}

#[test]
fn parse_pubkey_rejects_invalid_npub() {
    let err = parse_pubkey("npub1invalid").unwrap_err();

    assert!(err.to_string().contains("invalid npub"));
}

#[tokio::test]
async fn publish_metadata_succeeds_against_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let keys = Keys::generate();
    let expected_pubkey = keys.public_key().to_hex();
    let client = connected_client(keys, &url).await;

    let result = publish_metadata(&client, &profile_with_all_fields())
        .await
        .unwrap();

    assert!(result.saved);
    assert!(result.published);
    assert_eq!(result.pubkey.as_deref(), Some(expected_pubkey.as_str()));
    assert_eq!(result.success_relays, vec![url.to_string()]);
    assert!(result.failed_relays.is_empty());
    assert!(result.event_id.is_some());
}

#[tokio::test]
async fn publish_metadata_reports_send_errors() {
    let client = Client::new(Keys::generate());
    let err = publish_metadata(&client, &ProfileMetadata::default())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("publish metadata"));
}

#[tokio::test]
async fn publish_metadata_propagates_profile_conversion_errors() {
    let client = Client::new(Keys::generate());
    let err = publish_metadata(
        &client,
        &ProfileMetadata {
            picture: Some("not a url".to_string()),
            ..ProfileMetadata::default()
        },
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("invalid picture url"));
}

#[tokio::test]
async fn publish_metadata_reports_missing_signer() {
    let client = Client::builder().build();
    let err = publish_metadata(&client, &ProfileMetadata::default())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("get signer"));
}

#[tokio::test]
async fn publish_metadata_reports_signer_pubkey_errors() {
    let client = Client::builder()
        .signer(PublicKeyErrorSigner(Keys::generate()))
        .build();
    let err = publish_metadata(&client, &ProfileMetadata::default())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("get signer pubkey"));
}

#[tokio::test]
async fn fetch_metadata_with_timeout_reads_metadata_against_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let remote_keys = Keys::generate();
    seed_metadata(
        url.clone(),
        &remote_keys,
        &Metadata::new().name("remote").display_name("Remote"),
    )
    .await;

    let client = connected_client(Keys::generate(), &url).await;
    let metadata = fetch_metadata_with_timeout(&client, &remote_keys.public_key(), 1)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(metadata.name.as_deref(), Some("remote"));
    assert_eq!(metadata.display_name.as_deref(), Some("Remote"));
}

#[tokio::test]
async fn fetch_metadata_returns_none_against_empty_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let client = connected_client(Keys::generate(), &url).await;

    let metadata = fetch_metadata(&client, &Keys::generate().public_key())
        .await
        .unwrap();

    assert!(metadata.is_none());
}

#[tokio::test]
async fn fetch_metadata_reports_fetch_errors() {
    let client = Client::new(Keys::generate());
    let err = fetch_metadata(&client, &Keys::generate().public_key())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("fetch metadata"));
}

#[tokio::test]
async fn fetch_profile_accepts_hex_pubkey() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let remote_keys = Keys::generate();
    seed_metadata(
        url.clone(),
        &remote_keys,
        &Metadata::new().name("remote").about("about"),
    )
    .await;
    let client = connected_client(Keys::generate(), &url).await;

    let result = fetch_profile(
        &client,
        ProfileGetArgs {
            pubkey: remote_keys.public_key().to_hex(),
            timeout_secs: Some(1),
        },
    )
    .await
    .unwrap();

    assert_eq!(result.pubkey, remote_keys.public_key().to_bech32().unwrap());
    assert_eq!(result.metadata.unwrap().name.as_deref(), Some("remote"));
}

#[tokio::test]
async fn fetch_profile_accepts_trimmed_npub_pubkey() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let remote_keys = Keys::generate();
    seed_metadata(
        url.clone(),
        &remote_keys,
        &Metadata::new().name("remote").about("about"),
    )
    .await;
    let client = connected_client(Keys::generate(), &url).await;

    let result = fetch_profile(
        &client,
        ProfileGetArgs {
            pubkey: format!("  {}  ", remote_keys.public_key().to_bech32().unwrap()),
            timeout_secs: Some(1),
        },
    )
    .await
    .unwrap();

    assert_eq!(result.pubkey, remote_keys.public_key().to_bech32().unwrap());
    assert_eq!(result.metadata.unwrap().name.as_deref(), Some("remote"));
}

#[tokio::test]
async fn fetch_profile_rejects_invalid_format() {
    let client = Client::new(Keys::generate());
    let err = fetch_profile(
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

#[tokio::test]
async fn fetch_profile_rejects_invalid_npub() {
    let client = Client::new(Keys::generate());
    let err = fetch_profile(
        &client,
        ProfileGetArgs {
            pubkey: "npub1invalid".to_string(),
            timeout_secs: None,
        },
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("invalid npub"));
}

#[tokio::test]
async fn fetch_profile_rejects_invalid_hex_pubkey() {
    let client = Client::new(Keys::generate());
    let err = fetch_profile(
        &client,
        ProfileGetArgs {
            pubkey: "g".repeat(64),
            timeout_secs: None,
        },
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("invalid hex pubkey"));
}

#[tokio::test]
async fn fetch_profile_propagates_fetch_errors() {
    let client = Client::new(Keys::generate());
    let err = fetch_profile(
        &client,
        ProfileGetArgs {
            pubkey: Keys::generate().public_key().to_hex(),
            timeout_secs: Some(1),
        },
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("fetch metadata"));
}
