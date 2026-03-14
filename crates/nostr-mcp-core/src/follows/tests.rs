use super::{
    FollowSyncPlan, FollowsFetchFuture, FollowsReadFuture, FollowsSendFuture, FollowsSignerFuture,
    FollowsWriteFuture, PublishedFollowsOutput, client_publish_follows, collect_follow_events,
    fetch_follows, fetch_follows_with, follows_from_events, follows_to_tags, plan_follow_sync,
    publish_follows, publish_follows_with, published_follows_output, sync_follows,
    sync_follows_with, tags_to_follows,
};
use crate::error::CoreError;
use nostr_mcp_types::settings::FollowEntry;
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::future::ready;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn follow(pubkey: &str, relay_url: Option<&str>, petname: Option<&str>) -> FollowEntry {
    FollowEntry {
        pubkey: pubkey.to_string(),
        relay_url: relay_url.map(str::to_string),
        petname: petname.map(str::to_string),
    }
}

fn follow_pubkey() -> String {
    Keys::generate().public_key().to_hex()
}

fn contact_list_event(follows: &[FollowEntry]) -> Event {
    let keys = Keys::generate();
    EventBuilder::new(Kind::ContactList, "")
        .tags(follows_to_tags(follows))
        .sign_with_keys(&keys)
        .unwrap()
}

async fn connected_client(keys: Keys, url: &RelayUrl) -> Client {
    let client = Client::new(keys);
    client.add_relay(url).await.unwrap();
    client.connect().await;
    client
}

async fn seed_contact_list(url: RelayUrl, keys: &Keys, follows: &[FollowEntry]) {
    let client = connected_client(keys.clone(), &url).await;
    let builder = EventBuilder::new(Kind::ContactList, "")
        .tags(follows_to_tags(follows))
        .custom_created_at(Timestamp::now());
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
fn follows_tags_round_trip() {
    let follows = vec![
        follow(&follow_pubkey(), Some("wss://relay.example"), Some("alice")),
        follow(&follow_pubkey(), None, None),
    ];

    let tags = follows_to_tags(&follows);
    let decoded = tags_to_follows(&tags);

    assert_eq!(decoded, follows);
}

#[test]
fn tags_to_follows_skips_non_pubkey_tags_and_empty_optionals() {
    let pubkey = follow_pubkey();
    let pubkey_tag = Tag::parse(&[
        "p".to_string(),
        pubkey.clone(),
        String::new(),
        String::new(),
    ])
    .unwrap();
    let event_tag = Tag::parse(&["e".to_string(), EventId::all_zeros().to_hex()]).unwrap();

    let follows = tags_to_follows(&[pubkey_tag, event_tag]);

    assert_eq!(follows, vec![follow(&pubkey, None, None)]);
}

#[test]
fn tags_to_follows_skips_pubkey_tags_without_content() {
    let tag = Tag::parse(&["p".to_string()]).unwrap();

    let follows = tags_to_follows(&[tag]);

    assert!(follows.is_empty());
}

#[test]
fn follows_from_events_returns_first_contact_list_event() {
    let first = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.first"),
        Some("alice"),
    )];
    let second = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.second"),
        Some("bob"),
    )];

    let follows = follows_from_events(vec![
        contact_list_event(&first),
        contact_list_event(&second),
    ]);

    assert_eq!(follows, first);
}

#[test]
fn follows_from_events_returns_empty_when_no_events_exist() {
    let follows = follows_from_events(Vec::<Event>::new());

    assert!(follows.is_empty());
}

#[test]
fn collect_follow_events_accepts_events_collection() {
    let first = contact_list_event(&[follow(&follow_pubkey(), None, None)]);
    let second = contact_list_event(&[follow(&follow_pubkey(), Some("wss://relay"), None)]);
    let expected = HashSet::from([first.id, second.id]);
    let events = vec![first, second].into_iter().collect::<Events>();

    let collected = collect_follow_events(events)
        .into_iter()
        .map(|event| event.id)
        .collect::<HashSet<_>>();

    assert_eq!(collected, expected);
}

#[tokio::test]
async fn fetch_follows_with_reads_contact_list_from_first_event() {
    let author = Keys::generate().public_key();
    let expected = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.example"),
        Some("alice"),
    )];

    let mut fetch = {
        let expected = expected.clone();
        move |filter: Filter, timeout: Duration| -> FollowsFetchFuture {
            assert_eq!(
                filter,
                Filter::new()
                    .author(author)
                    .kind(Kind::ContactList)
                    .limit(1)
            );
            assert_eq!(timeout, Duration::from_secs(10));
            Box::pin(ready(Ok(vec![contact_list_event(&expected)])))
        }
    };

    let follows = fetch_follows_with(author, &mut fetch).await.unwrap();

    assert_eq!(follows, expected);
}

#[tokio::test]
async fn fetch_follows_with_returns_empty_when_fetch_returns_none() {
    let author = Keys::generate().public_key();
    let mut fetch = move |_filter: Filter, _timeout: Duration| -> FollowsFetchFuture {
        Box::pin(ready(Ok(vec![])))
    };

    let follows = fetch_follows_with(author, &mut fetch).await.unwrap();

    assert!(follows.is_empty());
}

#[tokio::test]
async fn fetch_follows_reports_fetch_errors() {
    let client = Client::new(Keys::generate());
    let err = fetch_follows(&client, &Keys::generate().public_key())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("fetch follows"));
}

#[tokio::test]
async fn publish_follows_succeeds_against_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let keys = Keys::generate();
    let expected_pubkey = keys.public_key().to_hex();
    let client = connected_client(keys, &url).await;
    let follows = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.example"),
        Some("alice"),
    )];

    let result = publish_follows(&client, &follows).await.unwrap();

    assert!(result.saved);
    assert!(result.published);
    assert_eq!(result.pubkey.as_deref(), Some(expected_pubkey.as_str()));
    assert_eq!(result.success_relays, vec![url.to_string()]);
    assert!(result.failed_relays.is_empty());
    assert!(result.event_id.is_some());
}

#[tokio::test]
async fn publish_follows_with_builds_contact_list_result() {
    let signer = Keys::generate();
    let expected_pubkey = signer.public_key().to_hex();
    let signer_pubkey_hex = expected_pubkey.clone();
    let follows = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.example"),
        Some("alice"),
    )];

    let mut send = {
        let follows = follows.clone();
        let signer = signer.clone();
        move |builder: EventBuilder| -> FollowsSendFuture {
            let follows = follows.clone();
            let signer = signer.clone();
            Box::pin(async move {
                let event = builder.sign_with_keys(&signer).unwrap();
                assert_eq!(event.kind, Kind::ContactList);
                assert_eq!(tags_to_follows(event.tags.as_slice()), follows);
                Ok(PublishedFollowsOutput {
                    event_id: event.id.to_string(),
                    success_relays: vec!["wss://relay.example".to_string()],
                    failed_relays: HashMap::from([(
                        "wss://relay.fail".to_string(),
                        "timeout".to_string(),
                    )]),
                })
            })
        }
    };
    let mut signer_pubkey = move || -> FollowsSignerFuture {
        let signer_pubkey_hex = signer_pubkey_hex.clone();
        Box::pin(ready(Ok(signer_pubkey_hex)))
    };

    let result = publish_follows_with(&follows, &mut send, &mut signer_pubkey)
        .await
        .unwrap();

    assert!(result.saved);
    assert!(result.published);
    assert_eq!(result.pubkey.as_deref(), Some(expected_pubkey.as_str()));
    assert_eq!(result.success_relays, vec!["wss://relay.example"]);
    assert_eq!(
        result.failed_relays,
        HashMap::from([("wss://relay.fail".to_string(), "timeout".to_string())])
    );
    assert!(result.event_id.is_some());
}

#[test]
fn published_follows_output_maps_sdk_output() {
    let relay = RelayUrl::parse("wss://relay.example").unwrap();
    let failed_relay = RelayUrl::parse("wss://relay.fail").unwrap();
    let output = Output {
        val: EventId::all_zeros(),
        success: HashSet::from([relay]),
        failed: HashMap::from([(failed_relay, "timeout".to_string())]),
    };

    let published = published_follows_output(output);

    assert_eq!(published.event_id, EventId::all_zeros().to_string());
    assert_eq!(published.success_relays, vec!["wss://relay.example"]);
    assert_eq!(
        published.failed_relays,
        HashMap::from([("wss://relay.fail".to_string(), "timeout".to_string())])
    );
}

#[tokio::test]
async fn publish_follows_with_propagates_signer_pubkey_errors() {
    let follows = vec![follow(&follow_pubkey(), None, None)];
    let mut send = move |_builder: EventBuilder| -> FollowsSendFuture {
        Box::pin(ready(Ok(PublishedFollowsOutput {
            event_id: EventId::all_zeros().to_string(),
            success_relays: vec![],
            failed_relays: HashMap::new(),
        })))
    };
    let mut signer_pubkey = move || -> FollowsSignerFuture {
        Box::pin(ready(Err(CoreError::operation(
            "get signer pubkey: failure",
        ))))
    };

    let err = publish_follows_with(&follows, &mut send, &mut signer_pubkey)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("get signer pubkey"));
}

#[tokio::test]
async fn publish_follows_with_propagates_send_errors() {
    let follows = vec![follow(&follow_pubkey(), None, None)];
    let mut send = move |_builder: EventBuilder| -> FollowsSendFuture {
        Box::pin(ready(Err(CoreError::operation("publish follows: boom"))))
    };
    let mut signer_pubkey = move || -> FollowsSignerFuture { Box::pin(ready(Ok(follow_pubkey()))) };

    let err = publish_follows_with(&follows, &mut send, &mut signer_pubkey)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("publish follows"));
}

#[tokio::test]
async fn publish_follows_reports_send_errors() {
    let client = Client::new(Keys::generate());
    let err = publish_follows(&client, &[follow(&follow_pubkey(), None, None)])
        .await
        .unwrap_err();

    assert!(err.to_string().contains("publish follows"));
}

#[tokio::test]
async fn publish_follows_reports_missing_signer() {
    let client = Client::builder().build();
    let err = publish_follows(&client, &[follow(&follow_pubkey(), None, None)])
        .await
        .unwrap_err();

    assert!(err.to_string().contains("get signer"));
}

#[tokio::test]
async fn publish_follows_reports_signer_pubkey_errors() {
    let client = Client::builder()
        .signer(PublicKeyErrorSigner(Keys::generate()))
        .build();
    let err = publish_follows(&client, &[follow(&follow_pubkey(), None, None)])
        .await
        .unwrap_err();

    assert!(err.to_string().contains("get signer pubkey"));
}

#[test]
fn plan_follow_sync_publishes_local_when_relay_differs() {
    let local = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.local"),
        Some("alice"),
    )];
    let relay = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.remote"),
        Some("bob"),
    )];

    let plan = plan_follow_sync(local.clone(), relay);

    assert_eq!(
        plan,
        FollowSyncPlan {
            follows: local.clone(),
            published: true,
            to_publish: Some(local),
        }
    );
}

#[tokio::test]
async fn sync_follows_with_publishes_local_when_relay_differs() {
    let pubkey = Keys::generate().public_key();
    let local = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.local"),
        Some("alice"),
    )];
    let relay = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.remote"),
        Some("bob"),
    )];
    let published = Arc::new(Mutex::new(Vec::new()));
    let published_clone = Arc::clone(&published);

    let mut fetch = move |received_pubkey: PublicKey| -> FollowsReadFuture {
        assert_eq!(received_pubkey, pubkey);
        let relay = relay.clone();
        Box::pin(ready(Ok(relay)))
    };
    let mut publish = move |follows: Vec<FollowEntry>| -> FollowsWriteFuture {
        *published_clone.lock().unwrap() = follows;
        Box::pin(ready(Ok(())))
    };

    let result = sync_follows_with(pubkey, local.clone(), &mut fetch, &mut publish)
        .await
        .unwrap();

    assert_eq!(result, (local.clone(), true));
    assert_eq!(*published.lock().unwrap(), local);
}

#[tokio::test]
async fn sync_follows_with_prefers_relay_when_local_is_empty() {
    let pubkey = Keys::generate().public_key();
    let relay = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.remote"),
        Some("bob"),
    )];
    let expected_relay = relay.clone();

    let mut fetch = move |_received_pubkey: PublicKey| -> FollowsReadFuture {
        let relay = relay.clone();
        Box::pin(ready(Ok(relay)))
    };
    let mut publish = move |_follows: Vec<FollowEntry>| -> FollowsWriteFuture {
        panic!("publish should not run when local follows are empty");
    };

    let result = sync_follows_with(pubkey, vec![], &mut fetch, &mut publish)
        .await
        .unwrap();

    assert_eq!(result, (expected_relay, false));
}

#[tokio::test]
async fn sync_follows_with_noops_when_local_matches_relay() {
    let pubkey = Keys::generate().public_key();
    let local = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.same"),
        Some("alice"),
    )];
    let expected_local = local.clone();

    let mut fetch = move |_received_pubkey: PublicKey| -> FollowsReadFuture {
        let local = local.clone();
        Box::pin(ready(Ok(local)))
    };
    let mut publish = move |_follows: Vec<FollowEntry>| -> FollowsWriteFuture {
        panic!("publish should not run when follows already match");
    };

    let result = sync_follows_with(pubkey, expected_local.clone(), &mut fetch, &mut publish)
        .await
        .unwrap();

    assert_eq!(result, (expected_local, false));
}

#[tokio::test]
async fn sync_follows_with_propagates_fetch_errors() {
    let pubkey = Keys::generate().public_key();
    let mut fetch = move |_received_pubkey: PublicKey| -> FollowsReadFuture {
        Box::pin(ready(Err(CoreError::operation("fetch follows: boom"))))
    };
    let mut publish =
        move |_follows: Vec<FollowEntry>| -> FollowsWriteFuture { Box::pin(ready(Ok(()))) };

    let err = sync_follows_with(pubkey, vec![], &mut fetch, &mut publish)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("fetch follows"));
}

#[tokio::test]
async fn sync_follows_with_propagates_publish_errors() {
    let pubkey = Keys::generate().public_key();
    let local = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.local"),
        Some("alice"),
    )];
    let relay = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.remote"),
        Some("bob"),
    )];

    let mut fetch = move |_received_pubkey: PublicKey| -> FollowsReadFuture {
        let relay = relay.clone();
        Box::pin(ready(Ok(relay)))
    };
    let mut publish = move |_follows: Vec<FollowEntry>| -> FollowsWriteFuture {
        Box::pin(ready(Err(CoreError::operation("publish follows: boom"))))
    };

    let err = sync_follows_with(pubkey, local, &mut fetch, &mut publish)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("publish follows"));
}

#[tokio::test]
async fn sync_follows_reports_fetch_errors() {
    let client = Client::new(Keys::generate());
    let err = sync_follows(&client, &Keys::generate().public_key(), vec![])
        .await
        .unwrap_err();

    assert!(err.to_string().contains("fetch follows"));
}

#[tokio::test]
async fn sync_follows_publishes_local_follows_against_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let remote_keys = Keys::generate();
    let remote_follows = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.remote"),
        Some("bob"),
    )];
    seed_contact_list(url.clone(), &remote_keys, &remote_follows).await;

    let local_keys = Keys::generate();
    let local_pubkey = local_keys.public_key();
    let client = connected_client(local_keys, &url).await;
    let local_follows = vec![follow(
        &follow_pubkey(),
        Some("wss://relay.local"),
        Some("alice"),
    )];

    let result = sync_follows(&client, &remote_keys.public_key(), local_follows.clone())
        .await
        .unwrap();
    let published = fetch_follows(&client, &local_pubkey).await.unwrap();

    assert_eq!(result, (local_follows.clone(), true));
    assert_eq!(published, local_follows);
}

#[tokio::test]
async fn client_publish_follows_surfaces_publish_errors() {
    let client = Client::new(Keys::generate());
    let err = client_publish_follows(client, vec![follow(&follow_pubkey(), None, None)])
        .await
        .unwrap_err();

    assert!(err.to_string().contains("publish follows"));
}
