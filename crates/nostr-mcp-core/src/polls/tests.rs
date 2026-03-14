use super::{
    build_poll_results, create_poll, fetch_poll_events, fetch_vote_events,
    get_poll_results_with_fetchers, map_invalid_poll_event, normalize_selected_options,
    normalize_vote_option_ids, options_map_for_poll, parse_poll_event_id, parse_poll_type,
    parse_relays, poll_from_events, prepare_poll, prepare_vote, selected_options_from_event,
    tally_votes, vote_poll,
};
use nostr::nips::nip88::{Poll, PollOption as Nip88PollOption, PollResponse, PollType};
use nostr_mcp_types::polls::{CreatePollArgs, PollOption as ApiPollOption, VotePollArgs};
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;
use std::collections::HashMap;

fn sample_options() -> Vec<ApiPollOption> {
    vec![
        ApiPollOption {
            option_id: "a".to_string(),
            label: "Alpha".to_string(),
        },
        ApiPollOption {
            option_id: "b".to_string(),
            label: "Beta".to_string(),
        },
    ]
}

fn sample_create_poll_args() -> CreatePollArgs {
    CreatePollArgs {
        question: " Which option? ".to_string(),
        options: sample_options(),
        relay_urls: vec!["wss://relay.example.com".to_string()],
        poll_type: None,
        ends_at: Some(2_000),
        pow: Some(18),
        to_relays: Some(vec!["wss://relay.example.com".to_string()]),
    }
}

fn sample_poll(relay: RelayUrl, poll_type: PollType, ends_at: Option<u64>) -> Poll {
    Poll {
        title: "Which option?".to_string(),
        r#type: poll_type,
        options: vec![
            Nip88PollOption {
                id: "b".to_string(),
                text: "Beta".to_string(),
            },
            Nip88PollOption {
                id: "a".to_string(),
                text: "Alpha".to_string(),
            },
        ],
        relays: vec![relay],
        ends_at: ends_at.map(Timestamp::from_secs),
    }
}

async fn connected_client(keys: Keys, url: &RelayUrl) -> Client {
    let client = Client::new(keys);
    client.add_relay(url).await.unwrap();
    client.connect().await;
    client
}

async fn seed_poll(url: RelayUrl, keys: &Keys, poll: Poll, created_at: u64) -> Event {
    let client = connected_client(keys.clone(), &url).await;
    let event = EventBuilder::poll(poll)
        .custom_created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .unwrap();
    client.send_event(&event).await.unwrap();
    event
}

async fn seed_vote(
    url: RelayUrl,
    keys: &Keys,
    poll_id: EventId,
    responses: Vec<String>,
    created_at: u64,
) -> Event {
    let client = connected_client(keys.clone(), &url).await;
    let response = if responses.len() == 1 {
        PollResponse::SingleChoice {
            poll_id,
            response: responses[0].clone(),
        }
    } else {
        PollResponse::MultipleChoice { poll_id, responses }
    };
    let event = EventBuilder::poll_response(response)
        .custom_created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .unwrap();
    client.send_event(&event).await.unwrap();
    event
}

fn build_vote_event(keys: &Keys, created_at: u64, responses: Vec<String>) -> Event {
    let mut tags = Vec::new();
    for response in responses {
        tags.push(Tag::parse(&["response".to_string(), response]).unwrap());
    }

    EventBuilder::new(Kind::from(1018), "")
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .unwrap()
}

#[test]
fn parse_poll_event_id_accepts_trimmed_event_id() {
    let event_id = EventId::all_zeros().to_hex();

    let parsed = parse_poll_event_id(&format!("  {event_id}  ")).unwrap();

    assert_eq!(parsed.to_hex(), event_id);
}

#[test]
fn parse_poll_event_id_rejects_invalid_event_id() {
    let err = parse_poll_event_id("not-an-event").unwrap_err();

    assert!(err.to_string().contains("invalid event id"));
}

#[test]
fn parse_poll_type_defaults_to_single_choice() {
    let poll_type = parse_poll_type(None).unwrap();
    assert_eq!(poll_type, PollType::SingleChoice);
}

#[test]
fn parse_poll_type_accepts_trimmed_multiple_choice() {
    let poll_type = parse_poll_type(Some("  multiplechoice  ")).unwrap();
    assert_eq!(poll_type, PollType::MultipleChoice);
}

#[test]
fn parse_poll_type_rejects_unknown_value() {
    let err = parse_poll_type(Some("ranked")).unwrap_err();

    assert!(err.to_string().contains("invalid poll_type"));
}

#[test]
fn parse_relays_accepts_valid_relays() {
    let expected_first = RelayUrl::parse("wss://relay.example.com").unwrap();
    let expected_second = RelayUrl::parse("wss://relay.radroots.org").unwrap();
    let relays = parse_relays(&[
        "wss://relay.example.com".to_string(),
        "wss://relay.radroots.org".to_string(),
    ])
    .unwrap();

    assert_eq!(relays.len(), 2);
    assert_eq!(relays[0], expected_first);
    assert_eq!(relays[1], expected_second);
}

#[test]
fn parse_relays_rejects_empty_value() {
    let err = parse_relays(&["   ".to_string()]).unwrap_err();

    assert!(err.to_string().contains("relay url must not be empty"));
}

#[test]
fn parse_relays_rejects_invalid_url() {
    let err = parse_relays(&["not-a-relay".to_string()]).unwrap_err();

    assert!(err.to_string().contains("invalid relay url"));
}

#[test]
fn normalize_vote_option_ids_accepts_valid_values() {
    let normalized = normalize_vote_option_ids(&["a".to_string(), "b2".to_string()]).unwrap();

    assert_eq!(normalized, vec!["a".to_string(), "b2".to_string()]);
}

#[test]
fn normalize_vote_option_ids_rejects_invalid_value() {
    let err = normalize_vote_option_ids(&["bad-id!".to_string()]).unwrap_err();

    assert!(err.to_string().contains("option_id must be alphanumeric"));
}

#[test]
fn normalize_vote_option_ids_rejects_empty_value() {
    let err = normalize_vote_option_ids(&["   ".to_string()]).unwrap_err();

    assert!(err.to_string().contains("option_id must not be empty"));
}

#[test]
fn prepare_poll_builds_expected_poll() {
    let expected_relay = RelayUrl::parse("wss://relay.example.com").unwrap();
    let prepared = prepare_poll(CreatePollArgs {
        poll_type: Some("multiplechoice".to_string()),
        ..sample_create_poll_args()
    })
    .unwrap();

    assert_eq!(prepared.pow, Some(18));
    assert_eq!(
        prepared.to_relays,
        Some(vec!["wss://relay.example.com".to_string()])
    );
    assert_eq!(prepared.poll.title, "Which option?");
    assert_eq!(prepared.poll.r#type, PollType::MultipleChoice);
    assert_eq!(prepared.poll.options.len(), 2);
    assert_eq!(prepared.poll.options[0].id, "a");
    assert_eq!(prepared.poll.options[0].text, "Alpha");
    assert_eq!(prepared.poll.relays[0], expected_relay);
    assert_eq!(prepared.poll.ends_at.unwrap().as_secs(), 2_000);
}

#[test]
fn prepare_poll_requires_non_empty_question() {
    let err = prepare_poll(CreatePollArgs {
        question: "   ".to_string(),
        ..sample_create_poll_args()
    })
    .unwrap_err();

    assert!(err.to_string().contains("question must not be empty"));
}

#[test]
fn prepare_poll_requires_two_options() {
    let err = prepare_poll(CreatePollArgs {
        options: vec![ApiPollOption {
            option_id: "a".to_string(),
            label: "Alpha".to_string(),
        }],
        ..sample_create_poll_args()
    })
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("poll must have at least 2 options")
    );
}

#[test]
fn prepare_poll_requires_relays() {
    let err = prepare_poll(CreatePollArgs {
        relay_urls: Vec::new(),
        ..sample_create_poll_args()
    })
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("relay_urls must include at least one relay")
    );
}

#[test]
fn prepare_poll_rejects_duplicate_option_ids() {
    let err = prepare_poll(CreatePollArgs {
        options: vec![
            ApiPollOption {
                option_id: "dup".to_string(),
                label: "Alpha".to_string(),
            },
            ApiPollOption {
                option_id: "dup".to_string(),
                label: "Beta".to_string(),
            },
        ],
        ..sample_create_poll_args()
    })
    .unwrap_err();

    assert!(err.to_string().contains("duplicate option ID"));
}

#[test]
fn prepare_poll_rejects_invalid_option_id() {
    let err = prepare_poll(CreatePollArgs {
        options: vec![
            ApiPollOption {
                option_id: "bad-id".to_string(),
                label: "Alpha".to_string(),
            },
            ApiPollOption {
                option_id: "b".to_string(),
                label: "Beta".to_string(),
            },
        ],
        ..sample_create_poll_args()
    })
    .unwrap_err();

    assert!(err.to_string().contains("option_id must be alphanumeric"));
}

#[test]
fn prepare_poll_rejects_empty_option_label() {
    let err = prepare_poll(CreatePollArgs {
        options: vec![
            ApiPollOption {
                option_id: "a".to_string(),
                label: "   ".to_string(),
            },
            ApiPollOption {
                option_id: "b".to_string(),
                label: "Beta".to_string(),
            },
        ],
        ..sample_create_poll_args()
    })
    .unwrap_err();

    assert!(err.to_string().contains("option label must not be empty"));
}

#[test]
fn prepare_poll_rejects_invalid_relay() {
    let err = prepare_poll(CreatePollArgs {
        relay_urls: vec!["not-a-relay".to_string()],
        ..sample_create_poll_args()
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid relay url"));
}

#[test]
fn prepare_poll_rejects_invalid_poll_type() {
    let err = prepare_poll(CreatePollArgs {
        poll_type: Some("ranked".to_string()),
        ..sample_create_poll_args()
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid poll_type"));
}

#[test]
fn prepare_vote_builds_single_choice_response() {
    let prepared = prepare_vote(VotePollArgs {
        poll_event_id: EventId::all_zeros().to_hex(),
        option_ids: vec!["a".to_string()],
        pow: Some(22),
        to_relays: Some(vec!["wss://relay.example.com".to_string()]),
    })
    .unwrap();

    assert_eq!(prepared.pow, Some(22));
    assert_eq!(
        prepared.to_relays,
        Some(vec!["wss://relay.example.com".to_string()])
    );
    match prepared.response {
        PollResponse::SingleChoice { poll_id, response } => {
            assert_eq!(poll_id.to_hex(), EventId::all_zeros().to_hex());
            assert_eq!(response, "a");
        }
        PollResponse::MultipleChoice { .. } => panic!("expected single choice"),
    }
}

#[test]
fn prepare_vote_builds_multiple_choice_response() {
    let prepared = prepare_vote(VotePollArgs {
        poll_event_id: EventId::all_zeros().to_hex(),
        option_ids: vec!["a".to_string(), "b".to_string()],
        pow: None,
        to_relays: None,
    })
    .unwrap();

    match prepared.response {
        PollResponse::SingleChoice { .. } => panic!("expected multiple choice"),
        PollResponse::MultipleChoice { poll_id, responses } => {
            assert_eq!(poll_id.to_hex(), EventId::all_zeros().to_hex());
            assert_eq!(responses, vec!["a".to_string(), "b".to_string()]);
        }
    }
}

#[test]
fn prepare_vote_requires_selection() {
    let err = prepare_vote(VotePollArgs {
        poll_event_id: EventId::all_zeros().to_hex(),
        option_ids: Vec::new(),
        pow: None,
        to_relays: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("must select at least one option"));
}

#[test]
fn prepare_vote_rejects_invalid_event_id() {
    let err = prepare_vote(VotePollArgs {
        poll_event_id: "not-an-event".to_string(),
        option_ids: vec!["a".to_string()],
        pow: None,
        to_relays: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid event id"));
}

#[test]
fn prepare_vote_rejects_invalid_option_id() {
    let err = prepare_vote(VotePollArgs {
        poll_event_id: EventId::all_zeros().to_hex(),
        option_ids: vec!["bad-id".to_string()],
        pow: None,
        to_relays: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("option_id must be alphanumeric"));
}

#[tokio::test]
async fn fetch_poll_events_reports_errors() {
    let client = Client::new(Keys::generate());
    let err = fetch_poll_events(&client, EventId::all_zeros(), 1)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("fetch poll"));
}

#[tokio::test]
async fn fetch_vote_events_reports_errors() {
    let client = Client::new(Keys::generate());
    let err = fetch_vote_events(&client, EventId::all_zeros(), 1)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("fetch votes"));
}

#[test]
fn poll_from_events_returns_poll() {
    let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
    let event = EventBuilder::poll(sample_poll(relay, PollType::SingleChoice, None))
        .sign_with_keys(&Keys::generate())
        .unwrap();
    let events = vec![event].into_iter().collect::<Events>();

    let poll = poll_from_events(&events).unwrap();

    assert_eq!(poll.r#type, PollType::SingleChoice);
}

#[test]
fn poll_from_events_rejects_missing_poll() {
    let events = Vec::<Event>::new().into_iter().collect::<Events>();
    let err = poll_from_events(&events).unwrap_err();

    assert!(err.to_string().contains("poll not found"));
}

#[test]
fn map_invalid_poll_event_formats_unexpected_tag() {
    let err = map_invalid_poll_event(nostr::nips::nip88::Error::UnexpectedTag);

    assert_eq!(
        err.to_string(),
        "invalid input: invalid poll event: unexpected tag"
    );
}

#[test]
fn options_map_for_poll_maps_option_ids_to_labels() {
    let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
    let poll = sample_poll(relay, PollType::SingleChoice, None);

    let options = options_map_for_poll(&poll);

    assert_eq!(options.get("a").map(String::as_str), Some("Alpha"));
    assert_eq!(options.get("b").map(String::as_str), Some("Beta"));
}

#[test]
fn selected_options_from_event_collects_poll_responses_only() {
    let tags = vec![
        Tag::parse(&["response".to_string(), "a".to_string()]).unwrap(),
        Tag::parse(&["response".to_string()]).unwrap(),
        Tag::parse(&["p".to_string(), Keys::generate().public_key().to_hex()]).unwrap(),
        Tag::parse(&["response".to_string(), "b".to_string()]).unwrap(),
    ];
    let event = EventBuilder::new(Kind::from(1018), "")
        .tags(tags)
        .sign_with_keys(&Keys::generate())
        .unwrap();

    let selected = selected_options_from_event(&event);

    assert_eq!(selected, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn tally_votes_prefers_latest_and_ignores_ended() {
    let mut options_map: HashMap<String, String> = HashMap::new();
    options_map.insert("a".to_string(), "Alpha".to_string());
    options_map.insert("b".to_string(), "Beta".to_string());

    let keys = Keys::generate();
    let vote_a = build_vote_event(&keys, 100, vec!["a".to_string()]);
    let vote_b = build_vote_event(&keys, 200, vec!["b".to_string()]);
    let late_vote = build_vote_event(&Keys::generate(), 300, vec!["a".to_string()]);

    let votes = [vote_a.clone(), vote_b.clone(), late_vote];
    let (counts, total_votes) = tally_votes(
        votes.iter(),
        &options_map,
        PollType::SingleChoice,
        Some(250),
    );

    assert_eq!(total_votes, 1);
    assert_eq!(*counts.get("a").unwrap_or(&0), 0);
    assert_eq!(*counts.get("b").unwrap_or(&0), 1);
}

#[test]
fn tally_votes_skips_votes_without_response_tags() {
    let mut options_map: HashMap<String, String> = HashMap::new();
    options_map.insert("a".to_string(), "Alpha".to_string());
    let event = EventBuilder::new(Kind::from(1018), "")
        .sign_with_keys(&Keys::generate())
        .unwrap();

    let (counts, total_votes) =
        tally_votes([event].iter(), &options_map, PollType::SingleChoice, None);

    assert!(counts.is_empty());
    assert_eq!(total_votes, 0);
}

#[test]
fn tally_votes_skips_votes_without_valid_selected_options() {
    let mut options_map: HashMap<String, String> = HashMap::new();
    options_map.insert("a".to_string(), "Alpha".to_string());
    let event = build_vote_event(&Keys::generate(), 100, vec!["missing".to_string()]);

    let (counts, total_votes) =
        tally_votes([event].iter(), &options_map, PollType::SingleChoice, None);

    assert!(counts.is_empty());
    assert_eq!(total_votes, 0);
}

#[test]
fn single_choice_counts_only_first_valid_response() {
    let mut options_map: HashMap<String, String> = HashMap::new();
    options_map.insert("a".to_string(), "Alpha".to_string());
    options_map.insert("b".to_string(), "Beta".to_string());

    let normalized = normalize_selected_options(
        &["b".to_string(), "a".to_string()],
        &options_map,
        PollType::SingleChoice,
    );

    assert_eq!(normalized, vec!["b".to_string()]);
}

#[test]
fn single_choice_returns_empty_when_no_valid_responses_exist() {
    let mut options_map: HashMap<String, String> = HashMap::new();
    options_map.insert("a".to_string(), "Alpha".to_string());

    let normalized = normalize_selected_options(
        &["missing".to_string()],
        &options_map,
        PollType::SingleChoice,
    );

    assert!(normalized.is_empty());
}

#[test]
fn multiple_choice_deduplicates_responses() {
    let mut options_map: HashMap<String, String> = HashMap::new();
    options_map.insert("a".to_string(), "Alpha".to_string());
    options_map.insert("b".to_string(), "Beta".to_string());

    let normalized = normalize_selected_options(
        &["a".to_string(), "a".to_string(), "b".to_string()],
        &options_map,
        PollType::MultipleChoice,
    );

    assert_eq!(normalized, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn multiple_choice_skips_invalid_responses() {
    let mut options_map: HashMap<String, String> = HashMap::new();
    options_map.insert("a".to_string(), "Alpha".to_string());

    let normalized = normalize_selected_options(
        &["missing".to_string(), "a".to_string()],
        &options_map,
        PollType::MultipleChoice,
    );

    assert_eq!(normalized, vec!["a".to_string()]);
}

#[test]
fn build_poll_results_sorts_options_and_marks_ended() {
    let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
    let poll = sample_poll(relay, PollType::SingleChoice, Some(100));
    let vote = build_vote_event(&Keys::generate(), 90, vec!["a".to_string()]);
    let vote_events = vec![vote].into_iter().collect::<Events>();

    let results = build_poll_results("poll-id", poll, &vote_events, 200);

    assert_eq!(results.poll_id, "poll-id");
    assert_eq!(results.poll_type, PollType::SingleChoice.to_string());
    assert_eq!(results.total_votes, 1);
    assert!(results.ended);
    assert_eq!(results.options[0].option_id, "a");
    assert_eq!(results.options[0].votes, 1);
    assert_eq!(results.options[1].option_id, "b");
    assert_eq!(results.options[1].votes, 0);
}

#[test]
fn build_poll_results_uses_multiple_choice_tally() {
    let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
    let poll = sample_poll(relay, PollType::MultipleChoice, None);
    let vote = build_vote_event(
        &Keys::generate(),
        90,
        vec!["a".to_string(), "b".to_string(), "a".to_string()],
    );
    let vote_events = vec![vote].into_iter().collect::<Events>();

    let results = build_poll_results("poll-id", poll, &vote_events, 90);

    assert_eq!(results.total_votes, 1);
    assert_eq!(results.options[0].votes, 1);
    assert_eq!(results.options[1].votes, 1);
    assert!(!results.ended);
}

#[tokio::test]
async fn create_poll_rejects_invalid_question_before_publish() {
    let client = Client::new(Keys::generate());
    let err = create_poll(
        &client,
        CreatePollArgs {
            question: "   ".to_string(),
            ..sample_create_poll_args()
        },
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("question must not be empty"));
}

#[tokio::test]
async fn create_poll_succeeds_against_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let keys = Keys::generate();
    let client = connected_client(keys.clone(), &url).await;

    let result = create_poll(
        &client,
        CreatePollArgs {
            relay_urls: vec![url.to_string()],
            pow: None,
            to_relays: Some(vec![url.to_string()]),
            ..sample_create_poll_args()
        },
    )
    .await
    .unwrap();

    let events = client
        .fetch_events(
            Filter::new()
                .kind(Kind::from(1068))
                .author(keys.public_key())
                .limit(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
    let poll = poll_from_events(&events).unwrap();

    assert_eq!(result.pubkey, keys.public_key().to_hex());
    assert_eq!(result.success, vec![url.to_string()]);
    assert_eq!(poll.title, "Which option?");
    assert_eq!(poll.r#type, PollType::SingleChoice);
    assert_eq!(poll.options.len(), 2);
}

#[tokio::test]
async fn create_poll_applies_pow_against_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let keys = Keys::generate();
    let client = connected_client(keys.clone(), &url).await;

    let result = create_poll(
        &client,
        CreatePollArgs {
            relay_urls: vec![url.to_string()],
            pow: Some(1),
            to_relays: Some(vec![url.to_string()]),
            ..sample_create_poll_args()
        },
    )
    .await
    .unwrap();

    let events = client
        .fetch_events(
            Filter::new()
                .kind(Kind::from(1068))
                .author(keys.public_key())
                .limit(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
    let poll_event = events.iter().next().unwrap();

    assert_eq!(result.success, vec![url.to_string()]);
    assert!(
        poll_event
            .tags
            .iter()
            .any(|tag| tag.kind() == TagKind::Nonce)
    );
}

#[tokio::test]
async fn vote_poll_rejects_empty_option_ids_before_publish() {
    let client = Client::new(Keys::generate());
    let err = vote_poll(
        &client,
        VotePollArgs {
            poll_event_id: EventId::all_zeros().to_hex(),
            option_ids: Vec::new(),
            pow: None,
            to_relays: None,
        },
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("must select at least one option"));
}

#[tokio::test]
async fn vote_poll_succeeds_against_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let poll_keys = Keys::generate();
    let voter_keys = Keys::generate();
    let poll_event = seed_poll(
        url.clone(),
        &poll_keys,
        sample_poll(url.clone(), PollType::SingleChoice, None),
        100,
    )
    .await;
    let client = connected_client(voter_keys.clone(), &url).await;

    let result = vote_poll(
        &client,
        VotePollArgs {
            poll_event_id: poll_event.id.to_hex(),
            option_ids: vec!["a".to_string()],
            pow: None,
            to_relays: Some(vec![url.to_string()]),
        },
    )
    .await
    .unwrap();

    let vote_events = client
        .fetch_events(
            Filter::new()
                .kind(Kind::from(1018))
                .author(voter_keys.public_key())
                .limit(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
    let vote_event = vote_events.iter().next().unwrap();

    assert_eq!(result.pubkey, voter_keys.public_key().to_hex());
    assert_eq!(result.success, vec![url.to_string()]);
    assert_eq!(
        selected_options_from_event(vote_event),
        vec!["a".to_string()]
    );
}

#[tokio::test]
async fn vote_poll_applies_pow_against_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let poll_keys = Keys::generate();
    let voter_keys = Keys::generate();
    let poll_event = seed_poll(
        url.clone(),
        &poll_keys,
        sample_poll(url.clone(), PollType::SingleChoice, None),
        100,
    )
    .await;
    let client = connected_client(voter_keys.clone(), &url).await;

    let result = vote_poll(
        &client,
        VotePollArgs {
            poll_event_id: poll_event.id.to_hex(),
            option_ids: vec!["a".to_string()],
            pow: Some(1),
            to_relays: Some(vec![url.to_string()]),
        },
    )
    .await
    .unwrap();

    let vote_events = client
        .fetch_events(
            Filter::new()
                .kind(Kind::from(1018))
                .author(voter_keys.public_key())
                .limit(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
    let vote_event = vote_events.iter().next().unwrap();

    assert_eq!(result.success, vec![url.to_string()]);
    assert!(
        vote_event
            .tags
            .iter()
            .any(|tag| tag.kind() == TagKind::Nonce)
    );
}

#[tokio::test]
async fn get_poll_results_reads_results_against_mock_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let poll_keys = Keys::generate();
    let first_voter = Keys::generate();
    let second_voter = Keys::generate();
    let poll_event = seed_poll(
        url.clone(),
        &poll_keys,
        sample_poll(
            url.clone(),
            PollType::SingleChoice,
            Some(Timestamp::now().as_secs() + 30),
        ),
        100,
    )
    .await;
    seed_vote(
        url.clone(),
        &first_voter,
        poll_event.id,
        vec!["a".to_string()],
        110,
    )
    .await;
    seed_vote(
        url.clone(),
        &first_voter,
        poll_event.id,
        vec!["b".to_string()],
        120,
    )
    .await;
    seed_vote(
        url.clone(),
        &second_voter,
        poll_event.id,
        vec!["a".to_string()],
        115,
    )
    .await;
    let client = connected_client(Keys::generate(), &url).await;

    let results = super::get_poll_results(&client, &poll_event.id.to_hex(), 1)
        .await
        .unwrap();

    assert_eq!(results.poll_id, poll_event.id.to_hex());
    assert_eq!(results.question, "Which option?");
    assert_eq!(results.total_votes, 2);
    assert!(!results.ended);
    assert_eq!(results.options[0].option_id, "a");
    assert_eq!(results.options[0].votes, 1);
    assert_eq!(results.options[1].option_id, "b");
    assert_eq!(results.options[1].votes, 1);
}

#[tokio::test]
async fn get_poll_results_with_fetchers_propagates_poll_fetch_error() {
    let err = get_poll_results_with_fetchers(
        &EventId::all_zeros().to_hex(),
        1,
        1_000,
        |_poll_id, _timeout_secs| async {
            Err(crate::error::CoreError::operation("fetch poll: boom"))
        },
        |_poll_id, _timeout_secs| async { Ok(Vec::<Event>::new().into_iter().collect::<Events>()) },
    )
    .await
    .unwrap_err();

    assert_eq!(err.to_string(), "operation error: fetch poll: boom");
}

#[tokio::test]
async fn get_poll_results_with_fetchers_propagates_real_poll_fetch_error() {
    let client = Client::new(Keys::generate());
    let err = get_poll_results_with_fetchers(
        &EventId::all_zeros().to_hex(),
        1,
        1_000,
        |poll_id, timeout_secs| fetch_poll_events(&client, poll_id, timeout_secs),
        |_poll_id, _timeout_secs| async { Ok(Vec::<Event>::new().into_iter().collect::<Events>()) },
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("fetch poll"));
}

#[tokio::test]
async fn get_poll_results_with_fetchers_propagates_vote_fetch_error() {
    let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
    let poll_event = EventBuilder::poll(sample_poll(relay, PollType::SingleChoice, None))
        .sign_with_keys(&Keys::generate())
        .unwrap();
    let poll_events = vec![poll_event].into_iter().collect::<Events>();

    let err = get_poll_results_with_fetchers(
        &EventId::all_zeros().to_hex(),
        1,
        1_000,
        move |_poll_id, _timeout_secs| async move { Ok(poll_events) },
        |_poll_id, _timeout_secs| async {
            Err(crate::error::CoreError::operation("fetch votes: boom"))
        },
    )
    .await
    .unwrap_err();

    assert_eq!(err.to_string(), "operation error: fetch votes: boom");
}

#[tokio::test]
async fn get_poll_results_with_fetchers_propagates_real_vote_fetch_error() {
    let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
    let poll_event = EventBuilder::poll(sample_poll(relay, PollType::SingleChoice, None))
        .sign_with_keys(&Keys::generate())
        .unwrap();
    let poll_events = vec![poll_event].into_iter().collect::<Events>();
    let client = Client::new(Keys::generate());

    let err = get_poll_results_with_fetchers(
        &EventId::all_zeros().to_hex(),
        1,
        1_000,
        move |_poll_id, _timeout_secs| async move { Ok(poll_events) },
        |poll_id, timeout_secs| fetch_vote_events(&client, poll_id, timeout_secs),
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("fetch votes"));
}

#[tokio::test]
async fn get_poll_results_rejects_missing_poll() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;
    let client = connected_client(Keys::generate(), &url).await;

    let err = super::get_poll_results(&client, &EventId::all_zeros().to_hex(), 1)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("poll not found"));
}

#[tokio::test]
async fn get_poll_results_propagates_fetch_poll_error() {
    let client = Client::new(Keys::generate());
    let err = super::get_poll_results(&client, &EventId::all_zeros().to_hex(), 1)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("fetch poll"));
}

#[tokio::test]
async fn get_poll_results_rejects_invalid_event_id() {
    let client = Client::new(Keys::generate());
    let err = super::get_poll_results(&client, "not-an-event", 1)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("invalid event id"));
}
