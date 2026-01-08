use crate::error::CoreError;
use crate::publish::{publish_event_builder, SendResult};
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct PollOption {
    pub option_id: String,
    pub label: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreatePollArgs {
    pub question: String,
    pub options: Vec<PollOption>,
    pub relay_urls: Vec<String>,
    pub poll_type: Option<String>,
    pub ends_at: Option<u64>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VotePollArgs {
    pub poll_event_id: String,
    pub option_ids: Vec<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetPollResultsArgs {
    pub poll_event_id: String,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct PollResultOption {
    pub option_id: String,
    pub label: String,
    pub votes: u64,
}

#[derive(Debug, Serialize)]
pub struct PollResults {
    pub poll_id: String,
    pub question: String,
    pub poll_type: String,
    pub total_votes: u64,
    pub options: Vec<PollResultOption>,
    pub ended: bool,
    pub ends_at: Option<u64>,
}

struct PollParsed {
    options: HashMap<String, String>,
    poll_type: String,
    ends_at: Option<u64>,
}

pub async fn create_poll(client: &Client, args: CreatePollArgs) -> Result<SendResult, CoreError> {
    if args.options.len() < 2 {
        return Err(CoreError::invalid_input(
            "poll must have at least 2 options".to_string(),
        ));
    }

    let mut option_ids = HashSet::new();
    for option in &args.options {
        if !option_ids.insert(&option.option_id) {
            return Err(CoreError::invalid_input(format!(
                "duplicate option ID: {}",
                option.option_id
            )));
        }
    }

    let mut tags = Vec::new();

    for option in &args.options {
        tags.push(
            Tag::parse(&[
                "option".to_string(),
                option.option_id.clone(),
                option.label.clone(),
            ])
            .map_err(|e| CoreError::Nostr(format!("option tag: {e}")))?,
        );
    }

    for relay_url in &args.relay_urls {
        tags.push(
            Tag::parse(&["relay".to_string(), relay_url.clone()])
                .map_err(|e| CoreError::Nostr(format!("relay tag: {e}")))?,
        );
    }

    let poll_type = args.poll_type.as_deref().unwrap_or("singlechoice");
    tags.push(
        Tag::parse(&["polltype".to_string(), poll_type.to_string()])
            .map_err(|e| CoreError::Nostr(format!("poll type tag: {e}")))?,
    );

    if let Some(ends_at) = args.ends_at {
        tags.push(
            Tag::parse(&["endsAt".to_string(), ends_at.to_string()])
                .map_err(|e| CoreError::Nostr(format!("endsAt tag: {e}")))?,
        );
    }

    let mut builder = EventBuilder::new(Kind::from(1068), args.question).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn vote_poll(client: &Client, args: VotePollArgs) -> Result<SendResult, CoreError> {
    if args.option_ids.is_empty() {
        return Err(CoreError::invalid_input(
            "must select at least one option".to_string(),
        ));
    }

    let poll_event_id = EventId::from_hex(&args.poll_event_id).map_err(|e| {
        CoreError::invalid_input(format!("invalid event id {}: {e}", args.poll_event_id))
    })?;

    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["e".to_string(), poll_event_id.to_hex()])
            .map_err(|e| CoreError::Nostr(format!("poll event tag: {e}")))?,
    );

    for option_id in &args.option_ids {
        tags.push(
            Tag::parse(&["response".to_string(), option_id.clone()])
                .map_err(|e| CoreError::Nostr(format!("response tag: {e}")))?,
        );
    }

    let mut builder = EventBuilder::new(Kind::from(1018), "").tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn get_poll_results(
    client: &Client,
    poll_event_id: &str,
    timeout_secs: u64,
) -> Result<PollResults, CoreError> {
    let poll_id = EventId::from_hex(poll_event_id).map_err(|e| {
        CoreError::invalid_input(format!("invalid event id {poll_event_id}: {e}"))
    })?;

    let poll_filter = Filter::new().id(poll_id).kind(Kind::from(1068)).limit(1);

    let poll_events = client
        .fetch_events(poll_filter, std::time::Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| CoreError::Nostr(format!("fetch poll: {e}")))?;

    let poll_event = poll_events
        .iter()
        .next()
        .ok_or_else(|| CoreError::invalid_input("poll not found".to_string()))?;

    let parsed = parse_poll_tags(&poll_event.tags);

    let vote_filter = Filter::new()
        .kind(Kind::from(1018))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::E), poll_id.to_hex());

    let vote_events = client
        .fetch_events(vote_filter, std::time::Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| CoreError::Nostr(format!("fetch votes: {e}")))?;

    let (vote_counts, total_votes) =
        tally_votes(vote_events.iter(), &parsed.options, parsed.ends_at);

    let now = Timestamp::now().as_secs();
    let ended = parsed.ends_at.map_or(false, |end_time| now > end_time);

    let mut options: Vec<PollResultOption> = parsed
        .options
        .into_iter()
        .map(|(option_id, label)| PollResultOption {
            option_id: option_id.clone(),
            label,
            votes: *vote_counts.get(&option_id).unwrap_or(&0),
        })
        .collect();

    options.sort_by(|a, b| a.option_id.cmp(&b.option_id));

    Ok(PollResults {
        poll_id: poll_event_id.to_string(),
        question: poll_event.content.clone(),
        poll_type: parsed.poll_type,
        total_votes,
        options,
        ended,
        ends_at: parsed.ends_at,
    })
}

fn parse_poll_tags(tags: &Tags) -> PollParsed {
    let mut options_map: HashMap<String, String> = HashMap::new();
    let mut poll_type = "singlechoice".to_string();
    let mut ends_at = None;

    for tag in tags.iter() {
        let tag_vec = tag.clone().to_vec();
        if tag_vec.is_empty() {
            continue;
        }

        match tag_vec[0].as_str() {
            "option" if tag_vec.len() >= 3 => {
                options_map.insert(tag_vec[1].clone(), tag_vec[2].clone());
            }
            "polltype" if tag_vec.len() >= 2 => {
                poll_type = tag_vec[1].clone();
            }
            "endsAt" if tag_vec.len() >= 2 => {
                if let Ok(timestamp) = tag_vec[1].parse::<u64>() {
                    ends_at = Some(timestamp);
                }
            }
            _ => {}
        }
    }

    PollParsed {
        options: options_map,
        poll_type,
        ends_at,
    }
}

fn tally_votes<'a, I>(
    vote_events: I,
    options_map: &HashMap<String, String>,
    ends_at: Option<u64>,
) -> (HashMap<String, u64>, u64)
where
    I: IntoIterator<Item = &'a Event>,
{
    let mut vote_counts: HashMap<String, u64> = HashMap::new();
    let mut votes_by_pubkey: HashMap<String, (u64, Vec<String>)> = HashMap::new();

    for vote_event in vote_events {
        let vote_time = vote_event.created_at.as_secs();

        if let Some(end_time) = ends_at {
            if vote_time > end_time {
                continue;
            }
        }

        let pubkey = vote_event.pubkey.to_hex();
        let mut selected_options = Vec::new();

        for tag in vote_event.tags.iter() {
            let tag_vec = tag.clone().to_vec();
            if tag_vec.len() >= 2 && tag_vec[0] == "response" {
                selected_options.push(tag_vec[1].clone());
            }
        }

        if selected_options.is_empty() {
            continue;
        }

        if let Some((existing_time, _)) = votes_by_pubkey.get(&pubkey) {
            if vote_time <= *existing_time {
                continue;
            }
        }

        votes_by_pubkey.insert(pubkey, (vote_time, selected_options));
    }

    for (_, (_time, selected_options)) in votes_by_pubkey.iter() {
        for option_id in selected_options {
            if options_map.contains_key(option_id) {
                *vote_counts.entry(option_id.clone()).or_insert(0) += 1;
            }
        }
    }

    let total_votes = votes_by_pubkey.len() as u64;

    (vote_counts, total_votes)
}

#[cfg(test)]
mod tests {
    use super::{parse_poll_tags, tally_votes};
    use nostr_sdk::prelude::*;
    use std::collections::HashMap;

    #[test]
    fn poll_tags_extract_fields() {
        let tags = vec![
            Tag::parse(&["option".to_string(), "a".to_string(), "Alpha".to_string()]).unwrap(),
            Tag::parse(&["option".to_string(), "b".to_string(), "Beta".to_string()]).unwrap(),
            Tag::parse(&["relay".to_string(), "wss://relay.example".to_string()]).unwrap(),
            Tag::parse(&["polltype".to_string(), "multiplechoice".to_string()]).unwrap(),
            Tag::parse(&["endsAt".to_string(), "123".to_string()]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::from(1068), "question")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(1))
            .sign_with_keys(&Keys::generate())
            .unwrap();

        let parsed = parse_poll_tags(&event.tags);

        assert_eq!(parsed.poll_type, "multiplechoice");
        assert_eq!(parsed.ends_at, Some(123));
        assert_eq!(parsed.options.get("a"), Some(&"Alpha".to_string()));
        assert_eq!(parsed.options.get("b"), Some(&"Beta".to_string()));
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

        let votes = vec![vote_a.clone(), vote_b.clone(), late_vote];
        let (counts, total_votes) = tally_votes(votes.iter(), &options_map, Some(250));

        assert_eq!(total_votes, 1);
        assert_eq!(*counts.get("a").unwrap_or(&0), 0);
        assert_eq!(*counts.get("b").unwrap_or(&0), 1);
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
}
