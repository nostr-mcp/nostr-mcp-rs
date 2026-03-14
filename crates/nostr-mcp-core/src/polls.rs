use crate::error::CoreError;
use crate::publish::{SendResult, publish_event_builder};
use nostr::nips::nip88::{Poll, PollOption as Nip88PollOption, PollResponse, PollType};
use nostr_mcp_types::polls::{CreatePollArgs, VotePollArgs};
use nostr_sdk::prelude::*;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

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

pub async fn create_poll(client: &Client, args: CreatePollArgs) -> Result<SendResult, CoreError> {
    let question = ensure_non_empty("question", &args.question)?;
    if args.options.len() < 2 {
        return Err(CoreError::invalid_input(
            "poll must have at least 2 options".to_string(),
        ));
    }
    if args.relay_urls.is_empty() {
        return Err(CoreError::invalid_input(
            "relay_urls must include at least one relay".to_string(),
        ));
    }

    let mut option_ids = HashSet::new();
    let mut options = Vec::with_capacity(args.options.len());
    for option in args.options {
        let option_id = ensure_option_id(&option.option_id)?;
        let label = ensure_non_empty("option label", &option.label)?;
        if !option_ids.insert(option_id.clone()) {
            return Err(CoreError::invalid_input(format!(
                "duplicate option ID: {option_id}"
            )));
        }
        options.push(Nip88PollOption {
            id: option_id,
            text: label,
        });
    }

    let relays = parse_relays(&args.relay_urls)?;
    let poll_type = parse_poll_type(args.poll_type.as_deref())?;
    let mut builder = EventBuilder::poll(Poll {
        title: question,
        r#type: poll_type,
        options,
        relays,
        ends_at: args.ends_at.map(Timestamp::from_secs),
    });

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

    let poll_event_id = EventId::parse(args.poll_event_id.trim()).map_err(|e| {
        CoreError::invalid_input(format!("invalid event id {}: {e}", args.poll_event_id))
    })?;
    let option_ids = normalize_vote_option_ids(&args.option_ids)?;

    let response = if option_ids.len() == 1 {
        PollResponse::SingleChoice {
            poll_id: poll_event_id,
            response: option_ids[0].clone(),
        }
    } else {
        PollResponse::MultipleChoice {
            poll_id: poll_event_id,
            responses: option_ids,
        }
    };

    let mut builder = EventBuilder::poll_response(response);

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
    let poll_id = EventId::parse(poll_event_id.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid event id {poll_event_id}: {e}")))?;

    let poll_filter = Filter::new().id(poll_id).kind(Kind::from(1068)).limit(1);

    let poll_events = client
        .fetch_events(poll_filter, std::time::Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| CoreError::Nostr(format!("fetch poll: {e}")))?;

    let poll_event = poll_events
        .iter()
        .next()
        .ok_or_else(|| CoreError::invalid_input("poll not found".to_string()))?;

    let poll = Poll::from_event(poll_event)
        .map_err(|e| CoreError::invalid_input(format!("invalid poll event: {e}")))?;

    let vote_filter = Filter::new()
        .kind(Kind::from(1018))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::E), poll_id.to_hex());

    let vote_events = client
        .fetch_events(vote_filter, std::time::Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| CoreError::Nostr(format!("fetch votes: {e}")))?;

    let options_map: HashMap<String, String> = poll
        .options
        .iter()
        .map(|option| (option.id.clone(), option.text.clone()))
        .collect();

    let (vote_counts, total_votes) = tally_votes(
        vote_events.iter(),
        &options_map,
        poll.r#type,
        poll.ends_at.map(|value| value.as_secs()),
    );

    let now = Timestamp::now().as_secs();
    let ended = poll
        .ends_at
        .is_some_and(|end_time| now > end_time.as_secs());

    let mut options: Vec<PollResultOption> = options_map
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
        question: poll.title,
        poll_type: poll.r#type.to_string(),
        total_votes,
        options,
        ended,
        ends_at: poll.ends_at.map(|value| value.as_secs()),
    })
}

fn ensure_non_empty(field: &str, value: &str) -> Result<String, CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CoreError::invalid_input(format!(
            "{field} must not be empty"
        )));
    }
    Ok(trimmed.to_string())
}

fn ensure_option_id(value: &str) -> Result<String, CoreError> {
    let trimmed = ensure_non_empty("option_id", value)?;
    if !trimmed.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return Err(CoreError::invalid_input(
            "option_id must be alphanumeric".to_string(),
        ));
    }
    Ok(trimmed)
}

fn parse_poll_type(value: Option<&str>) -> Result<PollType, CoreError> {
    match value {
        Some(value) => PollType::from_str(value.trim())
            .map_err(|e| CoreError::invalid_input(format!("invalid poll_type: {e}"))),
        None => Ok(PollType::SingleChoice),
    }
}

fn parse_relays(values: &[String]) -> Result<Vec<RelayUrl>, CoreError> {
    let mut relays = Vec::with_capacity(values.len());
    for value in values {
        let relay = RelayUrl::parse(ensure_non_empty("relay url", value)?.as_str())
            .map_err(|e| CoreError::invalid_input(format!("invalid relay url: {e}")))?;
        relays.push(relay);
    }
    Ok(relays)
}

fn normalize_vote_option_ids(values: &[String]) -> Result<Vec<String>, CoreError> {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        normalized.push(ensure_option_id(value)?);
    }
    Ok(normalized)
}

fn tally_votes<'a, I>(
    vote_events: I,
    options_map: &HashMap<String, String>,
    poll_type: PollType,
    ends_at: Option<u64>,
) -> (HashMap<String, u64>, u64)
where
    I: IntoIterator<Item = &'a Event>,
{
    let mut vote_counts: HashMap<String, u64> = HashMap::new();
    let mut votes_by_pubkey: HashMap<String, (u64, Vec<String>)> = HashMap::new();

    for vote_event in vote_events {
        let vote_time = vote_event.created_at.as_secs();

        if let Some(end_time) = ends_at
            && vote_time > end_time
        {
            continue;
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

        if let Some((existing_time, _)) = votes_by_pubkey.get(&pubkey)
            && vote_time <= *existing_time
        {
            continue;
        }

        votes_by_pubkey.insert(pubkey, (vote_time, selected_options));
    }

    let mut total_votes = 0;
    for (_time, selected_options) in votes_by_pubkey.values() {
        let normalized = normalize_selected_options(selected_options, options_map, poll_type);
        if normalized.is_empty() {
            continue;
        }

        total_votes += 1;
        for option_id in normalized {
            *vote_counts.entry(option_id).or_insert(0) += 1;
        }
    }

    (vote_counts, total_votes)
}

fn normalize_selected_options(
    selected_options: &[String],
    options_map: &HashMap<String, String>,
    poll_type: PollType,
) -> Vec<String> {
    match poll_type {
        PollType::SingleChoice => selected_options
            .iter()
            .find(|option_id| options_map.contains_key(option_id.as_str()))
            .cloned()
            .into_iter()
            .collect(),
        PollType::MultipleChoice => {
            let mut seen = HashSet::new();
            let mut normalized = Vec::new();
            for option_id in selected_options {
                if options_map.contains_key(option_id.as_str()) && seen.insert(option_id.clone()) {
                    normalized.push(option_id.clone());
                }
            }
            normalized
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_selected_options, parse_poll_type, tally_votes};
    use nostr::nips::nip88::PollType;
    use nostr_sdk::prelude::*;
    use std::collections::HashMap;

    #[test]
    fn parse_poll_type_defaults_to_single_choice() {
        let poll_type = parse_poll_type(None).unwrap();
        assert_eq!(poll_type, PollType::SingleChoice);
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
