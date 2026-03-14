use crate::error::CoreError;
use crate::publish::publish_event_builder;
use nostr::nips::nip88::{Poll, PollOption as Nip88PollOption, PollResponse, PollType};
use nostr_mcp_types::polls::{CreatePollArgs, PollResultOption, PollResults, VotePollArgs};
use nostr_mcp_types::publish::SendResult;
use nostr_sdk::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedPoll {
    poll: Poll,
    pow: Option<u8>,
    to_relays: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedVote {
    response: PollResponse,
    pow: Option<u8>,
    to_relays: Option<Vec<String>>,
}

pub async fn create_poll(client: &Client, args: CreatePollArgs) -> Result<SendResult, CoreError> {
    let prepared = prepare_poll(args)?;
    let mut builder = EventBuilder::poll(prepared.poll);

    if let Some(pow) = prepared.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, prepared.to_relays).await
}

pub async fn vote_poll(client: &Client, args: VotePollArgs) -> Result<SendResult, CoreError> {
    let prepared = prepare_vote(args)?;
    let mut builder = EventBuilder::poll_response(prepared.response);

    if let Some(pow) = prepared.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, prepared.to_relays).await
}

pub async fn get_poll_results(
    client: &Client,
    poll_event_id: &str,
    timeout_secs: u64,
) -> Result<PollResults, CoreError> {
    let poll_id = parse_poll_event_id(poll_event_id)?;
    let poll_events = fetch_poll_events(client, poll_id, timeout_secs).await?;

    get_poll_results_after_poll_fetch(
        client,
        poll_event_id,
        timeout_secs,
        Timestamp::now().as_secs(),
        poll_id,
        poll_events,
    )
    .await
}

fn prepare_poll(args: CreatePollArgs) -> Result<PreparedPoll, CoreError> {
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
    Ok(PreparedPoll {
        poll: Poll {
            title: question,
            r#type: poll_type,
            options,
            relays,
            ends_at: args.ends_at.map(Timestamp::from_secs),
        },
        pow: args.pow,
        to_relays: args.to_relays,
    })
}

fn prepare_vote(args: VotePollArgs) -> Result<PreparedVote, CoreError> {
    if args.option_ids.is_empty() {
        return Err(CoreError::invalid_input(
            "must select at least one option".to_string(),
        ));
    }

    let poll_event_id = parse_poll_event_id(&args.poll_event_id)?;
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

    Ok(PreparedVote {
        response,
        pow: args.pow,
        to_relays: args.to_relays,
    })
}

fn parse_poll_event_id(poll_event_id: &str) -> Result<EventId, CoreError> {
    EventId::parse(poll_event_id.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid event id {poll_event_id}: {e}")))
}

async fn fetch_poll_events(
    client: &Client,
    poll_id: EventId,
    timeout_secs: u64,
) -> Result<Events, CoreError> {
    let poll_filter = Filter::new().id(poll_id).kind(Kind::from(1068)).limit(1);
    strict_fetch_events(client, poll_filter, timeout_secs, "fetch poll").await
}

async fn fetch_vote_events(
    client: &Client,
    poll_id: EventId,
    timeout_secs: u64,
) -> Result<Events, CoreError> {
    let vote_filter = Filter::new()
        .kind(Kind::from(1018))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::E), poll_id.to_hex());
    strict_fetch_events(client, vote_filter, timeout_secs, "fetch votes").await
}

async fn strict_fetch_events(
    client: &Client,
    filter: Filter,
    timeout_secs: u64,
    context: &str,
) -> Result<Events, CoreError> {
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let relays = client
        .pool()
        .relays_with_flag(RelayServiceFlags::READ, FlagCheck::All)
        .await;
    let mut events = Events::new(&filter);

    if relays.is_empty() {
        return Err(CoreError::operation(format!("{context}: no relays")));
    }

    for (relay_url, relay) in relays {
        let relay_events = match relay
            .fetch_events(filter.clone(), timeout, ReqExitPolicy::ExitOnEOSE)
            .await
        {
            Ok(events) => events,
            Err(error) => return Err(relay_fetch_error(context, &relay_url, error)),
        };

        for event in relay_events.into_iter() {
            events.force_insert(event);
        }
    }

    Ok(events)
}

fn relay_fetch_error<E>(context: &str, relay_url: &RelayUrl, error: E) -> CoreError
where
    E: Display,
{
    CoreError::operation(format!("{context} from {relay_url}: {error}"))
}

fn poll_from_events(events: &Events) -> Result<Poll, CoreError> {
    let poll_event = events
        .iter()
        .next()
        .ok_or_else(|| CoreError::invalid_input("poll not found".to_string()))?;

    Poll::from_event(poll_event).map_err(map_invalid_poll_event)
}

fn map_invalid_poll_event(error: nostr::nips::nip88::Error) -> CoreError {
    CoreError::invalid_input(format!("invalid poll event: {error}"))
}

async fn get_poll_results_after_poll_fetch(
    client: &Client,
    poll_event_id: &str,
    timeout_secs: u64,
    now: u64,
    poll_id: EventId,
    poll_events: Events,
) -> Result<PollResults, CoreError> {
    let poll = poll_from_events(&poll_events)?;
    let vote_events = fetch_vote_events(client, poll_id, timeout_secs).await?;

    Ok(build_poll_results(poll_event_id, poll, &vote_events, now))
}

fn build_poll_results(
    poll_event_id: &str,
    poll: Poll,
    vote_events: &Events,
    now: u64,
) -> PollResults {
    let options_map = options_map_for_poll(&poll);
    let (vote_counts, total_votes) = tally_votes(
        vote_events,
        &options_map,
        poll.r#type,
        poll.ends_at.map(|value| value.as_secs()),
    );
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

    PollResults {
        poll_id: poll_event_id.to_string(),
        question: poll.title,
        poll_type: poll.r#type.to_string(),
        total_votes,
        options,
        ended,
        ends_at: poll.ends_at.map(|value| value.as_secs()),
    }
}

fn options_map_for_poll(poll: &Poll) -> HashMap<String, String> {
    poll.options
        .iter()
        .map(|option| (option.id.clone(), option.text.clone()))
        .collect()
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

fn selected_options_from_event(vote_event: &Event) -> Vec<String> {
    let mut selected_options = Vec::new();

    for tag in vote_event.tags.iter() {
        let tag_vec = tag.clone().to_vec();
        if tag_vec.len() >= 2 && tag_vec[0] == "response" {
            selected_options.push(tag_vec[1].clone());
        }
    }

    selected_options
}

#[allow(clippy::collapsible_if)]
fn tally_votes(
    vote_events: &Events,
    options_map: &HashMap<String, String>,
    poll_type: PollType,
    ends_at: Option<u64>,
) -> (HashMap<String, u64>, u64) {
    let mut vote_counts: HashMap<String, u64> = HashMap::new();
    let mut seen_pubkeys: HashSet<String> = HashSet::new();
    let mut total_votes = 0;

    for vote_event in vote_events.iter() {
        let vote_time = vote_event.created_at.as_secs();

        if let Some(end_time) = ends_at {
            if vote_time > end_time {
                continue;
            }
        }

        let pubkey = vote_event.pubkey.to_hex();
        let selected_options = selected_options_from_event(vote_event);

        if selected_options.is_empty() {
            continue;
        }

        if !seen_pubkeys.insert(pubkey) {
            continue;
        }

        let normalized = normalize_selected_options(&selected_options, options_map, poll_type);
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
mod tests;
