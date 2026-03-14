use crate::error::CoreError;
use crate::nip01;
use nostr_mcp_types::events::{
    EventsListArgs, LongFormListArgs, QueryEventsArgs, SearchEventsArgs,
};
use nostr_sdk::prelude::*;

pub struct EventFilterService;

impl EventFilterService {
    pub fn preset_filter(
        active_pubkey: PublicKey,
        args: &EventsListArgs,
    ) -> Result<Filter, CoreError> {
        nip01::validate_time_bounds(args.since, args.until)?;
        nip01::validate_limit(args.limit)?;

        let since = args.since.map(Timestamp::from);
        let until = args.until.map(Timestamp::from);
        let mut filter = match args.preset.to_ascii_lowercase().as_str() {
            "my_notes" => Self::my_notes(active_pubkey, since, until),
            "mentions_me" => Self::mentions_me(active_pubkey, since, until),
            "my_metadata" => Self::my_metadata(active_pubkey),
            "by_author" => {
                let author_npub = args.author_npub.as_deref().ok_or_else(|| {
                    CoreError::invalid_input("author_npub is required for preset 'by_author'")
                })?;
                Self::by_author(author_npub, since, until)?
            }
            "by_kind" => {
                let kind = args.kind.ok_or_else(|| {
                    CoreError::invalid_input("kind is required for preset 'by_kind'")
                })?;
                Self::by_kind(kind, args.author_npub.as_deref(), since, until)?
            }
            _ => return Err(CoreError::invalid_input("unknown preset")),
        };

        if let Some(limit) = args.limit {
            filter = filter.limit(limit as usize);
        }

        Ok(filter)
    }

    pub fn my_notes(
        pubkey: PublicKey,
        since: Option<Timestamp>,
        until: Option<Timestamp>,
    ) -> Filter {
        let default_since = Timestamp::now() - 86400 * 7;
        let mut filter = Filter::new()
            .author(pubkey)
            .kind(Kind::TextNote)
            .since(since.unwrap_or(default_since));

        if let Some(until) = until {
            filter = filter.until(until);
        }

        filter
    }

    pub fn mentions_me(
        pubkey: PublicKey,
        since: Option<Timestamp>,
        until: Option<Timestamp>,
    ) -> Filter {
        let default_since = Timestamp::now() - 86400 * 7;
        let mut filter = Filter::new()
            .kind(Kind::TextNote)
            .pubkey(pubkey)
            .since(since.unwrap_or(default_since));

        if let Some(until) = until {
            filter = filter.until(until);
        }

        filter
    }

    pub fn my_metadata(pubkey: PublicKey) -> Filter {
        Filter::new().author(pubkey).kind(Kind::Metadata).limit(1)
    }

    pub fn query_filters(args: &QueryEventsArgs) -> Result<Vec<Filter>, CoreError> {
        if args.filters.is_empty() {
            return Err(CoreError::invalid_input("filters must not be empty"));
        }
        nip01::validate_limit(args.limit)?;

        let mut filters = Vec::with_capacity(args.filters.len());
        for value in &args.filters {
            let mut filter: Filter = serde_json::from_value(value.clone())
                .map_err(|err| CoreError::invalid_input(format!("invalid filter json: {err}")))?;
            if let Some(limit) = args.limit {
                filter.limit = Some(limit as usize);
            }
            validate_filter_bounds(&filter)?;
            filters.push(filter);
        }

        Ok(filters)
    }

    pub fn search_filter(args: &SearchEventsArgs) -> Result<Filter, CoreError> {
        nip01::validate_time_bounds(args.since, args.until)?;
        nip01::validate_limit(args.limit)?;

        let query = args.query.trim();
        if query.is_empty() {
            return Err(CoreError::invalid_input("query must not be empty"));
        }

        let mut filter = Filter::new().search(query.to_string());

        if let Some(kinds) = &args.kinds {
            if kinds.is_empty() {
                return Err(CoreError::invalid_input("kinds must not be empty"));
            }
            let parsed_kinds = kinds.iter().copied().map(Kind::from).collect::<Vec<_>>();
            filter = filter.kinds(parsed_kinds);
        }

        if let Some(author_npub) = &args.author_npub {
            let pubkey = parse_public_key_with_context("author npub", author_npub)?;
            filter = filter.author(pubkey);
        }

        if let Some(since) = args.since {
            filter = filter.since(Timestamp::from(since));
        }

        if let Some(until) = args.until {
            filter = filter.until(Timestamp::from(until));
        }

        if let Some(limit) = args.limit {
            filter = filter.limit(limit as usize);
        }

        Ok(filter)
    }

    pub fn long_form_filter(args: &LongFormListArgs) -> Result<Filter, CoreError> {
        nip01::validate_time_bounds(args.since, args.until)?;
        nip01::validate_limit(args.limit)?;

        let mut filter = Filter::new().kind(Kind::from(30023));
        let mut has_constraint = false;

        if let Some(author_npub) = &args.author_npub {
            let pubkey = parse_public_key_with_context("author npub", author_npub)?;
            filter = filter.author(pubkey);
            has_constraint = true;
        }

        if let Some(identifier) = &args.identifier {
            filter = filter.identifier(ensure_non_empty("identifier", identifier)?);
            has_constraint = true;
        }

        if let Some(hashtags) = &args.hashtags {
            if hashtags.is_empty() {
                return Err(CoreError::invalid_input("hashtags must not be empty"));
            }

            let mut cleaned = Vec::with_capacity(hashtags.len());
            for hashtag in hashtags {
                cleaned.push(ensure_non_empty("hashtag", hashtag)?);
            }
            filter = filter.hashtags(cleaned);
            has_constraint = true;
        }

        if let Some(since) = args.since {
            filter = filter.since(Timestamp::from(since));
        }

        if let Some(until) = args.until {
            filter = filter.until(Timestamp::from(until));
        }

        if let Some(limit) = args.limit {
            filter = filter.limit(limit as usize);
        }

        if !has_constraint {
            return Err(CoreError::invalid_input(
                "at least one of author_npub, identifier, or hashtags is required",
            ));
        }

        Ok(filter)
    }

    fn by_author(
        author_npub: &str,
        since: Option<Timestamp>,
        until: Option<Timestamp>,
    ) -> Result<Filter, CoreError> {
        let pubkey = parse_public_key(author_npub)?;
        let default_since = Timestamp::now() - 86400 * 7;
        let mut filter = Filter::new()
            .author(pubkey)
            .since(since.unwrap_or(default_since));

        if let Some(until) = until {
            filter = filter.until(until);
        }

        Ok(filter)
    }

    fn by_kind(
        kind: u16,
        author_npub: Option<&str>,
        since: Option<Timestamp>,
        until: Option<Timestamp>,
    ) -> Result<Filter, CoreError> {
        let default_since = Timestamp::now() - 86400 * 7;
        let mut filter = Filter::new()
            .kind(Kind::from(kind))
            .since(since.unwrap_or(default_since));

        if let Some(until) = until {
            filter = filter.until(until);
        }

        if let Some(author_npub) = author_npub {
            filter = filter.author(parse_public_key(author_npub)?);
        }

        Ok(filter)
    }
}

fn ensure_non_empty(label: &str, value: &str) -> Result<String, CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CoreError::invalid_input(format!(
            "{label} must not be empty"
        )));
    }
    Ok(trimmed.to_string())
}

fn parse_public_key(author_npub: &str) -> Result<PublicKey, CoreError> {
    PublicKey::from_bech32(author_npub).map_err(|err| CoreError::invalid_input(err.to_string()))
}

fn parse_public_key_with_context(label: &str, author_npub: &str) -> Result<PublicKey, CoreError> {
    PublicKey::from_bech32(author_npub)
        .map_err(|err| CoreError::invalid_input(format!("invalid {label}: {err}")))
}

fn validate_filter_bounds(filter: &Filter) -> Result<(), CoreError> {
    let since = filter.since.map(|timestamp| timestamp.as_secs());
    let until = filter.until.map(|timestamp| timestamp.as_secs());
    nip01::validate_time_bounds(since, until)?;
    let limit = filter.limit.map(|value| value as u64);
    nip01::validate_limit(limit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        EventFilterService, ensure_non_empty, parse_public_key, parse_public_key_with_context,
    };
    use nostr_mcp_types::events::{
        EventsListArgs, LongFormListArgs, QueryEventsArgs, SearchEventsArgs,
    };
    use nostr_sdk::prelude::*;
    use serde_json::json;

    #[test]
    fn my_notes_sets_kind_and_author() {
        let pubkey = Keys::generate().public_key();
        let since = Timestamp::from(100);
        let until = Timestamp::from(200);
        let filter = EventFilterService::my_notes(pubkey, Some(since), Some(until));

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        assert!(filter.authors.as_ref().unwrap().contains(&pubkey));
        assert_eq!(filter.since, Some(since));
        assert_eq!(filter.until, Some(until));
    }

    #[test]
    fn my_notes_uses_default_since_without_until() {
        let pubkey = Keys::generate().public_key();
        let filter = EventFilterService::my_notes(pubkey, None, None);

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        assert!(filter.authors.as_ref().unwrap().contains(&pubkey));
        assert!(filter.since.is_some());
        assert_eq!(filter.until, None);
    }

    #[test]
    fn mentions_me_sets_search() {
        let pubkey = Keys::generate().public_key();
        let filter = EventFilterService::mentions_me(pubkey, None, None);

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        let p_tag = SingleLetterTag::lowercase(Alphabet::P);
        assert!(
            filter
                .generic_tags
                .get(&p_tag)
                .unwrap()
                .contains(&pubkey.to_hex())
        );
        assert!(filter.since.is_some());
    }

    #[test]
    fn my_metadata_limits_to_one() {
        let pubkey = Keys::generate().public_key();
        let filter = EventFilterService::my_metadata(pubkey);

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::Metadata));
        assert_eq!(filter.limit, Some(1));
    }

    #[test]
    fn preset_filter_requires_author_for_by_author() {
        let args = EventsListArgs {
            preset: "by_author".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: None,
            kind: None,
            since: None,
            until: None,
        };

        let err =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap_err();

        assert!(err.to_string().contains("author_npub is required"));
    }

    #[test]
    fn preset_filter_by_kind_includes_optional_author() {
        let keys = Keys::generate();
        let args = EventsListArgs {
            preset: "by_kind".to_string(),
            limit: Some(5),
            timeout_secs: None,
            author_npub: Some(keys.public_key().to_bech32().unwrap()),
            kind: Some(1),
            since: Some(10),
            until: Some(20),
        };

        let filter =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap();

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        assert!(
            filter
                .authors
                .as_ref()
                .unwrap()
                .contains(&keys.public_key())
        );
        assert_eq!(filter.limit, Some(5));
        assert_eq!(filter.since, Some(Timestamp::from(10)));
        assert_eq!(filter.until, Some(Timestamp::from(20)));
    }

    #[test]
    fn preset_filter_supports_my_notes_preset() {
        let active_pubkey = Keys::generate().public_key();
        let args = EventsListArgs {
            preset: "my_notes".to_string(),
            limit: Some(4),
            timeout_secs: None,
            author_npub: None,
            kind: None,
            since: Some(10),
            until: Some(20),
        };

        let filter = EventFilterService::preset_filter(active_pubkey, &args).unwrap();

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        assert!(filter.authors.as_ref().unwrap().contains(&active_pubkey));
        assert_eq!(filter.limit, Some(4));
        assert_eq!(filter.since, Some(Timestamp::from(10)));
        assert_eq!(filter.until, Some(Timestamp::from(20)));
    }

    #[test]
    fn preset_filter_supports_mentions_me_preset() {
        let active_pubkey = Keys::generate().public_key();
        let args = EventsListArgs {
            preset: "mentions_me".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: None,
            kind: None,
            since: None,
            until: Some(20),
        };

        let filter = EventFilterService::preset_filter(active_pubkey, &args).unwrap();

        let p_tag = SingleLetterTag::lowercase(Alphabet::P);
        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        assert!(
            filter
                .generic_tags
                .get(&p_tag)
                .unwrap()
                .contains(&active_pubkey.to_hex())
        );
        assert!(filter.since.is_some());
        assert_eq!(filter.until, Some(Timestamp::from(20)));
    }

    #[test]
    fn preset_filter_supports_my_metadata_preset() {
        let active_pubkey = Keys::generate().public_key();
        let args = EventsListArgs {
            preset: "my_metadata".to_string(),
            limit: Some(2),
            timeout_secs: None,
            author_npub: None,
            kind: None,
            since: None,
            until: None,
        };

        let filter = EventFilterService::preset_filter(active_pubkey, &args).unwrap();

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::Metadata));
        assert!(filter.authors.as_ref().unwrap().contains(&active_pubkey));
        assert_eq!(filter.limit, Some(2));
    }

    #[test]
    fn preset_filter_by_author_uses_default_since() {
        let keys = Keys::generate();
        let args = EventsListArgs {
            preset: "by_author".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: Some(keys.public_key().to_bech32().unwrap()),
            kind: None,
            since: None,
            until: None,
        };

        let filter =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap();

        assert!(filter.authors.as_ref().unwrap().contains(&keys.public_key()));
        assert!(filter.since.is_some());
        assert_eq!(filter.until, None);
    }

    #[test]
    fn preset_filter_by_author_preserves_until() {
        let keys = Keys::generate();
        let args = EventsListArgs {
            preset: "by_author".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: Some(keys.public_key().to_bech32().unwrap()),
            kind: None,
            since: Some(10),
            until: Some(20),
        };

        let filter =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap();

        assert!(filter.authors.as_ref().unwrap().contains(&keys.public_key()));
        assert_eq!(filter.since, Some(Timestamp::from(10)));
        assert_eq!(filter.until, Some(Timestamp::from(20)));
    }

    #[test]
    fn preset_filter_by_kind_requires_kind() {
        let args = EventsListArgs {
            preset: "by_kind".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: None,
            kind: None,
            since: None,
            until: None,
        };

        let err =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap_err();

        assert!(err.to_string().contains("kind is required"));
    }

    #[test]
    fn preset_filter_by_kind_allows_missing_author() {
        let args = EventsListArgs {
            preset: "by_kind".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: None,
            kind: Some(30023),
            since: None,
            until: None,
        };

        let filter =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap();

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::from(30023)));
        assert!(filter.authors.is_none());
        assert!(filter.since.is_some());
        assert_eq!(filter.until, None);
    }

    #[test]
    fn preset_filter_by_kind_rejects_invalid_optional_author() {
        let args = EventsListArgs {
            preset: "by_kind".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: Some("invalid".to_string()),
            kind: Some(1),
            since: None,
            until: None,
        };

        let err =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap_err();

        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn preset_filter_rejects_unknown_preset() {
        let args = EventsListArgs {
            preset: "other".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: None,
            kind: None,
            since: None,
            until: None,
        };

        let err =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap_err();

        assert!(err.to_string().contains("unknown preset"));
    }

    #[test]
    fn preset_filter_rejects_zero_limit() {
        let args = EventsListArgs {
            preset: "my_notes".to_string(),
            limit: Some(0),
            timeout_secs: None,
            author_npub: None,
            kind: None,
            since: None,
            until: None,
        };

        let err =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap_err();

        assert!(err.to_string().contains("limit must be"));
    }

    #[test]
    fn preset_filter_rejects_reverse_time_bounds() {
        let args = EventsListArgs {
            preset: "my_notes".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: None,
            kind: None,
            since: Some(20),
            until: Some(10),
        };

        let err =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap_err();

        assert!(err.to_string().contains("since must be"));
    }

    #[test]
    fn preset_filter_by_author_rejects_invalid_author() {
        let args = EventsListArgs {
            preset: "by_author".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: Some("invalid".to_string()),
            kind: None,
            since: None,
            until: None,
        };

        let err =
            EventFilterService::preset_filter(Keys::generate().public_key(), &args).unwrap_err();

        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn parse_filters_rejects_empty() {
        let args = QueryEventsArgs {
            filters: vec![],
            timeout_secs: None,
            limit: None,
        };
        let err = EventFilterService::query_filters(&args).unwrap_err();

        assert!(err.to_string().contains("filters must not be empty"));
    }

    #[test]
    fn parse_filters_rejects_invalid_time_bounds() {
        let args = QueryEventsArgs {
            filters: vec![json!({
                "kinds": [1],
                "since": 20,
                "until": 10
            })],
            timeout_secs: None,
            limit: None,
        };
        let err = EventFilterService::query_filters(&args).unwrap_err();

        assert!(err.to_string().contains("since must be"));
    }

    #[test]
    fn parse_filters_applies_limit_override() {
        let args = QueryEventsArgs {
            filters: vec![json!({
                "kinds": [1],
                "limit": 1
            })],
            timeout_secs: None,
            limit: Some(5),
        };
        let filters = EventFilterService::query_filters(&args).unwrap();

        assert_eq!(filters[0].limit, Some(5));
    }

    #[test]
    fn parse_filters_rejects_invalid_json() {
        let args = QueryEventsArgs {
            filters: vec![json!("bad-filter")],
            timeout_secs: None,
            limit: None,
        };

        let err = EventFilterService::query_filters(&args).unwrap_err();

        assert!(err.to_string().contains("invalid filter json"));
    }

    #[test]
    fn parse_filters_reject_invalid_limit_in_payload() {
        let args = QueryEventsArgs {
            filters: vec![json!({
                "kinds": [1],
                "limit": 0
            })],
            timeout_secs: None,
            limit: None,
        };

        let err = EventFilterService::query_filters(&args).unwrap_err();

        assert!(err.to_string().contains("limit must be"));
    }

    #[test]
    fn parse_filters_reject_zero_limit_override() {
        let args = QueryEventsArgs {
            filters: vec![json!({
                "kinds": [1]
            })],
            timeout_secs: None,
            limit: Some(0),
        };

        let err = EventFilterService::query_filters(&args).unwrap_err();

        assert!(err.to_string().contains("limit must be"));
    }

    #[test]
    fn parse_filters_accept_valid_payload_without_override() {
        let keys = Keys::generate();
        let args = QueryEventsArgs {
            filters: vec![json!({
                "authors": [keys.public_key().to_hex()],
                "kinds": [1],
                "since": 10,
                "until": 20,
                "limit": 2
            })],
            timeout_secs: None,
            limit: None,
        };

        let filters = EventFilterService::query_filters(&args).unwrap();

        assert!(filters[0].authors.as_ref().unwrap().contains(&keys.public_key()));
        assert_eq!(filters[0].limit, Some(2));
        assert_eq!(filters[0].since, Some(Timestamp::from(10)));
        assert_eq!(filters[0].until, Some(Timestamp::from(20)));
    }

    #[test]
    fn long_form_filter_requires_constraint() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: None,
            hashtags: None,
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::long_form_filter(&args).unwrap_err();

        assert!(
            err.to_string()
                .contains("at least one of author_npub, identifier, or hashtags is required")
        );
    }

    #[test]
    fn long_form_filter_includes_author_kind_and_tags() {
        let keys = Keys::generate();
        let args = LongFormListArgs {
            author_npub: Some(keys.public_key().to_bech32().unwrap()),
            identifier: Some("post-1".to_string()),
            hashtags: Some(vec!["nostr".to_string()]),
            limit: Some(5),
            since: Some(10),
            until: Some(20),
            timeout_secs: None,
        };

        let filter = EventFilterService::long_form_filter(&args).unwrap();

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::from(30023)));
        assert_eq!(filter.limit, Some(5));
        assert_eq!(filter.since, Some(Timestamp::from(10)));
        assert_eq!(filter.until, Some(Timestamp::from(20)));
        assert!(
            filter
                .authors
                .as_ref()
                .unwrap()
                .contains(&keys.public_key())
        );

        let hashtag_tag = SingleLetterTag::lowercase(Alphabet::T);
        let identifier_tag = SingleLetterTag::lowercase(Alphabet::D);
        assert!(
            filter
                .generic_tags
                .get(&hashtag_tag)
                .unwrap()
                .contains("nostr")
        );
        assert!(
            filter
                .generic_tags
                .get(&identifier_tag)
                .unwrap()
                .contains("post-1")
        );
    }

    #[test]
    fn long_form_filter_rejects_empty_identifier() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: Some("   ".to_string()),
            hashtags: Some(vec!["nostr".to_string()]),
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::long_form_filter(&args).unwrap_err();

        assert!(err.to_string().contains("identifier must not be empty"));
    }

    #[test]
    fn long_form_filter_rejects_empty_hashtag() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: Some("post-1".to_string()),
            hashtags: Some(vec![" ".to_string()]),
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::long_form_filter(&args).unwrap_err();

        assert!(err.to_string().contains("hashtag must not be empty"));
    }

    #[test]
    fn long_form_filter_rejects_empty_hashtag_list() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: Some("post-1".to_string()),
            hashtags: Some(vec![]),
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::long_form_filter(&args).unwrap_err();

        assert!(err.to_string().contains("hashtags must not be empty"));
    }

    #[test]
    fn long_form_filter_rejects_invalid_author() {
        let args = LongFormListArgs {
            author_npub: Some("invalid".to_string()),
            identifier: None,
            hashtags: None,
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::long_form_filter(&args).unwrap_err();

        assert!(err.to_string().contains("invalid author npub"));
    }

    #[test]
    fn long_form_filter_rejects_reverse_time_bounds() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: Some("post-1".to_string()),
            hashtags: None,
            limit: None,
            since: Some(20),
            until: Some(10),
            timeout_secs: None,
        };

        let err = EventFilterService::long_form_filter(&args).unwrap_err();

        assert!(err.to_string().contains("since must be"));
    }

    #[test]
    fn long_form_filter_rejects_zero_limit() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: Some("post-1".to_string()),
            hashtags: None,
            limit: Some(0),
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::long_form_filter(&args).unwrap_err();

        assert!(err.to_string().contains("limit must be"));
    }

    #[test]
    fn long_form_filter_accepts_identifier_only_constraint() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: Some(" post-1 ".to_string()),
            hashtags: None,
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let filter = EventFilterService::long_form_filter(&args).unwrap();
        let identifier_tag = SingleLetterTag::lowercase(Alphabet::D);

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::from(30023)));
        assert!(
            filter
                .generic_tags
                .get(&identifier_tag)
                .unwrap()
                .contains("post-1")
        );
    }

    #[test]
    fn search_filter_rejects_empty_query() {
        let args = SearchEventsArgs {
            query: "   ".to_string(),
            kinds: None,
            author_npub: None,
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::search_filter(&args).unwrap_err();

        assert!(err.to_string().contains("query must not be empty"));
    }

    #[test]
    fn search_filter_rejects_empty_kinds() {
        let args = SearchEventsArgs {
            query: "nostr".to_string(),
            kinds: Some(vec![]),
            author_npub: None,
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::search_filter(&args).unwrap_err();

        assert!(err.to_string().contains("kinds must not be empty"));
    }

    #[test]
    fn search_filter_accepts_all_supported_fields() {
        let keys = Keys::generate();
        let args = SearchEventsArgs {
            query: "  nostr search  ".to_string(),
            kinds: Some(vec![1, 30023]),
            author_npub: Some(keys.public_key().to_bech32().unwrap()),
            limit: Some(9),
            since: Some(10),
            until: Some(20),
            timeout_secs: None,
        };

        let filter = EventFilterService::search_filter(&args).unwrap();

        assert_eq!(filter.search.as_deref(), Some("nostr search"));
        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::from(30023)));
        assert!(filter.authors.as_ref().unwrap().contains(&keys.public_key()));
        assert_eq!(filter.limit, Some(9));
        assert_eq!(filter.since, Some(Timestamp::from(10)));
        assert_eq!(filter.until, Some(Timestamp::from(20)));
    }

    #[test]
    fn search_filter_accepts_query_without_limit() {
        let args = SearchEventsArgs {
            query: "nostr".to_string(),
            kinds: None,
            author_npub: None,
            limit: None,
            since: None,
            until: Some(20),
            timeout_secs: None,
        };

        let filter = EventFilterService::search_filter(&args).unwrap();

        assert_eq!(filter.search.as_deref(), Some("nostr"));
        assert_eq!(filter.limit, None);
        assert_eq!(filter.until, Some(Timestamp::from(20)));
    }

    #[test]
    fn search_filter_rejects_reverse_time_bounds() {
        let args = SearchEventsArgs {
            query: "nostr".to_string(),
            kinds: None,
            author_npub: None,
            limit: None,
            since: Some(20),
            until: Some(10),
            timeout_secs: None,
        };

        let err = EventFilterService::search_filter(&args).unwrap_err();

        assert!(err.to_string().contains("since must be"));
    }

    #[test]
    fn search_filter_rejects_zero_limit() {
        let args = SearchEventsArgs {
            query: "nostr".to_string(),
            kinds: None,
            author_npub: None,
            limit: Some(0),
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::search_filter(&args).unwrap_err();

        assert!(err.to_string().contains("limit must be"));
    }

    #[test]
    fn search_filter_rejects_invalid_author() {
        let args = SearchEventsArgs {
            query: "nostr".to_string(),
            kinds: None,
            author_npub: Some("invalid".to_string()),
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = EventFilterService::search_filter(&args).unwrap_err();

        assert!(err.to_string().contains("invalid author npub"));
    }

    #[test]
    fn helper_parsers_and_trimming_remain_stable() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();

        assert_eq!(ensure_non_empty("identifier", "  value  ").unwrap(), "value");
        assert_eq!(parse_public_key(&npub).unwrap(), keys.public_key());

        let err = parse_public_key("invalid").unwrap_err();
        assert!(err.to_string().contains("invalid"));

        let err = parse_public_key_with_context("author npub", "invalid").unwrap_err();
        assert!(err.to_string().contains("invalid author npub"));
    }
}
