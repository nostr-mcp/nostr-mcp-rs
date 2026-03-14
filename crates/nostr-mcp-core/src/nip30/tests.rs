use super::{
    extract_mentions, find_next_colon, is_supported_kind, parse_emoji_tags, parse_nip30_emojis,
};
use nostr_mcp_types::nip30::Nip30ParseArgs;

#[test]
fn parse_emoji_tags_accepts_valid() {
    let tags = vec![vec![
        "emoji".to_string(),
        "smile".to_string(),
        "https://example.com/smile.png".to_string(),
    ]];
    let (parsed, map) = parse_emoji_tags(tags);

    assert_eq!(parsed.len(), 1);
    assert!(parsed[0].valid);
    assert_eq!(map.get("smile").unwrap(), "https://example.com/smile.png");
}

#[test]
fn parse_emoji_tags_rejects_invalid_shortcode() {
    let tags = vec![vec![
        "emoji".to_string(),
        "bad-emoji".to_string(),
        "https://example.com/bad.png".to_string(),
    ]];
    let (parsed, map) = parse_emoji_tags(tags);

    assert_eq!(parsed.len(), 1);
    assert!(!parsed[0].valid);
    assert!(map.is_empty());
}

#[test]
fn parse_emoji_tags_rejects_empty_shortcode() {
    let tags = vec![vec![
        "emoji".to_string(),
        "".to_string(),
        "https://example.com/blank.png".to_string(),
    ]];
    let (parsed, map) = parse_emoji_tags(tags);

    assert_eq!(parsed.len(), 1);
    assert!(!parsed[0].valid);
    assert!(map.is_empty());
}

#[test]
fn parse_emoji_tags_rejects_invalid_url() {
    let tags = vec![vec![
        "emoji".to_string(),
        "smile".to_string(),
        "not-a-url".to_string(),
    ]];
    let (parsed, map) = parse_emoji_tags(tags);

    assert_eq!(parsed.len(), 1);
    assert!(!parsed[0].valid);
    assert!(map.is_empty());
}

#[test]
fn parse_emoji_tags_rejects_short_tags() {
    let tags = vec![vec!["emoji".to_string(), "smile".to_string()]];
    let (parsed, map) = parse_emoji_tags(tags);

    assert_eq!(parsed.len(), 1);
    assert!(!parsed[0].valid);
    assert_eq!(
        parsed[0].error.as_deref(),
        Some("emoji tag requires shortcode and url")
    );
    assert!(map.is_empty());
}

#[test]
fn parse_emoji_tags_skips_non_emoji_tags() {
    let tags = vec![vec![
        "p".to_string(),
        "smile".to_string(),
        "https://example.com/smile.png".to_string(),
    ]];
    let (parsed, map) = parse_emoji_tags(tags);

    assert!(parsed.is_empty());
    assert!(map.is_empty());
}

#[test]
fn parse_emoji_tags_skips_empty_tag() {
    let (parsed, map) = parse_emoji_tags(vec![vec![]]);

    assert!(parsed.is_empty());
    assert!(map.is_empty());
}

#[test]
fn parse_emoji_tags_preserves_first_shortcode_mapping() {
    let tags = vec![
        vec![
            "emoji".to_string(),
            "smile".to_string(),
            "https://example.com/first.png".to_string(),
        ],
        vec![
            "emoji".to_string(),
            "smile".to_string(),
            "https://example.com/second.png".to_string(),
        ],
    ];
    let (parsed, map) = parse_emoji_tags(tags);

    assert_eq!(parsed.len(), 2);
    assert_eq!(map.get("smile").unwrap(), "https://example.com/first.png");
}

#[test]
fn mentions_match_tags() {
    let tags = vec![vec![
        "emoji".to_string(),
        "smile".to_string(),
        "https://example.com/smile.png".to_string(),
    ]];
    let (parsed, map) = parse_emoji_tags(tags);
    let mentions = extract_mentions("hi :smile:", &map);

    assert!(parsed[0].valid);
    assert_eq!(mentions.len(), 1);
    assert!(mentions[0].valid);
    assert_eq!(
        mentions[0].url.as_deref(),
        Some("https://example.com/smile.png")
    );
}

#[test]
fn mentions_without_tags_are_invalid() {
    let mentions = extract_mentions("hi :smile:", &std::collections::HashMap::new());

    assert_eq!(mentions.len(), 1);
    assert!(!mentions[0].valid);
    assert_eq!(mentions[0].error.as_deref(), Some("missing emoji tag"));
}

#[test]
fn mentions_skip_empty_shortcode() {
    let mentions = extract_mentions("hi :: there", &std::collections::HashMap::new());

    assert!(mentions.is_empty());
}

#[test]
fn mentions_reject_invalid_shortcode() {
    let mentions = extract_mentions("hi :bad-emoji:", &std::collections::HashMap::new());

    assert_eq!(mentions.len(), 1);
    assert!(!mentions[0].valid);
    assert_eq!(
        mentions[0].error.as_deref(),
        Some("invalid emoji shortcode")
    );
}

#[test]
fn mentions_ignore_missing_closing_colon() {
    let mentions = extract_mentions("hi :smile", &std::collections::HashMap::new());

    assert!(mentions.is_empty());
}

#[test]
fn kind_supports_nip30_kinds() {
    assert!(is_supported_kind(0));
    assert!(is_supported_kind(1));
    assert!(is_supported_kind(7));
    assert!(is_supported_kind(30315));
    assert!(!is_supported_kind(42));
}

#[test]
fn find_next_colon_returns_none_out_of_range() {
    assert_eq!(find_next_colon(b"emoji", 5), None);
}

#[test]
fn find_next_colon_returns_none_when_not_present() {
    assert_eq!(find_next_colon(b"emoji", 0), None);
}

#[test]
fn parse_nip30_emojis_sets_kind_supported() {
    let result = parse_nip30_emojis(Nip30ParseArgs {
        content: "hi".to_string(),
        tags: None,
        kind: Some(1),
    });

    assert_eq!(result.kind_supported, Some(true));
}

#[test]
fn parse_nip30_emojis_sets_unsupported_kind() {
    let result = parse_nip30_emojis(Nip30ParseArgs {
        content: "hi".to_string(),
        tags: None,
        kind: Some(42),
    });

    assert_eq!(result.kind_supported, Some(false));
}

#[test]
fn parse_nip30_emojis_preserves_none_kind() {
    let result = parse_nip30_emojis(Nip30ParseArgs {
        content: "hi".to_string(),
        tags: None,
        kind: None,
    });

    assert_eq!(result.kind_supported, None);
}
