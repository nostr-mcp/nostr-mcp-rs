use nostr::prelude::Url;
use nostr_mcp_types::nip30::{Nip30EmojiMention, Nip30EmojiTag, Nip30ParseArgs, Nip30ParseResult};
use std::collections::HashMap;

pub fn parse_nip30_emojis(args: Nip30ParseArgs) -> Nip30ParseResult {
    let (tags, map) = parse_emoji_tags(args.tags.unwrap_or_default());
    let mentions = extract_mentions(&args.content, &map);
    let kind_supported = args.kind.map(is_supported_kind);

    Nip30ParseResult {
        tags,
        mentions,
        kind: args.kind,
        kind_supported,
    }
}

fn parse_emoji_tags(tags: Vec<Vec<String>>) -> (Vec<Nip30EmojiTag>, HashMap<String, String>) {
    let mut parsed = Vec::new();
    let mut map = HashMap::new();

    for tag in tags {
        if tag.first().map(String::as_str) != Some("emoji") {
            continue;
        }

        let shortcode = tag.get(1).cloned().unwrap_or_default();
        let url_value = tag.get(2).cloned();

        if tag.len() < 3 {
            parsed.push(Nip30EmojiTag {
                shortcode,
                url: url_value,
                valid: false,
                error: Some("emoji tag requires shortcode and url".to_string()),
            });
            continue;
        }

        if !is_valid_shortcode(&shortcode) {
            parsed.push(Nip30EmojiTag {
                shortcode,
                url: url_value,
                valid: false,
                error: Some("emoji shortcode must be alphanumeric or underscore".to_string()),
            });
            continue;
        }

        let url = url_value.unwrap_or_default();
        if Url::parse(&url).is_err() {
            parsed.push(Nip30EmojiTag {
                shortcode,
                url: Some(url),
                valid: false,
                error: Some("emoji url must be a valid URL".to_string()),
            });
            continue;
        }

        if !map.contains_key(&shortcode) {
            map.insert(shortcode.clone(), url.clone());
        }

        parsed.push(Nip30EmojiTag {
            shortcode,
            url: Some(url),
            valid: true,
            error: None,
        });
    }

    (parsed, map)
}

fn extract_mentions(content: &str, emoji_map: &HashMap<String, String>) -> Vec<Nip30EmojiMention> {
    let mut mentions = Vec::new();
    let bytes = content.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b':'
            && let Some(end) = find_next_colon(bytes, index + 1)
        {
            let shortcode = &content[index + 1..end];
            let raw = content[index..=end].to_string();

            if shortcode.is_empty() {
                index = end + 1;
                continue;
            }

            if !is_valid_shortcode(shortcode) {
                mentions.push(Nip30EmojiMention {
                    raw,
                    shortcode: shortcode.to_string(),
                    url: None,
                    valid: false,
                    error: Some("invalid emoji shortcode".to_string()),
                });
                index = end + 1;
                continue;
            }

            let url = emoji_map.get(shortcode).cloned();
            let valid = url.is_some();
            let error = if valid {
                None
            } else {
                Some("missing emoji tag".to_string())
            };

            mentions.push(Nip30EmojiMention {
                raw,
                shortcode: shortcode.to_string(),
                url,
                valid,
                error,
            });

            index = end + 1;
            continue;
        }

        index += 1;
    }

    mentions
}

fn is_valid_shortcode(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_supported_kind(kind: u16) -> bool {
    matches!(kind, 0 | 1 | 7 | 30315)
}

fn find_next_colon(bytes: &[u8], start: usize) -> Option<usize> {
    if start >= bytes.len() {
        return None;
    }

    bytes[start..]
        .iter()
        .position(|&b| b == b':')
        .map(|pos| pos + start)
}

#[cfg(test)]
mod tests {
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
        assert_eq!(mentions[0].error.as_deref(), Some("invalid emoji shortcode"));
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
}
