use nostr::prelude::Url;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip30ParseArgs {
    pub content: String,
    pub tags: Option<Vec<Vec<String>>>,
    pub kind: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct Nip30ParseResult {
    pub tags: Vec<Nip30EmojiTag>,
    pub mentions: Vec<Nip30EmojiMention>,
    pub kind: Option<u16>,
    pub kind_supported: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Nip30EmojiTag {
    pub shortcode: String,
    pub url: Option<String>,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Nip30EmojiMention {
    pub raw: String,
    pub shortcode: String,
    pub url: Option<String>,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

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

fn parse_emoji_tags(
    tags: Vec<Vec<String>>,
) -> (Vec<Nip30EmojiTag>, HashMap<String, String>) {
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

fn extract_mentions(
    content: &str,
    emoji_map: &HashMap<String, String>,
) -> Vec<Nip30EmojiMention> {
    let mut mentions = Vec::new();
    let bytes = content.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b':' {
            if let Some(end) = find_next_colon(bytes, index + 1) {
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
    use super::{extract_mentions, is_supported_kind, parse_emoji_tags, parse_nip30_emojis};
    use super::Nip30ParseArgs;

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
        assert_eq!(mentions[0].url.as_deref(), Some("https://example.com/smile.png"));
    }

    #[test]
    fn mentions_without_tags_are_invalid() {
        let mentions = extract_mentions("hi :smile:", &std::collections::HashMap::new());

        assert_eq!(mentions.len(), 1);
        assert!(!mentions[0].valid);
        assert_eq!(mentions[0].error.as_deref(), Some("missing emoji tag"));
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
    fn parse_nip30_emojis_sets_kind_supported() {
        let result = parse_nip30_emojis(Nip30ParseArgs {
            content: "hi".to_string(),
            tags: None,
            kind: Some(1),
        });

        assert_eq!(result.kind_supported, Some(true));
    }
}
