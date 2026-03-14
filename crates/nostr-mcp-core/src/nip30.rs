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
mod tests;
