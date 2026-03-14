use nostr::nips::nip19::{FromBech32, Nip19};
use nostr_mcp_types::references::{
    ParseReferencesArgs, ParseReferencesResult, ReferenceType, TextReference,
};

pub struct ReferenceParser;

impl ReferenceParser {
    pub fn parse(args: ParseReferencesArgs) -> ParseReferencesResult {
        ParseReferencesResult {
            references: Self::parse_content(&args.content),
        }
    }

    pub fn parse_content(content: &str) -> Vec<TextReference> {
        let mut references = Vec::new();
        let bytes = content.as_bytes();
        let mut index = 0;

        while let Some(position) = find_subslice(bytes, b"nostr:", index) {
            let start = position + "nostr:".len();
            let mut end = start;
            while end < bytes.len() && is_bech32_char(bytes[end]) {
                end += 1;
            }

            if end > start {
                let bech32 = &content[start..end];
                let raw = &content[position..end];
                references.push(decode_reference(raw, bech32));
            }

            index = end.max(position + 1);
        }

        references
    }
}

fn decode_reference(raw: &str, bech32: &str) -> TextReference {
    match Nip19::from_bech32(bech32) {
        Ok(Nip19::Pubkey(pubkey)) => TextReference {
            raw: raw.to_string(),
            bech32: bech32.to_string(),
            reference_type: ReferenceType::Npub,
            pubkey: Some(pubkey.to_hex()),
            event_id: None,
            kind: None,
            identifier: None,
            relays: None,
            error: None,
        },
        Ok(Nip19::Profile(profile)) => TextReference {
            raw: raw.to_string(),
            bech32: bech32.to_string(),
            reference_type: ReferenceType::Nprofile,
            pubkey: Some(profile.public_key.to_hex()),
            event_id: None,
            kind: None,
            identifier: None,
            relays: Some(
                profile
                    .relays
                    .iter()
                    .map(|relay| relay.to_string())
                    .collect(),
            ),
            error: None,
        },
        Ok(Nip19::EventId(event_id)) => TextReference {
            raw: raw.to_string(),
            bech32: bech32.to_string(),
            reference_type: ReferenceType::Note,
            pubkey: None,
            event_id: Some(event_id.to_hex()),
            kind: None,
            identifier: None,
            relays: None,
            error: None,
        },
        Ok(Nip19::Event(event)) => TextReference {
            raw: raw.to_string(),
            bech32: bech32.to_string(),
            reference_type: ReferenceType::Nevent,
            pubkey: event.author.map(|pubkey| pubkey.to_hex()),
            event_id: Some(event.event_id.to_hex()),
            kind: event.kind.map(|kind| kind.as_u16()),
            identifier: None,
            relays: Some(event.relays.iter().map(|relay| relay.to_string()).collect()),
            error: None,
        },
        Ok(Nip19::Coordinate(coordinate)) => TextReference {
            raw: raw.to_string(),
            bech32: bech32.to_string(),
            reference_type: ReferenceType::Naddr,
            pubkey: Some(coordinate.public_key.to_hex()),
            event_id: None,
            kind: Some(coordinate.kind.as_u16()),
            identifier: Some(coordinate.identifier.clone()),
            relays: Some(
                coordinate
                    .relays
                    .iter()
                    .map(|relay| relay.to_string())
                    .collect(),
            ),
            error: None,
        },
        Ok(Nip19::Secret(_)) => TextReference {
            raw: raw.to_string(),
            bech32: bech32.to_string(),
            reference_type: ReferenceType::Nsec,
            pubkey: None,
            event_id: None,
            kind: None,
            identifier: None,
            relays: None,
            error: Some("secret keys are not supported in references".to_string()),
        },
        Err(err) => TextReference {
            raw: raw.to_string(),
            bech32: bech32.to_string(),
            reference_type: ReferenceType::Invalid,
            pubkey: None,
            event_id: None,
            kind: None,
            identifier: None,
            relays: None,
            error: Some(err.to_string()),
        },
    }
}

fn is_bech32_char(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn find_subslice(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| position + start)
}

#[cfg(test)]
mod tests {
    use super::ReferenceParser;
    use nostr::prelude::*;
    use nostr_mcp_types::references::{ParseReferencesArgs, ReferenceType};

    #[test]
    fn parse_text_references_finds_multiple_mentions() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let event = EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();
        let note = event.id.to_bech32().unwrap();

        let content = format!("Hello nostr:{npub} and nostr:{note}!");
        let references = ReferenceParser::parse_content(&content);

        assert_eq!(references.len(), 2);
        assert!(
            references
                .iter()
                .any(|reference| matches!(reference.reference_type, ReferenceType::Npub))
        );
        assert!(
            references
                .iter()
                .any(|reference| matches!(reference.reference_type, ReferenceType::Note))
        );
    }

    #[test]
    fn parse_text_references_stops_on_punctuation() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let references = ReferenceParser::parse_content(&format!("hi nostr:{npub}, ok"));

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].bech32, npub);
    }

    #[test]
    fn parse_text_references_marks_invalid() {
        let references = ReferenceParser::parse_content("nostr:note1invalid");

        assert_eq!(references.len(), 1);
        assert!(matches!(
            references[0].reference_type,
            ReferenceType::Invalid
        ));
    }

    #[test]
    fn parse_wraps_references_in_result_shape() {
        let keys = Keys::generate();
        let args = ParseReferencesArgs {
            content: format!("nostr:{}", keys.public_key().to_bech32().unwrap()),
        };

        let result = ReferenceParser::parse(args);

        assert_eq!(result.references.len(), 1);
    }
}
