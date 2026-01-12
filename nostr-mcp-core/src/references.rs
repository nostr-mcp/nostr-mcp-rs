use nostr::nips::nip19::{FromBech32, Nip19};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ParseReferencesArgs {
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct ParseReferencesResult {
    pub references: Vec<TextReference>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceType {
    Npub,
    Nprofile,
    Note,
    Nevent,
    Naddr,
    Nsec,
    Invalid,
}

#[derive(Debug, Serialize)]
pub struct TextReference {
    pub raw: String,
    pub bech32: String,
    pub reference_type: ReferenceType,
    pub pubkey: Option<String>,
    pub event_id: Option<String>,
    pub kind: Option<u16>,
    pub identifier: Option<String>,
    pub relays: Option<Vec<String>>,
    pub error: Option<String>,
}

pub fn parse_text_references(args: ParseReferencesArgs) -> ParseReferencesResult {
    let references = extract_nostr_references(&args.content);
    ParseReferencesResult { references }
}

fn extract_nostr_references(content: &str) -> Vec<TextReference> {
    let mut out = Vec::new();
    let bytes = content.as_bytes();
    let mut index = 0;

    while let Some(pos) = find_subslice(bytes, b"nostr:", index) {
        let start = pos + "nostr:".len();
        let mut end = start;
        while end < bytes.len() && is_bech32_char(bytes[end]) {
            end += 1;
        }

        if end > start {
            let bech32 = &content[start..end];
            let raw = &content[pos..end];
            out.push(decode_reference(raw, bech32));
        }

        index = end.max(pos + 1);
    }

    out
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
            relays: Some(profile.relays.iter().map(|r| r.to_string()).collect()),
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
            pubkey: event.author.map(|pk| pk.to_hex()),
            event_id: Some(event.event_id.to_hex()),
            kind: event.kind.map(|k| k.as_u16()),
            identifier: None,
            relays: Some(event.relays.iter().map(|r| r.to_string()).collect()),
            error: None,
        },
        Ok(Nip19::Coordinate(coord)) => TextReference {
            raw: raw.to_string(),
            bech32: bech32.to_string(),
            reference_type: ReferenceType::Naddr,
            pubkey: Some(coord.public_key.to_hex()),
            event_id: None,
            kind: Some(coord.kind.as_u16()),
            identifier: Some(coord.identifier.clone()),
            relays: Some(coord.relays.iter().map(|r| r.to_string()).collect()),
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
        .map(|pos| pos + start)
}

#[cfg(test)]
mod tests {
    use super::{extract_nostr_references, ParseReferencesArgs, ReferenceType};
    use nostr::prelude::*;

    #[test]
    fn parse_text_references_finds_multiple_mentions() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let event = EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();
        let note = event.id.to_bech32().unwrap();

        let content = format!(
            "Hello nostr:{npub} and nostr:{note}!",
            npub = npub,
            note = note
        );
        let args = ParseReferencesArgs { content };
        let references = extract_nostr_references(&args.content);

        assert_eq!(references.len(), 2);
        assert!(references.iter().any(|r| matches!(r.reference_type, ReferenceType::Npub)));
        assert!(references.iter().any(|r| matches!(r.reference_type, ReferenceType::Note)));
    }

    #[test]
    fn parse_text_references_stops_on_punctuation() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let content = format!("hi nostr:{npub}, ok", npub = npub);
        let references = extract_nostr_references(&content);

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].bech32, npub);
    }

    #[test]
    fn parse_text_references_marks_invalid() {
        let content = "nostr:note1invalid".to_string();
        let references = extract_nostr_references(&content);

        assert_eq!(references.len(), 1);
        assert!(matches!(
            references[0].reference_type,
            ReferenceType::Invalid
        ));
    }
}
