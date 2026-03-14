use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs;
use std::path::PathBuf;

use crate::{
    common, config, events, follows, groups, key_store, keys, metadata, nip05, nip19, nip30, nip44,
    nip58, nip89, polls, publish, references, relay_info, relays, replies,
};

pub const SPEC_VERSION: &str = "0.1.12";
pub const REGISTRY_VERSION: &str = "0.1.12";

pub type JsonSchemaMap = Map<String, Value>;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Stable,
    Planned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolContract {
    pub name: String,
    pub status: ToolStatus,
    pub summary: String,
    #[serde(default)]
    pub nip: Vec<String>,
    #[serde(default)]
    pub input_schema: JsonSchemaMap,
    #[serde(default)]
    pub output_schema: JsonSchemaMap,
}

impl ToolContract {
    pub fn has_input_schema(&self) -> bool {
        !self.input_schema.is_empty()
    }

    pub fn has_output_schema(&self) -> bool {
        !self.output_schema.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolRegistry {
    pub spec_version: String,
    pub registry_version: String,
    pub tools: Vec<ToolContract>,
}

impl ToolRegistry {
    pub fn stable_tools(&self) -> impl Iterator<Item = &ToolContract> {
        self.tools
            .iter()
            .filter(|tool| matches!(tool.status, ToolStatus::Stable))
    }

    pub fn planned_tools(&self) -> impl Iterator<Item = &ToolContract> {
        self.tools
            .iter()
            .filter(|tool| matches!(tool.status, ToolStatus::Planned))
    }
}

fn schema_map_for<T: JsonSchema>() -> JsonSchemaMap {
    let value = serde_json::to_value(schema_for!(T)).expect("serialize schema");
    match value {
        Value::Object(map) => map,
        _ => panic!("schema root must be a json object"),
    }
}

fn placeholder_schema() -> JsonSchemaMap {
    Map::from_iter([
        ("type".to_string(), Value::String("object".to_string())),
        ("additionalProperties".to_string(), Value::Bool(true)),
    ])
}

fn typed_tool<I, O>(name: &str, status: ToolStatus, summary: &str, nip: &[&str]) -> ToolContract
where
    I: JsonSchema,
    O: JsonSchema,
{
    ToolContract {
        name: name.to_string(),
        status,
        summary: summary.to_string(),
        nip: nip.iter().map(|entry| (*entry).to_string()).collect(),
        input_schema: schema_map_for::<I>(),
        output_schema: schema_map_for::<O>(),
    }
}

fn placeholder_tool(name: &str, status: ToolStatus, summary: &str, nip: &[&str]) -> ToolContract {
    ToolContract {
        name: name.to_string(),
        status,
        summary: summary.to_string(),
        nip: nip.iter().map(|entry| (*entry).to_string()).collect(),
        input_schema: placeholder_schema(),
        output_schema: placeholder_schema(),
    }
}

pub fn generated_tool_registry() -> ToolRegistry {
    ToolRegistry {
        spec_version: SPEC_VERSION.to_string(),
        registry_version: REGISTRY_VERSION.to_string(),
        tools: vec![
            typed_tool::<key_store::GenerateArgs, key_store::KeyEntry>(
                "nostr_keys_generate",
                ToolStatus::Stable,
                "Generate a new Nostr keypair.",
                &[],
            ),
            typed_tool::<key_store::ImportArgs, key_store::KeyEntry>(
                "nostr_keys_import",
                ToolStatus::Stable,
                "Import a secret key (nsec or npub).",
                &[],
            ),
            typed_tool::<key_store::RemoveArgs, key_store::KeyRemovalResult>(
                "nostr_keys_remove",
                ToolStatus::Stable,
                "Remove a key by label.",
                &[],
            ),
            typed_tool::<common::EmptyArgs, key_store::KeysListResult>(
                "nostr_keys_list",
                ToolStatus::Stable,
                "List stored keys (metadata only).",
                &[],
            ),
            typed_tool::<key_store::SetActiveArgs, key_store::KeyEntry>(
                "nostr_keys_set_active",
                ToolStatus::Stable,
                "Set active key by label.",
                &[],
            ),
            typed_tool::<common::EmptyArgs, Option<key_store::KeyEntry>>(
                "nostr_keys_get_active",
                ToolStatus::Stable,
                "Get active key (metadata only).",
                &[],
            ),
            typed_tool::<key_store::RenameLabelArgs, key_store::KeyEntry>(
                "nostr_keys_rename_label",
                ToolStatus::Stable,
                "Rename a key label.",
                &[],
            ),
            typed_tool::<key_store::ExportArgs, key_store::ExportResult>(
                "nostr_keys_export",
                ToolStatus::Stable,
                "Export a key in bech32 or hex formats.",
                &[],
            ),
            typed_tool::<keys::VerifyArgs, keys::VerifyResult>(
                "nostr_keys_verify",
                ToolStatus::Stable,
                "Verify key format and validity.",
                &[],
            ),
            typed_tool::<keys::DerivePublicArgs, keys::DerivePublicResult>(
                "nostr_keys_derive_public",
                ToolStatus::Stable,
                "Derive public key from a private key.",
                &[],
            ),
            typed_tool::<common::EmptyArgs, config::ConfigDirResult>(
                "nostr_config_dir_get",
                ToolStatus::Stable,
                "Get config directory path.",
                &[],
            ),
            typed_tool::<config::ConfigDirSetArgs, config::ConfigDirResult>(
                "nostr_config_dir_set",
                ToolStatus::Stable,
                "Set config directory path.",
                &[],
            ),
            typed_tool::<relays::RelaysSetArgs, relays::RelayListResult>(
                "nostr_relays_set",
                ToolStatus::Stable,
                "Set relays and connect.",
                &["nip-01"],
            ),
            typed_tool::<relays::RelaysConnectArgs, relays::RelayListResult>(
                "nostr_relays_connect",
                ToolStatus::Stable,
                "Connect to configured relays.",
                &["nip-01"],
            ),
            typed_tool::<relays::RelaysDisconnectArgs, relays::RelayListResult>(
                "nostr_relays_disconnect",
                ToolStatus::Stable,
                "Disconnect or remove relays.",
                &["nip-01"],
            ),
            typed_tool::<common::EmptyArgs, relays::RelayStatusResult>(
                "nostr_relays_status",
                ToolStatus::Stable,
                "List relay status and flags.",
                &["nip-01"],
            ),
            typed_tool::<relay_info::RelayInfoArgs, relay_info::RelayInfoResult>(
                "nostr_relays_get_info",
                ToolStatus::Stable,
                "Fetch relay information document.",
                &["nip-11"],
            ),
            typed_tool::<nip05::Nip05ResolveArgs, nip05::Nip05ResolveResult>(
                "nostr_nip05_resolve",
                ToolStatus::Stable,
                "Resolve a NIP-05 identifier to a pubkey and relay hints.",
                &["nip-05"],
            ),
            typed_tool::<nip05::Nip05VerifyArgs, nip05::Nip05VerifyResult>(
                "nostr_nip05_verify",
                ToolStatus::Stable,
                "Verify a NIP-05 identifier against a pubkey.",
                &["nip-05"],
            ),
            typed_tool::<nip44::Nip44EncryptArgs, nip44::Nip44EncryptResult>(
                "nostr_nip44_encrypt",
                ToolStatus::Stable,
                "Encrypt plaintext with NIP-44.",
                &["nip-44"],
            ),
            typed_tool::<nip44::Nip44DecryptArgs, nip44::Nip44DecryptResult>(
                "nostr_nip44_decrypt",
                ToolStatus::Stable,
                "Decrypt NIP-44 ciphertext.",
                &["nip-44"],
            ),
            typed_tool::<nip89::Nip89RecommendArgs, publish::SendResult>(
                "nostr_handlers_recommend",
                ToolStatus::Stable,
                "Publish a NIP-89 handler recommendation event.",
                &["nip-89"],
            ),
            typed_tool::<nip89::Nip89HandlerInfoArgs, publish::SendResult>(
                "nostr_handlers_register",
                ToolStatus::Stable,
                "Publish a NIP-89 handler information event.",
                &["nip-89"],
            ),
            typed_tool::<nip58::Nip58BadgeDefinitionArgs, publish::SendResult>(
                "nostr_badges_define",
                ToolStatus::Stable,
                "Publish a NIP-58 badge definition event.",
                &["nip-58"],
            ),
            typed_tool::<nip58::Nip58BadgeAwardArgs, publish::SendResult>(
                "nostr_badges_award",
                ToolStatus::Stable,
                "Publish a NIP-58 badge award event.",
                &["nip-58"],
            ),
            typed_tool::<nip58::Nip58ProfileBadgesArgs, publish::SendResult>(
                "nostr_badges_set_profile",
                ToolStatus::Stable,
                "Publish a NIP-58 profile badges event.",
                &["nip-58"],
            ),
            typed_tool::<nip30::Nip30ParseArgs, nip30::Nip30ParseResult>(
                "nostr_events_parse_emojis",
                ToolStatus::Stable,
                "Parse NIP-30 emoji tags and shortcode mentions.",
                &["nip-30"],
            ),
            typed_tool::<events::EventsListArgs, events::EventItemsResult>(
                "nostr_events_list",
                ToolStatus::Stable,
                "List events using presets or filters.",
                &["nip-01"],
            ),
            typed_tool::<events::QueryEventsArgs, events::EventItemsResult>(
                "nostr_events_query",
                ToolStatus::Stable,
                "Query events with NIP-01 filters.",
                &["nip-01"],
            ),
            typed_tool::<events::SearchEventsArgs, events::EventItemsResult>(
                "nostr_events_search",
                ToolStatus::Stable,
                "Search events using relay search.",
                &["nip-50"],
            ),
            typed_tool::<publish::PostTextArgs, publish::SendResult>(
                "nostr_events_post_text",
                ToolStatus::Stable,
                "Post a kind 1 text note.",
                &["nip-01"],
            ),
            typed_tool::<publish::PostThreadArgs, publish::SendResult>(
                "nostr_events_post_thread",
                ToolStatus::Stable,
                "Post a kind 11 thread event.",
                &["nip-01"],
            ),
            typed_tool::<publish::PostGroupChatArgs, publish::SendResult>(
                "nostr_events_post_group_chat",
                ToolStatus::Stable,
                "Post a kind 9 group chat message.",
                &["nip-29"],
            ),
            typed_tool::<publish::PostReactionArgs, publish::SendResult>(
                "nostr_events_post_reaction",
                ToolStatus::Stable,
                "Post a kind 7 reaction.",
                &["nip-25"],
            ),
            typed_tool::<publish::PublishSignedEventArgs, publish::SendResult>(
                "nostr_events_publish_signed",
                ToolStatus::Stable,
                "Publish a fully signed Nostr event.",
                &["nip-01"],
            ),
            typed_tool::<replies::PostReplyArgs, publish::SendResult>(
                "nostr_events_post_reply",
                ToolStatus::Stable,
                "Post a reply/comment with NIP-10 or NIP-22.",
                &["nip-10", "nip-22"],
            ),
            typed_tool::<replies::PostCommentArgs, publish::SendResult>(
                "nostr_events_post_comment",
                ToolStatus::Stable,
                "Post a kind 1111 comment.",
                &["nip-22"],
            ),
            typed_tool::<polls::CreatePollArgs, publish::SendResult>(
                "nostr_events_create_poll",
                ToolStatus::Stable,
                "Create a kind 1068 poll.",
                &["nip-88"],
            ),
            typed_tool::<polls::VotePollArgs, publish::SendResult>(
                "nostr_events_vote_poll",
                ToolStatus::Stable,
                "Vote on a poll (kind 1018).",
                &["nip-88"],
            ),
            typed_tool::<polls::GetPollResultsArgs, polls::PollResults>(
                "nostr_events_get_poll_results",
                ToolStatus::Stable,
                "Fetch poll results.",
                &["nip-88"],
            ),
            typed_tool::<groups::PutUserArgs, publish::SendResult>(
                "nostr_groups_put_user",
                ToolStatus::Stable,
                "Add or update group user (kind 9000).",
                &["nip-29"],
            ),
            typed_tool::<groups::RemoveUserArgs, publish::SendResult>(
                "nostr_groups_remove_user",
                ToolStatus::Stable,
                "Remove group user (kind 9001).",
                &["nip-29"],
            ),
            typed_tool::<groups::EditGroupMetadataArgs, publish::SendResult>(
                "nostr_groups_edit_metadata",
                ToolStatus::Stable,
                "Edit group metadata (kind 9002).",
                &["nip-29"],
            ),
            typed_tool::<groups::DeleteEventArgs, publish::SendResult>(
                "nostr_groups_delete_event",
                ToolStatus::Stable,
                "Delete group event (kind 9005).",
                &["nip-29"],
            ),
            typed_tool::<groups::CreateGroupArgs, publish::SendResult>(
                "nostr_groups_create_group",
                ToolStatus::Stable,
                "Create group (kind 9007).",
                &["nip-29"],
            ),
            typed_tool::<groups::DeleteGroupArgs, publish::SendResult>(
                "nostr_groups_delete_group",
                ToolStatus::Stable,
                "Delete group (kind 9008).",
                &["nip-29"],
            ),
            typed_tool::<groups::CreateInviteArgs, publish::SendResult>(
                "nostr_groups_create_invite",
                ToolStatus::Stable,
                "Create group invite (kind 9009).",
                &["nip-29"],
            ),
            typed_tool::<groups::JoinGroupArgs, publish::SendResult>(
                "nostr_groups_join",
                ToolStatus::Stable,
                "Request to join group (kind 9021).",
                &["nip-29"],
            ),
            typed_tool::<groups::LeaveGroupArgs, publish::SendResult>(
                "nostr_groups_leave",
                ToolStatus::Stable,
                "Request to leave group (kind 9022).",
                &["nip-29"],
            ),
            typed_tool::<metadata::SetMetadataArgs, metadata::MetadataResult>(
                "nostr_metadata_set",
                ToolStatus::Stable,
                "Set kind 0 profile metadata.",
                &["nip-01"],
            ),
            typed_tool::<common::EmptyArgs, metadata::StoredMetadataResult>(
                "nostr_metadata_get",
                ToolStatus::Stable,
                "Get local profile metadata.",
                &["nip-01"],
            ),
            typed_tool::<metadata::FetchMetadataArgs, metadata::FetchedMetadataResult>(
                "nostr_metadata_fetch",
                ToolStatus::Stable,
                "Fetch profile metadata from relays.",
                &["nip-01"],
            ),
            typed_tool::<follows::SetFollowsArgs, follows::PublishFollowsResult>(
                "nostr_follows_set",
                ToolStatus::Stable,
                "Set follow list (kind 3).",
                &["nip-02"],
            ),
            typed_tool::<common::EmptyArgs, follows::FollowsLookupResult>(
                "nostr_follows_get",
                ToolStatus::Stable,
                "Get local follow list.",
                &["nip-02"],
            ),
            typed_tool::<common::EmptyArgs, follows::FollowsLookupResult>(
                "nostr_follows_fetch",
                ToolStatus::Stable,
                "Fetch follow list from relays.",
                &["nip-02"],
            ),
            typed_tool::<follows::AddFollowArgs, follows::FollowsMutationResult>(
                "nostr_follows_add",
                ToolStatus::Stable,
                "Add follow and publish.",
                &["nip-02"],
            ),
            typed_tool::<follows::RemoveFollowArgs, follows::FollowsMutationResult>(
                "nostr_follows_remove",
                ToolStatus::Stable,
                "Remove follow and publish.",
                &["nip-02"],
            ),
            typed_tool::<nip19::Nip19EncodeArgs, nip19::Nip19EncodeResult>(
                "nostr_nip19_convert",
                ToolStatus::Planned,
                "Convert between NIP-19 encodings.",
                &["nip-19"],
            ),
            typed_tool::<nip19::Nip19DecodeArgs, nip19::Nip19DecodeResult>(
                "nostr_nip19_analyze",
                ToolStatus::Planned,
                "Analyze NIP-19 entity.",
                &["nip-19"],
            ),
            typed_tool::<publish::PostLongFormArgs, publish::SendResult>(
                "nostr_events_post_long_form",
                ToolStatus::Stable,
                "Post a kind 30023 long-form note.",
                &["nip-23"],
            ),
            typed_tool::<events::LongFormListArgs, events::EventItemsResult>(
                "nostr_events_list_long_form",
                ToolStatus::Stable,
                "List kind 30023 long-form notes.",
                &["nip-23"],
            ),
            typed_tool::<references::ParseReferencesArgs, references::ParseReferencesResult>(
                "nostr_events_parse_refs",
                ToolStatus::Stable,
                "Parse nostr: references in text content.",
                &["nip-27"],
            ),
            typed_tool::<publish::DeleteEventsArgs, publish::SendResult>(
                "nostr_events_delete",
                ToolStatus::Stable,
                "Delete events or coordinates.",
                &["nip-09"],
            ),
            placeholder_tool(
                "nostr_zaps_get_received",
                ToolStatus::Planned,
                "List received zaps.",
                &["nip-57"],
            ),
            placeholder_tool(
                "nostr_zaps_get_sent",
                ToolStatus::Planned,
                "List sent zaps.",
                &["nip-57"],
            ),
            placeholder_tool(
                "nostr_zaps_get_all",
                ToolStatus::Planned,
                "List sent and received zaps.",
                &["nip-57"],
            ),
            placeholder_tool(
                "nostr_zaps_prepare_anonymous",
                ToolStatus::Planned,
                "Prepare anonymous zap request.",
                &["nip-57"],
            ),
            placeholder_tool(
                "nostr_zaps_validate_receipt",
                ToolStatus::Planned,
                "Validate a zap receipt.",
                &["nip-57"],
            ),
            typed_tool::<metadata::ProfileGetArgs, metadata::ProfileGetResult>(
                "nostr_profiles_get",
                ToolStatus::Stable,
                "Fetch profile metadata for a pubkey.",
                &["nip-01"],
            ),
            typed_tool::<publish::CreateTextArgs, publish::CreateTextResult>(
                "nostr_events_create_text",
                ToolStatus::Stable,
                "Create unsigned kind 1 note.",
                &["nip-01"],
            ),
            typed_tool::<publish::SignEventArgs, publish::SignEventResult>(
                "nostr_events_sign",
                ToolStatus::Stable,
                "Sign an unsigned Nostr event.",
                &["nip-01"],
            ),
            typed_tool::<publish::PostAnonymousArgs, publish::SendResult>(
                "nostr_events_post_anonymous",
                ToolStatus::Stable,
                "Post anonymous note with one-time key.",
                &["nip-01"],
            ),
            typed_tool::<publish::PostRepostArgs, publish::SendResult>(
                "nostr_events_repost",
                ToolStatus::Stable,
                "Repost a signed event.",
                &["nip-18"],
            ),
        ],
    }
}

pub fn generated_registry_json() -> String {
    serde_json::to_string_pretty(&generated_tool_registry()).expect("serialize generated registry")
}

pub fn generated_registry_artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("generated/registry/tools.json")
}

pub fn write_generated_registry_artifact() -> std::io::Result<PathBuf> {
    let path = generated_registry_artifact_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, generated_registry_json())?;
    Ok(path)
}

pub fn read_generated_registry_artifact() -> ToolRegistry {
    let raw =
        fs::read_to_string(generated_registry_artifact_path()).expect("read generated registry");
    serde_json::from_str(&raw).expect("parse generated registry")
}

#[cfg(test)]
mod tests {
    use super::{
        SPEC_VERSION, ToolRegistry, generated_tool_registry, read_generated_registry_artifact,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;

    fn spec_registry_fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec/registry/tools.json")
    }

    fn registry_fixture() -> ToolRegistry {
        let raw = fs::read_to_string(spec_registry_fixture_path()).expect("read registry fixture");
        serde_json::from_str(&raw).expect("parse registry fixture")
    }

    #[test]
    fn registry_fixture_parses_into_canonical_types() {
        let registry = registry_fixture();
        let unique_names: BTreeSet<_> = registry
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();

        assert!(!registry.spec_version.trim().is_empty());
        assert!(!registry.registry_version.trim().is_empty());
        assert!(!registry.tools.is_empty());
        assert_eq!(unique_names.len(), registry.tools.len());
        assert!(registry.stable_tools().next().is_some());
        assert!(
            registry
                .tools
                .iter()
                .all(|tool| !tool.summary.trim().is_empty())
        );
    }

    #[test]
    fn generated_registry_preserves_current_registry_metadata() {
        let fixture = registry_fixture();
        let generated = generated_tool_registry();

        let fixture_metadata: Vec<_> = fixture
            .tools
            .iter()
            .map(|tool| {
                (
                    tool.name.as_str(),
                    tool.status,
                    tool.summary.as_str(),
                    tool.nip.as_slice(),
                )
            })
            .collect();
        let generated_metadata: Vec<_> = generated
            .tools
            .iter()
            .map(|tool| {
                (
                    tool.name.as_str(),
                    tool.status,
                    tool.summary.as_str(),
                    tool.nip.as_slice(),
                )
            })
            .collect();

        assert_eq!(generated.spec_version, fixture.spec_version);
        assert_eq!(generated.registry_version, fixture.registry_version);
        assert_eq!(generated.spec_version, SPEC_VERSION);
        assert_eq!(generated_metadata, fixture_metadata);
    }

    #[test]
    fn generated_registry_defines_input_and_output_schemas_for_every_tool() {
        let generated = generated_tool_registry();

        assert!(generated.tools.iter().all(|tool| tool.has_input_schema()));
        assert!(generated.tools.iter().all(|tool| tool.has_output_schema()));
    }

    #[test]
    fn generated_registry_artifact_matches_generated_registry() {
        let artifact = read_generated_registry_artifact();
        let generated = generated_tool_registry();

        assert_eq!(artifact, generated);
    }
}
