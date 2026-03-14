use nostr_mcp_types::{
    events::{EventsListArgs, LongFormListArgs, QueryEventsArgs, SearchEventsArgs},
    metadata::ProfileGetArgs,
    nip05::{Nip05ResolveArgs, Nip05VerifyArgs},
    registry::{
        ToolRegistry, generated_registry_artifact_path, generated_registry_json,
        generated_tool_registry, read_generated_registry_artifact,
        write_generated_registry_artifact,
    },
    relay_info::RelayInfoArgs,
};
use std::process::Command;

#[test]
fn timeout_helpers_default_to_ten_seconds() {
    let events = EventsListArgs {
        preset: "global".to_string(),
        limit: None,
        timeout_secs: None,
        author_npub: None,
        kind: None,
        since: None,
        until: None,
    };
    let query = QueryEventsArgs {
        filters: Vec::new(),
        timeout_secs: None,
        limit: None,
    };
    let search = SearchEventsArgs {
        query: "nostr".to_string(),
        kinds: None,
        author_npub: None,
        limit: None,
        since: None,
        until: None,
        timeout_secs: None,
    };
    let long_form = LongFormListArgs {
        author_npub: None,
        identifier: None,
        hashtags: None,
        limit: None,
        since: None,
        until: None,
        timeout_secs: None,
    };
    let profile = ProfileGetArgs {
        pubkey: "pubkey".to_string(),
        timeout_secs: None,
    };
    let nip05_resolve = Nip05ResolveArgs {
        identifier: "alice@example.com".to_string(),
        timeout_secs: None,
    };
    let nip05_verify = Nip05VerifyArgs {
        identifier: "alice@example.com".to_string(),
        pubkey: "pubkey".to_string(),
        timeout_secs: None,
    };
    let relay_info = RelayInfoArgs {
        relay_url: "wss://relay.example.com".to_string(),
        timeout_secs: None,
    };

    assert_eq!(events.timeout(), 10);
    assert_eq!(query.timeout(), 10);
    assert_eq!(search.timeout(), 10);
    assert_eq!(long_form.timeout(), 10);
    assert_eq!(profile.timeout(), 10);
    assert_eq!(nip05_resolve.timeout(), 10);
    assert_eq!(nip05_verify.timeout(), 10);
    assert_eq!(relay_info.timeout(), 10);
}

#[test]
fn timeout_helpers_use_explicit_values() {
    let events = EventsListArgs {
        preset: "global".to_string(),
        limit: Some(20),
        timeout_secs: Some(11),
        author_npub: Some("npub1example".to_string()),
        kind: Some(1),
        since: Some(1),
        until: Some(2),
    };
    let query = QueryEventsArgs {
        filters: Vec::new(),
        timeout_secs: Some(12),
        limit: Some(30),
    };
    let search = SearchEventsArgs {
        query: "nostr".to_string(),
        kinds: Some(vec![1, 30023]),
        author_npub: Some("npub1example".to_string()),
        limit: Some(40),
        since: Some(3),
        until: Some(4),
        timeout_secs: Some(13),
    };
    let long_form = LongFormListArgs {
        author_npub: Some("npub1example".to_string()),
        identifier: Some("article".to_string()),
        hashtags: Some(vec!["nostr".to_string()]),
        limit: Some(50),
        since: Some(5),
        until: Some(6),
        timeout_secs: Some(14),
    };
    let profile = ProfileGetArgs {
        pubkey: "pubkey".to_string(),
        timeout_secs: Some(15),
    };
    let nip05_resolve = Nip05ResolveArgs {
        identifier: "alice@example.com".to_string(),
        timeout_secs: Some(16),
    };
    let nip05_verify = Nip05VerifyArgs {
        identifier: "alice@example.com".to_string(),
        pubkey: "pubkey".to_string(),
        timeout_secs: Some(17),
    };
    let relay_info = RelayInfoArgs {
        relay_url: "wss://relay.example.com".to_string(),
        timeout_secs: Some(18),
    };

    assert_eq!(events.timeout(), 11);
    assert_eq!(query.timeout(), 12);
    assert_eq!(search.timeout(), 13);
    assert_eq!(long_form.timeout(), 14);
    assert_eq!(profile.timeout(), 15);
    assert_eq!(nip05_resolve.timeout(), 16);
    assert_eq!(nip05_verify.timeout(), 17);
    assert_eq!(relay_info.timeout(), 18);
}

#[test]
fn registry_helpers_round_trip_through_the_public_api() {
    let registry = generated_tool_registry();
    let parsed: ToolRegistry =
        serde_json::from_str(&generated_registry_json()).expect("parse registry json");
    let stable_count = registry.stable_tools().count();
    let planned_count = registry.planned_tools().count();
    let mut no_input_schema = registry.tools[0].clone();
    no_input_schema.input_schema.clear();
    let mut no_output_schema = registry.tools[0].clone();
    no_output_schema.output_schema.clear();
    let artifact_path = write_generated_registry_artifact().expect("write registry artifact");

    assert_eq!(parsed, registry);
    assert_eq!(artifact_path, generated_registry_artifact_path());
    assert_eq!(read_generated_registry_artifact(), registry);
    assert!(stable_count > 0);
    assert!(planned_count > 0);
    assert_eq!(stable_count + planned_count, registry.tools.len());
    assert!(registry.tools.iter().all(|tool| tool.has_input_schema()));
    assert!(registry.tools.iter().all(|tool| tool.has_output_schema()));
    assert!(!no_input_schema.has_input_schema());
    assert!(!no_output_schema.has_output_schema());
}

#[test]
fn generator_binary_writes_the_generated_registry_artifact() {
    let output = Command::new(env!("CARGO_BIN_EXE_generate-tool-registry"))
        .output()
        .expect("run generate-tool-registry");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("utf8 stdout")
            .trim(),
        generated_registry_artifact_path().display().to_string()
    );
    assert_eq!(
        read_generated_registry_artifact(),
        generated_tool_registry()
    );
}
