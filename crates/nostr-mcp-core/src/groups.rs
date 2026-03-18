use crate::error::CoreError;
use crate::publish::publish_event_builder;
use nostr_mcp_types::groups::{
    CreateGroupArgs, CreateInviteArgs, DeleteEventArgs, DeleteGroupArgs, EditGroupMetadataArgs,
    JoinGroupArgs, LeaveGroupArgs, PutUserArgs, RemoveUserArgs,
};
use nostr_mcp_types::publish::SendResult;
use nostr_sdk::prelude::*;

pub async fn put_user(client: &Client, args: PutUserArgs) -> Result<SendResult, CoreError> {
    let tags = put_user_tags(&args);
    publish_group_action(client, 9000, args.content, tags, args.pow, args.to_relays).await
}

pub async fn remove_user(client: &Client, args: RemoveUserArgs) -> Result<SendResult, CoreError> {
    let tags = remove_user_tags(&args);
    publish_group_action(
        client,
        9001,
        args.content,
        tags,
        args.pow,
        args.to_relays,
    )
    .await
}

pub async fn edit_group_metadata(
    client: &Client,
    args: EditGroupMetadataArgs,
) -> Result<SendResult, CoreError> {
    let tags = edit_group_metadata_tags(&args);
    publish_group_action(
        client,
        9002,
        args.content,
        tags,
        args.pow,
        args.to_relays,
    )
    .await
}

pub async fn delete_group_event(
    client: &Client,
    args: DeleteEventArgs,
) -> Result<SendResult, CoreError> {
    let tags = delete_event_tags(&args);
    publish_group_action(
        client,
        9005,
        args.content,
        tags,
        args.pow,
        args.to_relays,
    )
    .await
}

pub async fn create_group(client: &Client, args: CreateGroupArgs) -> Result<SendResult, CoreError> {
    let tags = create_group_tags(&args);
    publish_group_action(
        client,
        9007,
        args.content,
        tags,
        args.pow,
        args.to_relays,
    )
    .await
}

pub async fn delete_group(client: &Client, args: DeleteGroupArgs) -> Result<SendResult, CoreError> {
    let tags = delete_group_tags(&args);
    publish_group_action(
        client,
        9008,
        args.content,
        tags,
        args.pow,
        args.to_relays,
    )
    .await
}

pub async fn create_invite(
    client: &Client,
    args: CreateInviteArgs,
) -> Result<SendResult, CoreError> {
    let tags = create_invite_tags(&args);
    publish_group_action(
        client,
        9009,
        args.content,
        tags,
        args.pow,
        args.to_relays,
    )
    .await
}

pub async fn join_group(client: &Client, args: JoinGroupArgs) -> Result<SendResult, CoreError> {
    let tags = join_group_tags(&args);
    publish_group_action(
        client,
        9021,
        args.content,
        tags,
        args.pow,
        args.to_relays,
    )
    .await
}

pub async fn leave_group(client: &Client, args: LeaveGroupArgs) -> Result<SendResult, CoreError> {
    let tags = leave_group_tags(&args);
    publish_group_action(
        client,
        9022,
        args.content,
        tags,
        args.pow,
        args.to_relays,
    )
    .await
}

fn parse_pubkey(pubkey: &str) -> Result<PublicKey, CoreError> {
    PublicKey::parse(pubkey.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid public key {pubkey}: {e}")))
}

fn parse_event_id(event_id: &str) -> Result<EventId, CoreError> {
    EventId::parse(event_id.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid event id {event_id}: {e}")))
}

fn validate_group_id(group_id: &str) -> Result<String, CoreError> {
    let trimmed = group_id.trim();
    if trimmed.is_empty() {
        return Err(CoreError::invalid_input("group_id must not be empty"));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_')
    {
        return Err(CoreError::invalid_input(
            "group_id must contain only a-z, 0-9, '-' or '_'",
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_previous_refs(previous_refs: &Option<Vec<String>>) -> Result<Vec<String>, CoreError> {
    let mut validated = Vec::new();
    if let Some(previous_refs) = previous_refs {
        validated.reserve(previous_refs.len());
        for reference in previous_refs {
            let trimmed = reference.trim();
            if trimmed.len() != 8 || !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(CoreError::invalid_input(
                    "previous_refs entries must be 8-character hex prefixes",
                ));
            }
            validated.push(trimmed.to_ascii_lowercase());
        }
    }
    Ok(validated)
}

fn validate_non_empty_field(field: &str, value: &str) -> Result<String, CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CoreError::invalid_input(format!(
            "{field} must not be empty"
        )));
    }
    Ok(trimmed.to_string())
}

fn apply_optional_pow(mut builder: EventBuilder, pow: Option<u8>) -> EventBuilder {
    if let Some(pow) = pow {
        builder = builder.pow(pow);
    }

    builder
}

async fn publish_group_action(
    client: &Client,
    kind: u16,
    content: String,
    tags: Result<Vec<Tag>, CoreError>,
    pow: Option<u8>,
    to_relays: Option<Vec<String>>,
) -> Result<SendResult, CoreError> {
    let builder = apply_optional_pow(EventBuilder::new(Kind::from(kind), content).tags(tags?), pow);
    publish_event_builder(client, builder, to_relays).await
}

fn push_group_id_tag(tags: &mut Vec<Tag>, group_id: &str) {
    tags.push(Tag::custom(TagKind::h(), [group_id.to_string()]));
}

fn push_previous_tags(tags: &mut Vec<Tag>, previous_refs: &[String]) {
    for reference in previous_refs {
        tags.push(Tag::custom(TagKind::custom("previous"), [reference.clone()]));
    }
}

fn put_user_tags(args: &PutUserArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let pubkey = parse_pubkey(&args.pubkey)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id);

    let mut p_tag = vec!["p".to_string(), pubkey.to_hex()];
    if let Some(roles) = args.roles.as_ref() {
        for role in roles {
            p_tag.push(validate_non_empty_field("role", role)?);
        }
    }
    tags.push(Tag::custom(TagKind::p(), p_tag.into_iter().skip(1)));

    push_previous_tags(&mut tags, &previous_refs);
    Ok(tags)
}

fn remove_user_tags(args: &RemoveUserArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let pubkey = parse_pubkey(&args.pubkey)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id);
    tags.push(Tag::public_key(pubkey));

    push_previous_tags(&mut tags, &previous_refs);
    Ok(tags)
}

fn edit_group_metadata_tags(args: &EditGroupMetadataArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id);

    if let Some(name) = args.name.as_ref() {
        tags.push(Tag::custom(
            TagKind::custom("name"),
            [validate_non_empty_field("name", name)?],
        ));
    }

    if let Some(picture) = args.picture.as_ref() {
        let picture = validate_non_empty_field("picture", picture)?;
        Url::parse(&picture)
            .map_err(|e| CoreError::invalid_input(format!("invalid picture url: {e}")))?;
        tags.push(Tag::custom(TagKind::custom("picture"), [picture]));
    }

    if let Some(about) = args.about.as_ref() {
        tags.push(Tag::custom(
            TagKind::custom("about"),
            [validate_non_empty_field("about", about)?],
        ));
    }

    if args.unrestricted.unwrap_or(false) {
        tags.push(Tag::custom(
            TagKind::custom("unrestricted"),
            std::iter::empty::<String>(),
        ));
    }

    if args.open.unwrap_or(false) {
        tags.push(Tag::custom(
            TagKind::custom("open"),
            std::iter::empty::<String>(),
        ));
    }

    if args.visible.unwrap_or(false) {
        tags.push(Tag::custom(
            TagKind::custom("visible"),
            std::iter::empty::<String>(),
        ));
    }

    if args.public.unwrap_or(false) {
        tags.push(Tag::custom(
            TagKind::custom("public"),
            std::iter::empty::<String>(),
        ));
    }

    push_previous_tags(&mut tags, &previous_refs);
    Ok(tags)
}

fn delete_event_tags(args: &DeleteEventArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let event_id = parse_event_id(&args.event_id)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id);
    tags.push(Tag::event(event_id));

    push_previous_tags(&mut tags, &previous_refs);
    Ok(tags)
}

fn create_group_tags(args: &CreateGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id);
    push_previous_tags(&mut tags, &previous_refs);
    Ok(tags)
}

fn delete_group_tags(args: &DeleteGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id);
    push_previous_tags(&mut tags, &previous_refs);
    Ok(tags)
}

fn create_invite_tags(args: &CreateInviteArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id);

    if let Some(code) = args.code.as_ref() {
        tags.push(Tag::custom(
            TagKind::custom("code"),
            [validate_non_empty_field("code", code)?],
        ));
    }

    push_previous_tags(&mut tags, &previous_refs);
    Ok(tags)
}

fn join_group_tags(args: &JoinGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id);

    if let Some(code) = args.invite_code.as_ref() {
        tags.push(Tag::custom(
            TagKind::custom("code"),
            [validate_non_empty_field("invite_code", code)?],
        ));
    }

    Ok(tags)
}

fn leave_group_tags(args: &LeaveGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id);
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::{
        create_group, create_group_tags, create_invite, create_invite_tags, delete_group,
        delete_group_event, delete_group_tags, delete_event_tags, edit_group_metadata,
        edit_group_metadata_tags, join_group, join_group_tags, leave_group, leave_group_tags,
        parse_event_id, parse_pubkey, put_user, put_user_tags, remove_user, remove_user_tags,
        validate_group_id, validate_non_empty_field, validate_previous_refs,
    };
    use nostr_mcp_types::groups::{
        CreateGroupArgs, CreateInviteArgs, DeleteEventArgs, DeleteGroupArgs,
        EditGroupMetadataArgs, JoinGroupArgs, LeaveGroupArgs, PutUserArgs, RemoveUserArgs,
    };
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::prelude::*;
    use std::collections::HashSet;

    fn sample_pubkey() -> String {
        Keys::generate().public_key().to_hex()
    }

    fn sample_put_user_args(pubkey: String) -> PutUserArgs {
        PutUserArgs {
            content: "put user".to_string(),
            group_id: "group-1".to_string(),
            pubkey,
            roles: Some(vec!["admin".to_string(), "mod".to_string()]),
            previous_refs: Some(vec!["deadbeef".to_string()]),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_remove_user_args(pubkey: String) -> RemoveUserArgs {
        RemoveUserArgs {
            content: "remove user".to_string(),
            group_id: "group-1".to_string(),
            pubkey,
            previous_refs: Some(vec!["deadbeef".to_string()]),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_edit_group_metadata_args() -> EditGroupMetadataArgs {
        EditGroupMetadataArgs {
            content: "edit metadata".to_string(),
            group_id: "group-2".to_string(),
            name: Some("name".to_string()),
            picture: Some("https://example.com/picture.png".to_string()),
            about: Some("about".to_string()),
            unrestricted: Some(true),
            visible: Some(true),
            public: Some(true),
            open: Some(true),
            previous_refs: Some(vec!["deadbeef".to_string()]),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_delete_event_args() -> DeleteEventArgs {
        DeleteEventArgs {
            content: "delete event".to_string(),
            group_id: "group-3".to_string(),
            event_id: "0".repeat(64),
            previous_refs: Some(vec!["deadbeef".to_string()]),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_create_group_args() -> CreateGroupArgs {
        CreateGroupArgs {
            content: "create group".to_string(),
            group_id: "group-4".to_string(),
            previous_refs: Some(vec!["deadbeef".to_string()]),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_delete_group_args() -> DeleteGroupArgs {
        DeleteGroupArgs {
            content: "delete group".to_string(),
            group_id: "group-4".to_string(),
            previous_refs: Some(vec!["deadbeef".to_string()]),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_create_invite_args() -> CreateInviteArgs {
        CreateInviteArgs {
            content: "create invite".to_string(),
            group_id: "group-5".to_string(),
            code: Some("invite-code".to_string()),
            previous_refs: Some(vec!["deadbeef".to_string()]),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_join_group_args() -> JoinGroupArgs {
        JoinGroupArgs {
            content: "join group".to_string(),
            group_id: "group-5".to_string(),
            invite_code: Some("invite-code".to_string()),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_leave_group_args() -> LeaveGroupArgs {
        LeaveGroupArgs {
            content: "leave group".to_string(),
            group_id: "group-5".to_string(),
            pow: None,
            to_relays: None,
        }
    }

    fn tag_set(tags: Vec<Tag>) -> HashSet<Vec<String>> {
        tags.into_iter().map(Tag::to_vec).collect()
    }

    fn event_tag_set(event: &Event) -> HashSet<Vec<String>> {
        event.tags.iter().cloned().map(Tag::to_vec).collect()
    }

    async fn connected_client(keys: Keys, url: &RelayUrl) -> Client {
        let client = Client::new(keys);
        client.add_relay(url).await.unwrap();
        client.connect().await;
        client
    }

    async fn latest_authored_event(client: &Client, author: PublicKey, kind: u16) -> Event {
        client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(kind))
                    .author(author)
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap()
            .first()
            .unwrap()
            .clone()
    }

    #[test]
    fn validators_accept_trimmed_values_and_normalize_previous_refs() {
        let pubkey = sample_pubkey();

        assert_eq!(
            parse_pubkey(&format!(" {pubkey} ")).unwrap().to_hex(),
            pubkey
        );
        assert_eq!(
            parse_event_id(&format!(" {} ", "0".repeat(64)))
                .unwrap()
                .to_hex(),
            "0".repeat(64)
        );
        assert_eq!(validate_group_id(" group-1_2 ").unwrap(), "group-1_2");
        assert_eq!(
            validate_previous_refs(&Some(vec![" DeadBeeF ".to_string()])).unwrap(),
            vec!["deadbeef".to_string()]
        );
        assert_eq!(
            validate_non_empty_field("name", " value ").unwrap(),
            "value".to_string()
        );
    }

    #[test]
    fn validators_reject_invalid_values() {
        assert!(validate_group_id(" ").unwrap_err().to_string().contains("group_id must not be empty"));
        assert!(validate_group_id("Group!").unwrap_err().to_string().contains("group_id must contain only a-z, 0-9, '-' or '_'"));
        assert!(validate_previous_refs(&Some(vec!["bad".to_string()])).unwrap_err().to_string().contains("previous_refs entries must be 8-character hex prefixes"));
        assert!(validate_previous_refs(&Some(vec!["zzzzzzzz".to_string()])).unwrap_err().to_string().contains("previous_refs entries must be 8-character hex prefixes"));
        assert!(validate_non_empty_field("role", " ").unwrap_err().to_string().contains("role must not be empty"));
        assert!(parse_pubkey("bad").unwrap_err().to_string().contains("invalid public key bad"));
        assert!(parse_event_id("bad").unwrap_err().to_string().contains("invalid event id bad"));
    }

    #[test]
    fn put_user_tags_include_group_and_roles() {
        let pubkey = sample_pubkey();
        let tags = tag_set(put_user_tags(&sample_put_user_args(pubkey.clone())).unwrap());

        assert!(tags.contains(&vec!["h".to_string(), "group-1".to_string()]));
        assert!(tags.contains(&vec![
            "p".to_string(),
            pubkey,
            "admin".to_string(),
            "mod".to_string(),
        ]));
        assert!(tags.contains(&vec!["previous".to_string(), "deadbeef".to_string()]));
    }

    #[test]
    fn put_user_tags_without_optional_roles_or_previous_refs() {
        let pubkey = sample_pubkey();
        let mut args = sample_put_user_args(pubkey.clone());
        args.roles = None;
        args.previous_refs = None;

        let tags = tag_set(put_user_tags(&args).unwrap());

        assert_eq!(tags.len(), 2);
        assert!(tags.contains(&vec!["h".to_string(), "group-1".to_string()]));
        assert!(tags.contains(&vec!["p".to_string(), pubkey]));
    }

    #[test]
    fn put_user_tags_reject_invalid_pubkey_and_empty_role() {
        let mut invalid_pubkey = sample_put_user_args("bad".to_string());
        let err = put_user_tags(&invalid_pubkey).unwrap_err();
        assert!(err.to_string().contains("invalid public key bad"));

        invalid_pubkey.pubkey = sample_pubkey();
        invalid_pubkey.roles = Some(vec![" ".to_string()]);
        let err = put_user_tags(&invalid_pubkey).unwrap_err();
        assert!(err.to_string().contains("role must not be empty"));
    }

    #[test]
    fn remove_user_tags_include_pubkey_and_previous_refs() {
        let pubkey = sample_pubkey();
        let tags = tag_set(remove_user_tags(&sample_remove_user_args(pubkey.clone())).unwrap());

        assert!(tags.contains(&vec!["h".to_string(), "group-1".to_string()]));
        assert!(tags.contains(&vec!["p".to_string(), pubkey]));
        assert!(tags.contains(&vec!["previous".to_string(), "deadbeef".to_string()]));
    }

    #[test]
    fn remove_user_tags_reject_invalid_inputs() {
        let mut args = sample_remove_user_args("bad".to_string());
        let err = remove_user_tags(&args).unwrap_err();
        assert!(err.to_string().contains("invalid public key bad"));

        args.pubkey = sample_pubkey();
        args.group_id = "Group!".to_string();
        let err = remove_user_tags(&args).unwrap_err();
        assert!(err.to_string().contains("group_id must contain only a-z, 0-9, '-' or '_'"));

        args.group_id = "group-1".to_string();
        args.previous_refs = Some(vec!["not-valid".to_string()]);
        let err = remove_user_tags(&args).unwrap_err();
        assert!(
            err.to_string()
                .contains("previous_refs entries must be 8-character hex prefixes")
        );
    }

    #[test]
    fn edit_group_metadata_tags_include_positive_flags_only() {
        let tags = tag_set(edit_group_metadata_tags(&sample_edit_group_metadata_args()).unwrap());

        assert!(tags.contains(&vec!["h".to_string(), "group-2".to_string()]));
        assert!(tags.contains(&vec!["name".to_string(), "name".to_string()]));
        assert!(tags.contains(&vec![
            "picture".to_string(),
            "https://example.com/picture.png".to_string(),
        ]));
        assert!(tags.contains(&vec!["about".to_string(), "about".to_string()]));
        assert!(tags.contains(&vec!["unrestricted".to_string()]));
        assert!(tags.contains(&vec!["open".to_string()]));
        assert!(tags.contains(&vec!["visible".to_string()]));
        assert!(tags.contains(&vec!["public".to_string()]));
        assert!(tags.contains(&vec!["previous".to_string(), "deadbeef".to_string()]));
    }

    #[test]
    fn edit_group_metadata_tags_accept_minimal_input_and_reject_invalid_fields() {
        let mut args = sample_edit_group_metadata_args();
        args.name = None;
        args.picture = None;
        args.about = None;
        args.unrestricted = Some(false);
        args.visible = Some(false);
        args.public = Some(false);
        args.open = Some(false);
        args.previous_refs = None;

        let tags = tag_set(edit_group_metadata_tags(&args).unwrap());
        assert_eq!(tags, HashSet::from([vec!["h".to_string(), "group-2".to_string()]]));

        let mut invalid_name = sample_edit_group_metadata_args();
        invalid_name.name = Some(" ".to_string());
        let err = edit_group_metadata_tags(&invalid_name).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));

        let mut invalid_picture = sample_edit_group_metadata_args();
        invalid_picture.picture = Some("not-a-url".to_string());
        let err = edit_group_metadata_tags(&invalid_picture).unwrap_err();
        assert!(err.to_string().contains("invalid picture url"));

        let mut empty_picture = sample_edit_group_metadata_args();
        empty_picture.picture = Some(" ".to_string());
        let err = edit_group_metadata_tags(&empty_picture).unwrap_err();
        assert!(err.to_string().contains("picture must not be empty"));

        let mut invalid_about = sample_edit_group_metadata_args();
        invalid_about.about = Some(" ".to_string());
        let err = edit_group_metadata_tags(&invalid_about).unwrap_err();
        assert!(err.to_string().contains("about must not be empty"));

        let mut invalid_group_id = sample_edit_group_metadata_args();
        invalid_group_id.group_id = "Group!".to_string();
        let err = edit_group_metadata_tags(&invalid_group_id).unwrap_err();
        assert!(
            err.to_string()
                .contains("group_id must contain only a-z, 0-9, '-' or '_'")
        );

        let mut invalid_previous_refs = sample_edit_group_metadata_args();
        invalid_previous_refs.previous_refs = Some(vec!["bad".to_string()]);
        let err = edit_group_metadata_tags(&invalid_previous_refs).unwrap_err();
        assert!(
            err.to_string()
                .contains("previous_refs entries must be 8-character hex prefixes")
        );
    }

    #[test]
    fn create_invite_tags_include_code() {
        let tags = tag_set(create_invite_tags(&sample_create_invite_args()).unwrap());

        assert!(tags.contains(&vec!["h".to_string(), "group-5".to_string()]));
        assert!(tags.contains(&vec!["code".to_string(), "invite-code".to_string()]));
        assert!(tags.contains(&vec!["previous".to_string(), "deadbeef".to_string()]));
    }

    #[test]
    fn create_invite_join_and_leave_tags_handle_optional_codes() {
        let mut invite_args = sample_create_invite_args();
        invite_args.code = None;
        invite_args.previous_refs = None;
        let invite_tags = tag_set(create_invite_tags(&invite_args).unwrap());
        assert_eq!(invite_tags, HashSet::from([vec!["h".to_string(), "group-5".to_string()]]));

        let join_tags = tag_set(join_group_tags(&sample_join_group_args()).unwrap());
        assert!(join_tags.contains(&vec!["h".to_string(), "group-5".to_string()]));
        assert!(join_tags.contains(&vec!["code".to_string(), "invite-code".to_string()]));

        let mut join_without_code = sample_join_group_args();
        join_without_code.invite_code = None;
        let join_without_code_tags = tag_set(join_group_tags(&join_without_code).unwrap());
        assert_eq!(
            join_without_code_tags,
            HashSet::from([vec!["h".to_string(), "group-5".to_string()]])
        );

        let leave_tags = tag_set(leave_group_tags(&sample_leave_group_args()).unwrap());
        assert_eq!(leave_tags, HashSet::from([vec!["h".to_string(), "group-5".to_string()]]));
    }

    #[test]
    fn invite_join_and_leave_tags_reject_invalid_inputs() {
        let mut create_invite_args = sample_create_invite_args();
        create_invite_args.code = Some(" ".to_string());
        let err = create_invite_tags(&create_invite_args).unwrap_err();
        assert!(err.to_string().contains("code must not be empty"));

        let mut join_args = sample_join_group_args();
        join_args.invite_code = Some(" ".to_string());
        let err = join_group_tags(&join_args).unwrap_err();
        assert!(err.to_string().contains("invite_code must not be empty"));

        let mut leave_args = sample_leave_group_args();
        leave_args.group_id = " ".to_string();
        let err = leave_group_tags(&leave_args).unwrap_err();
        assert!(err.to_string().contains("group_id must not be empty"));
    }

    #[test]
    fn delete_event_tags_include_event() {
        let tags = tag_set(delete_event_tags(&sample_delete_event_args()).unwrap());

        assert!(tags.contains(&vec!["h".to_string(), "group-3".to_string()]));
        assert!(tags.contains(&vec!["e".to_string(), "0".repeat(64)]));
        assert!(tags.contains(&vec!["previous".to_string(), "deadbeef".to_string()]));
    }

    #[test]
    fn delete_event_and_group_lifecycle_tags_reject_invalid_ids() {
        let mut delete_event_args = sample_delete_event_args();
        delete_event_args.event_id = "bad".to_string();
        let err = delete_event_tags(&delete_event_args).unwrap_err();
        assert!(err.to_string().contains("invalid event id bad"));

        delete_event_args.event_id = "0".repeat(64);
        delete_event_args.group_id = "Group!".to_string();
        let err = delete_event_tags(&delete_event_args).unwrap_err();
        assert!(
            err.to_string()
                .contains("group_id must contain only a-z, 0-9, '-' or '_'")
        );

        delete_event_args.group_id = "group-3".to_string();
        delete_event_args.previous_refs = Some(vec!["bad".to_string()]);
        let err = delete_event_tags(&delete_event_args).unwrap_err();
        assert!(
            err.to_string()
                .contains("previous_refs entries must be 8-character hex prefixes")
        );

        let mut create_group_args = sample_create_group_args();
        create_group_args.group_id = "Group!".to_string();
        let err = create_group_tags(&create_group_args).unwrap_err();
        assert!(err.to_string().contains("group_id must contain only a-z, 0-9, '-' or '_'"));

        create_group_args.group_id = "group-4".to_string();
        create_group_args.previous_refs = Some(vec!["bad".to_string()]);
        let err = create_group_tags(&create_group_args).unwrap_err();
        assert!(
            err.to_string()
                .contains("previous_refs entries must be 8-character hex prefixes")
        );

        let mut delete_group_args = sample_delete_group_args();
        delete_group_args.group_id = " ".to_string();
        let err = delete_group_tags(&delete_group_args).unwrap_err();
        assert!(err.to_string().contains("group_id must not be empty"));

        delete_group_args.group_id = "group-4".to_string();
        delete_group_args.previous_refs = Some(vec!["bad".to_string()]);
        let err = delete_group_tags(&delete_group_args).unwrap_err();
        assert!(
            err.to_string()
                .contains("previous_refs entries must be 8-character hex prefixes")
        );
    }

    #[test]
    fn group_tags_reject_invalid_previous_ref() {
        let pubkey = sample_pubkey();
        let mut args = sample_put_user_args(pubkey);
        args.previous_refs = Some(vec!["not-valid".to_string()]);

        let err = put_user_tags(&args).unwrap_err();
        assert!(
            err.to_string()
                .contains("previous_refs entries must be 8-character hex prefixes")
        );

        let mut create_invite_args = sample_create_invite_args();
        create_invite_args.group_id = "Group!".to_string();
        let err = create_invite_tags(&create_invite_args).unwrap_err();
        assert!(
            err.to_string()
                .contains("group_id must contain only a-z, 0-9, '-' or '_'")
        );

        create_invite_args.group_id = "group-5".to_string();
        create_invite_args.previous_refs = Some(vec!["not-valid".to_string()]);
        let err = create_invite_tags(&create_invite_args).unwrap_err();
        assert!(
            err.to_string()
                .contains("previous_refs entries must be 8-character hex prefixes")
        );

        let mut join_args = sample_join_group_args();
        join_args.group_id = " ".to_string();
        let err = join_group_tags(&join_args).unwrap_err();
        assert!(err.to_string().contains("group_id must not be empty"));
    }

    #[tokio::test]
    async fn group_membership_wrappers_publish_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let actor_pubkey = sample_pubkey();

        let mut put_args = sample_put_user_args(actor_pubkey.clone());
        put_args.pow = Some(1);
        put_args.to_relays = Some(vec![url.to_string()]);
        let put_result = put_user(&client, put_args).await.unwrap();
        let put_event = latest_authored_event(&client, keys.public_key(), 9000).await;
        assert_eq!(put_result.success, vec![url.to_string()]);
        assert!(put_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(event_tag_set(&put_event).contains(&vec![
            "p".to_string(),
            actor_pubkey.clone(),
            "admin".to_string(),
            "mod".to_string(),
        ]));

        let mut remove_args = sample_remove_user_args(actor_pubkey);
        remove_args.to_relays = Some(vec![url.to_string()]);
        let remove_result = remove_user(&client, remove_args).await.unwrap();
        let remove_event = latest_authored_event(&client, keys.public_key(), 9001).await;
        assert_eq!(remove_result.success, vec![url.to_string()]);
        assert!(!remove_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        let remove_pubkey_tag = event_tag_set(&remove_event)
            .into_iter()
            .find(|tag| tag.first().map(String::as_str) == Some("p"))
            .unwrap();
        assert_eq!(remove_pubkey_tag.len(), 2);
    }

    #[tokio::test]
    async fn group_metadata_and_invite_wrappers_publish_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;

        let mut edit_args = sample_edit_group_metadata_args();
        edit_args.pow = Some(1);
        edit_args.to_relays = Some(vec![url.to_string()]);
        let edit_result = edit_group_metadata(&client, edit_args).await.unwrap();
        let edit_event = latest_authored_event(&client, keys.public_key(), 9002).await;
        assert_eq!(edit_result.success, vec![url.to_string()]);
        assert!(edit_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(event_tag_set(&edit_event).contains(&vec![
            "picture".to_string(),
            "https://example.com/picture.png".to_string(),
        ]));

        let mut delete_event_args = sample_delete_event_args();
        delete_event_args.to_relays = Some(vec![url.to_string()]);
        let delete_event_result = delete_group_event(&client, delete_event_args).await.unwrap();
        let delete_event_event = latest_authored_event(&client, keys.public_key(), 9005).await;
        assert_eq!(delete_event_result.success, vec![url.to_string()]);
        assert!(!delete_event_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(event_tag_set(&delete_event_event).contains(&vec!["e".to_string(), "0".repeat(64)]));

        let mut create_invite_args = sample_create_invite_args();
        create_invite_args.pow = Some(1);
        create_invite_args.to_relays = Some(vec![url.to_string()]);
        let create_invite_result = create_invite(&client, create_invite_args).await.unwrap();
        let create_invite_event = latest_authored_event(&client, keys.public_key(), 9009).await;
        assert_eq!(create_invite_result.success, vec![url.to_string()]);
        assert!(create_invite_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(event_tag_set(&create_invite_event)
            .contains(&vec!["code".to_string(), "invite-code".to_string()]));
    }

    #[tokio::test]
    async fn group_lifecycle_wrappers_publish_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;

        let mut create_group_args = sample_create_group_args();
        create_group_args.to_relays = Some(vec![url.to_string()]);
        let create_group_result = create_group(&client, create_group_args).await.unwrap();
        let create_group_event = latest_authored_event(&client, keys.public_key(), 9007).await;
        assert_eq!(create_group_result.success, vec![url.to_string()]);
        assert!(!create_group_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));

        let mut delete_group_args = sample_delete_group_args();
        delete_group_args.pow = Some(1);
        delete_group_args.to_relays = Some(vec![url.to_string()]);
        let delete_group_result = delete_group(&client, delete_group_args).await.unwrap();
        let delete_group_event = latest_authored_event(&client, keys.public_key(), 9008).await;
        assert_eq!(delete_group_result.success, vec![url.to_string()]);
        assert!(delete_group_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));

        let mut join_args = sample_join_group_args();
        join_args.to_relays = Some(vec![url.to_string()]);
        let join_result = join_group(&client, join_args).await.unwrap();
        let join_event = latest_authored_event(&client, keys.public_key(), 9021).await;
        assert_eq!(join_result.success, vec![url.to_string()]);
        assert!(!join_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(event_tag_set(&join_event).contains(&vec![
            "code".to_string(),
            "invite-code".to_string(),
        ]));

        let mut leave_args = sample_leave_group_args();
        leave_args.pow = Some(1);
        leave_args.to_relays = Some(vec![url.to_string()]);
        let leave_result = leave_group(&client, leave_args).await.unwrap();
        let leave_event = latest_authored_event(&client, keys.public_key(), 9022).await;
        assert_eq!(leave_result.success, vec![url.to_string()]);
        assert!(leave_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(event_tag_set(&leave_event).contains(&vec!["h".to_string(), "group-5".to_string()]));
    }

    #[tokio::test]
    async fn group_publish_wrappers_reject_invalid_inputs_before_publish() {
        let client = Client::new(Keys::generate());
        let actor_pubkey = sample_pubkey();

        let mut put_args = sample_put_user_args(actor_pubkey.clone());
        put_args.group_id = " ".to_string();
        assert!(put_user(&client, put_args).await.unwrap_err().to_string().contains("group_id must not be empty"));

        let remove_args = sample_remove_user_args("bad".to_string());
        assert!(remove_user(&client, remove_args).await.unwrap_err().to_string().contains("invalid public key bad"));

        let mut edit_args = sample_edit_group_metadata_args();
        edit_args.picture = Some("bad".to_string());
        assert!(edit_group_metadata(&client, edit_args).await.unwrap_err().to_string().contains("invalid picture url"));

        let mut delete_event_args = sample_delete_event_args();
        delete_event_args.event_id = "bad".to_string();
        assert!(delete_group_event(&client, delete_event_args).await.unwrap_err().to_string().contains("invalid event id bad"));

        let mut create_group_args = sample_create_group_args();
        create_group_args.group_id = " ".to_string();
        assert!(create_group(&client, create_group_args).await.unwrap_err().to_string().contains("group_id must not be empty"));

        let mut delete_group_args = sample_delete_group_args();
        delete_group_args.group_id = " ".to_string();
        assert!(delete_group(&client, delete_group_args).await.unwrap_err().to_string().contains("group_id must not be empty"));

        let mut create_invite_args = sample_create_invite_args();
        create_invite_args.code = Some(" ".to_string());
        assert!(create_invite(&client, create_invite_args).await.unwrap_err().to_string().contains("code must not be empty"));

        let mut join_args = sample_join_group_args();
        join_args.invite_code = Some(" ".to_string());
        assert!(join_group(&client, join_args).await.unwrap_err().to_string().contains("invite_code must not be empty"));

        let mut leave_args = sample_leave_group_args();
        leave_args.group_id = " ".to_string();
        assert!(leave_group(&client, leave_args).await.unwrap_err().to_string().contains("group_id must not be empty"));
    }
}
