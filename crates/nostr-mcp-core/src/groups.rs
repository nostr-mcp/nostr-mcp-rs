use crate::error::CoreError;
use crate::publish::publish_event_builder;
use nostr_mcp_types::groups::{
    CreateGroupArgs, CreateInviteArgs, DeleteEventArgs, DeleteGroupArgs, EditGroupMetadataArgs,
    JoinGroupArgs, LeaveGroupArgs, PutUserArgs, RemoveUserArgs,
};
use nostr_mcp_types::publish::SendResult;
use nostr_sdk::prelude::*;

pub async fn put_user(client: &Client, args: PutUserArgs) -> Result<SendResult, CoreError> {
    let tags = put_user_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9000), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn remove_user(client: &Client, args: RemoveUserArgs) -> Result<SendResult, CoreError> {
    let tags = remove_user_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9001), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn edit_group_metadata(
    client: &Client,
    args: EditGroupMetadataArgs,
) -> Result<SendResult, CoreError> {
    let tags = edit_group_metadata_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9002), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn delete_group_event(
    client: &Client,
    args: DeleteEventArgs,
) -> Result<SendResult, CoreError> {
    let tags = delete_event_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9005), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn create_group(client: &Client, args: CreateGroupArgs) -> Result<SendResult, CoreError> {
    let tags = create_group_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9007), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn delete_group(client: &Client, args: DeleteGroupArgs) -> Result<SendResult, CoreError> {
    let tags = delete_group_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9008), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn create_invite(
    client: &Client,
    args: CreateInviteArgs,
) -> Result<SendResult, CoreError> {
    let tags = create_invite_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9009), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn join_group(client: &Client, args: JoinGroupArgs) -> Result<SendResult, CoreError> {
    let tags = join_group_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9021), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn leave_group(client: &Client, args: LeaveGroupArgs) -> Result<SendResult, CoreError> {
    let tags = leave_group_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9022), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
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

fn push_group_id_tag(tags: &mut Vec<Tag>, group_id: &str) -> Result<(), CoreError> {
    tags.push(
        Tag::parse(&["h".to_string(), group_id.to_string()])
            .map_err(|e| CoreError::operation(format!("group tag: {e}")))?,
    );
    Ok(())
}

fn push_previous_tags(tags: &mut Vec<Tag>, previous_refs: &[String]) -> Result<(), CoreError> {
    for reference in previous_refs {
        tags.push(
            Tag::parse(&["previous".to_string(), reference.clone()])
                .map_err(|e| CoreError::operation(format!("previous tag: {e}")))?,
        );
    }
    Ok(())
}

fn put_user_tags(args: &PutUserArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let pubkey = parse_pubkey(&args.pubkey)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id)?;

    let mut p_tag = vec!["p".to_string(), pubkey.to_hex()];
    if let Some(roles) = args.roles.as_ref() {
        for role in roles {
            p_tag.push(validate_non_empty_field("role", role)?);
        }
    }
    tags.push(Tag::parse(&p_tag).map_err(|e| CoreError::operation(format!("p tag: {e}")))?);

    push_previous_tags(&mut tags, &previous_refs)?;
    Ok(tags)
}

fn remove_user_tags(args: &RemoveUserArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let pubkey = parse_pubkey(&args.pubkey)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id)?;
    tags.push(
        Tag::parse(&["p".to_string(), pubkey.to_hex()])
            .map_err(|e| CoreError::operation(format!("p tag: {e}")))?,
    );

    push_previous_tags(&mut tags, &previous_refs)?;
    Ok(tags)
}

fn edit_group_metadata_tags(args: &EditGroupMetadataArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id)?;

    if let Some(name) = args.name.as_ref() {
        tags.push(
            Tag::parse(&["name".to_string(), validate_non_empty_field("name", name)?])
                .map_err(|e| CoreError::operation(format!("name tag: {e}")))?,
        );
    }

    if let Some(picture) = args.picture.as_ref() {
        let picture = validate_non_empty_field("picture", picture)?;
        Url::parse(&picture)
            .map_err(|e| CoreError::invalid_input(format!("invalid picture url: {e}")))?;
        tags.push(
            Tag::parse(&["picture".to_string(), picture])
                .map_err(|e| CoreError::operation(format!("picture tag: {e}")))?,
        );
    }

    if let Some(about) = args.about.as_ref() {
        tags.push(
            Tag::parse(&[
                "about".to_string(),
                validate_non_empty_field("about", about)?,
            ])
            .map_err(|e| CoreError::operation(format!("about tag: {e}")))?,
        );
    }

    if args.unrestricted.unwrap_or(false) {
        tags.push(
            Tag::parse(&["unrestricted".to_string()])
                .map_err(|e| CoreError::operation(format!("unrestricted tag: {e}")))?,
        );
    }

    if args.open.unwrap_or(false) {
        tags.push(
            Tag::parse(&["open".to_string()])
                .map_err(|e| CoreError::operation(format!("open tag: {e}")))?,
        );
    }

    if args.visible.unwrap_or(false) {
        tags.push(
            Tag::parse(&["visible".to_string()])
                .map_err(|e| CoreError::operation(format!("visible tag: {e}")))?,
        );
    }

    if args.public.unwrap_or(false) {
        tags.push(
            Tag::parse(&["public".to_string()])
                .map_err(|e| CoreError::operation(format!("public tag: {e}")))?,
        );
    }

    push_previous_tags(&mut tags, &previous_refs)?;
    Ok(tags)
}

fn delete_event_tags(args: &DeleteEventArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let event_id = parse_event_id(&args.event_id)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id)?;
    tags.push(
        Tag::parse(&["e".to_string(), event_id.to_hex()])
            .map_err(|e| CoreError::operation(format!("event tag: {e}")))?,
    );

    push_previous_tags(&mut tags, &previous_refs)?;
    Ok(tags)
}

fn create_group_tags(args: &CreateGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id)?;
    push_previous_tags(&mut tags, &previous_refs)?;
    Ok(tags)
}

fn delete_group_tags(args: &DeleteGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id)?;
    push_previous_tags(&mut tags, &previous_refs)?;
    Ok(tags)
}

fn create_invite_tags(args: &CreateInviteArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let previous_refs = validate_previous_refs(&args.previous_refs)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id)?;

    if let Some(code) = args.code.as_ref() {
        tags.push(
            Tag::parse(&["code".to_string(), validate_non_empty_field("code", code)?])
                .map_err(|e| CoreError::operation(format!("code tag: {e}")))?,
        );
    }

    push_previous_tags(&mut tags, &previous_refs)?;
    Ok(tags)
}

fn join_group_tags(args: &JoinGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id)?;

    if let Some(code) = args.invite_code.as_ref() {
        tags.push(
            Tag::parse(&[
                "code".to_string(),
                validate_non_empty_field("invite_code", code)?,
            ])
            .map_err(|e| CoreError::operation(format!("code tag: {e}")))?,
        );
    }

    Ok(tags)
}

fn leave_group_tags(args: &LeaveGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let group_id = validate_group_id(&args.group_id)?;
    let mut tags = Vec::new();

    push_group_id_tag(&mut tags, &group_id)?;
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::{create_invite_tags, delete_event_tags, edit_group_metadata_tags, put_user_tags};
    use nostr_mcp_types::groups::{
        CreateInviteArgs, DeleteEventArgs, EditGroupMetadataArgs, PutUserArgs,
    };
    use nostr_sdk::prelude::*;

    #[test]
    fn put_user_tags_include_group_and_roles() {
        let pubkey = Keys::generate().public_key().to_hex();
        let args = PutUserArgs {
            content: "content".to_string(),
            group_id: "group-1".to_string(),
            pubkey,
            roles: Some(vec!["admin".to_string(), "mod".to_string()]),
            previous_refs: Some(vec!["deadbeef".to_string()]),
            pow: None,
            to_relays: None,
        };

        let tags = put_user_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "h").unwrap_or(false))
        );
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "p").unwrap_or(false))
        );
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "previous").unwrap_or(false))
        );
    }

    #[test]
    fn edit_group_metadata_tags_include_positive_flags_only() {
        let args = EditGroupMetadataArgs {
            content: "content".to_string(),
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
        };

        let tags = edit_group_metadata_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "public").unwrap_or(false))
        );
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "open").unwrap_or(false))
        );
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "unrestricted").unwrap_or(false))
        );
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "visible").unwrap_or(false))
        );
        assert!(
            !values
                .iter()
                .any(|tag| tag.first().map(|v| v == "private").unwrap_or(false))
        );
        assert!(
            !values
                .iter()
                .any(|tag| tag.first().map(|v| v == "closed").unwrap_or(false))
        );
    }

    #[test]
    fn create_invite_tags_include_code() {
        let args = CreateInviteArgs {
            content: "content".to_string(),
            group_id: "group-4".to_string(),
            code: Some("invite-code".to_string()),
            previous_refs: None,
            pow: None,
            to_relays: None,
        };

        let tags = create_invite_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(
            values
                .iter()
                .any(|tag| { tag.len() == 2 && tag[0] == "code" && tag[1] == "invite-code" })
        );
    }

    #[test]
    fn delete_event_tags_include_event() {
        let event_id = "0".repeat(64);
        let args = DeleteEventArgs {
            content: "content".to_string(),
            group_id: "group-3".to_string(),
            event_id,
            previous_refs: Some(vec!["deadbeef".to_string()]),
            pow: None,
            to_relays: None,
        };

        let tags = delete_event_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "e").unwrap_or(false))
        );
    }

    #[test]
    fn group_tags_reject_invalid_previous_ref() {
        let pubkey = Keys::generate().public_key().to_hex();
        let args = PutUserArgs {
            content: "content".to_string(),
            group_id: "group-1".to_string(),
            pubkey,
            roles: None,
            previous_refs: Some(vec!["not-valid".to_string()]),
            pow: None,
            to_relays: None,
        };

        let err = put_user_tags(&args).unwrap_err();
        assert!(
            err.to_string()
                .contains("previous_refs entries must be 8-character hex prefixes")
        );
    }
}
