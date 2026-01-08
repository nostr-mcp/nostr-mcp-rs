use crate::error::CoreError;
use crate::publish::{publish_event_builder, SendResult};
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PutUserArgs {
    pub content: String,
    pub group_id: String,
    pub pubkey: String,
    pub roles: Option<Vec<String>>,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveUserArgs {
    pub content: String,
    pub group_id: String,
    pub pubkey: String,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EditGroupMetadataArgs {
    pub content: String,
    pub group_id: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub about: Option<String>,
    pub public: Option<bool>,
    pub open: Option<bool>,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteEventArgs {
    pub content: String,
    pub group_id: String,
    pub event_id: String,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateGroupArgs {
    pub content: String,
    pub group_id: String,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteGroupArgs {
    pub content: String,
    pub group_id: String,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateInviteArgs {
    pub content: String,
    pub group_id: String,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JoinGroupArgs {
    pub content: String,
    pub group_id: String,
    pub invite_code: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LeaveGroupArgs {
    pub content: String,
    pub group_id: String,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

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
    PublicKey::from_hex(pubkey)
        .map_err(|e| CoreError::invalid_input(format!("invalid public key {pubkey}: {e}")))
}

fn parse_event_id(event_id: &str) -> Result<EventId, CoreError> {
    EventId::from_hex(event_id)
        .map_err(|e| CoreError::invalid_input(format!("invalid event id {event_id}: {e}")))
}

fn put_user_tags(args: &PutUserArgs) -> Result<Vec<Tag>, CoreError> {
    let pubkey = parse_pubkey(&args.pubkey)?;
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );

    let mut p_tag = vec!["p".to_string(), pubkey.to_hex()];
    if let Some(roles) = args.roles.as_ref() {
        for role in roles {
            p_tag.push(role.clone());
        }
    }
    tags.push(Tag::parse(&p_tag).map_err(|e| CoreError::Nostr(format!("p tag: {e}")))?);

    if let Some(refs) = args.previous_refs.as_ref() {
        for ref_id in refs {
            tags.push(
                Tag::parse(&["previous".to_string(), ref_id.clone()])
                    .map_err(|e| CoreError::Nostr(format!("previous tag: {e}")))?,
            );
        }
    }

    Ok(tags)
}

fn remove_user_tags(args: &RemoveUserArgs) -> Result<Vec<Tag>, CoreError> {
    let pubkey = parse_pubkey(&args.pubkey)?;
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );
    tags.push(
        Tag::parse(&["p".to_string(), pubkey.to_hex()])
            .map_err(|e| CoreError::Nostr(format!("p tag: {e}")))?,
    );

    if let Some(refs) = args.previous_refs.as_ref() {
        for ref_id in refs {
            tags.push(
                Tag::parse(&["previous".to_string(), ref_id.clone()])
                    .map_err(|e| CoreError::Nostr(format!("previous tag: {e}")))?,
            );
        }
    }

    Ok(tags)
}

fn edit_group_metadata_tags(args: &EditGroupMetadataArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );

    if let Some(name) = args.name.as_ref() {
        tags.push(
            Tag::parse(&["name".to_string(), name.clone()])
                .map_err(|e| CoreError::Nostr(format!("name tag: {e}")))?,
        );
    }

    if let Some(picture) = args.picture.as_ref() {
        tags.push(
            Tag::parse(&["picture".to_string(), picture.clone()])
                .map_err(|e| CoreError::Nostr(format!("picture tag: {e}")))?,
        );
    }

    if let Some(about) = args.about.as_ref() {
        tags.push(
            Tag::parse(&["about".to_string(), about.clone()])
                .map_err(|e| CoreError::Nostr(format!("about tag: {e}")))?,
        );
    }

    if let Some(public) = args.public {
        let value = if public { "public" } else { "private" };
        tags.push(
            Tag::parse(&[value.to_string()])
                .map_err(|e| CoreError::Nostr(format!("public tag: {e}")))?,
        );
    }

    if let Some(open) = args.open {
        let value = if open { "open" } else { "closed" };
        tags.push(
            Tag::parse(&[value.to_string()])
                .map_err(|e| CoreError::Nostr(format!("open tag: {e}")))?,
        );
    }

    if let Some(refs) = args.previous_refs.as_ref() {
        for ref_id in refs {
            tags.push(
                Tag::parse(&["previous".to_string(), ref_id.clone()])
                    .map_err(|e| CoreError::Nostr(format!("previous tag: {e}")))?,
            );
        }
    }

    Ok(tags)
}

fn delete_event_tags(args: &DeleteEventArgs) -> Result<Vec<Tag>, CoreError> {
    let event_id = parse_event_id(&args.event_id)?;
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );
    tags.push(
        Tag::parse(&["e".to_string(), event_id.to_hex()])
            .map_err(|e| CoreError::Nostr(format!("event tag: {e}")))?,
    );

    if let Some(refs) = args.previous_refs.as_ref() {
        for ref_id in refs {
            tags.push(
                Tag::parse(&["previous".to_string(), ref_id.clone()])
                    .map_err(|e| CoreError::Nostr(format!("previous tag: {e}")))?,
            );
        }
    }

    Ok(tags)
}

fn create_group_tags(args: &CreateGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );

    if let Some(refs) = args.previous_refs.as_ref() {
        for ref_id in refs {
            tags.push(
                Tag::parse(&["previous".to_string(), ref_id.clone()])
                    .map_err(|e| CoreError::Nostr(format!("previous tag: {e}")))?,
            );
        }
    }

    Ok(tags)
}

fn delete_group_tags(args: &DeleteGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );

    if let Some(refs) = args.previous_refs.as_ref() {
        for ref_id in refs {
            tags.push(
                Tag::parse(&["previous".to_string(), ref_id.clone()])
                    .map_err(|e| CoreError::Nostr(format!("previous tag: {e}")))?,
            );
        }
    }

    Ok(tags)
}

fn create_invite_tags(args: &CreateInviteArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );

    if let Some(refs) = args.previous_refs.as_ref() {
        for ref_id in refs {
            tags.push(
                Tag::parse(&["previous".to_string(), ref_id.clone()])
                    .map_err(|e| CoreError::Nostr(format!("previous tag: {e}")))?,
            );
        }
    }

    Ok(tags)
}

fn join_group_tags(args: &JoinGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );

    if let Some(code) = args.invite_code.as_ref() {
        tags.push(
            Tag::parse(&["code".to_string(), code.clone()])
                .map_err(|e| CoreError::Nostr(format!("code tag: {e}")))?,
        );
    }

    Ok(tags)
}

fn leave_group_tags(args: &LeaveGroupArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );

    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::{delete_event_tags, edit_group_metadata_tags, put_user_tags, DeleteEventArgs, EditGroupMetadataArgs, PutUserArgs};
    use nostr_sdk::prelude::*;

    #[test]
    fn put_user_tags_include_group_and_roles() {
        let pubkey = Keys::generate().public_key().to_hex();
        let args = PutUserArgs {
            content: "content".to_string(),
            group_id: "group-1".to_string(),
            pubkey,
            roles: Some(vec!["admin".to_string(), "mod".to_string()]),
            previous_refs: None,
            pow: None,
            to_relays: None,
        };

        let tags = put_user_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(values.iter().any(|tag| tag.get(0).map(|v| v == "h").unwrap_or(false)));
        assert!(values.iter().any(|tag| tag.get(0).map(|v| v == "p").unwrap_or(false)));
    }

    #[test]
    fn edit_group_metadata_tags_include_flags() {
        let args = EditGroupMetadataArgs {
            content: "content".to_string(),
            group_id: "group-2".to_string(),
            name: Some("name".to_string()),
            picture: None,
            about: None,
            public: Some(true),
            open: Some(false),
            previous_refs: Some(vec!["ref1".to_string()]),
            pow: None,
            to_relays: None,
        };

        let tags = edit_group_metadata_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(values.iter().any(|tag| tag.get(0).map(|v| v == "public").unwrap_or(false)));
        assert!(values.iter().any(|tag| tag.get(0).map(|v| v == "closed").unwrap_or(false)));
        assert!(values.iter().any(|tag| tag.get(0).map(|v| v == "previous").unwrap_or(false)));
    }

    #[test]
    fn delete_event_tags_include_event() {
        let event_id = "0".repeat(64);
        let args = DeleteEventArgs {
            content: "content".to_string(),
            group_id: "group-3".to_string(),
            event_id,
            previous_refs: None,
            pow: None,
            to_relays: None,
        };

        let tags = delete_event_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(values.iter().any(|tag| tag.get(0).map(|v| v == "e").unwrap_or(false)));
    }
}
