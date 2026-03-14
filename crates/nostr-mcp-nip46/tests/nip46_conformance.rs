#![forbid(unsafe_code)]

use nostr::{PublicKey, RelayUrl};
use nostr_mcp_nip46::{
    Nip46ConnectRequest, Nip46ConnectUri, Nip46GetPublicKeyResponse, Nip46Message, Nip46Method,
    Nip46PendingSession, Nip46Request, Nip46RequestId, Nip46ResponseMessage,
    Nip46SwitchRelaysResponse, Nip46SwitchRelaysResult,
};
use serde_json::json;

const SPEC_REMOTE_SIGNER_PUBKEY: &str =
    "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52";
const SPEC_CLIENT_PUBKEY: &str = "83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5";
const SPEC_USER_PUBKEY: &str = "79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3";
const SPEC_CLIENT_SECRET: &str = "0s8j2djs";
const NON_HEX_NPUB: &str = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";
const SPEC_CLIENT_URI: &str = "nostrconnect://83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5?relay=wss%3A%2F%2Frelay1.example.com&perms=nip44_encrypt%2Cnip44_decrypt%2Csign_event%3A13%2Csign_event%3A14%2Csign_event%3A1059&name=My+Client&secret=0s8j2djs&relay=wss%3A%2F%2Frelay2.example2.com";
const SPEC_BUNKER_URI: &str = "bunker://fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52?relay=wss%3A%2F%2Frelay-to-connect-on.example.com&relay=wss%3A%2F%2Fanother-relay-to-connect-on.example.com&secret=single-use-secret";

#[test]
fn nip46_client_uri_spec_example_round_trips_through_public_api() {
    let uri = Nip46ConnectUri::parse(SPEC_CLIENT_URI).expect("parse spec client uri");
    let serialized = uri.to_string();
    let reparsed = Nip46ConnectUri::parse(&serialized).expect("reparse serialized client uri");

    match &uri {
        Nip46ConnectUri::Client {
            client_public_key,
            relays,
            secret,
            permissions,
            metadata,
        } => {
            assert_eq!(client_public_key.to_hex(), SPEC_CLIENT_PUBKEY);
            assert_eq!(
                relays
                    .iter()
                    .map(|relay| relay.as_str())
                    .collect::<Vec<_>>(),
                vec!["wss://relay1.example.com", "wss://relay2.example2.com"]
            );
            assert_eq!(secret, SPEC_CLIENT_SECRET);
            assert_eq!(
                permissions.to_string(),
                "nip44_encrypt,nip44_decrypt,sign_event:13,sign_event:14,sign_event:1059"
            );
            assert_eq!(metadata.name.as_deref(), Some("My Client"));
        }
        Nip46ConnectUri::Bunker { .. } => panic!("expected client uri"),
    }

    assert_eq!(reparsed, uri);
}

#[test]
fn nip46_bunker_connect_request_matches_spec_json_rpc_shape() {
    let uri = Nip46ConnectUri::parse(SPEC_BUNKER_URI).expect("parse bunker uri");
    let (pending, message) = Nip46PendingSession::initiate_bunker_connect(
        &uri,
        PublicKey::from_hex(SPEC_CLIENT_PUBKEY).expect("hex client pubkey"),
        Nip46RequestId::new("3047714669").expect("request id"),
        nostr_mcp_nip46::Nip46PermissionSet::parse_csv("nip44_encrypt,sign_event:13")
            .expect("permissions"),
    )
    .expect("initiate bunker connect");

    assert_eq!(pending.client_public_key.to_hex(), SPEC_CLIENT_PUBKEY);
    assert_eq!(
        pending
            .expected_remote_signer_public_key
            .expect("expected remote signer")
            .to_hex(),
        SPEC_REMOTE_SIGNER_PUBKEY
    );

    let wire = serde_json::from_str::<serde_json::Value>(&message.as_json().expect("wire json"))
        .expect("parse wire json");
    assert_eq!(
        wire,
        json!({
            "id": "3047714669",
            "method": "connect",
            "params": [
                SPEC_REMOTE_SIGNER_PUBKEY,
                "single-use-secret",
                "nip44_encrypt,sign_event:13"
            ]
        })
    );
}

#[test]
fn nip46_client_connect_flow_requires_secret_echo_then_gets_user_key_and_switches_relays() {
    let uri = Nip46ConnectUri::parse(SPEC_CLIENT_URI).expect("parse client uri");
    let pending = Nip46PendingSession::await_client_connect(&uri).expect("await client connect");
    let connected = pending
        .accept_connect_response(
            PublicKey::from_hex(SPEC_REMOTE_SIGNER_PUBKEY).expect("hex remote signer"),
            Nip46Message::response(Nip46ResponseMessage::with_result(
                Nip46RequestId::new("remote-connect-1").expect("request id"),
                SPEC_CLIENT_SECRET,
            )),
        )
        .expect("accept secret echo");

    assert_eq!(
        connected.remote_signer_public_key.to_hex(),
        SPEC_REMOTE_SIGNER_PUBKEY
    );
    assert_eq!(connected.user_public_key, None);

    let get_public_key_id = Nip46RequestId::new("3047714674").expect("request id");
    let get_public_key_request = connected.get_public_key_request(get_public_key_id.clone());
    let get_public_key_wire =
        serde_json::from_str::<serde_json::Value>(&get_public_key_request.as_json().expect("json"))
            .expect("wire json");
    assert_eq!(
        get_public_key_wire,
        json!({
            "id": "3047714674",
            "method": "get_public_key",
            "params": []
        })
    );

    let with_user_key = connected
        .accept_get_public_key_response(
            &get_public_key_id,
            Nip46Message::response(
                Nip46GetPublicKeyResponse {
                    id: get_public_key_id.clone(),
                    user_public_key: PublicKey::from_hex(SPEC_USER_PUBKEY)
                        .expect("hex user pubkey"),
                }
                .to_response_message(),
            ),
        )
        .expect("accept user public key");

    assert_eq!(
        with_user_key
            .user_public_key
            .expect("user public key")
            .to_hex(),
        SPEC_USER_PUBKEY
    );

    let switch_relays_id = Nip46RequestId::new("3047714675").expect("request id");
    let switch_relays_request = with_user_key.switch_relays_request(switch_relays_id.clone());
    let switch_relays_wire =
        serde_json::from_str::<serde_json::Value>(&switch_relays_request.as_json().expect("json"))
            .expect("wire json");
    assert_eq!(
        switch_relays_wire,
        json!({
            "id": "3047714675",
            "method": "switch_relays",
            "params": []
        })
    );

    let updated_relays = with_user_key
        .accept_switch_relays_response(
            &switch_relays_id,
            Nip46Message::response(
                Nip46SwitchRelaysResponse {
                    id: switch_relays_id.clone(),
                    result: Nip46SwitchRelaysResult::Updated(vec![
                        RelayUrl::parse("wss://relay3.example.com").expect("relay 3"),
                        RelayUrl::parse("wss://relay4.example.com").expect("relay 4"),
                    ]),
                }
                .to_response_message()
                .expect("relay response"),
            ),
        )
        .expect("accept relay update");

    assert_eq!(
        updated_relays
            .relays
            .iter()
            .map(|relay| relay.as_str())
            .collect::<Vec<_>>(),
        vec!["wss://relay3.example.com", "wss://relay4.example.com"]
    );
}

#[test]
fn nip46_wire_pubkeys_must_be_hex() {
    let uri_error = Nip46ConnectUri::parse(format!(
        "bunker://{NON_HEX_NPUB}?relay=wss%3A%2F%2Frelay.example.com"
    ))
    .expect_err("bech32 pubkey must be rejected in uri");
    assert!(uri_error.to_string().starts_with("invalid public key: "));

    let connect_error = Nip46ConnectRequest::from_params(vec![NON_HEX_NPUB.to_string()])
        .expect_err("bech32 pubkey must be rejected in connect params");
    assert!(
        connect_error
            .to_string()
            .starts_with("invalid public key: ")
    );

    let response_error =
        Nip46GetPublicKeyResponse::from_response_message(Nip46ResponseMessage::with_result(
            Nip46RequestId::new("3047714676").expect("request id"),
            NON_HEX_NPUB,
        ))
        .expect_err("bech32 pubkey must be rejected in get_public_key response");
    assert!(
        response_error
            .to_string()
            .starts_with("invalid public key: ")
    );
}

#[test]
fn shipped_surface_rejects_unimplemented_nip46_methods_explicitly() {
    for method in [
        Nip46Method::Ping,
        Nip46Method::SignEvent,
        Nip46Method::Nip04Encrypt,
        Nip46Method::Nip04Decrypt,
        Nip46Method::Nip44Encrypt,
        Nip46Method::Nip44Decrypt,
    ] {
        let err = Nip46Request::from_message(method, Vec::new())
            .expect_err("unimplemented method must be rejected");
        assert_eq!(err.to_string(), format!("unsupported method: {method}"));
    }
}
