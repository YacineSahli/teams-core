//! Call signaling module — parse incoming call invitations and manage call lifecycle.
//!
//! This handles signaling only (no media streaming).

#[cfg(feature = "audio")]
pub mod audio;
pub mod answer;
pub mod call_test;

pub use answer::{answer_call_with_stop, decline_call, CallAnswerResult};
pub use call_test::{
    call_controls, derive_epconv_url, run_call_test, run_call_with_controls, run_call_with_stop,
    CallControls, CallControlsHandle, CallTestResult,
};
#[cfg(feature = "video-cam")]
pub mod camera;
#[cfg(feature = "video-cam")]
pub mod codec;
#[cfg(feature = "video-capture")]
pub mod display;
pub mod ice;
pub mod macav;
pub mod media;
pub mod recording;
pub mod rtcp;
pub mod rtp;
pub mod sdp;
pub mod sdp_compress;
pub mod signaling;
pub mod srtp;
pub mod test_tone;
pub mod turn;
pub mod video;

use serde::Deserialize;

/// Links provided in a callInvitation for signaling actions.
#[derive(Debug, Clone, Deserialize)]
pub struct CallLinks {
    pub acceptance: Option<String>,
    pub end: Option<String>,
    #[serde(rename = "mediaAnswer")]
    pub media_answer: Option<String>,
    #[serde(rename = "p2pForkNotification")]
    pub p2p_fork_notification: Option<String>,
}

/// Media content (SDP blob) from the call invitation.
#[derive(Debug, Clone, Deserialize)]
pub struct MediaContent {
    pub blob: Option<String>,
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
}

/// Participant identity.
#[derive(Debug, Clone, Deserialize)]
pub struct Participant {
    pub id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "endpointId")]
    pub endpoint_id: Option<String>,
    #[serde(rename = "languageId")]
    pub language_id: Option<String>,
}

/// Participants block from the invitation.
#[derive(Debug, Clone, Deserialize)]
pub struct Participants {
    pub from: Option<Participant>,
    pub to: Option<Vec<Participant>>,
}

/// Conversation request links.
#[derive(Debug, Clone, Deserialize)]
pub struct ConversationLinks {
    #[serde(rename = "conversationEnd")]
    pub conversation_end: Option<String>,
    #[serde(rename = "conversationUpdate")]
    pub conversation_update: Option<String>,
    #[serde(rename = "localParticipantUpdate")]
    pub local_participant_update: Option<String>,
}

/// Conversation request from the invitation.
#[derive(Debug, Clone, Deserialize)]
pub struct ConversationRequest {
    pub links: Option<ConversationLinks>,
}

/// Debug content with call/endpoint/operation IDs.
#[derive(Debug, Clone, Deserialize)]
pub struct DebugContent {
    #[serde(rename = "callId")]
    pub call_id: Option<String>,
    #[serde(rename = "endpointId")]
    pub endpoint_id: Option<String>,
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
}

/// The core call invitation payload from a Trouter push.
#[derive(Debug, Clone, Deserialize)]
pub struct CallInvitation {
    #[serde(rename = "callModalities")]
    pub call_modalities: Option<Vec<String>>,
    pub links: Option<CallLinks>,
    #[serde(rename = "mediaContent")]
    pub media_content: Option<MediaContent>,
}

/// Top-level envelope for a call notification pushed via Trouter.
#[derive(Debug, Clone, Deserialize)]
pub struct CallNotification {
    #[serde(rename = "callInvitation")]
    pub call_invitation: Option<CallInvitation>,
    pub participants: Option<Participants>,
    #[serde(rename = "conversationRequest")]
    pub conversation_request: Option<ConversationRequest>,
    #[serde(rename = "debugContent")]
    pub debug_content: Option<DebugContent>,
}

/// Simple call lifecycle state.
#[derive(Debug, Clone, PartialEq)]
pub enum CallState {
    Idle,
    Ringing,
    Accepting,
    Connected,
    Ended,
}

/// Try to parse a call notification from the Trouter event JSON.
///
/// The Trouter frame body is an HTTP-like request where the body is JSON.
/// We try to extract the JSON and deserialize it.
pub fn parse_call_notification(json_str: &str) -> Option<CallNotification> {
    // The JSON may be the full Trouter event envelope or just the body.
    // Try to find a JSON object containing "callInvitation".
    let v: serde_json::Value = serde_json::from_str(json_str).ok()?;

    // The Trouter event JSON has a nested structure. The call notification
    // may be at the top level or nested under a "body" field parsed as string.
    if v.get("callInvitation").is_some() {
        return serde_json::from_value(v).ok();
    }

    // Sometimes the body is a stringified JSON inside the event wrapper.
    // Look for common Trouter event wrapper patterns.
    if let Some(body) = v.get("body") {
        if let Some(body_str) = body.as_str() {
            return parse_call_notification(body_str);
        }
        if body.get("callInvitation").is_some() {
            return serde_json::from_value(body.clone()).ok();
        }
    }

    None
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    /// Shape reconstructed from the fields `handle_call_event` /
    /// `answer_call_with_stop` consume (invitation arrives as a Trouter
    /// 5: frame body; capture-verified on the next live incoming call).
    const REALISTIC_INVITATION: &str = r#"{
        "callInvitation": {
            "callModalities": ["Audio", "Video"],
            "replaces": null,
            "transferor": null,
            "links": {
                "acceptance": "https://cc.example/invitations/abc/acceptance",
                "end": "https://cc.example/invitations/abc/end",
                "mediaAnswer": "https://cc.example/invitations/abc/mediaAnswer",
                "p2pForkNotification": "https://cc.example/invitations/abc/p2pFork"
            },
            "mediaContent": {
                "contentType": "application/sdp",
                "blob": "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n"
            }
        },
        "participants": {
            "from": {
                "id": "8:orgid:57afc548-de19-442c-83a9-5e0d76f127aa",
                "displayName": "Grace Hopper",
                "endpointId": "ep-1",
                "languageId": "en-US"
            },
            "to": []
        },
        "conversationRequest": {
            "links": {
                "conversationEnd": "https://trouter.example/callAgent/ep/h1/conversation/conversationEnd/",
                "conversationUpdate": "https://trouter.example/callAgent/ep/h2/conversation/conversationUpdate/"
            }
        },
        "debugContent": {
            "callId": "call-123",
            "endpointId": "ep-1",
            "operationId": "op-1"
        }
    }"#;

    #[test]
    fn invitation_parses_at_top_level() {
        let n = parse_call_notification(REALISTIC_INVITATION).expect("parses");
        let from = n.participants.and_then(|p| p.from).expect("from");
        assert_eq!(from.display_name.as_deref(), Some("Grace Hopper"));
        assert_eq!(from.id.as_deref(), Some("8:orgid:57afc548-de19-442c-83a9-5e0d76f127aa"));
    }

    #[test]
    fn invitation_parses_inside_body_object_and_string() {
        let wrapped = format!(r#"{{"id":1,"method":"POST","body":{REALISTIC_INVITATION}}}"#);
        let n = parse_call_notification(&wrapped).expect("body object");
        assert!(n.call_invitation.is_some());

        let wrapped_str = serde_json::json!({ "body": REALISTIC_INVITATION }).to_string();
        let n = parse_call_notification(&wrapped_str).expect("body string");
        assert_eq!(
            n.debug_content.and_then(|d| d.call_id).as_deref(),
            Some("call-123")
        );
    }

    #[test]
    fn links_and_modalities_round_trip() {
        let n = parse_call_notification(REALISTIC_INVITATION).expect("parses");
        let inv = n.call_invitation.expect("invitation");
        let links = inv.links.expect("links");
        assert!(links.acceptance.as_deref().unwrap().ends_with("/acceptance"));
        assert!(links.end.as_deref().unwrap().ends_with("/end"));
        assert!(links.media_answer.as_deref().unwrap().ends_with("/mediaAnswer"));
        assert!(links.p2p_fork_notification.is_some());
        let mods = inv.call_modalities.expect("modalities");
        assert!(mods.iter().any(|m| m.eq_ignore_ascii_case("video")));
        assert!(inv.media_content.and_then(|m| m.blob).is_some());
    }

    #[test]
    fn non_call_json_is_none() {
        assert!(parse_call_notification(r#"{"resourceType":"NewMessage"}"#).is_none());
        assert!(parse_call_notification("not json").is_none());
        // conversationEnd link strings alone must not read as an invitation.
        assert!(parse_call_notification(r#"{"links":{"conversationEnd":"https://x/"}}"#).is_none());
    }
}
