//! Call signaling module — parse incoming call invitations and manage call lifecycle.
//!
//! This handles signaling only (no media streaming).

#[cfg(feature = "audio")]
pub mod audio;
pub mod dtls;
pub mod answer;
pub mod call_test;

pub use answer::{answer_call_with_stop, decline_call, CallAnswerResult};
pub use call_test::{
    call_controls, derive_epconv_url, run_call_test, run_call_with_controls, run_call_with_stop,
    CallControls, CallControlsHandle, CallTestResult, ScreenShareSlot,
};
#[cfg(feature = "screen")]
pub mod screen;
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
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CallLinks {
    pub acceptance: Option<String>,
    pub end: Option<String>,
    #[serde(rename = "mediaAnswer")]
    pub media_answer: Option<String>,
    #[serde(rename = "p2pForkNotification")]
    pub p2p_fork_notification: Option<String>,
    /// CONSUMER (evt:107) invitations: the fork-attach entry point, the
    /// reject link (replaces `end`) and the ringing-progress link. The
    /// real mediaAnswer/acceptance URLs arrive in the ATTACH RESPONSE —
    /// the notification itself carries the marker `cc://ma`.
    pub attach: Option<String>,
    pub reject: Option<String>,
    pub progress: Option<String>,
    /// Broker long-poll channel (GET) from the fork-attach response —
    /// the web callee's incoming call-event stream. The callAcceptance
    /// ECHO arrives here and must be acknowledged quickly or the CC
    /// aborts the callee's acceptance POST (430/10065).
    pub subscribe: Option<String>,
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
    /// The fork-assigned participant id (consumer attaches mint a fresh
    /// one per leg — the acceptance must echo it back).
    #[serde(default, rename = "participantId")]
    pub participant_id: Option<String>,
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
    /// CONSUMER invitations: `conversationInvitation.conversationController`
    /// — the join URL the fork-attach `additionalActions` entry targets.
    #[serde(default)]
    pub conversation_controller: Option<String>,
    /// CONSUMER: the conversation's notificationLinks URL (from the
    /// fork-attach join response) — POSTing our conversation callback
    /// links there registers the conversation service's notification
    /// targets for our participant (the web callee's
    /// updateConversationLinks); without it the acceptance's
    /// notification fan-out has no target (430/10065).
    #[serde(default)]
    pub notification_links: Option<String>,
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
    // We try to extract the JSON and deserialize it.
    let v: serde_json::Value = serde_json::from_str(json_str).ok()?;

    // The Trouter event JSON has a nested structure. The call notification
    // may be at the top level or nested under a "body" field parsed as string.
    if v.get("callInvitation").is_some() {
        return serde_json::from_value(v).ok();
    }

    // CONSUMER (evt:107) invitations: the payload is wrapped — `cp` =
    // base64(gzip(json)), `gp` = base64(json) — and the inner object keys
    // the notification `callNotification` (roles are single objects, the
    // invitation lives in `conversationInvitation`).
    if let Some(cn) = v.get("callNotification") {
        return parse_consumer_notification(cn, v.get("conversationInvitation"));
    }
    for key in ["cp", "gp"] {
        if let Some(wrapped) = v.get(key).and_then(|c| c.as_str()) {
            let inner = crate::trouter::decode_wrapped(key == "cp", wrapped)?;
            if let Ok(iv) = serde_json::from_str::<serde_json::Value>(&inner) {
                if let Some(cn) = iv.get("callNotification") {
                    return parse_consumer_notification(cn, iv.get("conversationInvitation"));
                }
            }
        }
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
        if let Some(cn) = body.get("callNotification") {
            return parse_consumer_notification(cn, body.get("conversationInvitation"));
        }
    }

    None
}

/// Map the CONSUMER notification shape (`callNotification` +
/// `conversationInvitation`, live-captured 2026-10-20 on the A↔B rig)
/// onto [`CallNotification`]. Attach/reject/progress carry the pre-attach
/// links; `mediaAnswer` is the `cc://ma` marker until the attach response
/// supplies the real URLs.
fn parse_consumer_notification(
    cn: &serde_json::Value,
    inv: Option<&serde_json::Value>,
) -> Option<CallNotification> {
    let from: Participant = serde_json::from_value(cn.get("from")?.clone()).ok()?;
    let to: Option<Participant> = serde_json::from_value(cn.get("to")?.clone()).ok();
    let links: CallLinks =
        serde_json::from_value(cn.get("links").cloned().unwrap_or(serde_json::Value::Null))
            .unwrap_or_default();
    let media_content: Option<MediaContent> = serde_json::from_value(
        cn.get("mediaContent").cloned().unwrap_or(serde_json::Value::Null),
    )
    .ok();
    // Modalities are not a field on the consumer shape — derive them from
    // the offer (a video m-line = a video call).
    let call_modalities = media_content.as_ref().and_then(|m| m.blob.as_ref()).map(|blob| {
        if blob.contains("m=video") {
            vec!["Audio".to_string(), "Video".to_string()]
        } else {
            vec!["Audio".to_string()]
        }
    });
    Some(CallNotification {
        call_invitation: Some(CallInvitation {
            call_modalities,
            links: Some(links),
            media_content,
        }),
        participants: Some(Participants {
            from: Some(from),
            to: to.map(|t| vec![t]),
        }),
        conversation_request: None,
        debug_content: None,
        conversation_controller: inv
            .and_then(|i| i.get("conversationController"))
            .and_then(|u| u.as_str())
            .map(str::to_string),
            notification_links: None,
})
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
                "id": "8:orgid:22222222-3333-4444-5555-666666666666",
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
        assert_eq!(from.id.as_deref(), Some("8:orgid:22222222-3333-4444-5555-666666666666"));
    }

    /// The CONSUMER (evt:107) inner shape, field-for-field from the
    /// live-captured A→B invitation (2026-10-20, cp frame gunzipped):
    /// roles as single objects, links.attach/reject/progress, the
    /// cc://ma mediaAnswer marker, conversationController on the
    /// conversationInvitation sibling.
    const CONSUMER_INVITATION: &str = r#"{
        "callNotification": {
            "from": {
                "id": "8:live:rig-consumer-a",
                "displayName": "(unknown)",
                "displayNameSource": "unknown",
                "endpointId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "participantId": "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff"
            },
            "to": {
                "id": "8:live:.cid.0123456789abcdef",
                "displayName": null,
                "endpointId": "00000000-0000-0000-0000-000000000000",
                "participantId": "aaaaaaaa-bbbb-cccc-dddd-111111111111"
            },
            "links": {
                "attach": "https://api.flightproxy.skype.com/api/v2/cp/cc-euwe-06/cc/v1/forked/0a0a0a0a/27/i1/710/attach",
                "mediaAnswer": "cc://ma",
                "progress": "https://api.flightproxy.skype.com/api/v2/cp/cc-euwe-06/cc/v1/forked/0a0a0a0a/27/i1/710/progress",
                "reject": "https://api.flightproxy.skype.com/api/v2/cp/cc-euwe-06/cc/v1/forked/0a0a0a0a/27/i1/710/reject",
                "udpTransport": "udp://52.112.124.42:3478/"
            },
            "mediaContent": {
                "contentType": "application/sdp",
                "blob": "v=0\r\nm=audio 46598 RTP/SAVP 0\r\na=crypto:2 AES_CM_128_HMAC_SHA1_80 literal:inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2^31\r\nm=video 41109 RTP/SAVP 122\r\n"
            },
            "udpKey": { "sessionKey": "literal:AAAAAAAAAAAAAAAAAAAAAA==", "ticket": "literal:BBBBBBBBBBBBBBBBBBBBBB==" }
        },
        "conversationInvitation": {
            "conversationController": "https://api.flightproxy.teams.microsoft.com/api/v2/ep/conv-euwe-06/conv/QaQaQaQa",
            "isMultiParty": false,
            "isBroadcast": false
        },
        "groupChat": { "threadId": "19:11111111222233334444555566667777@thread.v2", "messageId": null }
    }"#;

    #[test]
    fn consumer_invitation_parses_with_attach_links() {
        let n = parse_call_notification(CONSUMER_INVITATION).expect("parses consumer shape");
        let from = n.participants.as_ref().and_then(|p| p.from.as_ref()).expect("from");
        assert_eq!(from.id.as_deref(), Some("8:live:rig-consumer-a"));
        let to = n.participants.as_ref().and_then(|p| p.to.as_ref()).expect("to");
        assert_eq!(to.len(), 1);
        assert_eq!(to[0].id.as_deref(), Some("8:live:.cid.0123456789abcdef"));
        let inv = n.call_invitation.as_ref().expect("invitation");
        let links = inv.links.as_ref().expect("links");
        assert!(links.attach.as_deref().unwrap().contains("/attach"));
        assert_eq!(links.media_answer.as_deref(), Some("cc://ma"));
        assert!(links.reject.as_deref().unwrap().contains("/reject"));
        assert!(links.progress.as_deref().unwrap().contains("/progress"));
        assert_eq!(
            n.conversation_controller.as_deref(),
            Some("https://api.flightproxy.teams.microsoft.com/api/v2/ep/conv-euwe-06/conv/QaQaQaQa")
        );
        // Modalities derive from the offer: the m=video line = video call.
        let mods = inv.call_modalities.as_ref().expect("modalities");
        assert!(mods.iter().any(|m| m.eq_ignore_ascii_case("video")));
        assert!(inv
            .media_content
            .as_ref()
            .and_then(|m| m.blob.as_deref())
            .unwrap_or_default()
            .contains("a=crypto"));
    }

    /// The trouter wire form: gzip+base64 of the inner object, wrapped in
    /// {"evt":107,"cp":…} — exactly what the 3::: data frame body carries.
    #[test]
    fn consumer_invitation_parses_from_evt_wrapped_cp() {
        use base64::Engine;
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(CONSUMER_INVITATION.as_bytes()).unwrap();
        let gz = enc.finish().unwrap();
        let cp = base64::engine::general_purpose::STANDARD.encode(gz);
        let wrapped = format!(r#"{{"evt":107,"cp":"{cp}"}}"#);
        let n = parse_call_notification(&wrapped).expect("parses evt-wrapped cp");
        assert!(n
            .call_invitation
            .as_ref()
            .and_then(|i| i.links.as_ref())
            .and_then(|l| l.attach.as_ref())
            .is_some());
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
