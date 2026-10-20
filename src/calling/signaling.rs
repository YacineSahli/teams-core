//! Call signaling HTTP operations — accept, send media answer, end call.
//!
//! Includes the two-phase conversation API for call placement via epconv.

use anyhow::{Context, Result};

use super::{CallLinks, CallNotification};
use uuid;

// Common headers for Teams calling API requests.
pub(crate) const SKYPE_CLIENT_HEADER: &str =
    "SkypeSpaces/1415/teams-cli/TsCallingVersion=2025.49.01.15";
pub(crate) const TEAMS_PARTITION: &str = "amer03";
pub(crate) const TEAMS_REGION: &str = "amer";
pub(crate) const TEAMS_RING: &str = "general";

/// Teams cloud region for the `ms-teams-*` request headers.
///
/// Defaults to the AMER cloud; non-default values ride on
/// `ConversationCallParams::region` / `RecordingParams::region`, sourced
/// from `from_config_or_env` at the call-placement entry points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamsRegion {
    pub partition: String,
    pub region: String,
    pub ring: String,
}

impl Default for TeamsRegion {
    fn default() -> Self {
        Self {
            partition: TEAMS_PARTITION.to_string(),
            region: TEAMS_REGION.to_string(),
            ring: TEAMS_RING.to_string(),
        }
    }
}

impl TeamsRegion {
    /// Region with per-field overrides over the AMER default.
    ///
    /// Pure helper so tests stay hermetic (process env is global).
    pub fn with_overrides(
        partition: Option<String>,
        region: Option<String>,
        ring: Option<String>,
    ) -> Self {
        let d = Self::default();
        Self {
            partition: partition.unwrap_or(d.partition),
            region: region.unwrap_or(d.region),
            ring: ring.unwrap_or(d.ring),
        }
    }

    /// Region from `TEAMS_PARTITION`/`TEAMS_REGION`/`TEAMS_RING` env
    /// vars, falling back to the AMER default per field. For entry
    /// points with no config in scope (ostmac-core calls).
    pub fn from_env_or_default() -> Self {
        Self::with_overrides(
            std::env::var("TEAMS_PARTITION").ok(),
            std::env::var("TEAMS_REGION").ok(),
            std::env::var("TEAMS_RING").ok(),
        )
    }

    /// Region from the config file's `teams_partition`/`teams_region`/
    /// `teams_ring` fields, falling back to the AMER default per field.
    ///
    /// Pure (no env read) so tests stay hermetic.
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self::with_overrides(
            config.teams_partition.clone(),
            config.teams_region.clone(),
            config.teams_ring.clone(),
        )
    }

    /// Region with per-field precedence: `TEAMS_PARTITION`/`TEAMS_REGION`/
    /// `TEAMS_RING` env vars win (mirrors the `TEAMS_EPCONV_URL` override
    /// pattern for region testing), then the config file, then the AMER
    /// default. Entry points use this so a persisted non-AMER region
    /// applies while ad-hoc env overrides still work.
    pub fn from_config_or_env(config: &crate::config::Config) -> Self {
        let base = Self::from_config(config);
        Self::with_overrides(
            std::env::var("TEAMS_PARTITION")
                .ok()
                .or(Some(base.partition)),
            std::env::var("TEAMS_REGION").ok().or(Some(base.region)),
            std::env::var("TEAMS_RING").ok().or(Some(base.ring)),
        )
    }
}

/// Request-builder extension applying the `ms-teams-*` region headers.
pub(crate) trait TeamsHeaders {
    fn teams_headers(self, region: &TeamsRegion) -> Self;
}

impl TeamsHeaders for reqwest::RequestBuilder {
    fn teams_headers(self, region: &TeamsRegion) -> Self {
        self.header("ms-teams-partition", &region.partition)
            .header("ms-teams-region", &region.region)
            .header("ms-teams-ring", &region.ring)
    }
}

/// Response from phase 1 (create conversation).
#[derive(Debug)]
pub struct ConversationCreated {
    /// URL to POST phase 2 to (the conversationController).
    pub conversation_controller: String,
    /// The exact addParticipant URL from the response links (if present).
    pub add_participant_url: Option<String>,
    /// Full response body for debugging.
    pub response_body: String,
}

/// Response from phase 2 (join with SDP).
#[derive(Debug)]
pub struct ConversationJoined {
    /// CC active URL from response headers (x-microsoft-skype-proxy-cluster-context).
    pub cc_active_url: Option<String>,
    /// Full response body for debugging.
    pub response_body: String,
}

/// Parameters for the two-phase conversation call placement.
/// Call-control auth: consumer (personal) accounts ride the
/// X-Skypetoken (the IC3 Gateway resource is AAD-only — AADSTS9002332;
/// the consumer epconv accepts the skype token, live-probed 400-on-
/// empty-body vs 401 for Bearer).
pub fn call_auth(params: &ConversationCallParams) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if params.consumer {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(params.skype_token) {
            h.insert("X-Skypetoken", v);
        }
    } else if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!(
        "Bearer {}",
        params.ic3_token
    )) {
        h.insert("Authorization", v);
    }
    h
}

pub struct ConversationCallParams<'a> {
    pub ic3_token: &'a str,
    /// Skype token (consumer call credential; work passes it too —
    /// recording and some endpoints want it either way).
    pub skype_token: &'a str,
    /// Personal (consumer) account: X-Skypetoken call auth.
    pub consumer: bool,
    pub trouter_surl: &'a str,
    pub caller_mri: &'a str,
    pub caller_display_name: &'a str,
    pub endpoint_id: &'a str,
    pub participant_id: &'a str,
    pub thread_id: &'a str,
    pub chain_id: &'a str,
    pub message_id: &'a str,
    /// OID (object ID) extracted from caller MRI, e.g. the GUID part of "8:orgid:{guid}".
    pub caller_oid: &'a str,
    pub tenant_id: &'a str,
    /// Teams cloud region for the `ms-teams-*` headers on every request.
    pub region: &'a TeamsRegion,
}

/// Build a Trouter callback URL for a specific path.
///
/// Each callback gets a unique 8-hex-char hash (matches Teams web client pattern).
/// Pattern: `{trouter_surl}callAgent/{endpoint_id}/{hash}/{path}`
pub(crate) fn trouter_callback(trouter_surl: &str, endpoint_id: &str, path: &str) -> String {
    let hash = format!("{:08x}", {
        // Simple hash from endpoint_id + path to produce unique per-path values
        let mut h: u32 = 0x811c9dc5; // FNV-1a init
        for b in endpoint_id.bytes().chain(path.bytes()) {
            h ^= b as u32;
            h = h.wrapping_mul(0x01000193);
        }
        h
    });
    format!(
        "{}callAgent/{}/{}/{}",
        trouter_surl, endpoint_id, hash, path
    )
}

/// Phase 1: Create a conversation by POSTing to /api/v2/epconv.
///
/// Returns the conversationController URL from the response.
pub async fn create_conversation(
    http: &reqwest::Client,
    epconv_url: &str,
    params: &ConversationCallParams<'_>,
) -> Result<ConversationCreated> {
    let tc = |path: &str| trouter_callback(params.trouter_surl, params.endpoint_id, path);
    let cause_id = &params.message_id[..8.min(params.message_id.len())];

    // Note: conversationRequest contains only subject/roster/properties/links.
    // Other fields (groupChat, participants, etc.) are siblings, not nested inside.
    let payload = serde_json::json!({
        "conversationRequest": {
            "subject": null,
            "roster": {
                "type": "Delta",
                "rosterUpdate": tc("conversation/rosterUpdate/")
            },
            "properties": {
                "allowConversationWithoutHost": true,
                "enableGroupCallEventMessages": true,
                "enableGroupCallUpgradeMessage": false,
                "enableGroupCallMeetupGeneration": true
            },
            "links": {
                "conversationEnd": tc("conversation/conversationEnd/"),
                "conversationUpdate": tc("conversation/conversationUpdate/"),
                "localParticipantUpdate": tc("conversation/localParticipantUpdate/"),
                "addParticipantSuccess": tc("conversation/addParticipantSuccess/"),
                "addParticipantFailure": tc("conversation/addParticipantFailure/"),
                "receiveMessage": tc("conversation/receiveMessage/")
            }
        },
        "groupContext": null,
        "groupChat": {
            "threadId": params.thread_id,
            "messageId": null
        },
        "participants": {
            "from": {
                "id": params.caller_mri,
                "displayName": params.caller_display_name,
                "endpointId": params.endpoint_id,
                "participantId": params.participant_id,
                "languageId": "en-US"
            }
        },
        "capabilities": null,
        // Capability bitmasks captured from Teams web client traffic
        "endpointCapabilities": 73463,
        "clientEndpointCapabilities": 9336554,
        "endpointMetadata": { "holographicCapabilities": 3 },
        "meetingInfo": null,
        "endpointState": {
            "endpointStateSequenceNumber": 0,
            "endpointProperties": {
                "additionalEndpointProperties": {
                    "infoShownInReportMode": "FullInformation"
                }
            }
        },
        "debugContent": {
            "ecsEtag": "\"0\"",
            "causeId": cause_id
        }
    });

    tracing::info!("Phase 1: POST {} (create conversation)", epconv_url);
    tracing::debug!(
        "Phase 1 payload: {}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );

    let resp = http
        .post(epconv_url)
        .headers(call_auth(params))
        .header("Content-Type", "application/json")
        .header("x-microsoft-skype-chain-id", params.chain_id)
        .header("x-microsoft-skype-message-id", params.message_id)
        .header("x-microsoft-skype-client", SKYPE_CLIENT_HEADER)
        .header("Referer", "https://teams.microsoft.com/")
        .teams_headers(params.region)
        .header("x-ms-migration", "True")
        .json(&payload)
        .send()
        .await
        .context("Phase 1 POST to epconv failed")?;

    let status = resp.status();

    // Extract conversationController from response headers or body
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    tracing::info!("Phase 1 response: {} ({} bytes)", status, body.len());
    tracing::debug!("Phase 1 response body: {}", &body[..body.len().min(2000)]);
    for (k, v) in headers.iter() {
        tracing::debug!(
            "Phase 1 header: {}: {}",
            k,
            v.to_str().unwrap_or("(binary)")
        );
    }

    if !status.is_success() {
        anyhow::bail!("Phase 1 epconv failed ({}): {}", status, body);
    }

    // Parse conversationController from response body
    let resp_json: serde_json::Value =
        serde_json::from_str(&body).context("Phase 1 response is not valid JSON")?;

    let conv_controller = resp_json
        .pointer("/conversationController")
        .or_else(|| resp_json.pointer("/conversationResponse/conversationController"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Also check Location header
    let conv_controller = conv_controller
        .or_else(|| {
            headers
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .context("No conversationController in phase 1 response")?;

    let add_participant_url = resp_json
        .pointer("/links/addParticipant")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    tracing::info!(
        "Phase 1 success: conversationController = {}, addParticipant link = {:?}",
        conv_controller,
        add_participant_url
    );

    Ok(ConversationCreated {
        conversation_controller: conv_controller,
        add_participant_url,
        response_body: body,
    })
}

/// Phase 2: Join the conversation with an SDP offer.
///
/// POSTs to the conversationController URL from phase 1.
pub async fn join_conversation_with_sdp(
    http: &reqwest::Client,
    conversation_controller: &str,
    params: &ConversationCallParams<'_>,
    sdp_offer: &str,
) -> Result<ConversationJoined> {
    join_conversation_with_sdp_video(http, conversation_controller, params, sdp_offer, false).await
}

/// Phase 2 with a modality choice: `video` joins with
/// `["Audio","Video"]` call modalities (group call / meeting video),
/// otherwise `["Audio"]` as [`join_conversation_with_sdp`]. The SDP
/// offer must already carry the video m-line.
pub async fn join_conversation_with_sdp_video(
    http: &reqwest::Client,
    conversation_controller: &str,
    params: &ConversationCallParams<'_>,
    sdp_offer: &str,
    video: bool,
) -> Result<ConversationJoined> {
    join_conversation_with_modalities(
        http,
        conversation_controller,
        params,
        sdp_offer,
        &accepted_call_modalities(video),
    )
    .await
}

/// Phase 2 with explicit `callModalities` (see [`join_call_modalities`]):
/// a receive-capable join declares what it can take (video, screen
/// share); the SDP direction says what it sends.
pub async fn join_conversation_with_modalities(
    http: &reqwest::Client,
    conversation_controller: &str,
    params: &ConversationCallParams<'_>,
    sdp_offer: &str,
    modalities: &[&str],
) -> Result<ConversationJoined> {
    let payload = join_conversation_payload_with_modalities(params, sdp_offer, modalities);

    tracing::info!("Phase 2: POST {} (join with SDP)", conversation_controller);
    tracing::debug!(
        "Phase 2 payload: {}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );

    let resp = http
        .post(conversation_controller)
        .headers(call_auth(params))
        .header("Content-Type", "application/json")
        .header("x-microsoft-skype-chain-id", params.chain_id)
        .header("x-microsoft-skype-message-id", params.message_id)
        .header("x-microsoft-skype-client", SKYPE_CLIENT_HEADER)
        .header("Referer", "https://teams.microsoft.com/")
        .teams_headers(params.region)
        .header("x-ms-migration", "True")
        .json(&payload)
        .send()
        .await
        .context("Phase 2 POST to conversationController failed")?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    tracing::info!("Phase 2 response: {} ({} bytes)", status, body.len());
    tracing::debug!("Phase 2 response body: {}", &body[..body.len().min(2000)]);

    if !status.is_success() {
        anyhow::bail!("Phase 2 join failed ({}): {}", status, body);
    }

    let cc_active_url = headers
        .get("x-microsoft-skype-proxy-cluster-context")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    tracing::info!("Phase 2 success. CC active URL: {:?}", cc_active_url);

    Ok(ConversationJoined {
        cc_active_url,
        response_body: body,
    })
}

/// The phase 2 join body (pure, no network): `callInvitation` carries
/// [`accepted_call_modalities`]`(video)` and the SDP offer blob.
pub fn join_conversation_payload(
    params: &ConversationCallParams<'_>,
    sdp_offer: &str,
    video: bool,
) -> serde_json::Value {
    join_conversation_payload_with_modalities(params, sdp_offer, &accepted_call_modalities(video))
}

/// The phase 2 join body with explicit `callInvitation.callModalities`.
pub fn join_conversation_payload_with_modalities(
    params: &ConversationCallParams<'_>,
    sdp_offer: &str,
    modalities: &[&str],
) -> serde_json::Value {
    let tc = |path: &str| trouter_callback(params.trouter_surl, params.endpoint_id, path);
    let cause_id = &params.message_id[..8.min(params.message_id.len())];

    // Same structure as phase 1: conversationRequest contains only
    // subject/roster/properties/links. Other fields are siblings.
    serde_json::json!({
        "conversationRequest": {
            "conversationType": null,
            "subject": "",
            "suppressDialout": true,
            "roster": {
                "type": "Delta",
                "rosterUpdate": tc("conversation/rosterUpdate/")
            },
            "properties": {
                "allowConversationWithoutHost": true,
                "enableGroupCallEventMessages": true,
                "enableGroupCallUpgradeMessage": false,
                "enableGroupCallMeetupGeneration": true
            },
            "links": {
                "conversationEnd": tc("conversation/conversationEnd/"),
                "conversationUpdate": tc("conversation/conversationUpdate/"),
                "localParticipantUpdate": tc("conversation/localParticipantUpdate/"),
                "addParticipantSuccess": tc("conversation/addParticipantSuccess/"),
                "addParticipantFailure": tc("conversation/addParticipantFailure/"),
                "addModalitySuccess": tc("conversation/addModalitySuccess/"),
                "addModalityFailure": tc("conversation/addModalityFailure/"),
                "confirmUnmute": tc("conversation/confirmUnmute/"),
                "receiveMessage": tc("conversation/receiveMessage/")
            }
        },
        "groupContext": null,
        "groupChat": {
            "threadId": params.thread_id,
            "messageId": null
        },
        "participants": {
            "from": {
                "id": params.caller_mri,
                "displayName": params.caller_display_name,
                "endpointId": params.endpoint_id,
                "participantId": params.participant_id,
                "languageId": "en-US"
            },
            "to": []
        },
        // Capability bitmasks captured from Teams web client traffic
        "capabilities": null,
        "endpointCapabilities": 73463,
        "clientEndpointCapabilities": 9336554,
        "endpointMetadata": { "holographicCapabilities": 3 },
        "meetingInfo": {
            "organizerId": params.caller_oid,
            "tenantId": params.tenant_id
        },
        "endpointState": {
            "endpointStateSequenceNumber": 0,
            "endpointProperties": {
                "preheatProperties": 1,
                "additionalEndpointProperties": {
                    "infoShownInReportMode": "FullInformation"
                }
            }
        },
        "callInvitation": {
            "callModalities": modalities,
            "replaces": null,
            "transferor": null,
            "links": {
                "progress": tc("call/progress/"),
                "mediaAnswer": tc("call/mediaAnswer/"),
                "acceptance": tc("call/acceptance/"),
                "redirection": tc("call/redirection/"),
                "end": tc("call/end/")
            },
            "clientContentForMediaController": {
                "controlVideoStreaming": tc("call/controlVideoStreaming/"),
                "csrcInfo": tc("call/csrcInfo/"),
                "dominantSpeakerInfo": tc("call/dominantSpeakerInfo/")
            },
            "pstnContent": {
                "emergencyCallCountry": "",
                "platformName": "teams-cli",
                "publicApiCall": false
            },
            "mediaContent": {
                "contentType": "application/sdp",
                "blob": sdp_offer
            }
        },
        "debugContent": {
            "ecsEtag": "\"0\"",
            "causeId": cause_id
        }
    })
}

/// Modalities an answering endpoint accepts: audio only, or audio +
/// video for a video answer (1:1 video calls).
pub fn accepted_call_modalities(video: bool) -> Vec<&'static str> {
    if video {
        vec!["Audio", "Video"]
    } else {
        vec!["Audio"]
    }
}

/// Modalities a live group call / meeting join declares: `Audio`, plus
/// `Video` when it receives video (camera on or off: the SDP direction
/// carries the camera), plus `ScreenViewer` when its offer carries a
/// screen share receive line (as the 1:1 and echo call bodies declare).
pub fn join_call_modalities(video: bool, screen_viewer: bool) -> Vec<&'static str> {
    let mut m = vec!["Audio"];
    if video {
        m.push("Video");
    }
    if screen_viewer {
        m.push("ScreenViewer");
    }
    m
}

/// Accept an incoming call by POSTing to the acceptance URL (audio only).
pub async fn accept_call(
    http: &reqwest::Client,
    skype_token: &str,
    notification: &CallNotification,
) -> Result<()> {
    accept_call_with_video(http, skype_token, notification, false).await
}

/// Accept an incoming call, advertising Video in `acceptedCallModalities`
/// when `video` is set (the SDP answer carries the video m-line either way).
pub async fn accept_call_with_video(
    http: &reqwest::Client,
    skype_token: &str,
    notification: &CallNotification,
    video: bool,
) -> Result<()> {
    accept_call_with_sdp(http, skype_token, notification, video, None).await
}

/// Accept with an optional SDP answer embedded — CONSUMER controllers
/// require the full `callAcceptance` envelope (acceptedBy + modalities +
/// mediaContent; live: 400 "The CallAcceptance field is required" for
/// the flat work shape) and the caller reads the answer SDP from
/// `callAcceptance.mediaContent.blob`.
pub async fn accept_call_with_sdp(
    http: &reqwest::Client,
    skype_token: &str,
    notification: &CallNotification,
    video: bool,
    sdp_answer: Option<&str>,
) -> Result<()> {
    let invitation = notification
        .call_invitation
        .as_ref()
        .context("No callInvitation in notification")?;
    let links = invitation
        .links
        .as_ref()
        .context("No links in callInvitation")?;
    let acceptance_url = links
        .acceptance
        .as_ref()
        .context("No acceptance URL in links")?;

    let is_consumer = links.attach.is_some();
    let payload = if is_consumer {
        let me = notification
            .participants
            .as_ref()
            .and_then(|p| p.to.as_ref())
            .and_then(|t| t.first())
            .map(|t| t.id.clone().unwrap_or_default())
            .unwrap_or_default();
        let to_part = notification
            .participants
            .as_ref()
            .and_then(|p| p.to.as_ref())
            .and_then(|t| t.first());
        let assigned_pid = to_part
            .and_then(|t| t.participant_id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        // acceptedBy.endpointId must be OUR REGISTERED endpoint (the
        // main session's epid): the CC's acceptance-notification
        // delivery resolves it against the registrar (live: random id
        // → 430/10065 trouter 504).
        let ep_for_links = to_part
            .and_then(|t| t.endpoint_id.clone())
            .filter(|e| !e.contains("0000-0000"))
            .or_else(crate::trouter::current_epid)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let cb = |path: &str| {
            crate::trouter::current_surl().map(|surl| trouter_callback(&surl, &ep_for_links, path))
        };
        let mut acceptance = serde_json::json!({
            "acceptedBy": {
                "id": me,
                "displayName": me,
                "endpointId": ep_for_links,
                "participantId": assigned_pid,
                "languageId": "en-US"
            },
            "acceptedCallModalities": accepted_call_modalities(video),
            "capabilities": null,
            "endpointCapabilities": 73463,
            // cy() bitmask from the web's AG builder: 1 = base calling
            // support (4/8 = AAD/CAE token support, which consumer
            // accounts don't declare).
            "clientEndpointCapabilities": 1,
            "callKeepAliveInterval": null,
            // Web-captured (HAR 2026-10-20): the consumer application
            // type on the acceptance.
            "applicationType": "TFL",
            // The acceptance's own callbacks are validated as required
            // (live: 400 "CallAcceptance.Links") — the AG link set.
            "links": {
                "mediaRenegotiation": cb("call/mediaRenegotiation/"),
                "transfer": cb("call/transfer/"),
                "replacement": cb("call/replacement/"),
                "balanceUpdate": cb("call/balanceUpdate/"),
                "retargetCompletion": cb("call/retargetCompletion/"),
                "controlVideoStreaming": cb("call/controlVideoStreaming/"),
                "updateMediaDescriptions": cb("call/updateMediaDescriptions/")
            },
            // The web client's AG builder always sends the media-
            // controller callback URLs with the acceptance.
            "clientContentForMediaController": {
                "controlVideoStreaming": cb("call/controlVideoStreaming/"),
                "csrcInfo": cb("call/csrcInfo/")
            }
        });
        if let Some(sdp) = sdp_answer {
            acceptance["mediaContent"] = serde_json::json!({
                "blob": sdp,
                "contentType": "application/sdp"
            });
        }
        serde_json::json!({ "callAcceptance": acceptance })
    } else {
        serde_json::json!({
            "acceptedCallModalities": accepted_call_modalities(video),
            "endpointMetadata": {
                "isCallMediaCaptured": false,
                "isMicrophoneOn": false
            }
        })
    };

    tracing::info!("Accepting call -> POST {}", acceptance_url);

    let resp = http
        .post(acceptance_url)
        .header("X-Skypetoken", skype_token)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .context("Failed to POST acceptance")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        tracing::info!("Call accepted ({}): {}", status, body);
        Ok(())
    } else {
        anyhow::bail!("Call acceptance failed ({}): {}", status, body);
    }
}

/// Send the SDP media answer to the mediaAnswer URL.
/// CONSUMER (evt:107) fork attach — the callee's entry into the call:
/// POST the attach link, receive the REAL mediaAnswer/acceptance/progress
/// links plus (when the notification carried no offer) the SDP offer.
/// Payload mirrors the web client's `sendAttachToCallInternal` (bG),
/// minimized: attach + a `join` additionalAction on the
/// conversationController. Returns a merged notification ready for the
/// shared media-answer/acceptance flow.
pub async fn attach_forked_call(
    http: &reqwest::Client,
    skype_token: &str,
    notification: &CallNotification,
) -> Result<CallNotification> {
    let invitation = notification
        .call_invitation
        .as_ref()
        .context("No callInvitation in notification")?;
    let attach_url = invitation
        .links
        .as_ref()
        .and_then(|l| l.attach.clone())
        .context("No attach URL in links (not a consumer invitation?)")?;
    let controller = notification
        .conversation_controller
        .as_deref()
        .context("No conversationController in consumer invitation")?;
    let me = notification
        .participants
        .as_ref()
        .and_then(|p| p.to.as_ref())
        .and_then(|t| t.first())
        .map(|t| t.id.clone().unwrap_or_default())
        .unwrap_or_default();
    // The DECLARED endpoint must be the main session's REGISTERED epid
    // (same reason as the caller's create — the CC delivers
    // endpoint-addressed call events via the registrar; a random id
    // has no registration and deliveries 504).
    let endpoint_id = crate::trouter::current_epid()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let participant_id = uuid::Uuid::new_v4().to_string();
    // attach.links.end is REQUIRED (live: 400 "The Links field is
    // required") — point it at our live trouter session's push path;
    // the call controller's end events then arrive on that socket.
    let end_link = crate::trouter::current_surl()
        .map(|surl| trouter_callback(&surl, &endpoint_id, "call/end/"));
    // Payload mirrors the web client's bG builder with the `payload`
    // wrapper unwrapped — this endpoint validates top-level `attach`
    // (live: 400 "The Attach field is required" when wrapped).
    // Callbacks for the join action, all on our live trouter path
    // (the web client's bG registers its own the same way).
    let cb = |path: &str| {
        crate::trouter::current_surl().map(|surl| trouter_callback(&surl, &endpoint_id, path))
    };
    let payload = serde_json::json!({
        "attach": {
            "requireMediaContent": true,
            "links": { "end": end_link },
            // Captured from the web client (HAR 2026-10-20): the consumer
            // fleet's application type rides the attach, the join's
            // conversationRequest, and the acceptance.
            "applicationType": "TFL",
        },
        "capabilities": null,
        "endpointCapabilities": 73463,
        "additionalActions": [{
            "input": {
                "capabilities": null,
                "endpointCapabilities": 73463,
                "conversationRequest": {
                    "applicationType": "TFL",
                    "roster": {
                        "type": "Delta",
                        "rosterUpdate": cb("conversation/rosterUpdate/"),
                    },
                    "links": {
                        "conversationEnd": cb("conversation/conversationEnd/"),
                        "conversationUpdate": cb("conversation/conversationUpdate/"),
                        "localParticipantUpdate": cb("conversation/localParticipantUpdate/"),
                        "addParticipantSuccess": cb("conversation/addParticipantSuccess/"),
                        "addParticipantFailure": cb("conversation/addParticipantFailure/"),
                        "receiveMessage": cb("conversation/receiveMessage/"),
                    }
                },
                "participants": {
                    "from": {
                        "id": me,
                        "displayName": me,
                        "endpointId": endpoint_id,
                        "participantId": participant_id,
                        "languageId": "en-US"
                    }
                }
            },
            "name": "join",
            "url": controller,
            "waitForResponse": true
        }]
    });

    tracing::info!("Fork attach -> POST {}", &attach_url[..attach_url.len().min(90)]);
    let resp = http
        .post(&attach_url)
        .header("X-Skypetoken", skype_token)
        .header("Content-Type", "application/json")
        .header("x-microsoft-skype-client", SKYPE_CLIENT_HEADER)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("Fork attach POST failed")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("Fork attach failed ({}): {}", status, &body.chars().take(400).collect::<String>());
    }
    tracing::info!("Fork attach OK ({} bytes)", body.len());
    tracing::debug!("Fork attach response: {}", &body.chars().take(12000).collect::<String>());

    let v: serde_json::Value =
        serde_json::from_str(&body).context("Fork attach response is not JSON")?;
    let resp_inv = v
        .pointer("/callInvitation")
        .context("No callInvitation in fork-attach response")?;
    let resp_links: CallLinks = serde_json::from_value(
        resp_inv
            .get("links")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .unwrap_or_default();

    // Merge: real mediaAnswer/acceptance/progress from the response; keep
    // attach/reject from the notification (reject may be refined to the
    // response's callLeg).
    let mut merged = notification.clone();
    let inv = merged
        .call_invitation
        .as_mut()
        .context("merged invitation")?;
    let links = inv.links.get_or_insert_with(CallLinks::default);
    if resp_links.media_answer.is_some() {
        links.media_answer = resp_links.media_answer;
    }
    if resp_links.acceptance.is_some() {
        links.acceptance = resp_links.acceptance;
    }
    if resp_links.progress.is_some() {
        links.progress = resp_links.progress;
    }
    if resp_links.end.is_some() {
        links.end = resp_links.end;
    }
    if resp_links.reject.is_some() {
        links.reject = resp_links.reject;
    }
    if resp_links.subscribe.is_some() {
        links.subscribe = resp_links.subscribe;
    }
    if inv.media_content.is_none()
        || inv
            .media_content
            .as_ref()
            .and_then(|m| m.blob.as_ref())
            .is_none()
    {
        if let Some(mc) = resp_inv.get("mediaContent") {
            inv.media_content = serde_json::from_value(mc.clone()).ok();
        }
    }
    // Stash the conversation's notificationLinks URL (the join
    // response's output.links) for the answer flow's
    // updateConversationLinks POST.
    if let Some(arr) = v.get("additionalActionResponses").and_then(|a| a.as_array()) {
        for r in arr {
            if let Some(nl) = r
                .pointer("/output/links/notificationLinks")
                .and_then(|x| x.as_str())
            {
                merged.notification_links = Some(nl.to_string());
                break;
            }
        }
    }
    // Adopt the fork-assigned identity for our leg: the acceptance must
    // echo the attach response's participantId, not a fresh one.
    if let Some(resp_to) = v
        .pointer("/participants/to")
        .and_then(|t| t.as_object())
        .or_else(|| v.get("participants").and_then(|p| p.as_object()))
    {
        let assigned = resp_to.get("participantId").and_then(|x| x.as_str());
        if let Some(assigned) = assigned {
            if let Some(parts) = merged.participants.as_mut() {
                if let Some(to) = parts.to.as_mut().and_then(|t| t.first_mut()) {
                    to.participant_id = Some(assigned.to_string());
                }
            }
        }
    }
    Ok(merged)
}

/// CONSUMER updateConversationLinks: register our conversation
/// callback links with the conversation service (the web callee does
/// this right after attach, then keeps it alive on a timer). Without
/// it the conversation service has no notification target for our
/// participant and the acceptance's fan-out dies (430/10065).
pub async fn update_conversation_links(
    http: &reqwest::Client,
    skype_token: &str,
    url: &str,
    notification: &CallNotification,
) -> Result<()> {
    let to_part = notification
        .participants
        .as_ref()
        .and_then(|p| p.to.as_ref())
        .and_then(|t| t.first());
    let me = to_part
        .map(|t| t.id.clone().unwrap_or_default())
        .unwrap_or_default();
    let ep = to_part
        .and_then(|t| t.endpoint_id.clone())
        .filter(|e| !e.contains("0000-0000"))
        .or_else(crate::trouter::current_epid)
        .unwrap_or_default();
    let pid = to_part
        .and_then(|t| t.participant_id.clone())
        .unwrap_or_default();
    let surl = crate::trouter::current_surl().context("no live trouter surl")?;
    let tc = |path: &str| trouter_callback(&surl, &ep, path);
    // QG shape (payload-unwrapped): participants + roster delta + the
    // conversation link set (fw over the ly table).
    let body = serde_json::json!({
        "participants": {
            "from": {
                "id": me,
                "displayName": me,
                "endpointId": ep,
                "participantId": pid,
                "languageId": "en-US"
            }
        },
        "roster": {
            "type": "Delta",
            "rosterUpdate": tc("conversation/rosterUpdate/")
        },
        "links": {
            "conversationEnd": tc("conversation/conversationEnd/"),
            "conversationUpdate": tc("conversation/conversationUpdate/"),
            "localParticipantUpdate": tc("conversation/localParticipantUpdate/"),
            "rosterUpdate": tc("conversation/rosterUpdate/"),
            "addParticipantSuccess": tc("conversation/addParticipantSuccess/"),
            "addParticipantFailure": tc("conversation/addParticipantFailure/"),
            "receiveMessage": tc("conversation/receiveMessage/")
        }
    });
    tracing::info!("updateConversationLinks -> POST {}", url);
    let resp = http
        .post(url)
        .header("X-Skypetoken", skype_token)
        .header("Content-Type", "application/json")
        .json(&body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .context("updateConversationLinks POST failed")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status.is_success() {
        tracing::info!("updateConversationLinks OK ({status})");
        Ok(())
    } else {
        anyhow::bail!("updateConversationLinks failed ({status}): {}", &body.chars().take(300).collect::<String>())
    }
}

/// CONSUMER ringing progress: POST the progress link
/// ({callProgress:{status:"ringing"}}) — the web client sends it right
/// after attach (best-effort).
pub async fn send_call_progress(
    http: &reqwest::Client,
    skype_token: &str,
    notification: &CallNotification,
) -> Result<()> {
    let Some(progress_url) = notification
        .call_invitation
        .as_ref()
        .and_then(|i| i.links.as_ref())
        .and_then(|l| l.progress.as_ref())
    else {
        return Ok(());
    };
    let me = notification
        .participants
        .as_ref()
        .and_then(|p| p.to.as_ref())
        .and_then(|t| t.first())
        .map(|t| t.id.clone().unwrap_or_default())
        .unwrap_or_default();
    let payload = serde_json::json!({
        "callProgress": {
            "sender": { "id": me },
            "status": "ringing",
            "phrase": "ringing"
        }
    });
    let resp = http
        .post(progress_url)
        .header("X-Skypetoken", skype_token)
        .header("Content-Type", "application/json")
        .json(&payload)
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await
        .context("Call progress POST failed")?;
    let status = resp.status();
    if status.is_success() {
        tracing::info!("Call progress (ringing) sent");
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Call progress failed ({}): {}", status, &body.chars().take(200).collect::<String>())
    }
}

pub async fn send_media_answer(
    http: &reqwest::Client,
    skype_token: &str,
    notification: &CallNotification,
    sdp_answer: &str,
) -> Result<()> {
    let invitation = notification
        .call_invitation
        .as_ref()
        .context("No callInvitation in notification")?;
    let links = invitation
        .links
        .as_ref()
        .context("No links in callInvitation")?;
    let media_answer_url = links
        .media_answer
        .as_ref()
        .context("No mediaAnswer URL in links")?;

    let media_content = serde_json::json!({
        "blob": sdp_answer,
        "contentType": "application/sdp"
    });
    // CONSUMER controllers validate a top-level `mediaAnswer` envelope
    // (live: 400 "The MediaAnswer field is required" when flat); the
    // work flow posts the flat mediaContent.
    let is_consumer = links.attach.is_some();
    let payload = if is_consumer {
        serde_json::json!({ "mediaAnswer": { "mediaContent": media_content } })
    } else {
        serde_json::json!({ "mediaContent": media_content })
    };

    tracing::info!("Sending media answer -> POST {}", media_answer_url);

    let resp = http
        .post(media_answer_url)
        .header("X-Skypetoken", skype_token)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .context("Failed to POST media answer")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        tracing::info!("Media answer sent ({}): {}", status, body);
        Ok(())
    } else {
        anyhow::bail!("Media answer failed ({}): {}", status, body);
    }
}

/// Build the standard CC signaling callback links for a call leg.
///
/// Used by both `acknowledge_call_acceptance` and `register_cc_callbacks`.
fn cc_call_links(tc: &dyn Fn(&str) -> String) -> serde_json::Value {
    serde_json::json!({
        "links": {
            "mediaAcknowledgement": tc("call/mediaAcknowledgement/"),
            "rejection": tc("call/rejection/"),
            "acknowledgement": tc("call/acknowledgement/"),
            "mediaRenegotiation": tc("call/mediaRenegotiation/"),
            "replacement": tc("call/replacement/"),
            "progress": tc("call/progress/"),
            "mediaAnswer": tc("call/mediaAnswer/"),
            "newMediaOffer": tc("call/newMediaOffer/"),
            "redirection": tc("call/redirection/"),
            "balanceUpdate": tc("call/balanceUpdate/"),
            "acceptance": tc("call/acceptance/"),
            "controlVideoStreaming": tc("call/controlVideoStreaming/"),
            "dominantSpeakerInfo": tc("call/dominantSpeakerInfo/"),
            "csrcInfo": tc("call/csrcInfo/"),
            "end": tc("call/end/"),
            "retargetCompletion": tc("call/retargetCompletion/"),
            "transfer": tc("call/transfer/"),
            "transferAcceptance": tc("call/transferAcceptance/"),
            "transferCompletion": tc("call/transferCompletion/"),
            "holdCompletion": tc("call/holdCompletion/"),
            "resumeCompletion": tc("call/resumeCompletion/"),
            "call": tc("call/updateMediaDescriptions"),
            "monitorCompletion": tc("call/monitorCompletion/")
        },
        "clientContentForMediaController": {
            "controlVideoStreaming": tc("call/controlVideoStreaming/"),
            "csrcInfo": tc("call/csrcInfo/")
        }
    })
}

/// Phase 3: Acknowledge call acceptance.
///
/// POST to the acknowledgement URL from the callAcceptance Trouter callback.
/// This tells the Call Controller we received the SDP answer and keeps the call alive.
/// Without this, CC times out and kills the call (error 430/subCode 10065).
pub async fn acknowledge_call_acceptance(
    http: &reqwest::Client,
    acknowledgement_url: &str,
    params: &ConversationCallParams<'_>,
) -> Result<()> {
    let tc = |path: &str| trouter_callback(params.trouter_surl, params.endpoint_id, path);

    tracing::info!(
        "Phase 3a: Acknowledging call acceptance -> POST {}",
        acknowledgement_url
    );

    let resp = http
        .post(acknowledgement_url)
        .headers(call_auth(params))
        .header("Content-Type", "application/json")
        .header("x-microsoft-skype-chain-id", params.chain_id)
        .header("x-microsoft-skype-message-id", params.message_id)
        .header("x-microsoft-skype-client", SKYPE_CLIENT_HEADER)
        .header("Referer", "https://teams.microsoft.com/")
        .teams_headers(params.region)
        .json(&serde_json::json!({
            "callAcceptanceAcknowledgement": cc_call_links(&tc)
        }))
        .send()
        .await
        .context("Failed to POST call acceptance acknowledgement")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        tracing::info!("Call acceptance acknowledged ({}): {}", status, body);
        Ok(())
    } else {
        anyhow::bail!(
            "Call acceptance acknowledgement failed ({}): {}",
            status,
            body
        );
    }
}

/// Phase 3b: Register CC signaling callbacks on the call leg.
///
/// POST callParticipantUpdate with Trouter callback links to the callLeg URL.
/// This tells the Call Controller where to send subsequent signaling events
/// (media renegotiation, call end, transfer, etc.).
pub async fn register_cc_callbacks(
    http: &reqwest::Client,
    call_leg_url: &str,
    params: &ConversationCallParams<'_>,
) -> Result<()> {
    let tc = |path: &str| trouter_callback(params.trouter_surl, params.endpoint_id, path);

    let payload = serde_json::json!({
        "callAcceptanceAcknowledgement": cc_call_links(&tc),
        "callParticipantUpdate": cc_call_links(&tc)
    });

    tracing::info!(
        "Phase 3b: Registering CC callbacks -> POST {}",
        call_leg_url
    );
    tracing::debug!(
        "Phase 3b payload: {}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );

    let resp = http
        .post(call_leg_url)
        .headers(call_auth(params))
        .header("Content-Type", "application/json")
        .header("x-microsoft-skype-chain-id", params.chain_id)
        .header("x-microsoft-skype-message-id", params.message_id)
        .header("x-microsoft-skype-client", SKYPE_CLIENT_HEADER)
        .header("Referer", "https://teams.microsoft.com/")
        .teams_headers(params.region)
        .json(&payload)
        .send()
        .await
        .context("Failed to POST CC callback registration")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        tracing::info!("CC callbacks registered ({}): {}", status, body);
        Ok(())
    } else {
        anyhow::bail!("CC callback registration failed ({}): {}", status, body);
    }
}

/// Echo bot MRI (Call Quality Tester).
pub const ECHO_BOT_MRI: &str = "28:cf28171e-fcfd-47e4-a1d6-79460b0b3ca0";

/// Echo bot OID (extracted from the MRI).
const ECHO_BOT_OID: &str = "cf28171e-fcfd-47e4-a1d6-79460b0b3ca0";

/// Build the 1:1 thread ID for a call to the Echo bot.
pub fn echo_thread_id(caller_oid: &str) -> String {
    format!("19:{}_{}@unq.gbl.spaces", caller_oid, ECHO_BOT_OID)
}

/// Create an Echo bot call in a single epconv POST (matching real Teams client flow).
///
/// Unlike the two-phase approach for channel calls, the echo call embeds the SDP
/// directly in the epconv request. Returns both ConversationCreated and ConversationJoined.
pub async fn create_echo_call(
    http: &reqwest::Client,
    epconv_url: &str,
    params: &ConversationCallParams<'_>,
    sdp_offer: &str,
) -> Result<(ConversationCreated, ConversationJoined)> {
    let tc = |path: &str| trouter_callback(params.trouter_surl, params.endpoint_id, path);
    let cause_id = &params.message_id[..8.min(params.message_id.len())];

    let payload = serde_json::json!({
        "conversationRequest": {
            "conversationType": null,
            "subject": "",
            "suppressDialout": true,
            "roster": {
                "type": "Delta",
                "rosterUpdate": tc("conversation/rosterUpdate/")
            },
            "properties": {
                "allowConversationWithoutHost": true,
                "enableGroupCallEventMessages": true,
                "enableGroupCallUpgradeMessage": false,
                "enableGroupCallMeetupGeneration": false
            },
            "links": {
                "conversationEnd": tc("conversation/conversationEnd/"),
                "conversationUpdate": tc("conversation/conversationUpdate/"),
                "localParticipantUpdate": tc("conversation/localParticipantUpdate/"),
                "addParticipantSuccess": tc("conversation/addParticipantSuccess/"),
                "addParticipantFailure": tc("conversation/addParticipantFailure/"),
                "addModalitySuccess": tc("conversation/addModalitySuccess/"),
                "addModalityFailure": tc("conversation/addModalityFailure/"),
                "confirmUnmute": tc("conversation/confirmUnmute/"),
                "receiveMessage": tc("conversation/receiveMessage/")
            }
        },
        "scenario": "UserInitiatedTestCall",
        "groupContext": null,
        "groupChat": {
            "threadId": params.thread_id,
            "messageId": null
        },
        "participants": {
            "from": {
                "id": params.caller_mri,
                "displayName": params.caller_display_name,
                "endpointId": params.endpoint_id,
                "participantId": params.participant_id,
                "languageId": "en-US"
            },
            "to": []
        },
        "capabilities": null,
        "endpointCapabilities": 73463,
        "clientEndpointCapabilities": 9336554,
        "endpointMetadata": { "holographicCapabilities": 3 },
        "meetingInfo": null,
        "endpointState": {
            "endpointStateSequenceNumber": 0,
            "endpointProperties": {
                "additionalEndpointProperties": {
                    "infoShownInReportMode": "FullInformation"
                }
            }
        },
        "callInvitation": {
            "callModalities": ["Audio", "Video", "ScreenViewer"],
            "replaces": null,
            "transferor": null,
            "links": {
                "progress": tc("call/progress/"),
                "mediaAnswer": tc("call/mediaAnswer/"),
                "acceptance": tc("call/acceptance/"),
                "redirection": tc("call/redirection/"),
                "end": tc("call/end/")
            },
            "clientContentForMediaController": {
                "controlVideoStreaming": tc("call/controlVideoStreaming/"),
                "csrcInfo": tc("call/csrcInfo/"),
                "dominantSpeakerInfo": tc("call/dominantSpeakerInfo/")
            },
            "pstnContent": {
                "emergencyCallCountry": "",
                "platformName": "teams-cli",
                "publicApiCall": false
            },
            "mediaContent": {
                "contentType": "application/sdp",
                "blob": sdp_offer
            }
        },
        "debugContent": {
            "ecsEtag": "\"0\"",
            "causeId": cause_id
        }
    });

    tracing::info!(
        "Echo call: POST {} (single-shot epconv with SDP, scenario=UserInitiatedTestCall)",
        epconv_url
    );

    let resp = http
        .post(epconv_url)
        .headers(call_auth(params))
        .header("Content-Type", "application/json")
        .header("x-microsoft-skype-chain-id", params.chain_id)
        .header("x-microsoft-skype-message-id", params.message_id)
        .header("x-microsoft-skype-client", SKYPE_CLIENT_HEADER)
        .header("Referer", "https://teams.microsoft.com/")
        .teams_headers(params.region)
        .header("x-ms-migration", "True")
        .json(&payload)
        .send()
        .await
        .context("Echo call POST to epconv failed")?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    tracing::info!("Echo call response: {} ({} bytes)", status, body.len());
    tracing::debug!("Echo call response body: {}", &body[..body.len().min(2000)]);
    for (k, v) in headers.iter() {
        tracing::debug!(
            "Echo call header: {}: {}",
            k,
            v.to_str().unwrap_or("(binary)")
        );
    }

    if !status.is_success() {
        anyhow::bail!("Echo call epconv failed ({}): {}", status, body);
    }

    // Parse conversationController from response
    let resp_json: serde_json::Value =
        serde_json::from_str(&body).context("Echo call response is not valid JSON")?;

    let conv_controller = resp_json
        .pointer("/conversationController")
        .or_else(|| resp_json.pointer("/conversationResponse/conversationController"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            headers
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .context("No conversationController in echo call response")?;

    let add_participant_url = resp_json
        .pointer("/links/addParticipant")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    tracing::info!(
        "Echo call: conversationController = {}, addParticipant link = {:?}",
        conv_controller,
        add_participant_url
    );

    let cc_active_url = resp_json
        .pointer("/links/active")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let created = ConversationCreated {
        conversation_controller: conv_controller,
        add_participant_url,
        response_body: body.clone(),
    };
    let joined = ConversationJoined {
        cc_active_url,
        response_body: body,
    };

    Ok((created, joined))
}

/// Invite the Echo bot into the conversation via POST /conv/{id}/add.
///
/// This is step 3 of the Echo call flow: after creating the conversation (epconv)
/// and joining with SDP, we add the Echo bot as a participant with the 1:1 thread context.
pub async fn invite_echo_bot(
    http: &reqwest::Client,
    conversation_controller: &str,
    params: &ConversationCallParams<'_>,
) -> Result<()> {
    let tc = |path: &str| trouter_callback(params.trouter_surl, params.endpoint_id, path);

    // Derive /add URL from conversation controller
    let add_url = if let Some(idx) = conversation_controller.find('?') {
        let (path, query) = conversation_controller.split_at(idx);
        format!("{}/add{}", path.trim_end_matches('/'), query)
    } else {
        format!("{}/add", conversation_controller.trim_end_matches('/'))
    };

    let echo_participant_id = uuid::Uuid::new_v4().to_string();

    let payload = serde_json::json!({
        "disableUnmute": false,
        "participants": {
            "from": {
                "id": params.caller_mri,
                "displayName": params.caller_display_name,
                "endpointId": params.endpoint_id,
                "participantId": params.participant_id,
                "languageId": "en-US"
            },
            "to": [{
                "id": ECHO_BOT_MRI,
                "participantId": echo_participant_id
            }]
        },
        "participantInvitationData": {},
        "replacementDetails": null,
        "groupContext": null,
        "groupChat": {
            "threadId": params.thread_id,
            "messageId": null
        },
        "links": {
            "addParticipantSuccess": tc("conversation/addParticipantSuccess/"),
            "addParticipantFailure": tc("conversation/addParticipantFailure/")
        }
    });

    // Fresh message-id: the conv server uses this for deduplication; reusing the
    // epconv message-id would cause a cached empty response.
    let echo_bot_msg_id = uuid::Uuid::new_v4().to_string();

    tracing::info!(
        "Inviting Echo bot -> POST {} (msg_id={})",
        add_url,
        echo_bot_msg_id
    );
    tracing::debug!(
        "Echo bot invite payload: {}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );

    let resp = http
        .post(&add_url)
        .headers(call_auth(params))
        .header("Content-Type", "application/json")
        .header("x-microsoft-skype-chain-id", params.chain_id)
        .header("x-microsoft-skype-message-id", &echo_bot_msg_id)
        .header("x-microsoft-skype-client", SKYPE_CLIENT_HEADER)
        .header("Referer", "https://teams.microsoft.com/")
        .teams_headers(params.region)
        .header("x-ms-migration", "True")
        .json(&payload)
        .send()
        .await
        .context("Failed to POST echo bot invite")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    tracing::info!(
        "Echo bot invite response: {} ({} bytes)",
        status,
        body.len()
    );
    tracing::debug!("Echo bot invite response body: {}", body);

    if !status.is_success() {
        anyhow::bail!("Echo bot invite failed ({}): {}", status, body);
    }

    Ok(())
}

/// Create a 1:1 call in a single epconv POST.
///
/// Similar to create_echo_call but without the UserInitiatedTestCall scenario.
/// Used for calling real users by their 1:1 thread ID.
pub async fn create_1to1_call(
    http: &reqwest::Client,
    epconv_url: &str,
    params: &ConversationCallParams<'_>,
    sdp_offer: &str,
    callee_mri: Option<&str>,
) -> Result<(ConversationCreated, ConversationJoined)> {
    // Consumer: the DECLARED endpoint must be the main session's
    // REGISTERED epid — the call controller resolves endpoint-addressed
    // deliveries (the acceptance notification) against the registrar; a
    // random per-call id has no registration and the acceptance aborts
    // (live: 412/430/10065 "Delivering call acceptance notification").
    let declared_epid = if params.consumer {
        crate::trouter::current_epid().unwrap_or_else(|| params.endpoint_id.to_string())
    } else {
        params.endpoint_id.to_string()
    };
    let tc = |path: &str| trouter_callback(params.trouter_surl, &declared_epid, path);
    let cause_id = &params.message_id[..8.min(params.message_id.len())];

    let payload = serde_json::json!({
        "conversationRequest": {
            "conversationType": null,
            "subject": "",
            "suppressDialout": false,  // false = ring the callee
            "roster": {
                "type": "Delta",
                "rosterUpdate": tc("conversation/rosterUpdate/")
            },
            "properties": {
                "allowConversationWithoutHost": true,
                "enableGroupCallEventMessages": true,
                "enableGroupCallUpgradeMessage": false,
                "enableGroupCallMeetupGeneration": false
            },
            "links": {
                "conversationEnd": tc("conversation/conversationEnd/"),
                "conversationUpdate": tc("conversation/conversationUpdate/"),
                "localParticipantUpdate": tc("conversation/localParticipantUpdate/"),
                "addParticipantSuccess": tc("conversation/addParticipantSuccess/"),
                "addParticipantFailure": tc("conversation/addParticipantFailure/"),
                "addModalitySuccess": tc("conversation/addModalitySuccess/"),
                "addModalityFailure": tc("conversation/addModalityFailure/"),
                "confirmUnmute": tc("conversation/confirmUnmute/"),
                "receiveMessage": tc("conversation/receiveMessage/")
            }
        },
        "groupContext": null,
        "groupChat": {
            "threadId": params.thread_id,
            "messageId": null
        },
        "participants": {
            "from": {
                "id": params.caller_mri,
                "displayName": params.caller_display_name,
                "endpointId": declared_epid,
                "participantId": params.participant_id,
                "languageId": "en-US"
            },
            "to": callee_mri
                .map(|mri| {
                    serde_json::json!([{
                        "id": mri,
                        "participantId": uuid::Uuid::new_v4().to_string()
                    }])
                })
                .unwrap_or_else(|| serde_json::json!([]))
        },
        "capabilities": null,
        "endpointCapabilities": 73463,
        "clientEndpointCapabilities": 9336554,
        "endpointMetadata": { "holographicCapabilities": 3 },
        "meetingInfo": null,
        "endpointState": {
            "endpointStateSequenceNumber": 0,
            "endpointProperties": {
                "additionalEndpointProperties": {
                    "infoShownInReportMode": "FullInformation"
                }
            }
        },
        "callInvitation": {
            "callModalities": ["Audio", "Video", "ScreenViewer"],
            "replaces": null,
            "transferor": null,
            "links": {
                "progress": tc("call/progress/"),
                "mediaAnswer": tc("call/mediaAnswer/"),
                "acceptance": tc("call/acceptance/"),
                "redirection": tc("call/redirection/"),
                "end": tc("call/end/")
            },
            "clientContentForMediaController": {
                "controlVideoStreaming": tc("call/controlVideoStreaming/"),
                "csrcInfo": tc("call/csrcInfo/"),
                "dominantSpeakerInfo": tc("call/dominantSpeakerInfo/")
            },
            "pstnContent": {
                "emergencyCallCountry": "",
                "platformName": "teams-cli",
                "publicApiCall": false
            },
            "mediaContent": {
                "contentType": "application/sdp",
                "blob": sdp_offer
            }
        },
        "debugContent": {
            "ecsEtag": "\"0\"",
            "causeId": cause_id
        }
    });

    tracing::info!(
        "1:1 call: POST {} (single-shot epconv with SDP)",
        epconv_url
    );

    let resp = http
        .post(epconv_url)
        .headers(call_auth(params))
        .header("Content-Type", "application/json")
        .header("x-microsoft-skype-chain-id", params.chain_id)
        .header("x-microsoft-skype-message-id", params.message_id)
        .header("x-microsoft-skype-client", SKYPE_CLIENT_HEADER)
        .header("Referer", "https://teams.microsoft.com/")
        .teams_headers(params.region)
        .header("x-ms-migration", "True")
        .json(&payload)
        .send()
        .await
        .context("1:1 call POST to epconv failed")?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    tracing::info!("1:1 call response: {} ({} bytes)", status, body.len());
    tracing::debug!("1:1 call response body: {}", &body[..body.len().min(2000)]);

    if !status.is_success() {
        anyhow::bail!("1:1 call epconv failed ({}): {}", status, body);
    }

    // Parse conversationController from response
    let resp_json: serde_json::Value =
        serde_json::from_str(&body).context("1:1 call response is not valid JSON")?;

    let conv_controller = resp_json
        .pointer("/conversationController")
        .or_else(|| resp_json.pointer("/conversationResponse/conversationController"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            headers
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .context("No conversationController in 1:1 call response")?;

    let add_participant_url = resp_json
        .pointer("/links/addParticipant")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    tracing::info!(
        "1:1 call: conversationController = {}, addParticipant link = {:?}",
        conv_controller,
        add_participant_url
    );

    let cc_active_url = resp_json
        .pointer("/links/active")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let created = ConversationCreated {
        conversation_controller: conv_controller,
        add_participant_url,
        response_body: body.clone(),
    };
    let joined = ConversationJoined {
        cc_active_url,
        response_body: body,
    };

    Ok((created, joined))
}

/// Invite a user into the conversation via POST /conv/{id}/add.
///
/// This is step 3 of the 1:1 call flow: after creating the conversation (epconv)
/// and joining with SDP, we add the callee as a participant.
///
/// If `include_video` is true, the call invitation will include Video modality.
pub async fn invite_user(
    http: &reqwest::Client,
    conversation_controller: &str,
    params: &ConversationCallParams<'_>,
    callee_mri: &str,
    include_video: bool,
) -> Result<()> {
    let tc = |path: &str| trouter_callback(params.trouter_surl, params.endpoint_id, path);

    // Derive /add URL from conversation controller
    let add_url = if let Some(idx) = conversation_controller.find('?') {
        let (path, query) = conversation_controller.split_at(idx);
        format!("{}/add{}", path.trim_end_matches('/'), query)
    } else {
        format!("{}/add", conversation_controller.trim_end_matches('/'))
    };

    let callee_participant_id = uuid::Uuid::new_v4().to_string();
    let call_modalities: Vec<&str> = if include_video {
        vec!["Audio", "Video"]
    } else {
        vec!["Audio"]
    };

    let payload = serde_json::json!({
        "disableUnmute": false,
        "participants": {
            "from": {
                "id": params.caller_mri,
                "displayName": params.caller_display_name,
                "endpointId": params.endpoint_id,
                "participantId": params.participant_id,
                "languageId": "en-US"
            },
            "to": [{
                "id": callee_mri,
                "participantId": callee_participant_id
            }]
        },
        // Empty participantInvitationData, exactly like the WORKING echo
        // bot invite. The previous shape — callModalities +
        // callDirection:"Outgoing" — produced one-sided calls against
        // real clients: they answered but never streamed RTP (peer RTCP
        // pkt_count stayed 0) and the CDR recorded the call with
        // REVERSED direction ("missed call from" the callee). The
        // modalities already ride on the epconv-level callInvitation.
        "participantInvitationData": {},
        // The callInvitation's OWN links are the CALLER's call-channel
        // callbacks — where the call controller delivers the caller's
        // call events. `acceptance` is the destination for the CC's
        // "call acceptance notification" (the callee's callAcceptance
        // fan-out); without it the CC falls back to an endpoint lookup
        // that has no target and 504s, aborting the whole acceptance
        // (live: 412/430/10065, 22s hold). Mined from the web client's
        // callInvitation builder (calling-pluginless chunk).
        "callInvitation": {
            "callModalities": call_modalities,
            "replaces": null,
            "transferor": null,
            "links": {
                "progress": tc("call/progress/"),
                "mediaAnswer": tc("call/mediaAnswer/"),
                "acceptance": tc("call/acceptance/"),
                "redirection": tc("call/redirection/"),
                "end": tc("call/end/")
            },
            "clientContentForMediaController": {
                "controlVideoStreaming": tc("call/controlVideoStreaming/"),
                "csrcInfo": tc("call/csrcInfo/")
            }
        },
        "replacementDetails": null,
        "groupContext": null,
        "groupChat": {
            "threadId": params.thread_id,
            "messageId": null
        },
        "links": {
            "addParticipantSuccess": tc("conversation/addParticipantSuccess/"),
            "addParticipantFailure": tc("conversation/addParticipantFailure/")
        }
    });

    // Fresh message-id for deduplication
    let invite_msg_id = uuid::Uuid::new_v4().to_string();

    tracing::info!(
        "Inviting user {} -> POST {} (msg_id={})",
        callee_mri,
        add_url,
        invite_msg_id
    );
    tracing::debug!(
        "User invite payload: {}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );

    let resp = http
        .post(&add_url)
        .headers(call_auth(params))
        .header("Content-Type", "application/json")
        .header("x-microsoft-skype-chain-id", params.chain_id)
        .header("x-microsoft-skype-message-id", &invite_msg_id)
        .header("x-microsoft-skype-client", SKYPE_CLIENT_HEADER)
        .header("Referer", "https://teams.microsoft.com/")
        .teams_headers(params.region)
        .header("x-ms-migration", "True")
        .json(&payload)
        .send()
        .await
        .context("Failed to POST user invite")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    tracing::info!("User invite response: {} ({} bytes)", status, body.len());
    tracing::debug!("User invite response body: {}", body);

    if !status.is_success() {
        anyhow::bail!("User invite failed ({}): {}", status, body);
    }

    Ok(())
}

/// End a call by POSTing to the end URL.
pub async fn end_call(
    http: &reqwest::Client,
    skype_token: &str,
    notification: &CallNotification,
) -> Result<()> {
    let invitation = notification
        .call_invitation
        .as_ref()
        .context("No callInvitation in notification")?;
    let links = invitation
        .links
        .as_ref()
        .context("No links in callInvitation")?;
    let end_url = links
        .end
        .as_ref()
        // CONSUMER invitations carry `reject` instead of `end`.
        .or(links.reject.as_ref())
        .context("No end/reject URL in links")?;

    // CONSUMER fork reject links answer 405 to POST — the web client
    // declines via DELETE on the reject link (rejectCallWithFetchAndKeepAlive
    // -> sendDeleteRequest). Plain `end` links stay POST.
    let is_fork_reject = links.end.is_none() && links.reject.is_some();
    let resp = if is_fork_reject {
        // Web shape (Vw builder): DELETE with {payload:{callEnd}} —
        // a bare DELETE 500s (10053). CALL_END_CODE.REJECT = 603.
        // The fork endpoints unwrap `payload` (live: 400 "The CallEnd
        // field is required" when nested).
        let body = serde_json::json!({
            "callEnd": {
                "code": 603,
                "subCode": 0,
                "phrase": "localUserInitiated",
                "resultCategories": ["Success"]
            }
        });
        tracing::info!("Ending call (fork reject) -> DELETE {}", end_url);
        http.delete(end_url)
            .header("X-Skypetoken", skype_token)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to DELETE reject call")?
    } else {
        tracing::info!("Ending call -> POST {}", end_url);
        http.post(end_url)
            .header("X-Skypetoken", skype_token)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({}))
            .send()
            .await
            .context("Failed to POST end call")?
    };

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        tracing::info!("Call ended ({}): {}", status, body);
        Ok(())
    } else {
        anyhow::bail!("Call end failed ({}): {}", status, body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_for(region: &TeamsRegion) -> reqwest::header::HeaderMap {
        reqwest::Client::new()
            .post("https://example.invalid/")
            .teams_headers(region)
            .build()
            .expect("build request")
            .headers()
            .clone()
    }

    #[test]
    fn default_region_headers_are_amer() {
        let h = headers_for(&TeamsRegion::default());
        assert_eq!(h.get("ms-teams-partition").unwrap(), "amer03");
        assert_eq!(h.get("ms-teams-region").unwrap(), "amer");
        assert_eq!(h.get("ms-teams-ring").unwrap(), "general");
    }

    #[test]
    fn custom_region_headers_override_default() {
        let eu = TeamsRegion {
            partition: "euwe01".to_string(),
            region: "euwe".to_string(),
            ring: "general".to_string(),
        };
        let h = headers_for(&eu);
        assert_eq!(h.get("ms-teams-partition").unwrap(), "euwe01");
        assert_eq!(h.get("ms-teams-region").unwrap(), "euwe");
        assert_eq!(h.get("ms-teams-ring").unwrap(), "general");
    }

    #[test]
    fn overrides_apply_per_field_over_default() {
        let r = TeamsRegion::with_overrides(None, Some("euwe".to_string()), None);
        assert_eq!(r.partition, "amer03");
        assert_eq!(r.region, "euwe");
        assert_eq!(r.ring, "general");

        let all_none = TeamsRegion::with_overrides(None, None, None);
        assert_eq!(all_none, TeamsRegion::default());
    }

    #[test]
    fn config_region_applies_per_field_over_default() {
        use crate::config::Config;
        let empty = Config::default();
        assert_eq!(TeamsRegion::from_config(&empty), TeamsRegion::default());

        let mut eu = Config::default();
        eu.teams_partition = Some("euwe01".to_string());
        eu.teams_region = Some("euwe".to_string());
        let r = TeamsRegion::from_config(&eu);
        assert_eq!(r.partition, "euwe01");
        assert_eq!(r.region, "euwe");
        assert_eq!(r.ring, "general");

        // Config values reach the wire headers.
        let h = headers_for(&r);
        assert_eq!(h.get("ms-teams-partition").unwrap(), "euwe01");
        assert_eq!(h.get("ms-teams-region").unwrap(), "euwe");
    }

    #[test]
    fn video_join_declares_video_modality() {
        // Group/meeting legs placed with a camera must JOIN with
        // ["Audio","Video"] callModalities — the label that makes the leg
        // video-capable (screen share, camera tiles). run_call_with_controls
        // threads use_camera here since the join-branch fix.
        let eu = TeamsRegion::default();
        let params = ConversationCallParams {
            ic3_token: "",
            skype_token: "",
            consumer: false,
            trouter_surl: "",
            caller_mri: "",
            caller_display_name: "",
            endpoint_id: "",
            participant_id: "",
            thread_id: "",
            chain_id: "",
            message_id: "0123456789abcdef",
            caller_oid: "",
            tenant_id: "",
            region: &eu,
        };
        let video = join_conversation_payload(&params, "v=0", true);
        assert_eq!(
            video["callInvitation"]["callModalities"],
            serde_json::json!(["Audio", "Video"])
        );
        let audio = join_conversation_payload(&params, "v=0", false);
        assert_eq!(
            audio["callInvitation"]["callModalities"],
            serde_json::json!(["Audio"])
        );
    }

    #[test]
    fn params_region_threads_into_headers() {
        let eu =
            TeamsRegion::with_overrides(Some("euwe01".to_string()), Some("euwe".to_string()), None);
        let params = ConversationCallParams {
            ic3_token: "",
            skype_token: "",
            consumer: false,
            trouter_surl: "",
            caller_mri: "",
            caller_display_name: "",
            endpoint_id: "",
            participant_id: "",
            thread_id: "",
            chain_id: "",
            message_id: "",
            caller_oid: "",
            tenant_id: "",
            region: &eu,
        };
        // Same call pattern as all 8 signaling request sites.
        let h = headers_for(params.region);
        assert_eq!(h.get("ms-teams-partition").unwrap(), "euwe01");
        assert_eq!(h.get("ms-teams-region").unwrap(), "euwe");
        assert_eq!(h.get("ms-teams-ring").unwrap(), "general");
    }
}
