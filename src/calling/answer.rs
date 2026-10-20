//! Answer an incoming call: SDP answer → media answer → acceptance → audio
//! session, with a cooperative stop (embedders hang up through it).
//!
//! Extracted from the CLI auto-answer path in `trouter::handle_call_event`
//! so the GUI can ring first and answer on user consent, sharing one
//! implementation. Protocol order preserved: media answer BEFORE acceptance.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::calling::{ice, media, sdp, signaling, srtp, turn};
use crate::calling::CallNotification;
use crate::config::Config;

/// Outcome of an answered incoming call.
#[derive(Debug, Default, Clone)]
pub struct CallAnswerResult {
    pub call_accepted: bool,
    pub media_started: bool,
    pub packets_sent: u64,
    pub packets_received: u64,
}

/// Decline a ringing call (or hang up an accepted one) by POSTing the
/// invitation's end link. Best-effort by design: caller side is a
/// fire-and-forget.
pub async fn decline_call(notification: &CallNotification) -> Result<()> {
    let config = Config::load_cached().context("Failed to load config")?;
    let skype_token = config
        .get_skype_token()
        .context("No skype token. Sign in first.")?;
    let http = crate::api::client::shared_http();
    signaling::end_call(&http, &skype_token.token, notification).await
}

/// Everything the audio session needs, parsed from the offer before
/// acceptance (the session itself starts after the acceptance POST).
type AudioPlan = (
    Vec<ice::IceCandidate>,
    ice::IceCredentials,
    ice::IceCredentials,
    srtp::SrtpKeyingMaterial,
    srtp::SrtpKeyingMaterial,
);

/// Answer an incoming call notification and run its audio until `stop`
/// flips true (or the stop sender drops). Video offers are answered
/// audio-only (`acceptedCallModalities: ["Audio"]`, same as the CLI).
pub async fn answer_call_with_stop(
    notification: &CallNotification,
    video: bool,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<CallAnswerResult> {
    let config = Config::load_cached().context("Failed to load config")?;
    let skype_token = config
        .get_skype_token()
        .context("No skype token. Sign in first.")?;
    anyhow::ensure!(
        !skype_token.is_expired(),
        "Skype token expired. Sign in again."
    );
    let skype_token_str = &skype_token.token;
    let http = crate::api::client::shared_http();

    // Caller identity (display name only; never tokens or SDP blobs in logs).
    if let Some(ref p) = notification.participants {
        if let Some(ref from) = p.from {
            tracing::info!(
                "Answering incoming call from: {} ({})",
                from.display_name.as_deref().unwrap_or("unknown"),
                from.id.as_deref().unwrap_or("?")
            );
        }
    }

    let mut result = CallAnswerResult::default();

    // CONSUMER (evt:107) invitations: the notification's mediaAnswer is
    // the `cc://ma` marker — attach to the fork first to receive the real
    // mediaAnswer/acceptance links, then run the shared answer flow on the
    // merged notification. Ringing progress rides along (best-effort).
    let notification_owned;
    let notification: &CallNotification = if notification
        .call_invitation
        .as_ref()
        .and_then(|i| i.links.as_ref())
        .map(|l| l.attach.is_some())
        .unwrap_or(false)
    {
        match signaling::attach_forked_call(&http, skype_token_str, notification).await {
            Ok(merged) => {
                let _ = signaling::send_call_progress(&http, skype_token_str, &merged).await;
                // The fork's broker channel (GET long-poll): the CC
                // delivers the callAcceptance ECHO to the CALLEE here,
                // and the callee must acknowledge it quickly or the CC
                // aborts the acceptance POST (22s hold → 430/10065
                // "Delivering call acceptance notification"). Start the
                // poll BEFORE the acceptance goes out.
                if let Some(sub) = merged
                    .call_invitation
                    .as_ref()
                    .and_then(|i| i.links.as_ref())
                    .and_then(|l| l.subscribe.clone())
                {
                    let http2 = http.clone();
                    let tok2 = skype_token_str.to_string();
                    tokio::spawn(async move {
                        broker_acceptance_echo(http2, tok2, sub).await;
                    });
                }
                notification_owned = merged;
                &notification_owned
            }
            Err(e) => {
                anyhow::bail!("Fork attach failed: {e:#}");
            }
        }
    } else {
        notification
    };

    // TURN relay (best-effort; direct/srflx still possible without it).
    let relay_config = match turn::acquire_relay_credentials(&http, skype_token_str).await {
        Ok(rc) => {
            tracing::info!(
                "Acquired relay credentials: {} servers, ttl={}s",
                rc.servers.len(),
                rc.ttl
            );
            Some(rc)
        }
        Err(e) => {
            tracing::info!("Relay credential acquisition failed (direct/srflx only): {:#}", e);
            None
        }
    };
    // The TurnClient is dropped deliberately (matches the CLI auto-answer
    // path); the allocation stays alive on the server for the call's life.
    let relay_candidate = if let Some(ref rc) = relay_config {
        turn::gather_relay_candidate(rc).await.map(|(c, _)| c)
    } else {
        None
    };
    if let Some(ref c) = relay_candidate {
        tracing::info!("Gathered relay candidate: {}:{}", c.address, c.port);
    }

    // Media answer from the offer's SDP blob (protocol order: media answer
    // BEFORE acceptance). The audio session itself starts BEFORE the answer
    // goes out: an answer SDP with `m=audio 0` REJECTS the m-line (RFC
    // 3264) — the CC then treats the callee's media leg as dead and the
    // acceptance transaction can never complete (30s hold → 408/10056
    // "waiting for acknowledgement", connectTime null — live-verified
    // 2026-10-20). The bound RTP port is patched into the SDP first.
    let mut audio_plan: Option<AudioPlan> = None;
    let mut consumer_sdp: Option<String> = None;
    let mut session: Option<media::MediaSession> = None;
    // DTLS-SRTP when the caller's offer declares a fingerprint (WebRTC
    // peers); we answered `a=setup:active` → we are the DTLS client.
    let mut dtls_client: Option<bool> = None;
    if let Some(ref inv) = notification.call_invitation {
        if let Some(ref mc) = inv.media_content {
            if let Some(ref blob) = mc.blob {
                match sdp::parse_sdp_offer(blob) {
                    Ok(offer_info) => {
                        let local_ip = sdp::get_local_ip();
                        let remote_audio_crypto = offer_info
                            .crypto_lines
                            .iter()
                            .find_map(|line| srtp::parse_crypto_line(line).ok());

                        let mut local_cands: Vec<ice::IceCandidate> = Vec::new();
                        if let Some(ref rc) = relay_candidate {
                            local_cands.push(rc.clone());
                        }

                        let answer_result = sdp::generate_sdp_answer_full(
                            &local_ip, 0, 0, &offer_info, &local_cands, &[],
                        );
                        let local_audio_crypto =
                            srtp::parse_crypto_line(&answer_result.audio_crypto_line).ok();

                        tracing::info!(
                            "Generated SDP answer ({} bytes, video={}, ufrag={})",
                            answer_result.sdp.len(),
                            offer_info.video.is_some(),
                            answer_result.audio_ice_ufrag
                        );

                        let mut sdp_out = answer_result.sdp.clone();
                        // DTLS-SRTP offers (the web is WebRTC — NO a=crypto)
                        // must not gate the media session on SDES materials:
                        // the handshake task swaps real keys into the
                        // placeholder context. Live-verified live: the web's
                        // accept-completed call started no media and the
                        // caller retried ("Missing audio SRTP keying
                        // material") because of exactly this gate.
                        let offer_dtls = blob.contains("a=fingerprint");
                        if offer_dtls {
                            dtls_client = Some(true);
                        }
                        let dummy_mat = || srtp::SrtpKeyingMaterial {
                            master_key: [0u8; 16],
                            master_salt: [0u8; 14],
                            tag: 2,
                        };
                        let (local_mat, remote_mat) = if offer_dtls {
                            (Some(dummy_mat()), Some(dummy_mat()))
                        } else {
                            (local_audio_crypto, remote_audio_crypto)
                        };
                        if let (Some(local_mat), Some(remote_mat)) =
                            (local_mat, remote_mat)
                        {
                            let candidates = ice::parse_candidates_from_sdp(blob);
                            if candidates
                                .iter()
                                .any(|c| c.transport == ice::Transport::Udp && c.component == 1)
                            {
                                audio_plan = Some((
                                    candidates.clone(),
                                    ice::IceCredentials {
                                        ufrag: answer_result.audio_ice_ufrag.clone(),
                                        pwd: answer_result.audio_ice_pwd.clone(),
                                    },
                                    ice::IceCredentials {
                                        ufrag: offer_info.ice_ufrag.clone(),
                                        pwd: offer_info.ice_pwd.clone(),
                                    },
                                    local_mat,
                                    remote_mat,
                                ));
                            } else {
                                tracing::warn!("No suitable audio ICE candidate found");
                            }
                        } else {
                            tracing::warn!(
                                "Missing audio SRTP keying material, audio session not started"
                            );
                        }

                        // Bind the RTP socket now so the answer carries the
                        // real port (see the comment above).
                        if let Some((candidates, local_creds, remote_creds, local_mat, remote_mat)) =
                            audio_plan.clone()
                        {
                            match media::MediaSession::start_with_ice(
                                0,
                                &candidates,
                                &local_creds,
                                &remote_creds,
                                &local_mat,
                                &remote_mat,
                                dtls_client,
                            )
                            .await
                            {
                                Ok(s) => {
                                    if let Ok(port) = s.local_port() {
                                        if port > 0 {
                                            sdp_out = patch_answer_media_port(&sdp_out, port);
                                            tracing::info!(
                                                "Answer SDP patched with bound RTP port {port}"
                                            );
                                        }
                                    }
                                    result.media_started = true;
                                    session = Some(s);
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to start audio session: {:#}", e)
                                }
                            }
                        }

                        if let Err(e) = signaling::send_media_answer(
                            &http,
                            skype_token_str,
                            notification,
                            &sdp_out,
                        )
                        .await
                        {
                            tracing::warn!("Failed to send media answer: {e:#}");
                        }
                        // Consumer acceptance embeds the SDP itself.
                        consumer_sdp = Some(sdp_out);
                    }
                    Err(e) => {
                        tracing::warn!("Could not parse SDP offer (may be compressed): {e:#}");
                        // Acceptance still proceeds without a media answer.
                    }
                }
            }
        }
    }

    // Acceptance (audio-only modalities).
    // Conversation notification-links registration (the web callee's
    // updateConversationLinks, after mediaAnswer, before acceptance).
    // Register our conversation notification links with
    // the conversation service (the web callee's
    // updateConversationLinks + keep-alive) — without a
    // registered target the acceptance's notification
    // fan-out 504s.
    if let Some(nl) = notification.notification_links.clone() {
        let http3 = http.clone();
        let tok3 = skype_token_str.to_string();
        let notif3 = notification.clone();
        tokio::spawn(async move {
            if let Err(e) =
                signaling::update_conversation_links(&http3, &tok3, &nl, &notif3).await
            {
                tracing::warn!("updateConversationLinks failed: {e:#}");
            }
            // Keep-alive: re-register for the call's life
            // (the conversation service expires stale
            // notification links).
            for _ in 0..20 {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                if let Err(e) =
        signaling::update_conversation_links(&http3, &tok3, &nl, &notif3)
            .await
                {
        tracing::info!("conversation keep-alive stopped: {e:#}");
        break;
                }
            }
        });
    }

    signaling::accept_call_with_sdp(&http, skype_token_str, notification, video, consumer_sdp.as_deref()).await?;
    result.call_accepted = true;
    tracing::info!("Incoming call accepted");

    // The audio session (if it started) is already running — it was
    // bound before the answer went out so the SDP carried the real
    // RTP port.

    // Run until hang-up (stop watch) — the call stays alive even when the
    // audio session failed to start (e.g. no usable ICE path in sandboxes).
    let mut stats_tick = tokio::time::interval(Duration::from_secs(5));
    stats_tick.tick().await; // skip the immediate first tick
    loop {
        tokio::select! {
            _ = stats_tick.tick() => {
                if let Some(ref s) = session {
                    let stats = s.stats().await;
                    tracing::info!(
                        "Audio stats: sent={}, recv={} ({} bytes)",
                        stats.packets_sent, stats.packets_received, stats.bytes_received
                    );
                    result.packets_sent = stats.packets_sent;
                    result.packets_received = stats.packets_received;
                }
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
        }
    }
    tracing::info!("Incoming call stopping (hang-up)");
    if let Some(mut s) = session {
        s.stop().await;
    }
    Ok(result)
}

/// Replace the placeholder (0) media port in a generated answer SDP with
/// the actually-bound RTP port. Only the audio m-line and its fallback
/// host candidate carry the placeholder (the video line intentionally
/// stays 0 = m-line rejected, for audio-only answers).
fn patch_answer_media_port(sdp: &str, port: u16) -> String {
    // Patch only the audio section (everything before the video m-line,
    // if any): the video line intentionally stays 0 = m-line rejected
    // for audio-only answers, and patching its candidate alone would
    // contradict the rejected m-line.
    let (head, tail) = match sdp.find("m=video") {
        Some(i) => (&sdp[..i], &sdp[i..]),
        None => (sdp, ""),
    };
    let head = head
        .replace("m=audio 0 RTP", &format!("m=audio {port} RTP"))
        .replace(" 0 typ host", &format!(" {port} typ host"));
    format!("{head}{tail}")
}

/// Long-poll the fork's broker message channel and acknowledge the
/// callAcceptance echo (the web callee's `handleCallAcceptance` +
/// quick-send acknowledgement). Exits when the channel 404s (call gone)
/// or after 3 minutes.
async fn broker_acceptance_echo(http: reqwest::Client, skype_token: String, url: String) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    while tokio::time::Instant::now() < deadline {
        let resp = match http
            .get(&url)
            .header("X-Skypetoken", &skype_token)
            .timeout(std::time::Duration::from_secs(35))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::info!("broker poll error (retrying): {e}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.as_u16() == 404 {
            tracing::info!("broker channel gone (404) — stopping echo poll");
            return;
        }
        if body.trim().is_empty() {
            continue;
        }
        tracing::info!(
            "broker event (HTTP {}): {}",
            status,
            &body.chars().take(2400).collect::<String>()
        );
        if !body.contains("callAcceptance") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
            continue;
        };
        let ack_url = [
            "/callAcceptance/links/acknowledgement",
            "/links/acknowledgement",
            "/callAcceptance/links/mediaAcknowledgement",
            "/callAcceptance/acknowledgement",
            "/mediaAcknowledgement",
        ]
        .iter()
        .find_map(|p| {
            v.pointer(p)
                .and_then(|x| x.as_str())
                .map(str::to_string)
        });
        let Some(ack_url) = ack_url else {
            tracing::warn!("broker callAcceptance echo carried no ack URL");
            continue;
        };
        // Ty-shaped body: the acknowledgement carries the callee's
        // renegotiation-era callback links.
        let (surl, epid) = (
            crate::trouter::current_surl(),
            crate::trouter::current_epid(),
        );
        let tc = |path: &str| -> String {
            let ep = epid.clone().unwrap_or_default();
            match &surl {
                Some(s) => crate::calling::signaling::trouter_callback(s, &ep, path),
                None => String::new(),
            }
        };
        let payload = serde_json::json!({
            "callAcceptanceAcknowledgement": {
                "links": {
                    "mediaRenegotiation": tc("call/mediaRenegotiation/"),
                    "transfer": tc("call/transfer/"),
                    "replacement": tc("call/replacement/"),
                    "balanceUpdate": tc("call/balanceUpdate/"),
                    "retargetCompletion": tc("call/retargetCompletion/"),
                    "controlVideoStreaming": tc("call/controlVideoStreaming/"),
                    "updateMediaDescriptions": tc("call/updateMediaDescriptions/")
                }
            }
        });
        match http
            .post(&ack_url)
            .header("X-Skypetoken", &skype_token)
            .header("Content-Type", "application/json")
            .json(&payload)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(r) => tracing::info!("broker acceptance ack -> HTTP {}", r.status()),
            Err(e) => tracing::warn!("broker acceptance ack failed: {e}"),
        }
    }
}
