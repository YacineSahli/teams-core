//! Answer an incoming call: SDP answer → media answer → acceptance → audio
//! session, with a cooperative stop (embedders hang up through it).
//!
//! Extracted from the CLI auto-answer path in `trouter::handle_call_event`
//! so the GUI can ring first and answer on user consent, sharing one
//! implementation. Protocol order preserved: media answer BEFORE acceptance.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::calling::{call_test::CallControls, ice, media, sdp, signaling, srtp, turn};
use crate::calling::CallNotification;
use crate::config::Config;

/// Outcome of an answered incoming call.
#[derive(Debug, Default, Clone)]
pub struct CallAnswerResult {
    pub call_accepted: bool,
    pub media_started: bool,
    pub packets_sent: u64,
    pub packets_received: u64,
    /// BUNDLE video plane counters (0 on audio-only answers).
    pub video_packets_sent: u64,
    pub video_packets_received: u64,
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

/// Answer an incoming call notification and run its media until `stop`
/// flips true (or the stop sender drops).
///
/// BUNDLE video offers (the consumer web's shape: all m-lines on one
/// transport, DTLS-SRTP) are answered with a REAL mid1 video section and
/// a video plane riding the audio session's transport. Other offers
/// answer audio-only, as before. `controls` (embedder pipes: camera
/// source, screen-share slot, remote-frame sink, camera gate) feeds the
/// video plane; `None` = headless (black frames out, frames counted in).
#[allow(clippy::too_many_arguments)]
pub async fn answer_call_with_stop(
    notification: &CallNotification,
    video: bool,
    mut stop: tokio::sync::watch::Receiver<bool>,
    controls: Option<CallControls>,
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

                        // JSEP: the answer must carry an m= section for
                        // EVERY offer m= section, in order. A short answer
                        // = instant setRemoteDescription failure (live:
                        // 410/3111 in ~600ms).
                        //
                        // BUNDLE offers (the consumer web: all m-lines on
                        // ONE transport, DTLS-only) get a REAL mid1 video
                        // answer on the same transport when we can match
                        // an H264 payload; everything else answers
                        // audio-only with port-0 reject stubs (the
                        // live-proven shape). TEAMSFAST_NO_VIDEO_ANSWER=1
                        // forces the stub path for A/B debugging.
                        let offer_dtls = blob.contains("a=fingerprint");
                        let offered_video =
                            sdp::parse_first_video_section(blob).filter(|_| video);
                        let bundle_video = offer_dtls
                            && sdp::offer_is_bundle(blob)
                            && offered_video.is_some()
                            && std::env::var("TEAMSFAST_NO_VIDEO_ANSWER").as_deref() != Ok("1");

                        let mut sdp_out = answer_result.sdp.clone();
                        if bundle_video {
                            // Audio section only; the video section (same
                            // transport) is appended after the session
                            // binds, with the real port.
                            sdp_out = sdp_out
                                .split("m=video")
                                .next()
                                .unwrap_or(&sdp_out)
                                .to_string();
                            if offer_dtls {
                                dtls_client = Some(true);
                            }
                        } else if offer_dtls {
                            let audio_part = sdp_out
                                .split("m=video")
                                .next()
                                .unwrap_or(&sdp_out)
                                .to_string();
                            sdp_out = audio_part + &reject_stub_sections(blob);
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
                        // real port (an answer SDP with `m=audio 0`
                        // REJECTS the m-line — RFC 3264 — and the
                        // acceptance transaction can never complete).
                        if let Some((candidates, local_creds, remote_creds, local_mat, remote_mat)) =
                            audio_plan.clone()
                        {
                            let video_cfg = bundle_video.then(|| {
                                let vid = offered_video.as_ref().expect("checked above");
                                media::VideoSessionConfig {
                                    send_payload_type: vid.payload_type,
                                    recv_payload_types: sdp::video_payload_types(blob),
                                    camera_on: controls.as_ref().map(|c| c.camera_on.clone()),
                                    camera_source: controls
                                        .as_ref()
                                        .map(|c| c.camera_source.clone()),
                                    screen_source: controls
                                        .as_ref()
                                        .map(|c| c.screen_source.clone()),
                                    remote_frames: controls
                                        .as_ref()
                                        .map(|c| c.remote_frames.clone()),
                                    local_preview: controls
                                        .as_ref()
                                        .and_then(|c| c.local_preview.clone()),
                                }
                            });
                            match media::MediaSession::start_with_ice_video(
                                0,
                                &candidates,
                                &local_creds,
                                &remote_creds,
                                &local_mat,
                                &remote_mat,
                                dtls_client,
                                video_cfg,
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
                                            // BUNDLE: append the mid1 video
                                            // section on the SAME transport
                                            // (real port) and port-0 stubs
                                            // for the remaining offer
                                            // m-lines (screenshare/x-data).
                                            if bundle_video {
                                                let vid =
                                                    offered_video.as_ref().expect("checked above");
                                                sdp_out = insert_bundle_group(sdp_out);
                                                sdp_out.push_str(
                                                    &sdp::bundle_video_answer_section(
                                                        &local_ip,
                                                        port,
                                                        &answer_result.audio_ice_ufrag,
                                                        &answer_result.audio_ice_pwd,
                                                        &local_cands,
                                                        vid,
                                                    ),
                                                );
                                                sdp_out.push_str(
                                                    &reject_stub_sections_after_audio(blob, true),
                                                );
                                                tracing::info!(
                                                    "BUNDLE video answered: PT {} dir {} ({} recv PTs)",
                                                    vid.payload_type,
                                                    vid.answer_direction(),
                                                    sdp::video_payload_types(blob).len()
                                                );
                                            }
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
    // Remote-gone watchdog: the CC does not reliably deliver call/end to
    // the callee (live 2026-10-20: caller hang-up produced NO trouter
    // frame and NO broker event; the callee kept streaming into the
    // void with recv frozen). Our sender always paces 50pps, so a frozen
    // recv counter after traffic means the remote leg is gone — end the
    // call locally after 30s of silence instead of wedging the slot.
    let mut last_recv: u64 = 0;
    let mut recv_stalled_since: Option<std::time::Instant> = None;
    loop {
        tokio::select! {
            _ = stats_tick.tick() => {
                if let Some(ref s) = session {
                    let stats = s.stats().await;
                    tracing::info!(
                        "Audio stats: sent={}, recv={} ({} bytes); video sent={} ({} frames), recv={} ({} frames, {} decoded)",
                        stats.packets_sent, stats.packets_received, stats.bytes_received,
                        stats.video_packets_sent, stats.video_frames_sent,
                        stats.video_packets_received, stats.video_frames_received,
                        stats.video_frames_decoded
                    );
                    result.packets_sent = stats.packets_sent;
                    result.packets_received = stats.packets_received;
                    result.video_packets_sent = stats.video_packets_sent;
                    result.video_packets_received = stats.video_packets_received;
                    if stats.packets_received > last_recv {
                        last_recv = stats.packets_received;
                        recv_stalled_since = None;
                    } else if last_recv > 0 {
                        let since = *recv_stalled_since.get_or_insert_with(std::time::Instant::now);
                        if since.elapsed() >= Duration::from_secs(30) {
                            tracing::warn!(
                                "remote end gone: recv frozen at {last_recv} for 30s — ending call"
                            );
                            break;
                        }
                    }
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

/// Port-0 reject stubs for every offer m-line after the first (audio).
/// Echoes the offer's own proto/payload list and mid per section.
fn reject_stub_sections(offer_blob: &str) -> String {
    reject_stub_sections_after_audio(offer_blob, false)
}

/// Port-0 reject stubs for every offer m-line after the first N answered
/// sections (N=1: audio only; N=2: audio + BUNDLE video). Echoes the
/// offer's own proto/payload list and mid per section.
fn reject_stub_sections_after_audio(offer_blob: &str, skip_video: bool) -> String {
    let mut sections: Vec<(String, Option<String>, bool)> = Vec::new();
    for line in offer_blob.lines() {
        if let Some(rest) = line.strip_prefix("m=") {
            let is_video = rest.starts_with("video");
            sections.push((rest.to_string(), None, is_video));
        } else if let Some(mid) = line.strip_prefix("a=mid:") {
            if let Some((_, m, _)) = sections.last_mut() {
                *m = Some(mid.trim().to_string());
            }
        }
    }
    let mut out = String::new();
    let mut video_seen = false;
    for (i, (mline, mid, is_video)) in sections.iter().enumerate() {
        if i == 0 {
            continue; // audio is answered fully
        }
        // With skip_video, the FIRST video section (mid1) is answered for
        // real — stub everything after it.
        if *is_video && !video_seen && skip_video {
            video_seen = true;
            continue;
        }
        // "audio 56575 RTP/SAVP 105 111 ..." -> "<type> 0 <proto> <pts>"
        let parts: Vec<&str> = mline.splitn(4, ' ').collect();
        if parts.len() < 4 {
            continue;
        }
        out.push_str(&format!("m={} 0 {} {}\r\n", parts[0], parts[2], parts[3]));
        out.push_str("c=IN IP4 127.0.0.1\r\n");
        if let Some(m) = mid {
            out.push_str(&format!("a=mid:{}\r\n", m));
        }
    }
    out
}

/// Insert `a=group:BUNDLE 0 1` at session level (before the first m=
/// line) when the answer carries an accepted video section.
fn insert_bundle_group(answer: String) -> String {
    if answer.contains("a=group:BUNDLE") {
        return answer;
    }
    match answer.find("m=audio") {
        Some(i) => format!("{}a=group:BUNDLE 0 1\r\n{}", &answer[..i], &answer[i..]),
        None => answer,
    }
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
