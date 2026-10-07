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
        .context("No skype token. Run `teams-cli login` first.")?;
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
        .context("No skype token. Run `teams-cli login` first.")?;
    anyhow::ensure!(
        !skype_token.is_expired(),
        "Skype token expired. Run `teams-cli login`."
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
    // BEFORE acceptance). The audio session itself starts after acceptance.
    let mut audio_plan: Option<AudioPlan> = None;
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

                        if let Err(e) = signaling::send_media_answer(
                            &http,
                            skype_token_str,
                            notification,
                            &answer_result.sdp,
                        )
                        .await
                        {
                            tracing::warn!("Failed to send media answer: {:#}", e);
                        }

                        if let (Some(local_mat), Some(remote_mat)) =
                            (local_audio_crypto, remote_audio_crypto)
                        {
                            let candidates = ice::parse_candidates_from_sdp(blob);
                            if candidates
                                .iter()
                                .any(|c| c.transport == ice::Transport::Udp && c.component == 1)
                            {
                                audio_plan = Some((
                                    candidates,
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
                    }
                    Err(e) => {
                        tracing::warn!("Could not parse SDP offer (may be compressed): {:#}", e);
                        // Acceptance still proceeds without a media answer.
                    }
                }
            }
        }
    }

    // Acceptance (audio-only modalities).
    signaling::accept_call_with_video(&http, skype_token_str, notification, video).await?;
    result.call_accepted = true;
    tracing::info!("Incoming call accepted");

    // Start the audio session now that the call is accepted.
    let mut session: Option<media::MediaSession> = None;
    if let Some((candidates, local_creds, remote_creds, local_mat, remote_mat)) = audio_plan {
        match media::MediaSession::start_with_ice(
            0,
            &candidates,
            &local_creds,
            &remote_creds,
            &local_mat,
            &remote_mat,
        )
        .await
        {
            Ok(s) => {
                tracing::info!("Audio session started on port {}", s.local_port().unwrap_or(0));
                result.media_started = true;
                session = Some(s);
            }
            Err(e) => tracing::warn!("Failed to start audio session: {:#}", e),
        }
    }

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
