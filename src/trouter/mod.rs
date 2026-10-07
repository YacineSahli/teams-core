//! Trouter v4 WebSocket push notification client
//!
//! Connects to Microsoft Teams' Trouter service to receive real-time
//! push notifications (messages, presence, calls, etc.).

pub mod registrar;
pub mod session;
pub mod websocket;

use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use tokio::time;

use crate::calling;
use crate::config::Config;

/// Reason the inner connection loop exited.
enum DisconnectReason {
    /// Clean shutdown (Ctrl+C). Do not reconnect.
    Shutdown,
    /// Error or server-initiated close. Should reconnect.
    Error(anyhow::Error),
}

/// Run the Trouter connection with automatic reconnection.
///
/// On transient errors or server-initiated disconnects, reconnects with
/// exponential backoff (1s, 2s, 4s, ... capped at 64s). On clean shutdown
/// (Ctrl+C), exits immediately.
pub async fn connect_and_run() -> Result<()> {
    let mut backoff = 1u64;

    loop {
        match connect_and_run_inner().await {
            Ok(DisconnectReason::Shutdown) => {
                return Ok(());
            }
            Ok(DisconnectReason::Error(e)) => {
                // Connection was stable (>60s), reset backoff before reconnecting.
                backoff = 1;
                tracing::warn!(
                    "Trouter disconnected after stable session: {:#}. Reconnecting in 1s...",
                    e,
                );

                tokio::select! {
                    _ = time::sleep(Duration::from_secs(1)) => {}
                    _ = tokio::signal::ctrl_c() => {
                        println!("Shutting down...");
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Trouter disconnected: {:#}. Reconnecting in {}s...",
                    e,
                    backoff
                );

                tokio::select! {
                    _ = time::sleep(Duration::from_secs(backoff)) => {}
                    _ = tokio::signal::ctrl_c() => {
                        println!("Shutting down...");
                        return Ok(());
                    }
                }

                backoff = (backoff * 2).min(64);
            }
        }
    }
}

/// Run one full Trouter session: negotiate, connect, event loop.
///
/// Returns `DisconnectReason::Shutdown` on clean Ctrl+C, or
/// `DisconnectReason::Error` when the connection should be retried.
async fn connect_and_run_inner() -> Result<DisconnectReason> {
    // Reload config each attempt so we pick up refreshed tokens.
    let config = Config::load_cached().context("Failed to load config")?;

    let skype_token = config
        .get_skype_token()
        .context("No skype token found. Run `teams-cli login` first.")?;
    anyhow::ensure!(
        !skype_token.is_expired(),
        "Skype token expired. Run `teams-cli login` to refresh."
    );

    let skype_token_str = &skype_token.token;
    let http = crate::api::client::shared_http();

    // 1. Negotiate session (returns session info + epid)
    let (session, epid) = session::negotiate(&http, skype_token_str).await?;

    // 2. Get socket.io session ID (authenticated via X-Skypetoken header)
    let session_id = session::get_session_id(&http, &session, skype_token_str, &epid).await?;

    // 3. Connect WebSocket (auth is via session ID in URL, no headers needed)
    let mut ws = websocket::TrouterSocket::connect(&session, &session_id, &epid).await?;

    // 4. Wait for handshake frame (1::)
    let frame = ws
        .recv_frame()
        .await?
        .context("Connection closed before handshake")?;

    if !frame.starts_with("1::") {
        tracing::warn!("Expected 1:: handshake, got: {}", frame);
    } else {
        tracing::info!("Received handshake frame");
    }

    // 5. Register with registrar
    let registrar_ttl_secs: u64 = 86400;
    if let Some(ref reg_url) = session.registrar_url {
        if let Err(e) = registrar::register_with_endpoint(
            &http, skype_token_str, reg_url, &session.surl, Some(&epid),
        )
        .await
        {
            tracing::warn!("Initial registrar registration failed: {:#}", e);
        }
    }
    // OstMac §106: mark the endpoint active (Teams clients send this
    // right after the handshake; the server acks with `6:1+::`).
    let activity = serde_json::json!({
        "name": "user.activity",
        "args": [{"state": "active", "cv": format!("{}.0.1", uuid::Uuid::new_v4().simple())}],
    });
    if let Err(e) = ws.send_text(&format!("5:1+::{}", activity)).await {
        tracing::warn!("user.activity send failed: {:#}", e);
    }

    // 6. Event loop: recv frames, send heartbeat, re-register before TTL,
    //    force reconnect after session max age.
    let connected_at = Instant::now();
    let mut heartbeat = time::interval(Duration::from_secs(30));
    heartbeat.tick().await; // skip first immediate tick

    // Re-register 30s before TTL expires.
    let re_register_interval = Duration::from_secs(registrar_ttl_secs.saturating_sub(30));
    let mut re_register_deadline = Box::pin(time::sleep(re_register_interval));

    // Force full reconnect after 1 hour to refresh the session.
    // The session TTL is typically ~589000s but rotating more frequently
    // keeps tokens and registrations fresh.
    let session_max_age = Duration::from_secs(3600);
    let mut session_deadline = Box::pin(time::sleep(session_max_age));

    // Stability threshold: reset backoff after 60s of successful connection.
    // We communicate this via the return value — the caller checks timing.
    let stability_threshold = Duration::from_secs(60);

    println!("Trouter connected. Listening for events... (Ctrl-C to stop)");

    let mut cdl_reregistered = false;
    let disconnect_reason = loop {
        tokio::select! {
            frame = ws.recv_frame() => {
                match frame {
                    Ok(Some(text)) => {
                        // OstMac §106: first message_loss after connect →
                        // re-register the chat (CDL) entry with the 1.9
                        // template, as the Teams clients do.
                        if !cdl_reregistered && text.contains("trouter.message_loss") {
                            cdl_reregistered = true;
                            if let Some(ref reg_url) = session.registrar_url {
                                let (h, tok, reg, surl, ep) = (http.clone(), skype_token_str.to_string(),
                                    reg_url.clone(), session.surl.clone(), epid.clone());
                                tokio::spawn(async move {
                                    if let Err(e) = registrar::register_cdl(&h, &tok, &reg, &surl, &ep,
                                        "TeamsCDLWebWorker_1.9").await {
                                        tracing::warn!("CDL re-registration failed: {:#}", e);
                                    }
                                });
                            }
                        }
                        handle_frame(&text).await
                    }
                    Ok(None) => {
                        break DisconnectReason::Error(anyhow::anyhow!("WebSocket closed by server"));
                    }
                    Err(e) => {
                        break DisconnectReason::Error(e.context("WebSocket recv error"));
                    }
                }
            }
            _ = heartbeat.tick() => {
                if let Err(e) = ws.send_text("2::").await {
                    break DisconnectReason::Error(e.context("Heartbeat send failed"));
                }
            }
            _ = &mut re_register_deadline => {
                tracing::info!("Re-registering with registrar (TTL refresh)");
                if let Some(ref reg_url) = session.registrar_url {
                    let http2 = http.clone();
                    let tok = skype_token_str.to_string();
                    let surl = session.surl.clone();
                    let reg = reg_url.clone();
                    let ep = epid.clone();
                    tokio::spawn(async move {
                        if let Err(e) = registrar::register_with_endpoint(&http2, &tok, &reg, &surl, Some(&ep)).await {
                            tracing::warn!("Re-registration failed: {:#}", e);
                        }
                    });
                }
                // Reset the timer for another cycle.
                re_register_deadline = Box::pin(time::sleep(re_register_interval));
            }
            _ = &mut session_deadline => {
                tracing::info!("Session max age reached (1h), forcing reconnect for fresh session");
                break DisconnectReason::Error(anyhow::anyhow!("Session max age reached"));
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Shutting down...");
                break DisconnectReason::Shutdown;
            }
        }
    };

    // If we were connected long enough, signal stability so caller resets backoff.
    // We do this by returning Ok (the caller pattern-matches on it).
    if connected_at.elapsed() >= stability_threshold {
        // Reset backoff indirectly: caller sees Ok and resets.
        // But we still need to convey the reason.
        // Use Ok for both shutdown and stable-error cases.
        return Ok(disconnect_reason);
    }

    match disconnect_reason {
        DisconnectReason::Shutdown => Ok(DisconnectReason::Shutdown),
        DisconnectReason::Error(e) => Err(e),
    }
}

/// Handle an incoming socket.io frame.
async fn handle_frame(frame: &str) {
    // socket.io framing:
    // 1:: — handshake (handled above)
    // 2:: — heartbeat ping (server)
    // 3::: — ephemeral message
    // 5:X::{json} — event
    // 6:X+::{json} — ack event

    if frame.starts_with("2::") {
        tracing::debug!("Heartbeat ping from server");
        return;
    }

    if frame.starts_with("5:::") || frame.starts_with("5:") {
        // Socket.IO v1 event frame: 5:ACK_ID:ENDPOINT:JSON
        // Ack (6:ID::) is sent automatically by recv_frame() in websocket.rs.
        // Here we just extract the JSON payload after the `::` separator.
        let after_5 = &frame[2..]; // skip "5:"
        let json_str = after_5
            .find("::")
            .map(|pos| &after_5[pos + 2..])
            .filter(|s| s.starts_with('{'));

        if let Some(json_str) = json_str {
            let is_call = frame.contains("NGCallManagerWin");
            let prefix = if is_call {
                "[CALL]"
            } else if frame.contains("SkypeSpacesWeb") {
                "[CALL-INFO]"
            } else {
                "[MSG]"
            };
            println!("{} Event: {}", prefix, json_str);
            crate::event_hub::publish(json_str.to_string()); // OstMac: feed embedders

            // If this is a call event, try to parse and auto-answer.
            // Embedders with UI-driven signaling (OstMac) set
            // TEAMS_MANUAL_CALLS=1 to take accept/end themselves; the
            // invitation is still published to event_hub above either way.
            if is_call && std::env::var_os("TEAMS_MANUAL_CALLS").is_none() {
                handle_call_event(json_str).await;
            }
        } else {
            println!("Frame: {}", frame);
        }
        return;
    }

    if frame.starts_with("6:") {
        if let Some(json_start) = frame.find(":::{") {
            let json_str = &frame[json_start + 3..];
            println!("Ack: {}", json_str);
        } else {
            println!("Ack frame: {}", frame);
        }
        return;
    }

    // OstMac §106: chat-service pushes arrive as HTTP-over-WS data frames
    // (`3:::`); embedders get the decoded event (was: printed, dropped).
    if let Some(payload) = frame.strip_prefix("3:::") {
        if let Some(ev) = data_frame_event(payload) {
            crate::event_hub::publish(ev); // OstMac: feed embedders
        }
    }

    println!("Frame: {}", frame);
}

/// OstMac §106: decode one Trouter `3:::` data frame payload
/// (`{id, method, url, headers, body}`) into the pushed chat-service
/// event JSON. `body` is the event itself, or base64 + gzip
/// (`X-Microsoft-Skype-Content-Encoding: gzip`, also tried when the
/// plain body isn't JSON). Only chat-service events (`resourceType` /
/// `resource` / `eventMessages`) are returned; anything else (calls,
/// other services) is None and keeps its existing path.
///
/// Exception: call-signalling callbacks posted to our registered
/// `callAgent` paths (`…/conversation/conversationEnd/`, `…/call/end/`)
/// come back through the same data frames. They are published as a
/// `callCallback` envelope so embedders can react to remote hang-up /
/// caller-cancel; every other call frame stays filtered out.
pub fn data_frame_event(payload: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    let obj = v.as_object()?;
    // `body` sits top-level or under `data` depending on the Trouter
    // version (same two shapes the call path reads); an object body is
    // the event itself.
    let find_body = |m: &serde_json::Map<String, serde_json::Value>| {
        m.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("body"))
            .map(|(_, v)| v.clone())
    };
    let body_val = find_body(obj).or_else(|| {
        obj.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("data"))
            .and_then(|(_, d)| d.as_object())
            .and_then(|d| find_body(d))
    })?;
    let url = obj
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("url"))
        .and_then(|(_, u)| u.as_str())
        .unwrap_or_default()
        .to_string();
    let is_call_callback = url.contains("conversationEnd") || url.contains("/call/end");

    if body_val.is_object() {
        if is_call_callback {
            return Some(call_callback_json(&url, &body_val));
        }
        return chat_event_json(&body_val.to_string());
    }
    let body = body_val.as_str()?;
    let gzip_header = obj
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("headers"))
        .and_then(|(_, h)| h.as_object())
        .map(|h| {
            h.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("X-Microsoft-Skype-Content-Encoding")
                    && v.as_str().map_or(false, |s| s.to_ascii_lowercase().contains("gzip"))
            })
        })
        .unwrap_or(false);
    // Decode the body: plain JSON, base64+gzip when flagged, or base64+gzip
    // unflagged when the plain text isn't JSON (legacy fallback).
    let decoded: Option<String> = if gzip_header {
        gunzip_base64(body)
    } else if serde_json::from_str::<serde_json::Value>(body).is_ok() {
        Some(body.to_string())
    } else {
        gunzip_base64(body)
    };
    let decoded = decoded?;
    if is_call_callback {
        return Some(call_callback_json(
            &url,
            &serde_json::from_str(&decoded).unwrap_or(serde_json::Value::Null),
        ));
    }
    chat_event_json(&decoded)
}

/// Wrap a call-signalling callback into the embedder envelope. The URL is
/// kept verbatim (its trailing segment names the callback: conversationEnd,
/// end, …); the body is passed through as-is (may be Null for non-JSON).
fn call_callback_json(url: &str, body: &serde_json::Value) -> String {
    serde_json::json!({ "type": "callCallback", "url": url, "body": body }).to_string()
}

fn chat_event_json(text: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    // Wrapped payloads (as the Teams clients unwrap them): `cp` = base64 +
    // gzip JSON, `gp` = base64 JSON.
    if let Some(cp) = v.get("cp").and_then(|c| c.as_str()) {
        return gunzip_base64(cp).and_then(|t| chat_event_json(&t));
    }
    if let Some(gp) = v.get("gp").and_then(|c| c.as_str()) {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD.decode(gp.trim()).ok()?;
        return chat_event_json(&String::from_utf8(raw).ok()?);
    }
    let is_chat = v.as_object()?.keys().any(|k| {
        k.eq_ignore_ascii_case("resourceType")
            || k.eq_ignore_ascii_case("resource")
            || k.eq_ignore_ascii_case("eventMessages")
    });
    is_chat.then(|| text.to_string())
}

fn gunzip_base64(body: &str) -> Option<String> {
    use base64::Engine;
    use std::io::Read;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .ok()?;
    let mut out = String::new();
    flate2::read::GzDecoder::new(&raw[..])
        .read_to_string(&mut out)
        .ok()?;
    Some(out)
}

/// Handle a call event from Trouter — parse invitation and auto-answer.
async fn handle_call_event(json_str: &str) {
    let notification = match calling::parse_call_notification(json_str) {
        Some(n) => n,
        None => {
            tracing::debug!("Could not parse call notification from JSON");
            return;
        }
    };

    // Log caller identity.
    if let Some(ref participants) = notification.participants {
        if let Some(ref from) = participants.from {
            println!(
                "  Incoming call from: {} ({})",
                from.display_name.as_deref().unwrap_or("unknown"),
                from.id.as_deref().unwrap_or("?")
            );
        }
    }

    // Log call modalities.
    if let Some(ref inv) = notification.call_invitation {
        if let Some(ref mods) = inv.call_modalities {
            println!("  Modalities: {:?}", mods);
        }
    }

    // Log call ID from debug content.
    if let Some(ref debug) = notification.debug_content {
        if let Some(ref call_id) = debug.call_id {
            println!("  Call ID: {}", call_id);
        }
    }

    // Determine if video modality is requested (the answer itself stays
    // audio-only; `answer_call_with_stop` owns the modalities).
    let has_video = notification
        .call_invitation
        .as_ref()
        .and_then(|inv| inv.call_modalities.as_ref())
        .map(|mods| mods.iter().any(|m| m.eq_ignore_ascii_case("video")))
        .unwrap_or(false);
    if has_video {
        println!("  (video offered; answering audio-only)");
    }

    // Auto-answer in a detached task: the trouter event loop must keep
    // draining (the answer flow runs until the call ends). Same behaviour
    // as the pre-extraction inline flow; embedders with UI-driven
    // signaling set TEAMS_MANUAL_CALLS=1 and take accept/end themselves.
    println!("  Auto-answering call...");
    let never_stop = tokio::sync::watch::channel(false).1;
    tokio::spawn(async move {
        if let Err(e) = crate::calling::answer_call_with_stop(&notification, false, never_stop)
            .await
        {
            tracing::warn!("Auto-answer flow failed: {:#}", e);
        }
    });
}

#[cfg(test)]
mod sendfix_tests {
    use super::data_frame_event;

    fn frame(body: &str, headers: serde_json::Value) -> String {
        serde_json::json!({"id": 7, "method": "POST", "url": "/v4/f/x/messaging",
            "headers": headers, "body": body})
        .to_string()
    }

    #[test]
    fn sendfix_data_frame_plain_chat_event_is_published() {
        let ev = r#"{"resourceType":"NewMessage","resource":{"id":"1","clientmessageid":"9"}}"#;
        let got = data_frame_event(&frame(ev, serde_json::json!({}))).unwrap();
        assert_eq!(got, ev);
    }

    #[test]
    fn sendfix_data_frame_gzip_body_is_decoded() {
        use base64::Engine;
        use std::io::Write;
        let ev = r#"{"eventMessages":[{"resourceType":"NewMessage","resource":{"id":"2"}}]}"#;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(ev.as_bytes()).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(enc.finish().unwrap());
        let hdr = serde_json::json!({"X-Microsoft-Skype-Content-Encoding": "gzip"});
        assert_eq!(data_frame_event(&frame(&b64, hdr)).as_deref(), Some(ev));
        // Header missing: the base64+gzip fallback still decodes.
        assert_eq!(data_frame_event(&frame(&b64, serde_json::json!({}))).as_deref(), Some(ev));
    }

    #[test]
    fn sendfix_data_frame_body_under_data_or_as_object() {
        let ev = r#"{"resourceType":"NewMessage","resource":{"id":"3"}}"#;
        let nested = serde_json::json!({"id": 9, "data": {"body": ev}}).to_string();
        assert_eq!(data_frame_event(&nested).as_deref(), Some(ev));
        let obj = serde_json::json!({"id": 9, "body": {"resourceType": "NewMessage"}}).to_string();
        assert!(data_frame_event(&obj).unwrap().contains("NewMessage"));
    }

    #[test]
    fn sendfix_data_frame_cp_and_gp_wrappers_are_unwrapped() {
        use base64::Engine;
        use std::io::Write;
        let ev = r#"{"type":"EventMessage","resourceType":"NewMessage","resource":{"id":"4"}}"#;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(ev.as_bytes()).unwrap();
        let cp = base64::engine::general_purpose::STANDARD.encode(enc.finish().unwrap());
        let body = serde_json::json!({"cp": cp}).to_string();
        assert_eq!(data_frame_event(&frame(&body, serde_json::json!({}))).as_deref(), Some(ev));
        let gp = base64::engine::general_purpose::STANDARD.encode(ev);
        let body = serde_json::json!({"gp": gp}).to_string();
        assert_eq!(data_frame_event(&frame(&body, serde_json::json!({}))).as_deref(), Some(ev));
    }

    #[test]
    fn sendfix_data_frame_non_chat_payloads_are_skipped() {
        assert!(data_frame_event(&frame(r#"{"callNotification":{}}"#, serde_json::json!({}))).is_none());
        assert!(data_frame_event("not json").is_none());
        assert!(data_frame_event(r#"{"id":1,"status":200}"#).is_none());
    }

    #[test]
    fn call_callback_conversation_end_is_published() {
        // Call-signalling callbacks arrive on our registered callAgent paths.
        // conversationEnd (remote hang-up / caller-cancel) must surface as a
        // callCallback envelope; other call paths stay filtered out.
        let conv_end = frame(r#"{"reason":"hangup"}"#, serde_json::json!({})).replace(
            "/v4/f/x/messaging",
            "/v4/f/EP/ab12cd34/conversation/conversationEnd/",
        );
        let got = data_frame_event(&conv_end).expect("conversationEnd publishes");
        let v: serde_json::Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["type"], "callCallback");
        assert!(v["url"].as_str().unwrap().contains("conversationEnd"));
        assert_eq!(v["body"]["reason"], "hangup");

        // A plain rosterUpdate (not conversationEnd/call end) stays filtered.
        let roster = conv_end.replace("conversationEnd", "rosterUpdate");
        assert!(data_frame_event(&roster).is_none());
    }

    #[test]
    fn call_callback_end_path_is_published_and_gzip_decoded() {
        use base64::Engine;
        use std::io::Write;
        let body = serde_json::json!({"callState": "Disconnected"}).to_string();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(body.as_bytes()).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(enc.finish().unwrap());
        let call_end = frame(
            &b64,
            serde_json::json!({"X-Microsoft-Skype-Content-Encoding": "gzip"}),
        )
        .replace("/v4/f/x/messaging", "/v4/f/EP/ab12cd34/call/end/");
        let got = data_frame_event(&call_end).expect("call/end publishes");
        let v: serde_json::Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["type"], "callCallback");
        assert_eq!(v["body"]["callState"], "Disconnected");
    }
}
