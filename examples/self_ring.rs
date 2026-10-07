//! Self-ring experiment: place a conversation and add OUR OWN MRI as a
//! call participant, so the Call Controller fans a real `callInvitation`
//! out to all our endpoints. Used to capture a live invitation payload and
//! verify the manual (UI-ringing) path end to end:
//!
//! - run the TeamsFast GUI at the same time; its trouter endpoint receives
//!   the same invitation and must show the ringing banner;
//! - this example also receives it (declining immediately, so real Teams
//!   clients only ring for a moment) and dumps the raw payload to
//!   `/tmp/self_ring_invitation.json`.
//!
//! Not part of the CLI; run with `cargo run --example self_ring --features audio`.

use anyhow::{Context, Result};
use base64::Engine as _;
use ost::calling::{self, signaling};
use ost::config::Config;
use ost::trouter::{registrar, session, websocket};

fn jwt_claim(token: &str, claim: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let padded = match payload.len() % 4 {
        2 => format!("{}==", payload),
        3 => format!("{}=", payload),
        _ => payload.to_string(),
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(padded.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload))
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get(claim).and_then(|v| v.as_str()).map(String::from)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,teams_cli=info".into()),
        )
        .init();
    let config = Config::load_cached().context("config")?;
    let skype_token = config.get_skype_token().context("no skype token")?;
    let ic3_token = config.get_ic3_token().context("no ic3 token")?;
    let skype = &skype_token.token;
    let http = ost::api::client::shared_http();

    let caller_mri = jwt_claim(skype, "skypeid")
        .map(|s| {
            if s.starts_with("orgid:") {
                format!("8:{}", s)
            } else {
                s
            }
        })
        .or_else(|| jwt_claim(skype, "oid").map(|oid| format!("8:orgid:{}", oid)))
        .context("no MRI in skype token")?;
    let caller_oid = caller_mri
        .strip_prefix("8:orgid:")
        .context("MRI not orgid form")?
        .to_string();
    let tenant_id = config
        .tenant_id
        .clone()
        .filter(|t| !t.trim().is_empty())
        .or_else(|| jwt_claim(skype, "tid"))
        .context("no tenant id")?;
    println!("self-ring as {caller_mri}");

    // 1. Own trouter endpoint (NGCallManagerWin routing) so we receive the
    //    fan-out invitation and can decline it fast.
    let (trouter_session, epid) = session::negotiate(&http, skype).await?;
    let session_id = session::get_session_id(&http, &trouter_session, skype, &epid).await?;
    let mut ws = websocket::TrouterSocket::connect(&trouter_session, &session_id, &epid).await?;
    let frame = ws
        .recv_frame()
        .await?
        .context("ws closed before handshake")?;
    if !frame.starts_with("1::") {
        tracing::warn!("expected handshake, got: {frame}");
    }
    if let Some(ref reg) = trouter_session.registrar_url {
        registrar::register_with_endpoint(&http, skype, reg, &trouter_session.surl, Some(&epid))
            .await?;
    }

    // 2. Create a conversation (phase-1 only — no SDP leg) and add OURSELVES
    //    as a call participant with audio modalities.
    let region_gtms = config.get_region_gtms().context("no region_gtms")?;
    let epconv_url = calling::derive_epconv_url(&region_gtms).context("no epconv url")?;
    let region = signaling::TeamsRegion::from_config(&config);
    let endpoint_id = uuid::Uuid::new_v4().to_string();
    let params = signaling::ConversationCallParams {
        ic3_token: &ic3_token.token,
        trouter_surl: &trouter_session.surl,
        caller_mri: &caller_mri,
        caller_display_name: "TeamsFast self-ring",
        endpoint_id: &endpoint_id,
        participant_id: &uuid::Uuid::new_v4().to_string(),
        thread_id: &signaling::echo_thread_id(&caller_oid),
        chain_id: &uuid::Uuid::new_v4().to_string(),
        message_id: &uuid::Uuid::new_v4().to_string(),
        caller_oid: &caller_oid,
        tenant_id: &tenant_id,
        region: &region,
    };
    let created = signaling::create_conversation(&http, &epconv_url, &params).await?;
    println!("conversation created; inviting ourselves…");
    signaling::invite_user(&http, &created.conversation_controller, &params, &caller_mri, false)
        .await?;

    // 3. Listen for the fan-out invitation; capture + decline fast.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut captured = false;
    loop {
        let frame = tokio::time::timeout_at(deadline, ws.recv_frame()).await;
        let Ok(frame) = frame else {
            println!("listen window over (captured={captured})");
            break;
        };
        let Some(text) = frame? else {
            println!("ws closed by server");
            break;
        };
        if !text.contains("callInvitation") {
            continue;
        }
        let json = text
            .split("::")
            .nth(1)
            .filter(|s| s.starts_with('{'))
            .unwrap_or("");
        std::fs::write("/tmp/self_ring_invitation.json", json).ok();
        println!("CAPTURED invitation -> /tmp/self_ring_invitation.json");
        match calling::parse_call_notification(json) {
            Some(n) => {
                let from = n
                    .participants
                    .as_ref()
                    .and_then(|p| p.from.as_ref())
                    .map(|f| {
                        format!(
                            "{} ({})",
                            f.display_name.as_deref().unwrap_or("?"),
                            f.id.as_deref().unwrap_or("?")
                        )
                    })
                    .unwrap_or_else(|| "(no participants)".into());
                println!("parsed caller: {from}");
                if let Err(e) = calling::decline_call(&n).await {
                    println!("decline failed: {e:#}");
                } else {
                    println!("declined (real clients stop ringing)");
                }
                captured = true;
                break;
            }
            None => println!("frame has callInvitation marker but did not parse — see dump"),
        }
    }
    if !captured {
        println!("NO invitation received — MS may dedupe self-adds; shape capture needs a real caller");
    }
    Ok(())
}
