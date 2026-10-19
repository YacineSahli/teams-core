//! Custom-reaction probe (sanctioned: own message in the probe thread,
//! run-8 add+immediate-DELETE precedent). Probes, with a UNICODE control
//! for comparison:
//!   1. v1.0 setReaction {"reactionType":"👍"}  (known good)
//!   2. beta  setReaction {"reactionType":"custom","displayName":…}
//! Each verified via the native message-LIST read's raw emotions map
//! (the single-message GET carries no emotions; the parser drops
//! unknown keys, so the raw dump is the evidence).
//! cargo run --example custom_reaction

use anyhow::{Context, Result};
use base64::Engine as _;
use ost::api::client::TeamsClient;
use ost::api::read_messages_data;
use ost::config::Config;

const CHAT: &str = "19:meeting_MjIyMjIyMjItMzMzMy00NDQ0LTU1NTUtNjY2NjY2NjY2NjY2@thread.v2";

/// Own MRI from the skype token's claims (self_ring pattern).
fn own_mri(config: &Config) -> Result<String> {
    let skype = config.get_skype_token().context("no skype token")?.token;
    let payload = skype.split('.').nth(1).context("jwt shape")?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload))
        .context("jwt b64")?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).context("jwt json")?;
    let id = json
        .get("skypeid")
        .and_then(|v| v.as_str())
        .map(|s| {
            if s.starts_with("orgid:") {
                format!("8:{}", s)
            } else {
                s.to_string()
            }
        })
        .or_else(|| json.get("oid").and_then(|v| v.as_str()).map(|o| format!("8:orgid:{}", o)))
        .context("no MRI claim")?;
    Ok(id)
}

/// Raw emotions of `msg_id` from the native LIST read (keys + small
/// values), so unknown/custom keys are visible.
async fn dump_emotions(client: &TeamsClient, msg_id: &str, tag: &str) -> Result<()> {
    let url = format!(
        "{}/v1/users/ME/conversations/{}/messages?pageSize=20",
        client.chat_service_url(),
        CHAT
    );
    let v: serde_json::Value = client.chat_get(&url).await?.json().await?;
    let msgs = v["messages"].as_array().context("no messages")?;
    let m = msgs.iter().find(|m| m["id"].as_str() == Some(msg_id)).context("msg not in page")?;
    let emotions = if m["properties"]["emotions"].is_null() {
        &m["emotions"]
    } else {
        &m["properties"]["emotions"]
    };
    let graph = &m["reactions"];
    if !graph.is_null() {
        println!("{tag} graph reactions: {graph}");
    }
    if emotions.is_null() {
        println!("{tag} emotions: <none>");
    } else {
        let raw = emotions.to_string();
        println!("{tag} emotions[{}]: {}", raw.len(), &raw[..raw.len().min(600)]);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,teams_cli=info".into()),
        )
        .init();
    let client = TeamsClient::new().await.context("client")?;
    let my_mri = own_mri(&Config::load_cached().context("config")?)?;
    println!("me: {my_mri}");

    let msgs = read_messages_data(&client, CHAT, 20).await.context("history")?;
    let _ = &msgs;
    // Fresh probe message (run-8 add+immediate-DELETE pattern): old
    // messages in this thread accepted 204s but never surfaced emotions
    // on the list read — probe against a message the server just made.
    let sent = ost::api::send_message_with_client_id(
        &client,
        CHAT,
        "reaction wire probe",
        &ost::api::new_client_message_id(),
    )
    .await
    .context("send probe message")?;
    let own_id = sent.id.clone().unwrap_or_else(|| sent.client_message_id.clone());
    println!("probe message {own_id}");

    // Soft-delete the probe message on exit (every path below falls
    // through to this).
    let res = run_probes(&client, &own_id).await;
    if let Err(e) = ost::api::delete_message_with_client(&client, CHAT, &own_id).await {
        println!("probe message delete failed: {e:#}");
    } else {
        println!("probe message deleted");
    }
    res
}

async fn run_probes(client: &TeamsClient, own_id: &str) -> Result<()> {
    let enc = |chat: &str| {
        chat.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{:02X}", b),
            })
            .collect::<String>()
    };
    let v1_set = format!("/chats/{}/messages/{}/setReaction", enc(CHAT), own_id);
    let v1_unset = format!("/chats/{}/messages/{}/unsetReaction", enc(CHAT), own_id);
    let beta_set = format!(
        "https://graph.microsoft.com/beta/chats/{}/messages/{}/setReaction",
        enc(CHAT),
        own_id
    );
    let beta_unset = format!(
        "https://graph.microsoft.com/beta/chats/{}/messages/{}/unsetReaction",
        enc(CHAT),
        own_id
    );

    // --- 1. Unicode control (v1.0, known good). ---
    let thumbs = serde_json::json!({"reactionType": "👍"});
    client.graph_post(&v1_set, &thumbs).await.context("unicode set")?;
    println!("UNICODE SET ok");
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    if let Err(e) = dump_emotions(client, own_id, "UNICODE-AFTER-SET").await {
        println!("dump failed: {e:#}");
    }
    client.graph_post(&v1_unset, &thumbs).await.context("unicode unset")?;
    println!("UNICODE UNSET ok");
    dump_emotions(client, own_id, "UNICODE-AFTER-UNSET").await.ok();

    // --- 2. Custom reaction (beta, displayName only — the documented
    //        minimal shape). ---
    let custom = serde_json::json!({"reactionType": "custom", "displayName": "sadcat1"});
    match client.graph_post_url(&beta_set, &custom).await {
        Ok(r) => println!("CUSTOM SET ok: {}", r.status()),
        Err(e) => {
            println!("CUSTOM SET failed: {e:#}");
            return Ok(());
        }
    }
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    if let Err(e) = dump_emotions(client, own_id, "CUSTOM-AFTER-SET").await {
        println!("dump failed: {e:#}");
    }
    match client.graph_post_url(&beta_unset, &custom).await {
        Ok(_) => println!("CUSTOM UNSET ok"),
        Err(e) => println!("CUSTOM UNSET failed: {e:#}"),
    }
    dump_emotions(client, own_id, "CUSTOM-AFTER-UNSET").await.ok();
    Ok(())
}
