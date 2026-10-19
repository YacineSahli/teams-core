//! Live probe: list the tenant's custom emoji via Graph beta
//! (`GET /beta/teamwork/messaging/customEmojis` — teamworkCustomEmoji:
//! displayName + inline base64 contentBytes). Read-only; run with
//! `cargo run --example custom_emoji`.

use anyhow::{Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,teams_cli=info".into()),
        )
        .init();
    let client = ost::api::client::TeamsClient::new().await.context("client")?;
    // Native directory probes first (skype token — the web client's own
    // token lacks TeamworkCustomEmoji.Read, so IT must use a non-Graph
    // endpoint for its picker; 404s are cheap).
    let base = client.chat_service_url();
    let objects = "https://eu-prod.asyncgw.teams.microsoft.com";
    for url in [
        format!("{base}/v1/users/ME/customEmojis"),
        format!("{base}/v1/customEmojis"),
        format!("{objects}/v1/customEmojis"),
        format!("{objects}/v1/users/ME/customEmojis"),
        format!("{base}/v1/users/ME/expressions"),
    ] {
        match client.chat_get(&url).await {
            Ok(r) => {
                let st = r.status();
                let body = r.text().await.unwrap_or_default();
                println!("NATIVE {} -> {} body[{}]: {}", url, st, body.len(), &body[..body.len().min(300)]);
            }
            Err(e) => println!("NATIVE {} -> {}", url, e.to_string().lines().next().unwrap_or("?")),
        }
    }
    let resp = client
        .graph_get_url("https://graph.microsoft.com/beta/teamwork/messaging/customEmojis")
        .await
        .context("GET customEmojis")?;
    let status = resp.status();
    let body = resp.text().await.context("body")?;
    println!("status {status}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let list = v["value"].as_array().cloned().unwrap_or_default();
    println!("count {}", list.len());
    for e in list.iter().take(12) {
        let name = e["displayName"].as_str().unwrap_or("?");
        let bytes = e["contentBytes"].as_str().map(str::len).unwrap_or(0);
        let ctype = e["contentType"].as_str().unwrap_or("-");
        println!("  {name}: contentBytes {bytes} b64-chars contentType={ctype}");
    }
    if list.is_empty() {
        // Print only the shape, never raw content bytes.
        let mut trimmed = v.clone();
        if let Some(arr) = trimmed["value"].as_array_mut() {
            for e in arr.iter_mut() {
                if e.get("contentBytes").is_some() {
                    e["contentBytes"] = "<elided>".into();
                }
            }
        }
        println!("raw: {}", serde_json::to_string_pretty(&trimmed)?);
    }
    Ok(())
}
