//! Presence API for Microsoft Teams

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::client::TeamsClient;

#[derive(Debug, Deserialize)]
struct PresenceResponse {
    availability: String,
    activity: String,
}

/// Get current presence status (prints to stdout).
pub async fn get_presence() -> Result<()> {
    let client = TeamsClient::new().await?;
    let info = get_presence_data(&client).await?;

    println!("\nPresence Status:");
    println!("  Availability: {}", info.availability);
    println!("  Activity: {}", info.activity);

    Ok(())
}

// ---------------------------------------------------------------------------
// Data-returning API functions for TUI integration
// ---------------------------------------------------------------------------

/// Presence info for TUI display.
#[allow(dead_code)]
pub struct PresenceInfo {
    pub availability: String,
    pub activity: String,
}

/// CONSUMER (Teams-for-Life) endpoint publish — the UPS model the web
/// client uses (mined from its presence-service chunk, live-verified
/// 2026-10-20): `PUT {unifiedPresence}/v1/me/endpoints/` with an
/// endpoint object carrying `capabilities` (the callee-callable signal
/// read by call routing). Auth = the plain skype token; the header
/// `x-ms-client-consumer-type: teams4life` is required. The record
/// EXPIRES after ~5 minutes — callers must re-publish on a cadence
/// (the web client's PresencePostHeartbeat); call routing treats an
/// expired callee as non-callable.
pub async fn publish_endpoint_personal(client: &TeamsClient) -> Result<()> {
    let base = client.unified_presence_url();
    let base = base.trim_end_matches('/');
    let endpoint_id = uuid::Uuid::new_v4().to_string();
    let body = serde_json::json!({
        "id": endpoint_id,
        "availability": "Available",
        "activity": "Available",
        "deviceType": "Desktop",
        "capabilities": ["Audio", "Video"],
    });
    let resp = super::client::shared_http()
        .put(format!("{base}/v1/me/endpoints/"))
        .header("X-Skypetoken", client.skype_token()?)
        .header("x-ms-client-consumer-type", "teams4life")
        .header("x-ms-client-user-agent", "Teams-V2-Desktop")
        .header("x-ms-endpoint-id", &endpoint_id)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .context("UPS endpoint publish request failed")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("UPS endpoint publish failed ({}): {}", status, body);
    }
    tracing::debug!("UPS endpoint published (capabilities Audio/Video)");
    Ok(())
}

/// Fetch current presence and return structured data.
pub async fn get_presence_data(client: &TeamsClient) -> Result<PresenceInfo> {
    let resp = client.graph_get("/me/presence").await?;
    let presence: PresenceResponse = resp
        .json()
        .await
        .context("Failed to parse presence response")?;

    Ok(PresenceInfo {
        availability: presence.availability,
        activity: presence.activity,
    })
}

/// Set presence status
pub async fn set_presence(status: &str) -> Result<()> {
    let client = TeamsClient::new().await?;
    set_presence_with_client(&client, status).await
}

/// Set presence through an existing client (embedder API).
pub async fn set_presence_with_client(client: &TeamsClient, status: &str) -> Result<()> {
    let (availability, activity) = match status.to_lowercase().as_str() {
        "available" => ("Available", "Available"),
        "busy" => ("Busy", "InACall"),
        "dnd" | "donotdisturb" => ("DoNotDisturb", "Presenting"),
        "away" => ("Away", "Away"),
        "offline" => ("Offline", "OffWork"),
        "brb" | "berightback" => ("BeRightBack", "BeRightBack"),
        other => bail!(
            "Unknown status: {}. Use: available, brb, busy, dnd, away, offline",
            other
        ),
    };

    let body = serde_json::json!({
        "sessionId": "teams-cli",
        "availability": availability,
        "activity": activity,
        "expirationDuration": "PT1H"
    });

    client
        .graph_post("/me/presence/setUserPreferredPresence", &body)
        .await?;

    Ok(())
}
