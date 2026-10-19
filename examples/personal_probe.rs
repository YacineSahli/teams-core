//! Teams PERSONAL (consumer) account probe — how far the consumer path
//! gets on our stack, with ONE device-code approval from a personal
//! Microsoft account.
//!
//! Wire facts established 2026-10-19 (all pre-approval, free probes):
//!   - v2 device code REJECTS api.spaces.skype.com for the consumer
//!     client/tenant (AADSTS70011 "scope does not exist"); graph,
//!     substrate and outlook v2 scopes ARE accepted.
//!   - The **v1** device-code endpoint (resource= form param) is ALIVE
//!     and ACCEPTS resource=https://api.spaces.skype.com (and
//!     https://teams.live.com) for client 8ec6bc83… — v1 is the
//!     consumer road.
//!   - teams.live.com/api/auth/v1.0/authz/consumer answers Skype-family
//!     error code 40110 "Invalid access token" for junk bearers (the
//!     exchange teams-core implements but never calls with personal=true).
//!
//! Chain this runs: v1 device code -> v1 token -> consumer authz ->
//! native conversations GET with X-SkypeToken. Success = two free
//! personal accounts can be the A<->B E2E messaging rig.
//!
//! Privacy: token LENGTHS and claim names only — never tokens. Chat
//! output is structure (ids), not content.
//!
//! Run:  cargo run --example personal_probe
//!       PERSONAL_RESOURCE=https://teams.live.com cargo run ...  (alt)

use serde_json::Value;

const CLIENT_ID: &str = "8ec6bc83-69c8-4392-8f08-b3c986009232";
const RESOURCE_DEFAULT: &str = "https://api.spaces.skype.com";

/// JWT payload claims (aud/tid/iss only — no signature, no token body).
fn jwt_claims(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).unwrap_or("");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload)
        })
        .unwrap_or_default();
    serde_json::from_slice(&decoded).unwrap_or(Value::Null)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let resource =
        std::env::var("PERSONAL_RESOURCE").unwrap_or_else(|_| RESOURCE_DEFAULT.to_string());
    let http = reqwest::Client::new();

    println!("== 1. v1 device code (client={CLIENT_ID}, resource={resource}) ==");
    let dev: Value = http
        .post("https://login.microsoftonline.com/common/oauth2/devicecode")
        .form(&[("client_id", CLIENT_ID), ("resource", resource.as_str())])
        .send()
        .await?
        .json()
        .await?;
    let user_code = dev.get("user_code").and_then(|v| v.as_str()).unwrap_or("?").to_string();
    let device_code = dev
        .get("device_code")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let verify = dev
        .get("verification_url")
        .and_then(|v| v.as_str())
        .unwrap_or("https://login.microsoft.com/device")
        .to_string();
    let interval = dev.get("interval").and_then(|v| v.as_u64()).unwrap_or(5) as u64;
    println!();
    println!("  visit: {verify}");
    println!("  code:  {user_code}");
    println!("  (approve with a PERSONAL Microsoft account, then wait…)");
    println!();

    // Poll the v1 token endpoint until approved (or expired).
    let mut aad = String::new();
    let mut refresh_token = String::new();
    for _ in 0..(900 / interval.max(1)) {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        // v1 shape (AADSTS900144 named it): grant_type=device_code with
        // the device code under the parameter name `code`.
        let resp = http
            .post("https://login.microsoftonline.com/common/oauth2/token")
            .form(&[
                ("grant_type", "device_code"),
                ("code", device_code.as_str()),
                ("client_id", CLIENT_ID),
                ("resource", resource.as_str()),
            ])
            .send()
            .await?;
        let tok: Value = resp.json().await.unwrap_or(Value::Null);
        if let Some(t) = tok.get("access_token").and_then(|v| v.as_str()) {
            aad = t.to_string();
            refresh_token = tok
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            break;
        }
        let err = tok.get("error").and_then(|v| v.as_str()).unwrap_or("");
        if err != "authorization_pending" && err != "slow_down" {
            anyhow::bail!("device-code exchange failed: {err} ({tok})");
        }
    }
    if aad.is_empty() {
        anyhow::bail!("no token (code expired without approval?)");
    }
    println!(
        "  MSA token acquired ({} bytes), refresh token: {}",
        aad.len(),
        !refresh_token.is_empty()
    );
    let claims = jwt_claims(&aad);
    println!(
        "  claims: aud={:?} tid={:?} iss={:?}",
        claims.get("aud").and_then(|v| v.as_str()),
        claims.get("tid").and_then(|v| v.as_str()),
        claims.get("iss").and_then(|v| v.as_str()),
    );

    println!();
    println!("== 2. consumer authz exchange (teams.live.com) ==");
    let resp = http
        .post("https://teams.live.com/api/auth/v1.0/authz/consumer")
        .bearer_auth(&aad)
        .header("Content-Length", "0")
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    println!("  HTTP {status}");
    if !status.is_success() {
        println!("  body: {body}");
        println!(
            "=> authz rejected this token — retry with \
             PERSONAL_RESOURCE=https://teams.live.com"
        );
        return Ok(());
    }
    let skype = body
        .pointer("/tokens/skypeToken")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    println!(
        "  skype token: {} bytes, expires_in={:?}",
        skype.len(),
        body.pointer("/tokens/expiresIn").and_then(|v| v.as_u64())
    );
    let gtms = body.get("regionGtms").cloned().unwrap_or(Value::Null);
    println!("  regionGtms: {gtms}");

    println!();
    println!("== 3. native chat list (X-SkypeToken) ==");
    let chat_service = gtms
        .get("chatService")
        .and_then(|v| v.as_str())
        .unwrap_or("https://amer.ng.msg.teams.microsoft.com");
    println!("  chatService host: {chat_service}");
    let url = format!("{chat_service}/v1/users/ME/conversations?view=mychats&pageSize=5");
    let resp = http
        .get(&url)
        .header("X-SkypeToken", &*skype)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    println!("  HTTP {status}, {} bytes", text.len());
    let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if let Some(chats) = parsed.get("conversations").and_then(|v| v.as_array()) {
        println!("  => {} conversation(s):", chats.len());
        for c in chats.iter().take(5) {
            println!(
                "     id={} type={:?}",
                c.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
                c.get("type").and_then(|v| v.as_str()).unwrap_or("?"),
            );
        }
        println!("=> PERSONAL CHAT WORKS: two personal accounts can be the");
        println!("   A<->B messaging rig. Next: registration + trouter + send;");
        println!("   then the calling probe.");
    } else {
        println!(
            "  body head: {}",
            &text.chars().take(400).collect::<String>()
        );
        println!("=> conversations failed — registration may be required first");
        println!("   (that's the next unit if the code is 401/403).");
    }
    Ok(())
}
