//! Teams PERSONAL (consumer) account probe — consumer-path viability.
//!
//! Wire facts (2026-10-19, live runs + the consumer web client's own JS
//! config, mined from its bundles):
//!   - ESTS v2 scopes reject api.spaces.skype.com for the consumer
//!     client; v1 mints it but the authz rejects those tokens (40110).
//!   - v1 CANNOT mint `service::` resources (AADSTS500011).
//!   - v2 CONSUMERS + scope `service::api.fl.spaces.skype.com::MBI_SSL`
//!     (the web client's authzResource for MSA) MINTS a working token:
//!     /api/auth/v1.0/authz/consumer answered **HTTP 200**.
//!   - v2 verification page is microsoft.com/link (field
//!     verification_uri, not v1's verification_url/login.microsoft.com).
//!
//! The 200's body differs from the work shape (/tokens/skypeToken) —
//! this probe dumps the response STRUCTURE (token values never printed)
//! and uses the longest string as the X-SkypeToken candidate against
//! the native chat list.
//!
//! The refresh token persists to /tmp/tfl_personal_rt (0600) — reruns
//! mint without another approval. Delete the file to re-provision.
//!
//! Run: cargo run --example personal_probe

use serde_json::Value;

const CLIENT_ID: &str = "8ec6bc83-69c8-4392-8f08-b3c986009232";
/// The consumer web client's MSA-native authz resource (its JS config:
/// authzResource = service::api.fl.spaces.skype.com::MBI_SSL).
const RESOURCE_DEFAULT: &str = "service::api.fl.spaces.skype.com::MBI_SSL";
const RT_PATH: &str = "/tmp/tfl_personal_rt";

const AUTHZ_ENDPOINTS: [&str; 3] = [
    "https://teams.live.com/api/auth/v1.0/authz/consumer",
    "https://teams.live.com/api/auth/v2.0/authz/consumer",
    "https://teams.live.com/api/auth/v1.0/authzcore/consumer",
];

/// Recursive structure dump: keys, types, long strings as lengths only.
fn dump_structure(indent: &str, v: &Value) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                match val {
                    Value::String(s) if s.len() > 80 => {
                        println!("{indent}{k}: <string {} bytes>", s.len())
                    }
                    Value::String(s) => println!("{indent}{k}: {s:?}"),
                    Value::Array(a) => println!("{indent}{k}: [array {}]", a.len()),
                    Value::Object(_) => {
                        println!("{indent}{k}: {{");
                        dump_structure(&format!("{indent}  "), val);
                        println!("{indent}}}");
                    }
                    other => println!("{indent}{k}: {other}"),
                }
            }
        }
        other => println!("{indent}(root) {other}"),
    }
}

/// Longest string anywhere in the JSON (skype-token candidate).
fn longest_string(v: &Value) -> Option<(String, String)> {
    fn walk(v: &Value, path: &str, best: &mut Option<(usize, String, String)>) {
        match v {
            Value::Object(m) => {
                for (k, val) in m {
                    walk(val, &format!("{path}/{k}"), best);
                }
            }
            Value::String(s) => {
                if best.as_ref().is_none_or(|(l, _, _)| s.len() > *l) {
                    *best = Some((s.len(), path.to_string(), s.clone()));
                }
            }
            _ => {}
        }
    }
    let mut best = None;
    walk(v, "", &mut best);
    best.map(|(_, p, s)| (p, s))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let resource =
        std::env::var("PERSONAL_RESOURCE").unwrap_or_else(|_| RESOURCE_DEFAULT.to_string());
    let http = reqwest::Client::new();

    // Saved RT: mint without another approval.
    if let Ok(rt) = std::fs::read_to_string(RT_PATH) {
        let rt = rt.trim().to_string();
        if !rt.is_empty() {
            println!("== 0. refreshing from saved RT ({RT_PATH}) ==");
            let resp = http
                .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", rt.as_str()),
                    ("client_id", CLIENT_ID),
                    ("scope", &format!("{resource} offline_access")),
                ])
                .send()
                .await?;
            let tok: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(t) = tok.get("access_token").and_then(|v| v.as_str()) {
                let new_rt = tok
                    .get("refresh_token")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&rt)
                    .to_string();
                let _ = std::fs::write(RT_PATH, new_rt);
                println!("  token refreshed ({} bytes)", t.len());
                return authz_and_chat(&http, t.to_string()).await;
            }
            println!(
                "  refresh failed ({}), falling back to device code",
                tok.get("error").and_then(|v| v.as_str()).unwrap_or("?")
            );
        }
    }

    println!("== 1. device code (v2 consumers: {resource}) ==");
    let dev: Value = http
        .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode")
        .form(&[
            ("client_id", CLIENT_ID),
            ("scope", &format!("{resource} offline_access")),
        ])
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
    // v1 names it verification_url, v2 verification_uri (RFC) — a v2
    // code shown on the v1 page reads "did not work".
    let verify = dev
        .get("verification_uri")
        .or_else(|| dev.get("verification_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("https://www.microsoft.com/link")
        .to_string();
    let interval = dev.get("interval").and_then(|v| v.as_u64()).unwrap_or(5) as u64;
    println!();
    println!("  visit: {verify}");
    println!("  code:  {user_code}");
    println!("  (approve with a PERSONAL Microsoft account, then wait…)");
    println!();

    let mut aad = String::new();
    let mut refresh_token = String::new();
    for _ in 0..(900 / interval.max(1)) {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        let resp = http
            .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", CLIENT_ID),
                ("scope", &format!("{resource} offline_access")),
                ("device_code", device_code.as_str()),
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
    if !refresh_token.is_empty() {
        let _ = std::fs::write(RT_PATH, &refresh_token);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(RT_PATH, std::fs::Permissions::from_mode(0o600));
        }
        println!("  refresh token saved to {RT_PATH} (0600) — future runs need no approval");
    }
    authz_and_chat(&http, aad).await
}

/// Authz + native chat-list attempt with one minted token.
async fn authz_and_chat(http: &reqwest::Client, aad: String) -> anyhow::Result<()> {
    println!();
    println!("== 2. consumer authz (v1.0 endpoint first — the live 200) ==");
    let mut skype = String::new();
    let mut gtms = Value::Null;
    for ep in AUTHZ_ENDPOINTS {
        let resp = http
            .post(ep)
            .bearer_auth(&aad)
            .header("Content-Length", "0")
            .header("Origin", "https://teams.live.com")
            .header("Referer", "https://teams.live.com/")
            .send()
            .await?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        let tag = ep.split("teams.live.com").nth(1).unwrap_or(ep);
        println!("  {tag:<34} HTTP {status}");
        if status.is_success() {
            println!("    response structure:");
            dump_structure("      ", &body);
            if let Some(t) = body.pointer("/tokens/skypeToken").and_then(|v| v.as_str()) {
                skype = t.to_string();
            } else if let Some((path, t)) = longest_string(&body) {
                if t.len() >= 100 {
                    println!("    skype-token candidate: {path} ({} bytes)", t.len());
                    skype = t;
                }
            }
            gtms = body
                .get("regionGtms")
                .or_else(|| body.get("regiongtms"))
                .or_else(|| body.pointer("/regionGtms"))
                .or_else(|| body.pointer("/region/regionGtms"))
                .cloned()
                .unwrap_or(Value::Null);
            break;
        }
    }
    if skype.is_empty() {
        println!("=> no usable skype token in any 2xx response.");
        return Ok(());
    }

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
