//! Trouter registrar — registers our endpoint with the Teams notification service

use anyhow::{Context, Result};

/// Registration entry: appId, templateKey, path suffix, context
struct RegEntry {
    app_id: &'static str,
    template_key: &'static str,
    path_suffix: &'static str,
    context: &'static str,
}

const REGISTRATIONS: &[RegEntry] = &[
    RegEntry {
        // OstMac §106: business-tenant CDL registration (template 2.1, empty
        // transport context). Was 2.6 + transport context "TFL" (the
        // consumer "Teams for Life" product context, and in the wrong
        // field): registrations succeeded but no chat-service messaging
        // push ever reached the socket.
        app_id: "TeamsCDLWebWorker",
        template_key: "TeamsCDLWebWorker_2.1",
        path_suffix: "",
        context: "",
    },
    RegEntry {
        app_id: "SkypeSpacesWeb",
        template_key: "SkypeSpacesWeb_2.4",
        path_suffix: "SkypeSpacesWeb",
        context: "",
    },
    RegEntry {
        app_id: "NextGenCalling",
        template_key: "DesktopNgc_2.5:SkypeNgc",
        path_suffix: "NGCallManagerWin",
        context: "",
    },
];

/// CONSUMER (personal) registrations: the TFL product context and the
/// 2.6 template keys — the exact shape the work flow moved AWAY from
/// (its §106 note above), which is precisely why it is the consumer
/// shape: it was built for Teams-for-Life.
const REGISTRATIONS_PERSONAL: &[RegEntry] = &[
    RegEntry {
        app_id: "TeamsCDLWebWorker",
        template_key: "TeamsCDLWebWorker_2.6",
        path_suffix: "",
        context: "TFL",
    },
    RegEntry {
        app_id: "SkypeSpacesWeb",
        template_key: "SkypeSpacesWeb_2.6",
        path_suffix: "SkypeSpacesWeb",
        context: "",
    },
    RegEntry {
        app_id: "NextGenCalling",
        template_key: "DesktopNgc_2.5:SkypeNgc",
        path_suffix: "NGCallManagerWin",
        context: "",
    },
];

/// Register our trouter endpoint with the Teams registrar service.
///
/// Performs three separate registrations (TeamsCDLWebWorker, SkypeSpacesWeb,
/// NextGenCalling) as the real Teams client does.
pub async fn register(
    http: &reqwest::Client,
    skype_token: &str,
    registrar_url: &str,
    trouter_surl: &str,
) -> Result<()> {
    register_with_endpoint(http, skype_token, registrar_url, trouter_surl, None).await
}

/// OstMac §106: [`register`] where the CDL (chat) registration's
/// `registrationId` is the socket's endpoint id (`epid`), as the Teams
/// clients do; other apps keep a random id.
pub async fn register_with_endpoint(
    http: &reqwest::Client,
    skype_token: &str,
    registrar_url: &str,
    trouter_surl: &str,
    epid: Option<&str>,
) -> Result<()> {
    register_inner(http, skype_token, registrar_url, trouter_surl, epid, REGISTRATIONS).await
}

/// Personal (consumer) variant: the TFL table.
pub async fn register_personal_with_endpoint(
    http: &reqwest::Client,
    skype_token: &str,
    registrar_url: &str,
    trouter_surl: &str,
    epid: Option<&str>,
) -> Result<()> {
    register_inner(http, skype_token, registrar_url, trouter_surl, epid, REGISTRATIONS_PERSONAL).await
}

/// The CONSUMER calling registration: the appliance V2 registrar (the
/// web client's calling_registrarUrl template, :8443). Everything else
/// about consumer calls works over 443, but this one rides 8443 —
/// networks that filter 8443 (the dev network does — both skype hosts
/// time out while 443 answers) starve incoming-call routing: invites
/// never reach the callee. Timeout-tolerant: logs and continues.
pub async fn register_calling_v2(
    http: &reqwest::Client,
    skype_token: &str,
    call_controller: &str,
    trouter_surl: &str,
) -> Result<()> {
    let host = call_controller
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let url = format!("https://{host}:8443/V2/registrations");
    let payload = serde_json::json!({
        "clientDescription": {
            "appId": "NextGenCalling",
            "aesKey": "",
            "languageId": "en-US",
            "platform": "edge",
            "templateKey": "DesktopNgc_2.5:SkypeNgc",
            "platformUIVersion": "49/1.0.0"
        },
        "registrationId": uuid::Uuid::new_v4().to_string(),
        "nodeId": "",
        "transports": {
            "TROUTER": [{ "context": "", "path": format!("{trouter_surl}NGCallManagerWin"), "ttl": 86400 }]
        }
    });
    let resp = http
        .post(&url)
        .header("X-Skypetoken", skype_token)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!("V2 calling registration OK at {url}");
            Ok(())
        }
        Ok(r) => anyhow::bail!("V2 calling registration HTTP {} at {url}", r.status()),
        Err(e) => anyhow::bail!("V2 calling registration unreachable at {url} ({e}) — is outbound 8443 filtered?"),
    }
}

/// One registration call with the table chosen by the personal flag.
pub async fn register_flagged(
    http: &reqwest::Client,
    skype_token: &str,
    registrar_url: &str,
    trouter_surl: &str,
    epid: Option<&str>,
    personal: bool,
) -> Result<()> {
    register_inner(
        http,
        skype_token,
        registrar_url,
        trouter_surl,
        epid,
        if personal {
            REGISTRATIONS_PERSONAL
        } else {
            REGISTRATIONS
        },
    )
    .await
}

async fn register_inner(
    http: &reqwest::Client,
    skype_token: &str,
    registrar_url: &str,
    trouter_surl: &str,
    epid: Option<&str>,
    table: &'static [RegEntry],
) -> Result<()> {
    let url = registrar_url.trim_end_matches('/').to_string();

    for entry in table {
        let reg_id = match epid {
            Some(e) if entry.app_id == "TeamsCDLWebWorker" && !e.trim().is_empty() => e.to_string(),
            _ => uuid::Uuid::new_v4().to_string(),
        };
        let path = format!("{}{}", trouter_surl, entry.path_suffix);

        let payload = serde_json::json!({
            "clientDescription": {
                "appId": entry.app_id,
                "aesKey": "",
                "languageId": "en-US",
                "platform": "edge",
                "templateKey": entry.template_key,
                "platformUIVersion": "49/1.0.0"
            },
            "registrationId": reg_id,
            "nodeId": "",
            "transports": {
                "TROUTER": [{
                    "context": entry.context,
                    "path": path,
                    "ttl": 86400
                }]
            }
        });

        tracing::info!(
            "Registering {} at {} (appId={}, templateKey={})",
            entry
                .path_suffix
                .is_empty()
                .then_some("base")
                .unwrap_or(entry.path_suffix),
            url,
            entry.app_id,
            entry.template_key,
        );

        let resp = http
            .post(&url)
            .header("X-Skypetoken", skype_token)
            .json(&payload)
            .send()
            .await
            .context("Registrar POST failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Registrar {} returned {}: {}", entry.app_id, status, body);
        }
        tracing::info!("Registrar {} registration succeeded", entry.app_id);
    }

    Ok(())
}

/// OstMac §106: re-register only the CDL (chat) entry under `template_key`
/// with `registrationId` = `epid` (same id → replaces the first one). The
/// Teams clients do this with `TeamsCDLWebWorker_1.9` when the server
/// reports `trouter.message_loss` right after connect.
pub async fn register_cdl(
    http: &reqwest::Client,
    skype_token: &str,
    registrar_url: &str,
    trouter_surl: &str,
    epid: &str,
    template_key: &str,
) -> Result<()> {
    let payload = serde_json::json!({
        "clientDescription": {
            "appId": "TeamsCDLWebWorker",
            "aesKey": "",
            "languageId": "en-US",
            "platform": "edge",
            "templateKey": template_key,
            "platformUIVersion": "49/1.0.0"
        },
        "registrationId": epid,
        "nodeId": "",
        "transports": {"TROUTER": [{"context": "", "path": trouter_surl, "ttl": 86400}]}
    });
    let resp = http
        .post(registrar_url.trim_end_matches('/'))
        .header("X-Skypetoken", skype_token)
        .json(&payload)
        .send()
        .await
        .context("Registrar POST failed")?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("Registrar CDL {} returned {}", template_key, status);
    }
    tracing::info!("Registrar CDL {} registration succeeded", template_key);
    Ok(())
}
