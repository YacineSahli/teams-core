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

/// The CONSUMER (Teams-for-Life) calling registrar. The life web config
/// (config-life) sets registrarServiceUrl =
/// `https://teams.microsoft.com/registrar/prod/v2/registrations` with
/// pnhContext "TFL" and pnhTemplate TFLSkypeSpacesWeb_2.0 (web) /
/// SkypeSpacesWeb_2.6 — SEPARATE from the eu v3 registrar the trouter
/// negotiation hints at (which serves consumer MESSAGING fine but never
/// routes call invites: the controller only sees the life registrar's
/// store). All three payloads below are accepted 202 (live-verified).
pub const LIFE_REGISTRAR: &str = "https://teams.microsoft.com/registrar/prod/v2/registrations";

const REGISTRATIONS_LIFE: &[RegEntry] = &[
    RegEntry {
        app_id: "SkypeSpacesWeb",
        template_key: "TFLSkypeSpacesWeb_2.0",
        path_suffix: "SkypeSpacesWeb",
        context: "TFL",
    },
    RegEntry {
        app_id: "SkypeSpacesWeb",
        template_key: "SkypeSpacesWeb_2.6",
        path_suffix: "NGCallManagerWin",
        context: "TFL",
    },
    RegEntry {
        app_id: "NextGenCalling",
        template_key: "DesktopNgc_2.5:SkypeNgc",
        path_suffix: "NGCallManagerWin",
        context: "TFL",
    },
];

/// Delete every registration whose trouter path is bound to a
/// superseded surl. The session reconnects hourly (session-max-age) and
/// re-registers on a NEW surl; the old entries would linger their full
/// 24h TTL pointing at dead sockets — every event fan-out to them 504s
/// and poisons consumers of the registrar (live: the call controller's
/// acceptance fan-out aborts on one dead binding).
pub async fn delete_for_path(
    http: &reqwest::Client,
    skype_token: &str,
    registrar_url: &str,
    path_prefix: &str,
) -> Result<usize> {
    let base = registrar_url.trim_end_matches('/');
    let Ok(resp) = http
        .get(base)
        .header("X-Skypetoken", skype_token)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    else {
        return Ok(0);
    };
    let Ok(v) = resp.json::<serde_json::Value>().await else {
        return Ok(0);
    };
    let mut deleted = 0;
    for b in v
        .get("bindings")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let path = b
            .pointer("/transports/trouter/0/path")
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        if !path.starts_with(path_prefix) {
            continue;
        }
        let rid = b
            .get("registrationId")
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        if rid.is_empty() {
            continue;
        }
        if let Ok(r) = http
            .delete(format!("{base}/{rid}"))
            .header("X-Skypetoken", skype_token)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            if r.status().is_success() {
                deleted += 1;
            }
        }
    }
    if deleted > 0 {
        tracing::info!("Registrar cleanup: deleted {deleted} stale binding(s) for superseded surl");
    }
    Ok(deleted)
}

/// Register the consumer calling transports at the LIFE registrar.
pub async fn register_life(
    http: &reqwest::Client,
    skype_token: &str,
    trouter_surl: &str,
) -> Result<()> {
    register_inner(http, skype_token, LIFE_REGISTRAR, trouter_surl, None, REGISTRATIONS_LIFE).await
}

/// Experimental: register the CALLING entries with
/// `registrationId = the declared endpoint id` — the call controller's
/// endpoint-addressed deliveries ("Delivering call acceptance
/// notification") plausibly resolve the caller's endpoint through the
/// registrar, and our calling registrations otherwise carry random
/// registrationIds with no link to the endpoint the signaling payloads
/// declare. Registers the SkypeSpacesWeb + NextGenCalling entries of
/// BOTH tables at both registrars under `epid`.
pub async fn register_calling_epid(
    http: &reqwest::Client,
    skype_token: &str,
    trouter_surl: &str,
    epid: &str,
) -> Result<()> {
    let mut entries: Vec<(String, String, String)> = Vec::new(); // (app_id, template, suffix)
    for t in [REGISTRATIONS_PERSONAL, REGISTRATIONS_LIFE] {
        for e in t.iter().filter(|e| e.app_id != "TeamsCDLWebWorker") {
            let key = format!("{}/{}", e.app_id, e.template_key);
            if !entries.iter().any(|(a, _, _)| format!("{a}") == key) {
                entries.push((e.app_id.to_string(), e.template_key.to_string(), e.path_suffix.to_string()));
            }
        }
    }
    for (app_id, template, suffix) in entries {
        let path = format!("{trouter_surl}{suffix}");
        let payload = serde_json::json!({
            "clientDescription": {
                "appId": app_id,
                "aesKey": "",
                "languageId": "en-US",
                "platform": "edge",
                "templateKey": template,
                "platformUIVersion": "49/1.0.0"
            },
            "registrationId": epid,
            "nodeId": "",
            "transports": {
                "TROUTER": [{ "context": "", "path": path, "ttl": 86400 }]
            }
        });
        for url in [
            "https://edge.skype.com/registrar/prod/V3/registrations",
            LIFE_REGISTRAR,
        ] {
            let resp = http
                .post(url)
                .header("X-Skypetoken", skype_token)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
                .context("Registrar POST failed")?;
            tracing::info!(
                "Epid registration {app_id}/{template} at {url}: HTTP {}",
                resp.status()
            );
        }
    }
    Ok(())
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
