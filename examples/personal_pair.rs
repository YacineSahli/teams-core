//! A<->B personal-account pair archaeology: create the 1:1, send, and
//! verify receipt on the other side. Runs entirely from the two saved
//! refresh tokens (no approvals).
//!
//! MRIs: consumer members use 8:live:<skypeid> (skypeid from the authz:
//! live:<handle> or live:.cid.<hex> — the unmigrated CID form).
//! Thread create mirrors the work shape (POST /v1/threads, unique
//! roster); send mirrors the work shape (clientmessageid + Location).
//!
//! Run: cargo run --example personal_pair

use serde_json::Value;

const CLIENT_ID: &str = "8ec6bc83-69c8-4392-8f08-b3c986009232";
const RESOURCE: &str = "service::api.fl.spaces.skype.com::MBI_SSL";
const A_RT: &str = "/tmp/tfl_personal_rt";
const B_RT: &str = "/tmp/tfl_personal_rt2";

struct Session {
    http: reqwest::Client,
    aad: String,
    skype: String,
    chat_service: String,
    skypeid: String,
}

async fn open(rt_path: &str, label: &str) -> anyhow::Result<Session> {
    let http = reqwest::Client::new();
    let rt = std::fs::read_to_string(rt_path)?.trim().to_string();
    let resp = http
        .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
            ("client_id", CLIENT_ID),
            ("scope", &format!("{RESOURCE} offline_access")),
        ])
        .send()
        .await?;
    let tok: Value = resp.json().await?;
    let aad = tok
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("{label}: refresh failed"))?
        .to_string();
    if let Some(new_rt) = tok.get("refresh_token").and_then(|v| v.as_str()) {
        let _ = std::fs::write(rt_path, new_rt);
    }
    let resp = http
        .post("https://teams.live.com/api/auth/v1.0/authz/consumer")
        .bearer_auth(&aad)
        .header("Content-Length", "0")
        .send()
        .await?;
    let body: Value = resp.json().await?;
    Ok(Session {
        http,
        aad: aad.clone(),
        skype: body
            .pointer("/skypeToken/skypetoken")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("{label}: no skypetoken"))?
            .to_string(),
        chat_service: body
            .pointer("/regionGtms/chatService")
            .and_then(|v| v.as_str())
            .unwrap_or("https://msgapi.teams.live.com")
            .to_string(),
        skypeid: body
            .pointer("/skypeToken/skypeid")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}

impl Session {
    fn get(&self, url: &str) -> reqwest::RequestBuilder {
        self.http.get(url).header("X-SkypeToken", &*self.skype)
    }
    fn post(&self, url: &str, body: &Value) -> reqwest::RequestBuilder {
        self.http
            .post(url)
            .header("X-SkypeToken", &*self.skype)
            .json(body)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a = open(A_RT, "A").await?;
    let b = open(B_RT, "B").await?;
    if std::env::var("PAIR_PROBE_CALLAUTH").is_ok() {
        let url = "https://api.flightproxy.skype.com/api/v2/epconv";
        for (label, builder) in [
            ("bearer-skype", a.http.post(url).header("Authorization", format!("Bearer {}", a.skype)).header("Content-Type", "application/json")),
            ("x-skypetoken", a.http.post(url).header("X-Skypetoken", &*a.skype).header("Content-Type", "application/json")),
        ] {
            let resp = builder.body("{}").timeout(std::time::Duration::from_secs(10)).send().await?;
            println!("{label}: HTTP {} {}", resp.status(), resp.text().await.unwrap_or_default().chars().take(100).collect::<String>());
        }
        // The web client's ic3 resources (its JS config): mint the
        // non-CAE GUID scope and try it as the epconv Bearer.
        let rt = std::fs::read_to_string(A_RT)?.trim().to_string();
        let resp = a.http
            .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", rt.as_str()),
                ("client_id", CLIENT_ID),
                ("scope", "93aca3ff-e61e-477f-b3e7-9fe10c6b97af/.default offline_access"),
            ])
            .send()
            .await?;
        let v: Value = resp.json().await?;
        match v.get("access_token").and_then(|t| t.as_str()) {
            Some(ic3) => {
                println!("ic3 GUID mint OK ({} bytes)", ic3.len());
                let resp = a.http
                    .post("https://api.flightproxy.skype.com/api/v2/epconv")
                    .header("Authorization", format!("Bearer {ic3}"))
                    .header("Content-Type", "application/json")
                    .body("{}")
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await?;
                println!(
                    "epconv with ic3 bearer: HTTP {} {}",
                    resp.status(),
                    resp.text().await.unwrap_or_default().chars().take(120).collect::<String>()
                );
            }
            None => println!(
                "ic3 GUID mint failed: {}",
                v.get("error_description").and_then(|e| e.as_str()).unwrap_or("?")
            ),
        }
        return Ok(());
    }
    if std::env::var("PAIR_REG_CLEAN").is_ok() {
        // Enumerate our registrar registrations; the CC's acceptance
        // fan-out 504s on dead ones (430/10065). Try list + delete.
        // Live paths per account (env: PAIR_KEEP_A / PAIR_KEEP_B) — every
        // registration bound to a different path is stale (dead socket,
        // 24h TTL) and gets deleted.
        let keep_a = std::env::var("PAIR_KEEP_A").unwrap_or_default();
        let keep_b = std::env::var("PAIR_KEEP_B").unwrap_or_default();
        let base = "https://edge.skype.com/registrar/prod/V3/registrations";
        for (label, sess, keep) in [("A", &a, &keep_a), ("B", &b, &keep_b)] {
            let Ok(r) = sess
                .http
                .get(base)
                .header("X-SkypeToken", &*sess.skype)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
            else {
                println!("REGLIST {label}: GET failed");
                continue;
            };
            let v: Value = match r.json().await {
                Ok(v) => v,
                Err(e) => {
                    println!("REGLIST {label}: parse {e}");
                    continue;
                }
            };
            let mut stale = 0;
            let mut kept = 0;
            for b_ in v
                .get("bindings")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let rid = b_
                    .get("registrationId")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                let path = b_
                    .pointer("/transports/trouter/0/path")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                let is_live = !keep.is_empty() && path.starts_with(keep.as_str());
                if is_live {
                    kept += 1;
                    continue;
                }
                stale += 1;
                match sess
                    .http
                    .delete(format!("{base}/{rid}"))
                    .header("X-SkypeToken", &*sess.skype)
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await
                {
                    Ok(r) => println!("REGDEL {label} {rid:.8} HTTP {}", r.status()),
                    Err(e) => println!("REGDEL {label} {rid:.8} ERR {e}"),
                }
            }
            println!("REGSUM {label}: kept {kept} live, deleted {stale} stale");
        }
        return Ok(());
    }
    if std::env::var("PAIR_ADD_CONTACTS").is_ok() {
        // Call-end forensics: 403 "Permission check for callee to
        // interact with caller is not allowed" — the consumer privacy
        // model gates calls to contacts. Make A and B mutual contacts.
        let b_mri = format!("8:{}", b.skypeid);
        let a_mri = format!("8:{}", a.skypeid);
        for (label, sess, mri) in [("A adds B", &a, &b_mri), ("B adds A", &b, &a_mri)] {
            let enc = mri.replace(':', "%3A").replace('@', "%40");
            for (form, url) in [
                ("put-enc", format!("{}/v1/users/ME/contacts/{enc}", sess.chat_service)),
                ("post-invite", format!("{}/v1/users/ME/contacts", sess.chat_service)),
            ] {
                let body = match form {
                    "put-enc" => serde_json::json!({"id": mri}),
                    _ => serde_json::json!({"mri": mri}),
                };
                let req = if form == "put-enc" {
                    sess.http.put(&url)
                } else {
                    sess.http.post(&url)
                };
                match req
                    .header("X-SkypeToken", &*sess.skype)
                    .header("Content-Type", "application/json")
                    .body(body.to_string())
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await
                {
                    Ok(r) => println!(
                        "CONTACT {label} {form:<12} HTTP {} {}",
                        r.status(),
                        r.text().await.unwrap_or_default().chars().take(200).collect::<String>()
                    ),
                    Err(e) => println!("CONTACT {label} {form:<12} ERR {e}"),
                }
            }
            // contacts.skype.com v2 form
            match sess
                .http
                .post("https://contacts.skype.com/contacts/v2/users/ME/contacts")
                .header("Authorization", format!("SkypeToken {}", sess.skype))
                .header("X-SkypeToken", &*sess.skype)
                .header("Content-Type", "application/json")
                .body(serde_json::json!({"mri": mri}).to_string())
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
            {
                Ok(r) => println!(
                    "CONTACT {label} contacts.skype.com HTTP {} {}",
                    r.status(),
                    r.text().await.unwrap_or_default().chars().take(250).collect::<String>()
                ),
                Err(e) => println!("CONTACT {label} contacts.skype.com ERR {e}"),
            }
            // classic api.skype.com forms
            for (form, url, body) in [
                (
                    "api.skype.com me/contacts",
                    "https://api.skype.com/users/ME/contacts".to_string(),
                    serde_json::json!({"mri": mri}).to_string(),
                ),
                (
                    "api.skype.com profile invite",
                    "https://api.skype.com/users/ME/contacts/invite".to_string(),
                    serde_json::json!({"mri": mri}).to_string(),
                ),
                (
                    "profile.skype.com contacts",
                    "https://profile.skype.com/profile/v1/users/ME/contacts".to_string(),
                    serde_json::json!({"mri": mri}).to_string(),
                ),
            ] {
                match sess
                    .http
                    .post(&url)
                    .header("Authorization", format!("SkypeToken {}", sess.skype))
                    .header("X-SkypeToken", &*sess.skype)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await
                {
                    Ok(r) => println!(
                        "CONTACT {label} {form:<30} HTTP {} {}",
                        r.status(),
                        r.text().await.unwrap_or_default().chars().take(180).collect::<String>()
                    ),
                    Err(e) => println!("CONTACT {label} {form:<30} ERR {e}"),
                }
            }
        }
        // Read back A's contact list.
        match a
            .http
            .get(format!("{}/v1/users/ME/contacts", a.chat_service))
            .header("X-SkypeToken", &*a.skype)
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await
        {
            Ok(r) => println!(
                "CONTACTS A readback: HTTP {} {}",
                r.status(),
                r.text().await.unwrap_or_default().chars().take(300).collect::<String>()
            ),
            Err(e) => println!("CONTACTS A readback ERR {e}"),
        }
        // contacts.skype.com LIST (auth sanity) + full 403 detail.
        match a
            .http
            .get("https://contacts.skype.com/contacts/v2/users/ME/contacts")
            .header("Authorization", format!("SkypeToken {}", a.skype))
            .header("X-SkypeToken", &*a.skype)
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(r) => {
                let st = r.status();
                let hdrs: Vec<String> = r
                    .headers()
                    .iter()
                    .filter(|(k, _)| {
                        let ks = k.as_str();
                        ks.starts_with("x-") || ks == "www-authenticate" || ks.starts_with("content-type")
                    })
                    .map(|(k, v)| format!("{}={}", k, String::from_utf8_lossy(v.as_ref())))
                    .collect();
                println!(
                    "CONTACTS skype LIST: HTTP {st} {} | headers: {}",
                    r.text().await.unwrap_or_default().chars().take(400).collect::<String>(),
                    hdrs.join("; ")
                );
            }
            Err(e) => println!("CONTACTS skype LIST ERR {e}"),
        }
        // Per-service tokens via authz v1 ?resource= (MT pattern worked).
        for res in [
            "https://contacts.skype.com/",
            "https://people.skype.com/",
        ] {
            let tok = mint_service_token(&a.http, &a.aad, res).await;
            match tok {
                Some(t) => {
                    for (label, hdr) in [
                        ("bearer", format!("Bearer {t}")),
                        ("skypetoken", format!("SkypeToken {t}")),
                    ] {
                        match a
                            .http
                            .get("https://contacts.skype.com/contacts/v2/users/ME/contacts")
                            .header("Authorization", &hdr)
                            .header("x-ms-client-consumer-type", "teams4life")
                            .header("Accept", "application/json")
                            .timeout(std::time::Duration::from_secs(10))
                            .send()
                            .await
                        {
                            Ok(r) => println!(
                                "SVCTOK {res} {label}: HTTP {} {}",
                                r.status(),
                                r.text().await.unwrap_or_default().chars().take(250).collect::<String>()
                            ),
                            Err(e) => println!("SVCTOK {res} {label}: ERR {e}"),
                        }
                    }
                }
                None => println!("SVCTOK {res}: mint failed"),
            }
        }
        for (label, hdrs) in [
            (
                "x-skype+consumer",
                vec![
                    ("X-SkypeToken", a.skype.clone()),
                    ("x-ms-client-consumer-type", "teams4life".to_string()),
                ],
            ),
            (
                "auth-skypetoken+consumer",
                vec![
                    ("Authorization", format!("SkypeToken {}", a.skype)),
                    ("x-ms-client-consumer-type", "teams4life".to_string()),
                ],
            ),
            (
                "bearer-msa+consumer",
                vec![
                    ("Authorization", format!("Bearer {}", a.aad)),
                    ("x-ms-client-consumer-type", "teams4life".to_string()),
                ],
            ),
            (
                "flightproxy+x-skype",
                vec![
                    ("X-SkypeToken", a.skype.clone()),
                    ("x-ms-client-consumer-type", "teams4life".to_string()),
                ],
            ),
        ] {
            let url = if label == "flightproxy+x-skype" {
                "https://api.flightproxy.skype.com/api/v2/ep/contacts.skype.com/contacts/v2/users/ME/contacts"
            } else {
                "https://contacts.skype.com/contacts/v2/users/ME/contacts"
            };
            let mut req = a.http.get(url);
            for (k, v) in &hdrs {
                req = req.header(k.clone(), v.clone());
            }
            match req.timeout(std::time::Duration::from_secs(10)).send().await {
                Ok(r) => println!(
                    "CONTACTS skype LIST {label:<26} HTTP {} {}",
                    r.status(),
                    r.text().await.unwrap_or_default().chars().take(300).collect::<String>()
                ),
                Err(e) => println!("CONTACTS skype LIST {label:<26} ERR {e}"),
            }
        }
        return Ok(());
    }
    if std::env::var("PAIR_PROBE_MTPRESENCE").is_ok() {
        // LIFE presence: enableSendPresenceTokenToUPS=false → mtAuthResource
        // (middle-tier auth), enableAfdPresenceEndpoint → base
        // https://teams.live.com/ups/global/ (defaultPresenceAfdRegionGTM).
        // MT token = authz consumer with resource
        // https://mtsvc.fl.teams.microsoft.com/teams.mt.readwrite.
        let base = "https://teams.live.com/ups/global";
        let mt_resource = "https://mtsvc.fl.teams.microsoft.com/teams.mt.readwrite";
        // The v2/TFL authz endpoint 401s default-scope MSA tokens; the web
        // client's own audience for teams.live.com APIs is the site origin.
        let tl_aad = mint_msa(&b.http, B_RT, "https://teams.live.com/.default").await;
        println!(
            "teams.live-scoped MSA: {}",
            if tl_aad.is_some() { "OK" } else { "FAILED" }
        );
        let mut mt_token: Option<String> = None;
        for (label, req) in [
            (
                "v2 query tl-token",
                b.http
                    .post(format!("https://teams.live.com/api/auth/v2.0/authz/consumer?resource={}", urlencoding_simple(mt_resource)))
                    .bearer_auth(tl_aad.as_deref().unwrap_or(&b.aad))
                    .header("Content-Length", "0"),
            ),
            (
                "v1 query tl-token",
                b.http
                    .post(format!("https://teams.live.com/api/auth/v1.0/authz/consumer?resource={}", urlencoding_simple(mt_resource)))
                    .bearer_auth(tl_aad.as_deref().unwrap_or(&b.aad))
                    .header("Content-Length", "0"),
            ),
            (
                "v1 body tl-token",
                b.http
                    .post("https://teams.live.com/api/auth/v1.0/authz/consumer")
                    .bearer_auth(tl_aad.as_deref().unwrap_or(&b.aad))
                    .header("Content-Type", "application/json")
                    .body(format!(r#"{{"resource":"{mt_resource}"}}"#)),
            ),
        ] {
            match req.timeout(std::time::Duration::from_secs(10)).send().await {
                Ok(r) => {
                    let st = r.status();
                    let txt = r.text().await.unwrap_or_default();
                    println!("MTAUTH {label}: HTTP {st} {}", &txt.chars().take(220).collect::<String>());
                    if st.is_success() {
                        if let Ok(v) = serde_json::from_str::<Value>(&txt) {
                            let tok = v
                                .pointer("/skypeToken/skypetoken")
                                .or_else(|| v.pointer("/skypetoken"))
                                .and_then(|t| t.as_str())
                                .map(str::to_string)
                                .or_else(|| {
                                    v.get("token").and_then(|t| t.as_str()).map(str::to_string)
                                });
                            mt_token = tok;
                        }
                    }
                }
                Err(e) => println!("MTAUTH {label}: ERR {e}"),
            }
            if mt_token.is_some() {
                break;
            }
        }
        let Some(mt) = mt_token else {
            println!("=> MT token mint failed; aborting");
            return Ok(());
        };
        println!("MT token minted ({} bytes)", mt.len());

        let ep = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "id": ep,
            "availability": "Available",
            "activity": "Available",
            "deviceType": "Desktop",
            "capabilities": ["Audio", "Video"],
        });
        // Publish for B through the MT path.
        match b
            .http
            .put(format!("{base}/v1/me/endpoints/"))
            .header("Content-Type", "application/json")
            .header("x-ms-client-consumer-type", "teams4life")
            .header("x-ms-client-user-agent", "Teams-V2-Desktop")
            .header("x-ms-endpoint-id", &ep)
            .header("Authorization", format!("Bearer {mt}"))
            .header("x-skypetoken", &*b.skype)
            .body(body.to_string())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(r) => println!(
                "MT PUT endpoints: HTTP {} {}",
                r.status(),
                r.text().await.unwrap_or_default().chars().take(240).collect::<String>()
            ),
            Err(e) => println!("MT PUT endpoints: ERR {e}"),
        }
        match b
            .http
            .get(format!("{base}/v1/me/presence"))
            .header("x-ms-client-consumer-type", "teams4life")
            .header("Authorization", format!("Bearer {mt}"))
            .header("x-skypetoken", &*b.skype)
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await
        {
            Ok(r) => println!(
                "MT GET presence: HTTP {} {}",
                r.status(),
                r.text().await.unwrap_or_default().chars().take(300).collect::<String>()
            ),
            Err(e) => println!("MT GET presence: ERR {e}"),
        }
        // reportmyactivity heartbeat — the endpoint is only ACTIVE (and
        // thus counted by the aggregator) after this per the JS model.
        match b
            .http
            .post(format!("{base}/v1/me/reportmyactivity/"))
            .header("Content-Type", "application/json")
            .header("x-ms-client-consumer-type", "teams4life")
            .header("x-ms-endpoint-id", &ep)
            .header("Authorization", format!("Bearer {mt}"))
            .header("x-skypetoken", &*b.skype)
            .body(serde_json::json!({"endpointId": ep, "isActive": true}).to_string())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(r) => println!(
                "MT reportmyactivity: HTTP {} {}",
                r.status(),
                r.text().await.unwrap_or_default().chars().take(200).collect::<String>()
            ),
            Err(e) => println!("MT reportmyactivity: ERR {e}"),
        }
        // And the directory view from A.
        let body = serde_json::json!([{"mri": format!("8:{}", b.skypeid)}]);
        match a
            .http
            .post("https://presence.teams.live.com/v1/presence/getpresence/")
            .header("X-SkypeToken", &*a.skype)
            .header("x-ms-client-consumer-type", "teams4life")
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await
        {
            Ok(r) => println!(
                "getPresence B after MT publish: HTTP {} {}",
                r.status(),
                r.text().await.unwrap_or_default().chars().take(300).collect::<String>()
            ),
            Err(e) => println!("getPresence B after MT publish: ERR {e}"),
        }
        return Ok(());
    }
    if std::env::var("PAIR_PROBE_SKYPEREG").is_ok() {
        // config-life trouterService: registrarDefaultEndpoint
        //   https://edge.skype.com/registrar/prod/v2/registrations
        // trouterDefaultEndpoint https://go.trouter.skype.com/v4/a —
        // the CONSUMER notification spine (work prod = teams.microsoft.com
        // /registrar/prod/v3). NGCall invites for consumer↔consumer (event
        // 107 SKYPE_SKYPE_CALL) ride THIS fleet.
        let epid = uuid::Uuid::new_v4().to_string();
        let resp = b
            .http
            .get(format!("https://go.trouter.skype.com/v4/a?epid={epid}"))
            .header("X-SkypeToken", &*b.skype)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;
        println!("skype trouter negotiate: HTTP {}", resp.status());
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        let surl = v
            .get("surl")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string();
        println!(
            "skype surl: {surl}\n  socketio: {:?}\n  registrarUrl hint: {:?}",
            v.get("socketio").and_then(|s| s.as_str()).map(|s| s.chars().take(90).collect::<String>()),
            v.get("registrarUrl").and_then(|s| s.as_str())
        );
        if !surl.is_empty() {
            // Channel auth: config-life trouterAuthUrlSuffix (web "/auth",
            // win "/NGCallManagerWin/auth") — slimcore authorizes its
            // trouter channels after connect. Probe the shape.
            for (label, path, tok_hdr) in [
                ("NGCallManagerWin/auth skypehdr", "NGCallManagerWin/auth", "skype"),
                ("auth skypehdr", "auth", "skype"),
                ("NGCallManagerWin/auth bearer", "NGCallManagerWin/auth", "bearer"),
            ] {
                let mut req = b.http.post(format!("{surl}{path}"));
                req = match tok_hdr {
                    "skype" => req.header("X-SkypeToken", &*b.skype),
                    _ => req.header("Authorization", format!("Bearer {}", b.aad)),
                };
                match req
                    .timeout(std::time::Duration::from_secs(8))
                    .send()
                    .await
                {
                    Ok(r) => println!(
                        "CHANNELAUTH {label:<34} HTTP {} {}",
                        r.status(),
                        r.text().await.unwrap_or_default().chars().take(200).collect::<String>()
                    ),
                    Err(e) => println!("CHANNELAUTH {label:<34} ERR {e}"),
                }
            }
        }
        if !surl.is_empty() {
            for (label, app_id, template, ctx, suffix) in [
                ("CDL 2.6 TFL", "TeamsCDLWebWorker", "TeamsCDLWebWorker_2.6", "TFL", ""),
                ("SkypeSpacesWeb_2.6", "SkypeSpacesWeb", "SkypeSpacesWeb_2.6", "", "SkypeSpacesWeb"),
                ("NGCall DesktopNgc", "NextGenCalling", "DesktopNgc_2.5:SkypeNgc", "", "NGCallManagerWin"),
                ("TFLSkypeSpacesWeb_2.0", "SkypeSpacesWeb", "TFLSkypeSpacesWeb_2.0", "TFL", "NGCallManagerWin"),
            ] {
                let payload = serde_json::json!({
                    "clientDescription": {
                        "appId": app_id, "aesKey": "", "languageId": "en-US",
                        "platform": "edge", "templateKey": template,
                        "platformUIVersion": "49/1.0.0"
                    },
                    "registrationId": uuid::Uuid::new_v4().to_string(),
                    "nodeId": "",
                    "transports": {"TROUTER": [{"context": ctx, "path": format!("{surl}{suffix}"), "ttl": 3600}]}
                });
                match b
                    .http
                    .post("https://edge.skype.com/registrar/prod/v2/registrations")
                    .header("X-SkypeToken", &*b.skype)
                    .json(&payload)
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await
                {
                    Ok(r) => println!(
                        "SKYPEREG {label:<24} HTTP {} {}",
                        r.status(),
                        r.text().await.unwrap_or_default().chars().take(200).collect::<String>()
                    ),
                    Err(e) => println!("SKYPEREG {label:<24} ERR {e}"),
                }
            }
        }
        return Ok(());
    }
    if std::env::var("PAIR_PROBE_LIFEREG").is_ok() {
        // config-life: registrarServiceUrl =
        //   https://teams.microsoft.com/registrar/prod/v2/registrations
        // pnhContext=TFL, pnhTemplate=TFLSkypeSpacesWeb_2.0 (web) /
        // SkypeSpacesWeb_2.6; webRegistrarTtlInSeconds=3600. Probe which
        // payload shape it accepts, using a fresh negotiated trouter path.
        let epid = uuid::Uuid::new_v4().to_string();
        let neg = b
            .http
            .get(format!("https://go.trouter.teams.microsoft.com/v4/a?epid={epid}"))
            .header("X-SkypeToken", &*b.skype)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;
        let negv: Value = neg.json().await?;
        let surl = negv
            .get("surl")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        println!("negotiated surl: {surl} (registrarUrl hint: {:?})", negv.get("registrarUrl"));

        let candidates: Vec<(&str, Value)> = vec![
            (
                "SkypeSpacesWeb TFLSkypeSpacesWeb_2.0 ctxTFL",
                serde_json::json!({
                    "clientDescription": {
                        "appId": "SkypeSpacesWeb", "aesKey": "", "languageId": "en-US",
                        "platform": "edge", "templateKey": "TFLSkypeSpacesWeb_2.0",
                        "platformUIVersion": "49/1.0.0"
                    },
                    "registrationId": uuid::Uuid::new_v4().to_string(),
                    "nodeId": "",
                    "transports": {"TROUTER": [{"context": "TFL", "path": format!("{surl}SkypeSpacesWeb"), "ttl": 3600}]}
                }),
            ),
            (
                "SkypeSpacesWeb SkypeSpacesWeb_2.6 ctxTFL",
                serde_json::json!({
                    "clientDescription": {
                        "appId": "SkypeSpacesWeb", "aesKey": "", "languageId": "en-US",
                        "platform": "edge", "templateKey": "SkypeSpacesWeb_2.6",
                        "platformUIVersion": "49/1.0.0"
                    },
                    "registrationId": uuid::Uuid::new_v4().to_string(),
                    "nodeId": "",
                    "transports": {"TROUTER": [{"context": "TFL", "path": format!("{surl}NGCallManagerWin"), "ttl": 3600}]}
                }),
            ),
            (
                "NextGenCalling DesktopNgc ctxTFL",
                serde_json::json!({
                    "clientDescription": {
                        "appId": "NextGenCalling", "aesKey": "", "languageId": "en-US",
                        "platform": "edge", "templateKey": "DesktopNgc_2.5:SkypeNgc",
                        "platformUIVersion": "49/1.0.0"
                    },
                    "registrationId": uuid::Uuid::new_v4().to_string(),
                    "nodeId": "",
                    "transports": {"TROUTER": [{"context": "TFL", "path": format!("{surl}NGCallManagerWin"), "ttl": 3600}]}
                }),
            ),
        ];
        for (label, payload) in candidates {
            match b
                .http
                .post("https://teams.microsoft.com/registrar/prod/v2/registrations")
                .header("X-SkypeToken", &*b.skype)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
            {
                Ok(r) => println!(
                    "LIFEREG {label:<44} HTTP {} {}",
                    r.status(),
                    r.text().await.unwrap_or_default().chars().take(300).collect::<String>()
                ),
                Err(e) => println!("LIFEREG {label:<44} ERR {e}"),
            }
        }
        return Ok(());
    }
    if std::env::var("PAIR_PROBE_PRESENCE").is_ok() {        // Mined from the web client's presence-service chunk (2026-10-19):
        // the ONLY write path is PUT v1/me/endpoints/ with an endpoint
        // object; auth = authorizeByUrl(req, true) which resolves to
        // aad.authorizeRequest(req, "https://presence.teams.live.com/") —
        // i.e. an MSA token scoped to the service ORIGIN, not the default
        // service:: resource.
        let base = std::env::var("PAIR_UPS")
            .unwrap_or_else(|_| "https://presence.teams.live.com".to_string());
        let origin = base.trim_end_matches('/').to_string();

        let mint = |scope: String| {
            let http = &a.http;
            let rt = std::fs::read_to_string(A_RT)
                .ok()
                .map(|s| s.trim().to_string());
            async move {
                let rt = rt?;
                let resp = http
                    .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
                    .form(&[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", rt.as_str()),
                        ("client_id", CLIENT_ID),
                        ("scope", &format!("{scope} offline_access")),
                    ])
                    .send()
                    .await
                    .ok()?;
                let v: Value = resp.json().await.ok()?;
                v.get("access_token")
                    .and_then(|t| t.as_str())
                    .map(str::to_string)
            }
        };
        let scoped = mint(format!("{origin}/.default")).await;
        // Target view: what the CC would see for the callee (A asks
        // about B) — the getPresence batch API from the presence chunk.
        {
            let body = serde_json::json!([{"mri": format!("8:{}", b.skypeid)}]);
            match a
                .http
                .post(format!("{origin}/v1/presence/getpresence/"))
                .header("X-SkypeToken", &*a.skype)
                .header("x-ms-client-consumer-type", "teams4life")
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .timeout(std::time::Duration::from_secs(8))
                .send()
                .await
            {
                Ok(r) => println!(
                    "getPresence B: HTTP {} {}",
                    r.status(),
                    r.text().await.unwrap_or_default().chars().take(400).collect::<String>()
                ),
                Err(e) => println!("getPresence B: ERR {e}"),
            }
        }
        println!(
            "presence-scoped MSA mint: {}",
            match &scoped {
                Some(t) => format!("OK ({} bytes)", t.len()),
                None => "FAILED".into(),
            }
        );

        let ep_id = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "id": ep_id,
            "availability": "Available",
            "activity": "Available",
            "deviceType": "Desktop",
            "capabilities": ["Audio", "Video"],
        });
        let attempts: Vec<(&str, String, bool)> =
            vec![("x-skypetoken default", a.skype.clone(), false)];
        for (label, token, bearer) in attempts {
            let mut req = a
                .http
                .put(format!("{origin}/v1/me/endpoints/"))
                .header("Content-Type", "application/json")
                .header("x-ms-client-consumer-type", "teams4life")
                .header("x-ms-client-user-agent", "Teams-V2-Desktop")
                .header("x-ms-endpoint-id", &ep_id)
                .header("x-ms-client-caller", "callqa")
                .body(body.to_string());
            req = if bearer {
                req.header("Authorization", format!("Bearer {token}"))
            } else {
                req.header("X-SkypeToken", token)
            };
            match req.timeout(std::time::Duration::from_secs(8)).send().await {
                Ok(r) => println!(
                    "PUT endpoints {label:<24} HTTP {} {}",
                    r.status(),
                    r.text().await.unwrap_or_default().chars().take(200).collect::<String>()
                ),
                Err(e) => println!("PUT endpoints {label:<24} ERR {e}"),
            }
        }

        // Publish for BOTH rig endpoints — the CALLEE needs capabilities
        // for invite routing (5-min expiry; the app must re-publish).
        for (label, sess) in [("A", &a), ("B", &b)] {
            let ep = uuid::Uuid::new_v4().to_string();
            let body = serde_json::json!({
                "id": ep,
                "availability": "Available",
                "activity": "Available",
                "deviceType": "Desktop",
                "capabilities": ["Audio", "Video"],
            });
            match sess
                .http
                .put(format!("{origin}/v1/me/endpoints/"))
                .header("Content-Type", "application/json")
                .header("x-ms-client-consumer-type", "teams4life")
                .header("x-ms-client-user-agent", "Teams-V2-Desktop")
                .header("x-ms-endpoint-id", &ep)
                .body(body.to_string())
                .header("X-SkypeToken", &*sess.skype)
                .timeout(std::time::Duration::from_secs(8))
                .send()
                .await
            {
                Ok(r) => println!("PUBLISH {label}: HTTP {}", r.status()),
                Err(e) => println!("PUBLISH {label}: ERR {e}"),
            }
            match sess
                .http
                .get(format!("{origin}/v1/me/presence"))
                .header("X-SkypeToken", &*sess.skype)
                .header("x-ms-client-consumer-type", "teams4life")
                .timeout(std::time::Duration::from_secs(8))
                .send()
                .await
            {
                Ok(r) => println!(
                    "READBACK {label}: {} ",
                    r.text().await.unwrap_or_default().chars().take(300).collect::<String>()
                ),
                Err(e) => println!("READBACK {label}: ERR {e}"),
            }
        }
        // Target view AFTER the fresh publish: does B now read Available?
        {
            let body = serde_json::json!([{"mri": format!("8:{}", b.skypeid)}]);
            for i in 0..7 {
                match a
                    .http
                    .post(format!("{origin}/v1/presence/getpresence/"))
                    .header("X-SkypeToken", &*a.skype)
                    .header("x-ms-client-consumer-type", "teams4life")
                    .header("Content-Type", "application/json")
                    .body(body.to_string())
                    .timeout(std::time::Duration::from_secs(8))
                    .send()
                    .await
                {
                    Ok(resp) => println!(
                        "getPresence B t+{}s: HTTP {} {}",
                        i * 10,
                        resp.status(),
                        resp.text().await.unwrap_or_default().chars().take(220).collect::<String>()
                    ),
                    Err(e) => println!("getPresence B t+{}s: ERR {e}", i * 10),
                }
                if i < 6 {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            }
        }
        return Ok(());
    }
    if std::env::var("PAIR_PROBE_LOCATION").is_ok() {
        let resp = a
            .http
            .get("https://teams.live.com/api/location/prod")
            .header("X-Skypetoken", &*a.skype)
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await?;
        println!("location: HTTP {}\n{}", resp.status(), resp.text().await.unwrap_or_default().chars().take(900).collect::<String>());
        return Ok(());
    }
    if std::env::var("PAIR_DUMP_THREAD").is_ok() {
        let resp = a
            .get(&format!("{}/v1/users/ME/conversations/19:11111111222233334444555566667777@thread.v2/messages?pageSize=15", a.chat_service))
            .send()
            .await?;
        let v: Value = resp.json().await?;
        for m in v.get("messages").and_then(|m| m.as_array()).unwrap_or(&vec![]).iter().rev() {
            if m.get("messagetype").and_then(|t| t.as_str()) == Some("Event/Call") {
                println!("=== FULL Event/Call ===");
                println!("{}", m.get("content").and_then(|c| c.as_str()).unwrap_or(""));
                println!("props: {}", serde_json::to_string(m.get("properties").unwrap_or(&Value::Null)).unwrap_or_default());
                println!("ids: id={:?} clientmessageid={:?}", m.get("id"), m.get("clientmessageid"));
                continue;
            }
            println!(
                "{} | type={:?} | {}",
                m.get("composetime").and_then(|c| c.as_str()).unwrap_or("?"),
                m.get("messagetype").and_then(|t| t.as_str()).unwrap_or("?"),
                &m.get("content").and_then(|c| c.as_str()).unwrap_or("").chars().take(80).collect::<String>(),
            );
            if let Some(p) = m.get("properties") {
                let keys: Vec<&str> = p.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
                if !keys.is_empty() { println!("      props: {keys:?}"); }
            }
        }
        return Ok(());
    }
    if std::env::var("PAIR_PROBE_EPCONV").is_ok() {
        for url in [
            "https://api.cc.skype.com/api/v2/epconv",
            "https://api.conv.skype.com/api/v2/epconv",
            "https://api.cc.skype.com/cc/v1/epconv",
            "https://api.conv.skype.com/cc/v1/epconv",
            "https://api.cc.skype.com/api/v1/epconv",
            "https://api.conv.skype.com/v1/epconv",
            "https://api.cc.skype.com/v1/epconv",
            "https://api.conv.skype.com/api/v2/conversations",
            "https://us-api.asm.skype.com/v1/epconv",
            "https://api.cc.skype.com:8443/api/v1/conv",
            "https://api.conv.skype.com:8443/api/v1/conv",
            "https://api.cc.skype.com:8443/api/v1/epconv",
            "https://api.conv.skype.com:8443/api/v1/epconv",
            "https://api.conv.skype.com:8443/api/v1/conv",
            "https://api.flightproxy.skype.com/api/v2/cp/api.conv.skype.com/api/v1/conv",
            "https://api.flightproxy.skype.com/api/v2/cp/api.cc.skype.com:8443/api/v1/conv",
            "https://api.flightproxy.skype.com/api/v2/epconv",
            "https://us-api.flightproxy.skype.com/api/v2/epconv",
            "https://api.flightproxy.skype.com/api/v2/cp/api.cc.skype.com:8443/V2/registrations",
            "https://api.flightproxy.skype.com/api/v2/cp/api.conv.skype.com/V2/registrations",
            "https://api.flightproxy.skype.com/api/v2/ep/api.cc.skype.com:8443/V2/registrations",
        ] {
            match a
                .http
                .post(url)
                .header("X-Skypetoken", &*a.skype)
                .header("Content-Type", "application/json")
                .body("{}")
                .timeout(std::time::Duration::from_secs(8))
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    println!("{url:<56} HTTP {status} {}", &body.chars().take(120).collect::<String>());
                }
                Err(e) => println!("{url:<56} ERR {e}"),
            }
        }
        return Ok(());
    }
    if std::env::var("PAIR_DUMP_MEMBERS").is_ok() {
        let resp = a
            .get(&format!("{}/v1/threads/19:11111111222233334444555566667777@thread.v2/members", a.chat_service))
            .send()
            .await?;
        println!("members HTTP {}", resp.status());
        let v: Value = resp.json().await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        let resp = a
            .get(&format!("{}/v1/users/ME/conversations?view=mychats&pageSize=3", a.chat_service))
            .send()
            .await?;
        let v: Value = resp.json().await?;
        if let Some(conv) = v.get("conversations").and_then(|c| c.as_array()).and_then(|c| c.first()) {
            println!("first conversation object:\n{}", serde_json::to_string_pretty(conv)?);
        }
        for suffix in ["/properties?reason=roster", "/profile?reason=roster"] {
            let resp = a
                .get(&format!("{}/v1/users/8:live:rig-consumer-a{suffix}", a.chat_service))
                .send()
                .await?;
            println!("GET {suffix}: HTTP {}", resp.status());
            let v: Value = resp.json().await.unwrap_or(Value::Null);
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        return Ok(());
    }
    println!("A skypeid: {}", a.skypeid);
    println!("B skypeid: {}", b.skypeid);
    let a_mri = format!("8:{}", a.skypeid);
    let b_mri = format!("8:{}", b.skypeid);

    println!();
    println!("== 1. A creates (or opens) the 1:1 with B ==");
    let body = serde_json::json!({
        "members": [
            {"id": b_mri, "role": "Admin"},
            {"id": a_mri, "role": "Admin"},
        ],
        "properties": {
            "threadType": "chat",
            "fixedRoster": "true",
        },
    });
    let resp = a.post(&format!("{}/v1/threads", a.chat_service), &body).send().await?;
    let status = resp.status();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let text = resp.text().await.unwrap_or_default();
    println!("  HTTP {status}, Location: {:?}", location.as_deref().map(|l| l.split('?').next()));
    if !status.is_success() {
        println!("  body: {}", &text.chars().take(400).collect::<String>());
        anyhow::bail!("thread create failed");
    }
    let thread = location
        .and_then(|l| l.split('?').next().map(str::to_string))
        .and_then(|l| l.rsplit('/').next().map(str::to_string))
        .map(|id| id.replace("%3A", ":").replace("%3a", ":").replace("%40", "@"))
        .unwrap_or_default();
    println!("  thread id: {thread}");

    println!();
    println!("== 2. A sends a probe message ==");
    let cmid = format!("{}000", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_millis());
    let msg = serde_json::json!({
        "content": format!("<p>rig probe {cmid}</p>"),
        "messagetype": "RichText/Html",
        "contenttype": "text",
        "clientmessageid": cmid,
    });
    let url = format!("{}/v1/users/ME/conversations/{}/messages", a.chat_service, thread);
    let resp = a.post(&url, &msg).send().await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    println!("  HTTP {status}");
    if !status.is_success() {
        println!("  body: {}", &text.chars().take(400).collect::<String>());
        anyhow::bail!("send failed");
    }

    println!();
    println!("== 3. B sees the thread and the message ==");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let resp = b
        .get(&format!("{}/v1/users/ME/conversations?view=mychats&pageSize=50", b.chat_service))
        .send()
        .await?;
    let list: Value = resp.json().await?;
    let chats = list.get("conversations").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    println!("  B sees {} conversation(s)", chats.len());
    let mut found = false;
    for c in &chats {
        let id = c.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id.contains("@unq") || id == thread {
            found = true;
            println!("  new thread visible to B: {id}");
        }
    }
    let target = chats
        .iter()
        .filter_map(|c| c.get("id").and_then(|v| v.as_str()))
        .find(|id| *id == thread || id.contains("@unq"))
        .map(str::to_string);
    let (target, via) = match target {
        Some(t) => (t, "listed"),
        None => (thread.clone(), "location"),
    };
    if !found {
        println!("  (thread not in B's list yet — reading via {via} id)");
    }
    let resp = b
        .get(&format!(
            "{}/v1/users/ME/conversations/{}/messages?pageSize=10",
            b.chat_service, target
        ))
        .send()
        .await?;
    let status = resp.status();
    let msgs: Value = resp.json().await.unwrap_or(Value::Null);
    println!("  B read messages: HTTP {status}");
    let arr = msgs.get("messages").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut ok = false;
    for m in &arr {
        let content = m.get("content").and_then(|v| v.as_str()).unwrap_or("");
        if content.contains(&cmid) {
            ok = true;
            println!("  => MESSAGE RECEIVED by B (clientmessageid {cmid})");
        }
    }
    println!("  ({} message(s) in thread)", arr.len());
    if ok {
        println!("=> A<->B PERSONAL MESSAGING WORKS: create + send + receive.");
    } else {
        println!("=> receive not confirmed — see statuses above.");
    }
    Ok(())
}

fn urlencoding_simple(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

async fn mint_msa(http: &reqwest::Client, rt_path: &str, scope: &str) -> Option<String> {
    let rt = std::fs::read_to_string(rt_path).ok()?.trim().to_string();
    let resp = http
        .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
            ("client_id", CLIENT_ID),
            ("scope", &format!("{scope} offline_access")),
        ])
        .send()
        .await
        .ok()?;
    let v: Value = resp.json().await.ok()?;
    v.get("access_token").and_then(|t| t.as_str()).map(str::to_string)
}

async fn mint_service_token(http: &reqwest::Client, aad: &str, resource: &str) -> Option<String> {
    let resp = http
        .post(format!(
            "https://teams.live.com/api/auth/v1.0/authz/consumer?resource={}",
            resource.replace(':', "%3A").replace('/', "%2F")
        ))
        .bearer_auth(aad)
        .header("Content-Length", "0")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    v.pointer("/skypeToken/skypetoken")
        .and_then(|t| t.as_str())
        .map(str::to_string)
}
