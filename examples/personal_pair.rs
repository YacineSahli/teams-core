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
