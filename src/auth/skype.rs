//! Skype token exchange
//!
//! After obtaining an AAD access token, exchange it for a Skype token
//! via the Teams authsvc endpoint. The Skype token is what Teams APIs
//! actually require for most operations.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Response from Teams authsvc token exchange
#[derive(Debug, Deserialize)]
pub struct AuthzResponse {
    pub tokens: Option<AuthzTokens>,
    #[serde(rename = "regionGtms")]
    pub region_gtms: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AuthzTokens {
    #[serde(rename = "skypeToken")]
    pub skype_token: Option<String>,
    #[serde(rename = "expiresIn")]
    pub expires_in: Option<u64>,
}

const AUTHZ_URL_WORK: &str = "https://teams.microsoft.com/api/authsvc/v1.0/authz";
const AUTHZ_URL_PERSONAL: &str = "https://teams.live.com/api/auth/v1.0/authz/consumer";

/// Exchange an AAD access token for a Skype token.
/// Returns (skype_token, expires_in_secs, region_gtms).
pub async fn exchange_skype_token(
    aad_token: &str,
    personal: bool,
) -> Result<(String, Option<u64>, Option<serde_json::Value>)> {
    let url = if personal {
        AUTHZ_URL_PERSONAL
    } else {
        AUTHZ_URL_WORK
    };

    tracing::debug!("Exchanging AAD token for Skype token at {}", url);

    let client = crate::api::client::shared_http();
    let resp = client
        .post(url)
        .bearer_auth(aad_token)
        .header("Content-Length", "0")
        .send()
        .await
        .context("Failed to call authsvc for Skype token exchange")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "Skype token exchange failed (HTTP {}): {}",
            status.as_u16(),
            body
        );
    }

    let authz: AuthzResponse = resp
        .json()
        .await
        .context("Failed to parse authsvc response")?;

    let tokens = authz
        .tokens
        .context("authsvc response missing 'tokens' field")?;
    let skype_token = tokens
        .skype_token
        .context("authsvc response missing 'skypeToken'")?;

    Ok((skype_token, tokens.expires_in, authz.region_gtms))
}

/// Consumer (personal) authz response — the FLAT shape, verified live
/// 2026-10-19: {skypeToken: {skypetoken, expiresIn, skypeid,
/// signinname}, regionGtms, consumerLicenseDetails, regionSettings}.
#[derive(Debug, Deserialize)]
pub struct PersonalAuthz {
    #[serde(rename = "skypeToken")]
    pub skype_token: PersonalSkypeToken,
    #[serde(rename = "regionGtms", default)]
    pub region_gtms: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct PersonalSkypeToken {
    #[serde(rename = "skypetoken")]
    pub token: String,
    #[serde(rename = "expiresIn", default)]
    pub expires_in: Option<u64>,
    /// live:<handle> or live:.cid.<hex> — the MRI suffix (8:live:…).
    #[serde(default)]
    pub skypeid: Option<String>,
}

/// Exchange a consumer (MSA-native, service:: scope) token at the
/// consumer authz. Distinct from the work exchange: different endpoint
/// AND a flat response shape.
pub async fn exchange_skype_token_personal(
    aad_token: &str,
) -> Result<PersonalAuthz> {
    let client = crate::api::client::shared_http();
    let resp = client
        .post(AUTHZ_URL_PERSONAL)
        .bearer_auth(aad_token)
        .header("Content-Length", "0")
        .send()
        .await
        .context("consumer authz request failed")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("consumer authz failed (HTTP {}): {}", status.as_u16(), body);
    }
    resp.json()
        .await
        .context("consumer authz response parse failed")
}
