//! DTLS-SRTP certificate material.
//!
//! The consumer web client is a WebRTC stack (calling-pluginless: 57 dtls
//! references, zero SDES): it cannot answer an SDES-only offer, and the
//! consumer fleet's call controller never completes an all-SDES acceptance
//! transaction (408/10056 "waiting for acknowledgement" at its 30s
//! deadline, connectTime null while raw RTP flows — run-13, four HAR
//! captures). Every offer and answer therefore carries a real self-signed
//! certificate's sha-256 `a=fingerprint` (plus `a=setup`), while the
//! `a=crypto` SDES lines stay for SFB-stack peers (echo bot, work legs).

use std::sync::OnceLock;

/// The colon-separated UPPERCASE sha-256 fingerprint of our DTLS
/// certificate (the exact `a=fingerprint:sha-256 …` value, e.g.
/// `26:12:AA:…`). Generated once per process.
pub fn fingerprint_sha256() -> &'static str {
    static FP: OnceLock<String> = OnceLock::new();
    FP.get_or_init(|| {
        let cert = generate_cert();
        let der = cert.cert.der();
        let digest = {
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            h.update(der.as_ref());
            h.finalize()
        };
        digest
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    })
}

/// `a=fingerprint` + `a=setup` lines for SDP (session level).
pub fn sdp_attributes(setup: Setup) -> String {
    format!(
        "a=fingerprint:sha-256 {}\r\na=setup:{}\r\n",
        fingerprint_sha256(),
        setup.as_str()
    )
}

/// DTLS connection role declared via `a=setup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    /// Offerer: can act as either DTLS endpoint.
    ActPass,
    /// Answerer: we initiate the connection to the peer.
    Active,
    /// Answerer: we wait for the peer to connect.
    Passive,
}

impl Setup {
    fn as_str(self) -> &'static str {
        match self {
            Setup::ActPass => "actpass",
            Setup::Active => "active",
            Setup::Passive => "passive",
        }
    }
}

fn generate_cert() -> rcgen::CertifiedKey {
    // Distinguishing name content is irrelevant for WebRTC DTLS (the
    // fingerprint is the identity); a fixed CN keeps generation cheap.
    let params = rcgen::CertificateParams::new(vec!["teamsfast".to_string()])
        .expect("certificate params");
    // WebRTC checks the key type: ECDSA P-256 is universally accepted.
    let key_pair = rcgen::KeyPair::generate().expect("key pair");
    rcgen::CertifiedKey {
        cert: params.self_signed(&key_pair).expect("self-signed cert"),
        key_pair,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_well_formed_sha256() {
        let fp = fingerprint_sha256();
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 32, "32 octets: {fp}");
        for p in parts {
            assert_eq!(p.len(), 2);
            assert!(p.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_digit() || b.is_ascii_digit()));
        }
        // Stable within the process
        assert_eq!(fp, fingerprint_sha256());
    }

    #[test]
    fn sdp_attributes_shape() {
        let attr = sdp_attributes(Setup::ActPass);
        assert!(attr.starts_with("a=fingerprint:sha-256 "));
        assert!(attr.ends_with("\r\na=setup:actpass\r\n"));
    }
}
