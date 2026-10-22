//! Minimal SDP answer generator for audio-only calls.
//!
//! Parses enough of the incoming SDP offer to extract ICE credentials and
//! crypto keys, then generates a minimal SDP answer with PCMU codec.

use anyhow::Result;
use base64::Engine;

/// Extracted fields from the incoming SDP offer.
#[derive(Debug, Clone)]
pub struct SdpOfferInfo {
    pub ice_ufrag: String,
    pub ice_pwd: String,
    /// First crypto line from the offer (we echo it back).
    pub crypto_line: String,
    /// All crypto lines from the offer (for SRTP key extraction).
    pub crypto_lines: Vec<String>,
    /// First candidate address and port from the offer.
    pub candidate_ip: String,
    pub candidate_port: u16,
    /// Video section info (if present in the offer).
    pub video: Option<SdpVideoInfo>,
}

/// Extracted video-specific fields from the SDP offer.
#[derive(Debug, Clone)]
pub struct SdpVideoInfo {
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub crypto_lines: Vec<String>,
    pub candidate_ip: String,
    pub candidate_port: u16,
}

/// Parse the SDP offer blob to extract ICE credentials, crypto, and candidates.
///
/// The blob may be compressed (auf::compress with raw DEFLATE + base64 encoding).
/// This function automatically decompresses if needed via `sdp_compress::decompress_sdp`.
/// The offer as plain SDP, decompressing when needed (idempotent on
/// plain text). Call this ONCE at entry and hand the result to every
/// raw-blob helper — decompressing only inside [`parse_sdp_offer`] left
/// the bundle/video/mid helpers reading compressed bytes.
pub fn ensure_plain_sdp(blob: &str) -> String {
    super::sdp_compress::decompress_sdp(blob).unwrap_or_else(|_| blob.to_string())
}

pub fn parse_sdp_offer(blob: &str) -> Result<SdpOfferInfo> {
    let blob = ensure_plain_sdp(blob);    let mut ice_ufrag = String::new();
    let mut ice_pwd = String::new();
    let mut crypto_line = String::new();
    let mut crypto_lines = Vec::new();
    let mut candidate_ip = String::new();
    let mut candidate_port: u16 = 0;

    // Video section fields
    let mut vid_ice_ufrag = String::new();
    let mut vid_ice_pwd = String::new();
    let mut vid_crypto_lines = Vec::new();
    let mut vid_candidate_ip = String::new();
    let mut vid_candidate_port: u16 = 0;
    let mut has_video = false;

    #[derive(PartialEq)]
    enum Section {
        Session,
        Audio,
        Video,
        Other,
    }
    let mut section = Section::Session;

    for line in blob.lines() {
        let line = line.trim();

        if line.starts_with("m=audio") {
            section = Section::Audio;
        } else if line.starts_with("m=video") {
            section = Section::Video;
            has_video = true;
        } else if line.starts_with("m=") {
            section = Section::Other;
        }

        // ICE credentials
        if line.starts_with("a=ice-ufrag:") {
            let val = line.trim_start_matches("a=ice-ufrag:").to_string();
            match section {
                Section::Audio => ice_ufrag = val,
                Section::Video => vid_ice_ufrag = val,
                Section::Session if ice_ufrag.is_empty() => ice_ufrag = val,
                _ => {}
            }
        }
        if line.starts_with("a=ice-pwd:") {
            let val = line.trim_start_matches("a=ice-pwd:").to_string();
            match section {
                Section::Audio => ice_pwd = val,
                Section::Video => vid_ice_pwd = val,
                Section::Session if ice_pwd.is_empty() => ice_pwd = val,
                _ => {}
            }
        }

        // Crypto lines
        if line.starts_with("a=crypto:") || line.starts_with("a=cryptoscale:") {
            if crypto_line.is_empty() {
                crypto_line = line.to_string();
            }
            match section {
                Section::Audio => crypto_lines.push(line.to_string()),
                Section::Video => vid_crypto_lines.push(line.to_string()),
                _ => {}
            }
        }

        // Candidates
        if line.starts_with("a=candidate:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let ip = parts[4].to_string();
                let port: u16 = parts[5].parse().unwrap_or(0);
                match section {
                    Section::Audio if candidate_ip.is_empty() => {
                        candidate_ip = ip;
                        candidate_port = port;
                    }
                    Section::Video if vid_candidate_ip.is_empty() => {
                        vid_candidate_ip = ip;
                        vid_candidate_port = port;
                    }
                    _ => {}
                }
            }
        }
    }

    if ice_ufrag.is_empty() {
        anyhow::bail!("Could not extract ice-ufrag from SDP offer");
    }

    let video = if has_video {
        Some(SdpVideoInfo {
            ice_ufrag: if vid_ice_ufrag.is_empty() {
                ice_ufrag.clone()
            } else {
                vid_ice_ufrag
            },
            ice_pwd: if vid_ice_pwd.is_empty() {
                ice_pwd.clone()
            } else {
                vid_ice_pwd
            },
            crypto_lines: if vid_crypto_lines.is_empty() {
                crypto_lines.clone()
            } else {
                vid_crypto_lines
            },
            candidate_ip: if vid_candidate_ip.is_empty() {
                candidate_ip.clone()
            } else {
                vid_candidate_ip
            },
            candidate_port: if vid_candidate_port == 0 {
                candidate_port
            } else {
                vid_candidate_port
            },
        })
    } else {
        None
    };

    Ok(SdpOfferInfo {
        ice_ufrag,
        ice_pwd,
        crypto_line,
        crypto_lines,
        candidate_ip,
        candidate_port,
        video,
    })
}

/// Generate a minimal SDP answer for audio-only with PCMU codec.
///
/// `local_ip` is the local IP address to put in the SDP.
/// `local_port` is the actual UDP port we are listening on (0 for placeholder).
/// `offer` is the parsed offer info (we echo back ICE credentials and crypto).
pub fn generate_sdp_answer(local_ip: &str, offer: &SdpOfferInfo) -> String {
    generate_sdp_answer_with_port(local_ip, 20000, offer)
}

/// Generate SDP answer with a specific local port.
pub fn generate_sdp_answer_with_port(
    local_ip: &str,
    local_port: u16,
    _offer: &SdpOfferInfo,
) -> String {
    let our_ufrag = generate_ice_ufrag();
    let our_pwd = generate_ice_pwd();
    let our_crypto_key = generate_srtp_key();
    let port = local_port;

    let mut sdp = String::new();

    // Session level
    sdp.push_str("v=0\r\n");
    sdp.push_str(&format!("o=- 0 0 IN IP4 {}\r\n", local_ip));
    sdp.push_str("s=session\r\n");
    sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
    sdp.push_str("t=0 0\r\n");

    // Audio media line — PCMU only (payload type 0)
    sdp.push_str(&format!("m=audio {} RTP/SAVP 0\r\n", port));
    sdp.push_str("a=rtpmap:0 PCMU/8000\r\n");
    sdp.push_str("a=sendrecv\r\n");
    sdp.push_str("a=rtcp-mux\r\n");
    sdp.push_str("a=label:main-audio\r\n");
    sdp.push_str("a=x-source:main-audio\r\n");

    // ICE credentials (our own)
    sdp.push_str(&format!("a=ice-ufrag:{}\r\n", our_ufrag));
    sdp.push_str(&format!("a=ice-pwd:{}\r\n", our_pwd));

    // Host candidate
    sdp.push_str(&format!(
        "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
        local_ip, port
    ));

    // SRTP crypto — use standard crypto line
    sdp.push_str(&format!(
        "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}|2^31\r\n",
        our_crypto_key
    ));

    sdp
}

/// Generate an SDP answer and return it along with the crypto line we included.
///
/// This is needed so the caller can extract SRTP keying material for the local side.
pub fn generate_sdp_answer_with_crypto(
    local_ip: &str,
    local_port: u16,
    _offer: &SdpOfferInfo,
) -> (String, String) {
    let our_ufrag = generate_ice_ufrag();
    let our_pwd = generate_ice_pwd();
    let our_crypto_key = generate_srtp_key();
    let port = local_port;

    let crypto_line = format!(
        "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}|2^31",
        our_crypto_key
    );

    let mut sdp = String::new();
    sdp.push_str("v=0\r\n");
    sdp.push_str(&format!("o=- 0 0 IN IP4 {}\r\n", local_ip));
    sdp.push_str("s=session\r\n");
    sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
    sdp.push_str("t=0 0\r\n");
    sdp.push_str(&format!("m=audio {} RTP/SAVP 0\r\n", port));
    sdp.push_str("a=rtpmap:0 PCMU/8000\r\n");
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str("a=sendrecv\r\n");
    sdp.push_str("a=rtcp-mux\r\n");
    sdp.push_str("a=label:main-audio\r\n");
    sdp.push_str("a=x-source:main-audio\r\n");
    sdp.push_str(&format!("a=ice-ufrag:{}\r\n", our_ufrag));
    sdp.push_str(&format!("a=ice-pwd:{}\r\n", our_pwd));
    sdp.push_str(&format!(
        "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
        local_ip, port
    ));
    sdp.push_str(&crypto_line);
    sdp.push_str("\r\n");

    (sdp, crypto_line)
}

/// Generate a random 4-character ICE ufrag.
/// MS-style SDP session id in o= (a modest decimal number, e.g. 418176
/// captured from the echo bot — not the 0 we used to send).
fn rand_session_id() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos % 900_000) + 100_000
}

pub fn generate_ice_ufrag() -> String {
    use std::fmt::Write;
    let bytes: [u8; 3] = rand_bytes();
    let mut s = String::with_capacity(4);
    for b in &bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s.truncate(4);
    s
}

/// Generate a random 24-character ICE password using only alphanumeric characters.
///
/// RFC 5245 requires ice-pwd to be 22-256 ice-chars. We use hex encoding
/// to avoid any special characters (`+`, `/`, `=`) that some SDP parsers reject.
pub fn generate_ice_pwd() -> String {
    let bytes: [u8; 12] = rand_bytes();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Generate a random 30-byte base64 SRTP master key.
fn generate_srtp_key() -> String {
    let bytes: [u8; 30] = rand_bytes();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Generate cryptographically secure random bytes via OS CSPRNG.
fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG failed");
    buf
}

/// Generate SDP answer with crypto, including a video section if the offer has video.
///
/// Returns (sdp_answer, audio_crypto_line, video_crypto_line).
/// The video_crypto_line is None if the offer had no video.
pub fn generate_sdp_answer_with_video(
    local_ip: &str,
    audio_port: u16,
    video_port: u16,
    offer: &SdpOfferInfo,
) -> (String, String, Option<String>) {
    let our_ufrag = generate_ice_ufrag();
    let our_pwd = generate_ice_pwd();
    let our_crypto_key = generate_srtp_key();

    let audio_crypto_line = format!(
        "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}|2^31",
        our_crypto_key
    );

    let mut sdp = String::new();
    sdp.push_str("v=0\r\n");
    sdp.push_str(&format!("o=- 0 0 IN IP4 {}\r\n", local_ip));
    sdp.push_str("s=session\r\n");
    sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
    sdp.push_str("t=0 0\r\n");

    // Video bandwidth hint at session level (if video present)
    if offer.video.is_some() {
        sdp.push_str("a=x-mediabw:main-video send=2000;recv=2000\r\n");
    }

    // Audio section
    sdp.push_str(&format!("m=audio {} RTP/SAVP 0\r\n", audio_port));
    sdp.push_str("a=rtpmap:0 PCMU/8000\r\n");
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str("a=sendrecv\r\n");
    sdp.push_str("a=rtcp-mux\r\n");
    sdp.push_str("a=label:main-audio\r\n");
    sdp.push_str("a=x-source:main-audio\r\n");
    sdp.push_str(&format!("a=ice-ufrag:{}\r\n", our_ufrag));
    sdp.push_str(&format!("a=ice-pwd:{}\r\n", our_pwd));
    sdp.push_str(&format!(
        "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
        local_ip, audio_port
    ));
    sdp.push_str(&audio_crypto_line);
    sdp.push_str("\r\n");

    // Video section (if offer includes video)
    let video_crypto_line = if offer.video.is_some() {
        let vid_ufrag = generate_ice_ufrag();
        let vid_pwd = generate_ice_pwd();
        let vid_crypto_key = generate_srtp_key();
        let vid_crypto = format!(
            "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}|2^31",
            vid_crypto_key
        );

        sdp.push_str(&format!("m=video {} RTP/SAVP 122 121 123\r\n", video_port));
        sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
        sdp.push_str("a=rtpmap:122 X-H264UC/90000\r\n");
        sdp.push_str("a=fmtp:122 packetization-mode=1;mst-mode=NI-TC\r\n");
        sdp.push_str("a=rtpmap:121 x-rtvc1/90000\r\n");
        sdp.push_str("a=rtpmap:123 x-ulpfecuc/90000\r\n");
        sdp.push_str("a=rtcp-fb:* x-message app send:src,x-pli recv:src,x-pli\r\n");
        sdp.push_str("a=x-signaling-fb:* x-message app send:src,csrc,vc recv:src\r\n");
        sdp.push_str("a=rtcp-rsize\r\n");
        sdp.push_str("a=x-source-streamid:202\r\n");
        sdp.push_str(&format!("a=rtcp:{}\r\n", video_port));
        sdp.push_str("a=rtcp-mux\r\n");
        sdp.push_str("a=label:main-video\r\n");
        sdp.push_str("a=x-source:main-video\r\n");
        sdp.push_str("a=mid:1\r\n");
        sdp.push_str(&format!("a=ice-ufrag:{}\r\n", vid_ufrag));
        sdp.push_str(&format!("a=ice-pwd:{}\r\n", vid_pwd));
        sdp.push_str(&format!(
            "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
            local_ip, video_port
        ));
        sdp.push_str(&vid_crypto);
        sdp.push_str("\r\n");

        Some(vid_crypto)
    } else {
        None
    };

    (sdp, audio_crypto_line, video_crypto_line)
}

/// Result of SDP answer generation, including ICE credentials and crypto lines.
#[derive(Debug, Clone)]
pub struct SdpAnswerResult {
    pub sdp: String,
    pub audio_crypto_line: String,
    pub video_crypto_line: Option<String>,
    pub audio_ice_ufrag: String,
    pub audio_ice_pwd: String,
    pub video_ice_ufrag: Option<String>,
    pub video_ice_pwd: Option<String>,
}

/// Generate SDP answer with video support, returning ICE credentials for connectivity checks.
///
/// If `local_candidates` is provided, they are included in the audio section.
/// If `video_candidates` is provided, they are included in the video section.
pub fn generate_sdp_answer_full(
    local_ip: &str,
    audio_port: u16,
    video_port: u16,
    offer: &SdpOfferInfo,
    local_candidates: &[crate::calling::ice::IceCandidate],
    video_candidates: &[crate::calling::ice::IceCandidate],
) -> SdpAnswerResult {
    let our_ufrag = generate_ice_ufrag();
    let our_pwd = generate_ice_pwd();
    let our_crypto_key = generate_srtp_key();

    let audio_crypto_line = format!(
        "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}|2^31",
        our_crypto_key
    );

    let mut sdp = String::new();
    // MS-shaped SDP (see generate_av_sdp_offer): per-m-line c=, rtcp,
    // x-signaling-fb, x-source-streamid, no direction attribute, real
    // session id in o=.
    let session_id = rand_session_id();
    sdp.push_str("v=0\r\n");
    sdp.push_str(&format!("o=- {} 0 IN IP4 127.0.0.1\r\n", session_id));
    sdp.push_str("s=session\r\n");
    sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
    sdp.push_str("t=0 0\r\n");
    // DTLS capability (see generate_av_sdp_offer): answers declare active.
    sdp.push_str(&super::dtls::sdp_attributes(super::dtls::Setup::Active));

    if offer.video.is_some() {
        sdp.push_str("a=x-mediabw:main-video send=2000;recv=2000\r\n");
    }

    // Audio section
    sdp.push_str(&format!("m=audio {} RTP/SAVP 0\r\n", audio_port));
    sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
    sdp.push_str("a=rtpmap:0 PCMU/8000\r\n");
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str("a=rtcp-fb:* x-message app send:dsh recv:dsh\r\n");
    sdp.push_str("a=x-signaling-fb:* x-message app send:dsh recv:dsh\r\n");
    sdp.push_str("a=rtcp-rsize\r\n");
    sdp.push_str("a=x-source-streamid:201\r\n");
    sdp.push_str("a=x-source:main-audio\r\n");
    sdp.push_str(&format!("a=rtcp:{}\r\n", audio_port));
    sdp.push_str("a=rtcp-mux\r\n");
    sdp.push_str("a=label:main-audio\r\n");
    sdp.push_str("a=mid:0\r\n");
    sdp.push_str(&format!("a=ice-ufrag:{}\r\n", our_ufrag));
    sdp.push_str(&format!("a=ice-pwd:{}\r\n", our_pwd));

    // Include gathered candidates
    if local_candidates.is_empty() {
        // Fallback: single host candidate
        sdp.push_str(&format!(
            "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
            local_ip, audio_port
        ));
    } else {
        for c in local_candidates {
            sdp.push_str(&format!("a={}\r\n", c.to_sdp_line()));
        }
    }

    // RFC 3264: never answer with SDES crypto the offer did not offer
    // (a WebRTC peer fails setRemoteDescription on the extra a=crypto
    // lines — live: the web tore the call 500ms after its 200).
    if !offer.crypto_lines.is_empty() {
        sdp.push_str(&audio_crypto_line);
        sdp.push_str("\r\n");
    }

    // Video section
    let (video_crypto_line, video_ice_ufrag, video_ice_pwd) = if offer.video.is_some() {
        let vid_ufrag = generate_ice_ufrag();
        let vid_pwd = generate_ice_pwd();
        let vid_crypto_key = generate_srtp_key();
        let vid_crypto = format!(
            "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}|2^31",
            vid_crypto_key
        );

        sdp.push_str(&format!("m=video {} RTP/SAVP 122 121 123\r\n", video_port));
        sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
        sdp.push_str("a=rtpmap:122 X-H264UC/90000\r\n");
        sdp.push_str("a=fmtp:122 packetization-mode=1;mst-mode=NI-TC\r\n");
        sdp.push_str("a=rtpmap:121 x-rtvc1/90000\r\n");
        sdp.push_str("a=rtpmap:123 x-ulpfecuc/90000\r\n");
        sdp.push_str("a=rtcp-fb:* x-message app send:src,x-pli recv:src,x-pli\r\n");
        sdp.push_str("a=x-signaling-fb:* x-message app send:src,csrc,vc recv:src\r\n");
        sdp.push_str("a=rtcp-rsize\r\n");
        sdp.push_str("a=x-source-streamid:202\r\n");
        sdp.push_str(&format!("a=rtcp:{}\r\n", video_port));
        sdp.push_str("a=rtcp-mux\r\n");
        sdp.push_str("a=label:main-video\r\n");
        sdp.push_str("a=x-source:main-video\r\n");
        sdp.push_str("a=mid:1\r\n");
        sdp.push_str(&format!("a=ice-ufrag:{}\r\n", vid_ufrag));
        sdp.push_str(&format!("a=ice-pwd:{}\r\n", vid_pwd));

        if video_candidates.is_empty() {
            sdp.push_str(&format!(
                "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
                local_ip, video_port
            ));
        } else {
            for c in video_candidates {
                sdp.push_str(&format!("a={}\r\n", c.to_sdp_line()));
            }
        }

        if !offer.crypto_lines.is_empty() {
            sdp.push_str(&vid_crypto);
        }

        (Some(vid_crypto), Some(vid_ufrag), Some(vid_pwd))
    } else {
        (None, None, None)
    };

    SdpAnswerResult {
        sdp,
        audio_crypto_line,
        video_crypto_line,
        audio_ice_ufrag: our_ufrag,
        audio_ice_pwd: our_pwd,
        video_ice_ufrag,
        video_ice_pwd,
    }
}

/// Result of SDP offer generation (for outgoing calls).
#[derive(Debug, Clone)]
pub struct SdpOfferResult {
    pub sdp: String,
    pub crypto_line: String,
    pub ice_ufrag: String,
    pub ice_pwd: String,
}

/// Generate an SDP offer for an outgoing audio-only call (PCMU).
pub fn generate_sdp_offer(
    local_ip: &str,
    local_port: u16,
    ice_ufrag: &str,
    ice_pwd: &str,
    candidates: &[crate::calling::ice::IceCandidate],
) -> SdpOfferResult {
    let crypto_key = generate_srtp_key();
    let crypto_line = format!(
        "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}|2^31",
        crypto_key
    );

    let mut sdp = String::new();
    sdp.push_str("v=0\r\n");
    sdp.push_str(&format!("o=- 0 0 IN IP4 {}\r\n", local_ip));
    sdp.push_str("s=session\r\n");
    sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
    sdp.push_str("t=0 0\r\n");
    sdp.push_str(&format!("m=audio {} RTP/SAVP 0\r\n", local_port));
    sdp.push_str("a=rtpmap:0 PCMU/8000\r\n");
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str("a=sendrecv\r\n");
    sdp.push_str("a=rtcp-mux\r\n");
    sdp.push_str("a=label:main-audio\r\n");
    sdp.push_str("a=x-source:main-audio\r\n");
    sdp.push_str(&format!("a=ice-ufrag:{}\r\n", ice_ufrag));
    sdp.push_str(&format!("a=ice-pwd:{}\r\n", ice_pwd));

    if candidates.is_empty() {
        sdp.push_str(&format!(
            "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
            local_ip, local_port
        ));
    } else {
        for c in candidates {
            sdp.push_str(&format!("a={}\r\n", c.to_sdp_line()));
        }
    }

    sdp.push_str(&crypto_line);
    sdp.push_str("\r\n");

    SdpOfferResult {
        sdp,
        crypto_line,
        ice_ufrag: ice_ufrag.to_string(),
        ice_pwd: ice_pwd.to_string(),
    }
}

/// Result of audio+video SDP generation (used for both offer and answer).
#[derive(Debug, Clone)]
pub struct AvSdpResult {
    pub sdp: String,
    pub audio_crypto_line: String,
    pub video_crypto_line: String,
    pub audio_ufrag: String,
    pub audio_pwd: String,
    pub video_ufrag: String,
    pub video_pwd: String,
}

/// Parameters for audio+video SDP generation.
pub struct AvSdpParams<'a> {
    pub local_ip: &'a str,
    pub audio_port: u16,
    pub video_port: u16,
    pub audio_ufrag: &'a str,
    pub audio_pwd: &'a str,
    pub video_ufrag: &'a str,
    pub video_pwd: &'a str,
    pub audio_candidates: &'a [crate::calling::ice::IceCandidate],
    pub video_candidates: &'a [crate::calling::ice::IceCandidate],
    /// Base SSRC for the video x-ssrc-range attribute.
    pub video_ssrc_base: u32,
    /// SSRC for audio x-ssrc-range attribute.
    pub audio_ssrc: u32,
}

/// Generate an SDP offer with both audio (PCMU) and video (H.264) m-lines.
///
/// Teams uses separate transports per media (no BUNDLE) — each m-line gets its
/// own ICE credentials, port, and SRTP crypto key.
pub fn generate_av_sdp_offer(p: &AvSdpParams) -> AvSdpResult {
    let audio_crypto_key = generate_srtp_key();
    let audio_crypto_line = format!(
        "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}|2^31",
        audio_crypto_key
    );
    let video_crypto_key = generate_srtp_key();
    let video_crypto_line = format!(
        "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}|2^31",
        video_crypto_key
    );
    let mut sdp = String::new();

    // Session level — shaped like MS-generated SDP (captured live from the
    // echo bot's callAcceptance, 2026-10-20): the web client's SFB-SDP
    // parser dies on offers that deviate (its Accept failed client-side
    // with CallEndReasonMediaOfferProcessingError before any HTTP request
    // while our offers carried host-style shapes). MS includes per-m-line
    // c=/rtcp/x-signaling-fb/x-source-streamid, omits direction
    // attributes, and puts 127.0.0.1 + a real session id in o=.
    let session_id = p.audio_ssrc;
    sdp.push_str("v=0\r\n");
    sdp.push_str(&format!("o=- {} 0 IN IP4 127.0.0.1\r\n", session_id));
    sdp.push_str("s=session\r\n");
    sdp.push_str(&format!("c=IN IP4 {}\r\n", p.local_ip));
    sdp.push_str("b=CT:99980\r\n");
    sdp.push_str("t=0 0\r\n");
    sdp.push_str("a=x-mediabw:main-video send=12000;recv=12000\r\n");
    // DTLS capability (WebRTC answerers require a=fingerprint+setup; SFB
    // peers ignore them and keep using a=crypto below).
    sdp.push_str(&super::dtls::sdp_attributes(super::dtls::Setup::ActPass));

    // Audio m-line
    sdp.push_str(&format!("m=audio {} RTP/SAVP 0\r\n", p.audio_port));
    sdp.push_str(&format!("c=IN IP4 {}\r\n", p.local_ip));
    sdp.push_str(&format!(
        "a=x-ssrc-range:{}-{}\r\n",
        p.audio_ssrc, p.audio_ssrc
    ));
    sdp.push_str("a=rtcp-fb:* x-message app send:dsh recv:dsh\r\n");
    sdp.push_str("a=x-signaling-fb:* x-message app send:dsh recv:dsh\r\n");
    sdp.push_str("a=rtcp-rsize\r\n");
    sdp.push_str("a=x-source-streamid:201\r\n");
    sdp.push_str("a=x-source:main-audio\r\n");
    sdp.push_str(&format!("a=rtcp:{}\r\n", p.audio_port));
    sdp.push_str("a=mid:0\r\n");
    sdp.push_str("a=rtpmap:0 PCMU/8000\r\n");
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str("a=rtcp-mux\r\n");
    sdp.push_str("a=label:main-audio\r\n");
    sdp.push_str(&format!("a=ice-ufrag:{}\r\n", p.audio_ufrag));
    sdp.push_str(&format!("a=ice-pwd:{}\r\n", p.audio_pwd));

    if p.audio_candidates.is_empty() {
        sdp.push_str(&format!(
            "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
            p.local_ip, p.audio_port
        ));
    } else {
        for c in p.audio_candidates {
            sdp.push_str(&format!("a={}\r\n", c.to_sdp_line()));
        }
    }

    sdp.push_str(&audio_crypto_line);
    sdp.push_str("\r\n");

    // Video m-line — X-H264UC (Teams proprietary H.264 SVC variant)
    sdp.push_str(&format!(
        "m=video {} RTP/SAVP 122 121 123\r\n",
        p.video_port
    ));
    sdp.push_str(&format!("c=IN IP4 {}\r\n", p.local_ip));
    sdp.push_str("a=mid:1\r\n");
    sdp.push_str("a=rtpmap:122 X-H264UC/90000\r\n");
    sdp.push_str("a=fmtp:122 packetization-mode=1;mst-mode=NI-TC\r\n");
    sdp.push_str("a=rtpmap:121 x-rtvc1/90000\r\n");
    sdp.push_str("a=rtpmap:123 x-ulpfecuc/90000\r\n");
    // STANDARD RTCP feedback (RFC 4585/5104) alongside the MS x-message
    // line: a WebRTC peer only honors PLI/FIR when the SDP negotiated
    // them — meeting/group video legs answered by browsers hit the exact
    // consumer-path bug otherwise (Chrome ignores PLIs; video goes black
    // after any keyframe loss). Same three lines as the BUNDLE offer;
    // SFB-shaped peers ignore what they don't negotiate.
    sdp.push_str("a=rtcp-fb:* ccm fir\r\n");
    sdp.push_str("a=rtcp-fb:* nack\r\n");
    sdp.push_str("a=rtcp-fb:* nack pli\r\n");
    sdp.push_str("a=rtcp-fb:* x-message app send:src,x-pli recv:src,x-pli\r\n");
    sdp.push_str("a=x-signaling-fb:* x-message app send:src,csrc,vc recv:src\r\n");
    sdp.push_str("a=rtcp-rsize\r\n");
    sdp.push_str("a=x-source-streamid:202\r\n");
    sdp.push_str(&format!(
        "a=x-ssrc-range:{}-{}\r\n",
        p.video_ssrc_base,
        p.video_ssrc_base
            .saturating_add(super::video::VIDEO_SSRC_RANGE_SIZE - 1)
    ));
    sdp.push_str("a=x-caps:121 263:320:240:15.0:250000:1;4359:176:144:15.0:100000:1\r\n");
    sdp.push_str(&format!("a=rtcp:{}\r\n", p.video_port));
    sdp.push_str("a=rtcp-mux\r\n");
    sdp.push_str("a=label:main-video\r\n");
    sdp.push_str("a=x-source:main-video\r\n");
    sdp.push_str(&format!("a=ice-ufrag:{}\r\n", p.video_ufrag));
    sdp.push_str(&format!("a=ice-pwd:{}\r\n", p.video_pwd));

    if p.video_candidates.is_empty() {
        sdp.push_str(&format!(
            "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
            p.local_ip, p.video_port
        ));
    } else {
        for c in p.video_candidates {
            sdp.push_str(&format!("a={}\r\n", c.to_sdp_line()));
        }
    }

    sdp.push_str(&video_crypto_line);
    sdp.push_str("\r\n");

    AvSdpResult {
        sdp,
        audio_crypto_line,
        video_crypto_line,
        audio_ufrag: p.audio_ufrag.to_string(),
        audio_pwd: p.audio_pwd.to_string(),
        video_ufrag: p.video_ufrag.to_string(),
        video_pwd: p.video_pwd.to_string(),
    }
}

/// Strip the video m-line (and everything after it) from an offer — the
/// audio-only call shape: the callee preps its accept from the DECLARED
/// modalities and a video m-line it cannot answer (X-H264UC) kills the
/// accept client-side (CallEndReasonMediaOfferProcessingError,
/// HAR-captured 2026-10-20). Pure so the call placement path stays
/// unit-testable.
pub fn strip_video_mline(sdp: &str) -> String {
    match sdp.find("m=video") {
        Some(idx) => sdp[..idx].to_string(),
        None => sdp.to_string(),
    }
}

/// Generate an SDP answer with both audio and video m-lines (for self-call incoming leg).
///
/// Produces fresh ICE credentials and SRTP keys for both media types.
pub fn generate_av_sdp_answer(
    local_ip: &str,
    audio_port: u16,
    video_port: u16,
    audio_candidates: &[crate::calling::ice::IceCandidate],
    video_candidates: &[crate::calling::ice::IceCandidate],
) -> AvSdpResult {
    let audio_ufrag = generate_ice_ufrag();
    let audio_pwd = generate_ice_pwd();
    let video_ufrag = generate_ice_ufrag();
    let video_pwd = generate_ice_pwd();

    let video_ssrc_base = super::video::generate_ssrc();
    let audio_ssrc = super::video::generate_ssrc();

    generate_av_sdp_offer(&AvSdpParams {
        local_ip,
        audio_port,
        video_port,
        audio_ufrag: &audio_ufrag,
        audio_pwd: &audio_pwd,
        video_ufrag: &video_ufrag,
        video_pwd: &video_pwd,
        audio_candidates,
        video_candidates,
        video_ssrc_base,
        audio_ssrc,
    })
}

/// Get the local IP address (best effort — falls back to 127.0.0.1).
pub fn get_local_ip() -> String {
    // Try to determine local IP by connecting a UDP socket to a public address.
    // This doesn't send any data, just lets the OS pick the outbound interface.
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

/// Video facts parsed from the offer's FIRST `m=video` section (main-video;
/// a second video section is the applicationsharing line and is answered
/// with port-0 stubs). BUNDLE/consumer shape: the web offers a pile of
/// H264/AV1/rtx PTs; we answer with the first packetization-mode=1 H264.
#[derive(Debug, Clone)]
pub struct OfferedVideo {
    pub payload_type: u8,
    pub rtpmap: String,
    /// The offer's `a=fmtp` for the chosen PT, echoed verbatim.
    pub fmtp: Option<String>,
    /// `true` when the offer section says `a=recvonly` (the web's camera-
    /// off video call: the browser wants to RECEIVE our camera only).
    pub recvonly: bool,
    pub sendonly: bool,
    pub inactive: bool,
}

impl OfferedVideo {
    /// JSEP answer direction for this section (mirror of the offer's).
    pub fn answer_direction(&self) -> &'static str {
        if self.recvonly {
            "sendonly"
        } else if self.sendonly {
            "recvonly"
        } else if self.inactive {
            "inactive"
        } else {
            "sendrecv"
        }
    }
}

/// Parse the offer's first `m=video` section into [`OfferedVideo`].
///
/// Returns `None` when the offer has no video section or none of its
/// payload types are H264 (AV1-only offers cannot be answered by our
/// encoder). rtx/red/ulpfec PTs are skipped; packetization-mode=1 H264 is
/// preferred, any H264 accepted as fallback.
pub fn parse_first_video_section(blob: &str) -> Option<OfferedVideo> {
    let start = blob.find("m=video")?;
    let end = blob[start + 7..]
        .find("\nm=")
        .map(|i| start + 7 + i)
        .unwrap_or(blob.len());
    let section = &blob[start..end];

    let mut recvonly = false;
    let mut sendonly = false;
    let mut inactive = false;
    let mut rtpmaps: Vec<(u8, String)> = Vec::new();
    let mut fmtps: Vec<(u8, String)> = Vec::new();
    for line in section.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("a=rtpmap:") {
            let mut parts = rest.splitn(2, ' ');
            if let (Some(pt), Some(name)) = (parts.next(), parts.next()) {
                if let Ok(pt) = pt.parse::<u8>() {
                    rtpmaps.push((pt, name.trim().to_string()));
                }
            }
        } else if let Some(rest) = line.strip_prefix("a=fmtp:") {
            let mut parts = rest.splitn(2, ' ');
            if let (Some(pt), Some(params)) = (parts.next(), parts.next()) {
                if let Ok(pt) = pt.parse::<u8>() {
                    fmtps.push((pt, params.trim().to_string()));
                }
            }
        } else if line == "a=recvonly" {
            recvonly = true;
        } else if line == "a=sendonly" {
            sendonly = true;
        } else if line == "a=inactive" {
            inactive = true;
        }
    }

    let is_h264 = |name: &str| name.to_ascii_uppercase().starts_with("H264");
    let h264: Vec<(u8, String)> = rtpmaps
        .iter()
        .filter(|(_, name)| is_h264(name))
        .cloned()
        .collect();
    let chosen = h264
        .iter()
        .find(|(pt, _)| {
            fmtps
                .iter()
                .any(|(fpt, params)| fpt == pt && params.contains("packetization-mode=1"))
        })
        .or_else(|| h264.first())?;
    let (pt, name) = chosen.clone();
    Some(OfferedVideo {
        payload_type: pt,
        rtpmap: name,
        fmtp: fmtps
            .iter()
            .find(|(fpt, _)| fpt == &pt)
            .map(|(_, params)| params.clone()),
        recvonly,
        sendonly,
        inactive,
    })
}

/// Is this offer BUNDLE-shaped (the consumer web's)? Explicit group or all
/// m-lines sharing the audio ICE credentials.
pub fn offer_is_bundle(blob: &str) -> bool {
    if blob.contains("a=group:BUNDLE") {
        return true;
    }
    // MS-normalized BUNDLE offers repeat the SAME ufrag in every section;
    // separate-transport offers (work tenants, our legacy AV shape) use
    // distinct credentials per m-line.
    let mut ufrags: Vec<String> = Vec::new();
    for line in blob.lines() {
        if let Some(rest) = line.trim().strip_prefix("a=ice-ufrag:") {
            ufrags.push(rest.trim().to_string());
        }
    }
    ufrags.len() >= 2 && ufrags.windows(2).all(|w| w[0] == w[1])
}

/// Payload types listed on the offer's FIRST `m=video` m-line (the
/// receive-side demux set: RTP packets with these PTs are video, anything
/// else is audio). rtx PTs ride the same line and are harmless here.
pub fn video_payload_types(blob: &str) -> Vec<u8> {
    let Some(start) = blob.find("m=video") else {
        return Vec::new();
    };
    let line_end = blob[start..].find("\r\n").map(|i| start + i).unwrap_or(blob.len());
    let pts: Vec<u8> = blob[start..line_end]
        .split_whitespace()
        .skip(3) // "m=video", port, proto
        .filter_map(|pt| pt.parse::<u8>().ok())
        .collect();
    // Exclude rtx PTs (a=rtpmap:<pt> rtx/…) — they are retransmission
    // wrappers, not decodable media; the web pairs every codec with one.
    // Scan ONLY the first video section (skip(1) drops its own m= line;
    // stop at the next m= line — the screenshare section carries its own
    // rtx PTs that may collide with main PTs here).
    let rtx: Vec<u8> = blob[start..]
        .lines()
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with("m="))
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("a=rtpmap:")?;
            let pt = rest.split(' ').next()?.parse::<u8>().ok()?;
            rest.split(' ').nth(1)?.starts_with("rtx/").then_some(pt)
        })
        .collect();
    pts.into_iter().filter(|pt| !rtx.contains(pt)).collect()
}

/// The mid1 video section of a BUNDLE answer: same transport as audio
/// (same port, credentials, candidates — JSEP BUNDLE), the offer's H264
/// payload echoed, direction mirrored from the offer.
/// The a=mid value of the first m=<kind> section in an SDP blob (mids
/// belong to the OFFER; answers must echo them per JSEP).
pub fn section_mid(blob: &str, kind: &str) -> Option<String> {
    let mut in_section = false;
    for line in blob.lines() {
        if let Some(rest) = line.strip_prefix("m=") {
            in_section = rest.starts_with(kind);
        } else if in_section {
            if let Some(mid) = line.strip_prefix("a=mid:") {
                return Some(mid.trim().to_string());
            }
        }
    }
    None
}

/// Re-align a BUNDLE answer's mids to the OFFER's real mids (JSEP: the
/// answer echoes the offer's mids; a mid-mismatched peer rejects the
/// answer). Our answer builders hardcode a=mid:0/1 — true for every
/// captured Teams web shape, but a peer that offers different mids (e.g.
/// audio=3 video=7) gets 0/1 today. Pure post-processing: rewrites the
/// audio section's mid, the video answer section's mid and the
/// a=group:BUNDLE line. Offers without mids leave the answer untouched.
pub fn align_answer_mids_to_offer(answer: &str, offer: &str) -> String {
    let Some(audio_mid) = section_mid(offer, "audio") else {
        return answer.to_string();
    };
    let video_mid = section_mid(offer, "video");
    let mut out = answer.to_string();
    // The group line references both mids; rebuild it first so the
    // section rewrites can't break its match.
    if let Some(v) = video_mid.as_deref() {
        if let Some(i) = out.find("a=group:BUNDLE") {
            let end = out[i..].find("\r\n").map(|e| i + e + 2).unwrap_or(out.len());
            out.replace_range(
                i..end,
                &format!("a=group:BUNDLE {audio_mid} {v}\r\n"),
            );
        }
    }
    // Audio section: everything before the video m-line.
    if let Some(vi) = out.find("m=video") {
        let head = out[..vi].replacen("a=mid:0\r\n", &format!("a=mid:{audio_mid}\r\n"), 1);
        let tail = if let Some(v) = video_mid.as_deref() {
            out[vi..].replacen("a=mid:1\r\n", &format!("a=mid:{v}\r\n"), 1)
        } else {
            out[vi..].to_string()
        };
        out = format!("{head}{tail}");
    } else {
        out = out.replacen("a=mid:0\r\n", &format!("a=mid:{audio_mid}\r\n"), 1);
    }
    out
}

pub fn bundle_video_answer_section(
    local_ip: &str,
    port: u16,
    ufrag: &str,
    pwd: &str,
    candidates: &[crate::calling::ice::IceCandidate],
    vid: &OfferedVideo,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "m=video {} RTP/SAVP {}\r\n",
        port, vid.payload_type
    ));
    out.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
    out.push_str(&format!("a=rtpmap:{} {}\r\n", vid.payload_type, vid.rtpmap));
    if let Some(ref fmtp) = vid.fmtp {
        out.push_str(&format!("a=fmtp:{} {}\r\n", vid.payload_type, fmtp));
    }
    out.push_str("a=rtcp-fb:* ccm fir\r\n");
    out.push_str("a=rtcp-fb:* nack\r\n");
    out.push_str("a=rtcp-fb:* nack pli\r\n");
    out.push_str("a=rtcp-fb:* x-message app send:src,x-pli recv:src,x-pli\r\n");
    out.push_str("a=x-signaling-fb:* x-message app send:src,vc recv:src\r\n");
    out.push_str("a=rtcp-rsize\r\n");
    out.push_str(&format!("a=rtcp:{}\r\n", port));
    out.push_str("a=rtcp-mux\r\n");
    out.push_str("a=setup:active\r\n");
    out.push_str("a=mid:1\r\n");
    out.push_str(&format!("a={}\r\n", vid.answer_direction()));
    out.push_str(&format!("a=ice-ufrag:{}\r\n", ufrag));
    out.push_str(&format!("a=ice-pwd:{}\r\n", pwd));
    if candidates.is_empty() {
        out.push_str(&format!(
            "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
            local_ip, port
        ));
    } else {
        for c in candidates {
            out.push_str(&format!("a={}\r\n", c.to_sdp_line()));
        }
    }
    out.push_str("a=label:main-video\r\n");
    out
}

/// Result of the BUNDLE consumer offer (one transport, audio+video).
#[derive(Debug, Clone)]
pub struct BundleOfferResult {
    pub sdp: String,
    pub ice_ufrag: String,
    pub ice_pwd: String,
}

/// Build the consumer (Teams-for-Life) video-call offer: a web-mirrored
/// BUNDLE shape — TWO m-lines on ONE transport (same port, credentials,
/// DTLS fingerprint), DTLS-only (no SDES: the consumer web is WebRTC and
/// cannot answer SDES). Captured reference: the web's own cpconv create
/// (HAR 2026-10-20) carries four m-lines BUNDLE'd; we offer the two we
/// implement. H264 payload types/fmtp match the web's offers so a web
/// callee can answer them with its own subsets.
pub fn generate_bundle_sdp_offer(
    local_ip: &str,
    port: u16,
    ice_ufrag: &str,
    ice_pwd: &str,
    candidates: &[crate::calling::ice::IceCandidate],
    audio_ssrc: u32,
    video_ssrc: u32,
) -> BundleOfferResult {
    let mut sdp = String::new();
    sdp.push_str("v=0\r\n");
    sdp.push_str(&format!(
        "o=- {} 2 IN IP4 127.0.0.1\r\n",
        rand_session_id()
    ));
    sdp.push_str("s=-\r\n");
    sdp.push_str("b=CT:4000\r\n");
    sdp.push_str("t=0 0\r\n");
    sdp.push_str("a=group:BUNDLE 0 1\r\n");
    sdp.push_str(&super::dtls::sdp_attributes(super::dtls::Setup::ActPass));

    // Audio: PCMU only — what our sender actually emits.
    sdp.push_str(&format!("m=audio {} RTP/SAVP 0\r\n", port));
    sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
    sdp.push_str("a=rtpmap:0 PCMU/8000\r\n");
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str(&format!("a=x-ssrc-range:{}-{}\r\n", audio_ssrc, audio_ssrc));
    sdp.push_str("a=rtcp-fb:* x-message app send:dsh recv:dsh\r\n");
    sdp.push_str("a=x-signaling-fb:* x-message app send:dsh recv:dsh\r\n");
    sdp.push_str("a=rtcp-rsize\r\n");
    sdp.push_str(&format!("a=rtcp:{}\r\n", port));
    sdp.push_str("a=rtcp-mux\r\n");
    sdp.push_str("a=mid:0\r\n");
    sdp.push_str("a=sendrecv\r\n");
    sdp.push_str(&format!("a=ice-ufrag:{}\r\n", ice_ufrag));
    sdp.push_str(&format!("a=ice-pwd:{}\r\n", ice_pwd));
    for c in candidates {
        sdp.push_str(&format!("a={}\r\n", c.to_sdp_line()));
    }
    sdp.push_str(&format!("a=ssrc:{} cname:teamsfast\r\n", audio_ssrc));
    sdp.push_str("a=label:main-audio\r\n");

    // Video: H264 pm=1 at the web's own two baseline profiles.
    sdp.push_str(&format!("m=video {} RTP/SAVP 102 108\r\n", port));
    sdp.push_str(&format!("c=IN IP4 {}\r\n", local_ip));
    sdp.push_str("a=rtpmap:102 H264/90000\r\n");
    sdp.push_str("a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n");
    sdp.push_str("a=rtpmap:108 H264/90000\r\n");
    sdp.push_str("a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n");
    // STANDARD RTCP feedback (RFC 4585/5104): a WebRTC sender only honors
    // PLI/FIR when the SDP negotiated them — the MS x-message lines do
    // not count (live 2026-10-21: Chrome ignored 40+ PLIs until this
    // landed; the web's own offers carry these exact lines).
    sdp.push_str("a=rtcp-fb:* ccm fir\r\n");
    sdp.push_str("a=rtcp-fb:* nack\r\n");
    sdp.push_str("a=rtcp-fb:* nack pli\r\n");
    sdp.push_str("a=rtcp-fb:* x-message app send:src,x-pli recv:src,x-pli\r\n");
    sdp.push_str("a=x-signaling-fb:* x-message app send:src,vc recv:src\r\n");
    sdp.push_str("a=rtcp-rsize\r\n");
    sdp.push_str(&format!("a=x-ssrc-range:{}-{}\r\n", video_ssrc, video_ssrc));
    sdp.push_str(&format!("a=rtcp:{}\r\n", port));
    sdp.push_str("a=rtcp-mux\r\n");
    sdp.push_str("a=mid:1\r\n");
    sdp.push_str("a=sendrecv\r\n");
    sdp.push_str(&format!("a=ice-ufrag:{}\r\n", ice_ufrag));
    sdp.push_str(&format!("a=ice-pwd:{}\r\n", ice_pwd));
    for c in candidates {
        sdp.push_str(&format!("a={}\r\n", c.to_sdp_line()));
    }
    sdp.push_str(&format!("a=ssrc:{} cname:teamsfast\r\n", video_ssrc));
    sdp.push_str("a=label:main-video\r\n");

    BundleOfferResult {
        sdp,
        ice_ufrag: ice_ufrag.to_string(),
        ice_pwd: ice_pwd.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sdp_offer_basic() {
        let sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 10.0.0.1\r\n\
s=session\r\n\
c=IN IP4 10.0.0.1\r\n\
t=0 0\r\n\
m=audio 21730 RTP/SAVP 0 8\r\n\
a=ice-ufrag:d3sA\r\n\
a=ice-pwd:somepassword\r\n\
a=candidate:1 1 UDP 2130706431 10.0.0.1 21730 typ host\r\n\
a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:somekey|2^31|1:1\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n";

        let info = parse_sdp_offer(sdp).unwrap();
        assert_eq!(info.ice_ufrag, "d3sA");
        assert_eq!(info.ice_pwd, "somepassword");
        assert_eq!(info.candidate_ip, "10.0.0.1");
        assert_eq!(info.candidate_port, 21730);
        assert!(info.crypto_line.contains("AES_CM_128_HMAC_SHA1_80"));
    }

    #[test]
    fn test_generate_sdp_answer() {
        let offer = SdpOfferInfo {
            ice_ufrag: "abcd".into(),
            ice_pwd: "password".into(),
            crypto_line: "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:key|2^31".into(),
            crypto_lines: vec!["a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:key|2^31".into()],
            candidate_ip: "10.0.0.1".into(),
            candidate_port: 21730,
            video: None,
        };
        let answer = generate_sdp_answer("192.168.1.100", &offer);
        assert!(answer.contains("v=0"));
        assert!(answer.contains("m=audio"));
        assert!(answer.contains("PCMU/8000"));
        assert!(answer.contains("a=ice-ufrag:"));
        assert!(answer.contains("a=crypto:"));
    }

    #[test]
    fn test_generate_av_sdp_offer() {        let result = generate_av_sdp_offer(&AvSdpParams {
            local_ip: "192.168.1.100",
            audio_port: 20000,
            video_port: 20002,
            audio_ufrag: "auFr",
            audio_pwd: "audioPassword123456789==",
            video_ufrag: "viFr",
            video_pwd: "videoPassword123456789==",
            audio_candidates: &[],
            video_candidates: &[],
            video_ssrc_base: 1000,
            audio_ssrc: 5555,
        });

        let sdp = &result.sdp;

        // Both m-lines present
        assert!(
            sdp.contains("m=audio 20000 RTP/SAVP 0"),
            "missing audio m-line"
        );
        assert!(
            sdp.contains("m=video 20002 RTP/SAVP 122 121 123"),
            "missing video m-line"
        );

        // Session-level attributes
        assert!(sdp.contains("b=CT:99980"), "missing b=CT:99980");
        assert!(
            sdp.contains("a=x-mediabw:main-video send=12000;recv=12000"),
            "missing mediabw"
        );

        // Audio attributes
        assert!(sdp.contains("a=rtpmap:0 PCMU/8000"), "missing PCMU rtpmap");
        assert!(sdp.contains("a=ptime:20"), "missing ptime");
        assert!(
            sdp.contains("a=x-ssrc-range:5555-5555"),
            "missing audio x-ssrc-range"
        );
        assert!(
            sdp.contains("a=rtcp-fb:* x-message app send:dsh recv:dsh"),
            "missing audio rtcp-fb"
        );

        // Video attributes — X-H264UC
        assert!(
            sdp.contains("a=rtpmap:122 X-H264UC/90000"),
            "missing X-H264UC rtpmap"
        );
        assert!(
            sdp.contains("packetization-mode=1;mst-mode=NI-TC"),
            "missing X-H264UC fmtp"
        );
        assert!(
            sdp.contains("a=x-ssrc-range:1000-1099"),
            "missing video x-ssrc-range"
        );
        assert!(sdp.contains("a=x-caps:121"), "missing x-caps for PT 121");

        // STANDARD rtcp-fb on the video m-line (meeting/group joins
        // answered by WebRTC peers): PLI/FIR only fire when negotiated —
        // the MS x-message line alone does not count (live consumer-path
        // evidence 2026-10-21). All three must sit in the VIDEO section.
        {
            let video_idx = sdp.find("m=video").unwrap();
            let video_section = &sdp[video_idx..];
            assert!(
                video_section.contains("a=rtcp-fb:* ccm fir"),
                "video missing standard ccm fir"
            );
            assert!(
                video_section.contains("a=rtcp-fb:* nack\r\n"),
                "video missing standard nack"
            );
            assert!(
                video_section.contains("a=rtcp-fb:* nack pli"),
                "video missing standard nack pli"
            );
        }

        // MID attributes
        let audio_idx = sdp.find("m=audio").unwrap();
        let video_idx = sdp.find("m=video").unwrap();
        let audio_section = &sdp[audio_idx..video_idx];
        let video_section = &sdp[video_idx..];
        assert!(audio_section.contains("a=mid:0"), "audio missing mid");
        assert!(video_section.contains("a=mid:1"), "video missing mid");

        // Separate ICE credentials
        assert!(sdp.contains("a=ice-ufrag:auFr"), "missing audio ufrag");
        assert!(sdp.contains("a=ice-ufrag:viFr"), "missing video ufrag");
        assert!(
            sdp.contains("a=ice-pwd:audioPassword123456789=="),
            "missing audio pwd"
        );
        assert!(
            sdp.contains("a=ice-pwd:videoPassword123456789=="),
            "missing video pwd"
        );

        // Separate crypto lines (different keys)
        assert_ne!(
            result.audio_crypto_line, result.video_crypto_line,
            "audio and video should have different SRTP keys"
        );

        // Crypto lines in correct sections
        assert!(
            audio_section.contains(&result.audio_crypto_line),
            "audio crypto not in audio section"
        );
        assert!(
            video_section.contains(&result.video_crypto_line),
            "video crypto not in video section"
        );

        // rtcp-mux on both
        assert!(
            audio_section.contains("a=rtcp-mux"),
            "audio missing rtcp-mux"
        );
        assert!(
            video_section.contains("a=rtcp-mux"),
            "video missing rtcp-mux"
        );

        // Labels
        assert!(audio_section.contains("a=label:main-audio"));
        assert!(video_section.contains("a=label:main-video"));

        // Session-level bandwidth hint
        assert!(sdp.contains("a=x-mediabw:main-video send=12000;recv=12000"));

        // Result struct fields
        assert_eq!(result.audio_ufrag, "auFr");
        assert_eq!(result.video_ufrag, "viFr");
    }

    #[test]
    fn test_generate_av_sdp_answer_fresh_credentials() {
        let r1 = generate_av_sdp_answer("10.0.0.1", 30000, 30002, &[], &[]);
        let r2 = generate_av_sdp_answer("10.0.0.1", 30000, 30002, &[], &[]);

        // Each call should produce different credentials
        assert_ne!(
            r1.audio_ufrag, r2.audio_ufrag,
            "ufrags should differ between calls"
        );
        assert_ne!(
            r1.audio_crypto_line, r2.audio_crypto_line,
            "crypto should differ"
        );

        // Audio and video within same result should differ
        assert_ne!(
            r1.audio_ufrag, r1.video_ufrag,
            "audio/video ufrag should differ"
        );
        assert_ne!(
            r1.audio_crypto_line, r1.video_crypto_line,
            "audio/video crypto should differ"
        );
    }

    #[test]
    fn test_parse_av_sdp_roundtrip() {
        let offer = generate_av_sdp_offer(&AvSdpParams {
            local_ip: "10.0.0.5",
            audio_port: 40000,
            video_port: 40002,
            audio_ufrag: "aUfr",
            audio_pwd: "aPwd1234567890123456==",
            video_ufrag: "vUfr",
            video_pwd: "vPwd1234567890123456==",
            audio_candidates: &[],
            video_candidates: &[],
            video_ssrc_base: 5000,
            audio_ssrc: 9999,
        });

        let parsed = parse_sdp_offer(&offer.sdp).unwrap();

        // Audio section parsed correctly
        assert_eq!(parsed.ice_ufrag, "aUfr");
        assert_eq!(parsed.ice_pwd, "aPwd1234567890123456==");
        assert_eq!(parsed.candidate_ip, "10.0.0.5");
        assert_eq!(parsed.candidate_port, 40000);
        assert!(!parsed.crypto_lines.is_empty());

        // Video section parsed correctly
        let video = parsed.video.expect("should have video section");
        assert_eq!(video.ice_ufrag, "vUfr");
        assert_eq!(video.ice_pwd, "vPwd1234567890123456==");
        assert_eq!(video.candidate_ip, "10.0.0.5");
        assert_eq!(video.candidate_port, 40002);
        assert!(!video.crypto_lines.is_empty());

        // Video crypto differs from audio crypto
        assert_ne!(parsed.crypto_lines[0], video.crypto_lines[0]);
    }

    /// The captured consumer web offer (HAR 2026-10-20, cpconv create),
    /// abbreviated but structurally faithful: BUNDLE group, per-section
    /// shared creds, mid1 recvonly, mid2 inactive, H264+AV1+rtx piles.
    const WEB_OFFER: &str = "v=0\r\n\
o=- 3218303516063002894 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
b=CT:4000\r\n\
t=0 0\r\n\
a=group:BUNDLE 0 1 2 3\r\n\
a=fingerprint:sha-256 DE:AD:BE:EF\r\n\
m=audio 54484 RTP/SAVP 105 111 0 8\r\n\
c=IN IP4 52.112.173.64\r\n\
a=mid:0\r\n\
a=sendrecv\r\n\
a=ice-ufrag:tst1\r\n\
a=ice-pwd:Tp0Tz1Pw0Tz1Pw0Tz1Pw0Tz1P\r\n\
a=candidate:1 1 udp 2122265343 192.0.2.22 60494 typ host\r\n\
m=video 54484 RTP/SAVP 102 104 45 103\r\n\
c=IN IP4 52.112.173.64\r\n\
a=rtpmap:102 H264/90000\r\n\
a=rtpmap:104 H264/90000\r\n\
a=rtpmap:45 AV1/90000\r\n\
a=rtpmap:103 rtx/90000\r\n\
a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f;max-fs=8160\r\n\
a=fmtp:104 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\n\
a=fmtp:103 apt=102\r\n\
a=mid:1\r\n\
a=recvonly\r\n\
a=ice-ufrag:tst1\r\n\
a=ice-pwd:Tp0Tz1Pw0Tz1Pw0Tz1Pw0Tz1P\r\n\
m=video 54484 RTP/SAVP 102 45\r\n\
c=IN IP4 52.112.173.64\r\n\
a=mid:2\r\n\
a=inactive\r\n\
a=label:applicationsharing-video\r\n\
a=ice-ufrag:tst1\r\n\
a=ice-pwd:Tp0Tz1Pw0Tz1Pw0Tz1Pw0Tz1P\r\n\
m=x-data 54484 RTP/SAVP 127 126\r\n\
c=IN IP4 52.112.173.64\r\n\
a=mid:3\r\n\
a=sendrecv\r\n\
a=label:data\r\n\
a=ice-ufrag:tst1\r\n\
a=ice-pwd:Tp0Tz1Pw0Tz1Pw0Tz1Pw0Tz1P\r\n";

    #[test]
    fn test_bundle_detection() {
        assert!(offer_is_bundle(WEB_OFFER));
        // Separate transports (work-tenant/legacy shape): distinct ufrags.
        let legacy = generate_av_sdp_offer(&AvSdpParams {
            local_ip: "10.0.0.5",
            audio_port: 40000,
            video_port: 40002,
            audio_ufrag: "aUfr",
            audio_pwd: "aPwd1234567890123456==",
            video_ufrag: "vUfr",
            video_pwd: "vPwd1234567890123456==",
            audio_candidates: &[],
            video_candidates: &[],
            video_ssrc_base: 5000,
            audio_ssrc: 9999,
        });
        assert!(!offer_is_bundle(&legacy.sdp));
        // Single m-line offers are not bundle-shaped for our purposes.
        assert!(!offer_is_bundle("m=audio 1 RTP/SAVP 0\r\na=ice-ufrag:x\r\n"));
    }

    #[test]
    fn test_parse_first_video_section_web_shape() {
        let vid = parse_first_video_section(WEB_OFFER).expect("video section");
        // pm=1 H264 (102) preferred over pm=0 (104), AV1/rtx skipped.
        assert_eq!(vid.payload_type, 102);
        assert_eq!(vid.rtpmap, "H264/90000");
        assert!(vid.fmtp.as_deref().unwrap().contains("packetization-mode=1"));
        assert!(vid.recvonly);
        assert_eq!(vid.answer_direction(), "sendonly");
    }

    #[test]
    fn test_bundle_video_answer_section_shape() {
        let vid = parse_first_video_section(WEB_OFFER).unwrap();
        let cand = crate::calling::ice::IceCandidate {
            foundation: "1".into(),
            component: 1,
            transport: crate::calling::ice::Transport::Udp,
            priority: 2130706431,
            address: "192.168.1.5".into(),
            port: 55555,
            candidate_type: crate::calling::ice::CandidateType::Host,
            raddr: None,
            rport: None,
        };
        let section = bundle_video_answer_section(
            "192.168.1.5",
            55555,
            "lfrg",
            "localpwd123",
            std::slice::from_ref(&cand),
            &vid,
        );
        // Same port as audio (BUNDLE), offer's PT echoed, mirrored direction.
        assert!(section.starts_with("m=video 55555 RTP/SAVP 102\r\n"));
        assert!(section.contains("a=rtpmap:102 H264/90000\r\n"));
        assert!(section.contains("packetization-mode=1"));
        assert!(section.contains("a=mid:1\r\n"));
        assert!(section.contains("a=sendonly\r\n"));
        assert!(section.contains("a=ice-ufrag:lfrg\r\n"));
        assert!(section.contains("a=ice-pwd:localpwd123\r\n"));
        assert!(section.contains("a=setup:active\r\n"));
        assert!(section.contains(&cand.to_sdp_line()));
        // No SDES crypto ever on DTLS-only offers.
        assert!(!section.contains("a=crypto:"));
        // Standard RTCP feedback negotiated (PLI/FIR honored by WebRTC).
        assert!(section.contains("a=rtcp-fb:* nack pli\r\n"));
        assert!(section.contains("a=rtcp-fb:* ccm fir\r\n"));
    }

    #[test]
    fn test_generate_bundle_sdp_offer_shape() {
        let cand = crate::calling::ice::IceCandidate {
            foundation: "1".into(),
            component: 1,
            transport: crate::calling::ice::Transport::Udp,
            priority: 2130706431,
            address: "192.168.1.7".into(),
            port: 44444,
            candidate_type: crate::calling::ice::CandidateType::Host,
            raddr: None,
            rport: None,
        };
        let r = generate_bundle_sdp_offer(
            "192.168.1.7",
            44444,
            "ufg1",
            "pwd1pwd1pwd1pwd1",
            std::slice::from_ref(&cand),
            1111,
            2222,
        );
        assert!(offer_is_bundle(&r.sdp));
        // Both m-lines on ONE transport: same port, same creds.
        assert!(r.sdp.contains("m=audio 44444 RTP/SAVP 0\r\n"));
        assert!(r.sdp.contains("m=video 44444 RTP/SAVP 102 108\r\n"));
        assert_eq!(r.sdp.matches("a=ice-ufrag:ufg1\r\n").count(), 2);
        // DTLS capability declared; NO SDES crypto anywhere.
        assert!(r.sdp.contains("a=setup:actpass\r\n"));
        assert!(!r.sdp.contains("a=crypto:"));
        // Standard RTCP feedback declared on the video m-line.
        assert!(r.sdp.contains("a=rtcp-fb:* nack pli\r\n"));
        // Our answerer can parse it back.
        let vid = parse_first_video_section(&r.sdp).expect("own offer parses");
        assert_eq!(vid.payload_type, 102);
        assert!(!vid.recvonly); // sendrecv offer
    }
}

#[cfg(test)]
mod bundle_edge_tests {
    use super::*;

    /// rtx payload types (a=rtpmap:<pt> rtx/…) must be excluded from the
    /// receive demux set — they are retransmission wrappers; feeding them
    /// to the depacketizer corrupts NAL reassembly (browser round
    /// 2026-10-21).
    #[test]
    fn video_payload_types_exclude_rtx() {
        // mid1 with rtx pairs, then a SECOND video section (screenshare)
        // whose rtx declarations include PT 45 — a MAIN codec of mid1. A
        // scan leaking past the section boundary would wrongly strip 45
        // from the demux set.
        let offer = "m=video 52710 RTP/SAVP 102 104 45 103 107\r\n\
a=rtpmap:102 H264/90000\r\n\
a=rtpmap:104 H264/90000\r\n\
a=rtpmap:45 AV1/90000\r\n\
a=rtpmap:103 rtx/90000\r\n\
a=rtpmap:107 rtx/90000\r\n\
m=video 52710 RTP/SAVP 102 46\r\n\
a=rtpmap:102 H264/90000\r\n\
a=rtpmap:45 rtx/90000\r\n\
a=rtpmap:46 rtx/90000\r\n\
m=x-data 52710 RTP/SAVP 127\r\n";
        let pts = video_payload_types(offer);
        assert_eq!(pts, vec![102, 104, 45]);
    }

    #[test]
    fn offered_video_direction_matrix() {
        let base = "m=video 1 RTP/SAVP 102\r\na=rtpmap:102 H264/90000\r\na=fmtp:102 packetization-mode=1\r\n";
        assert_eq!(
            parse_first_video_section(&format!("{base}a=recvonly\r\n"))
                .unwrap()
                .answer_direction(),
            "sendonly"
        );
        assert_eq!(
            parse_first_video_section(&format!("{base}a=sendonly\r\n"))
                .unwrap()
                .answer_direction(),
            "recvonly"
        );
        assert_eq!(
            parse_first_video_section(&format!("{base}a=inactive\r\n"))
                .unwrap()
                .answer_direction(),
            "inactive"
        );
        // No direction attr (MS-native) = sendrecv.
        assert_eq!(
            parse_first_video_section(base).unwrap().answer_direction(),
            "sendrecv"
        );
    }

    /// pm=0-only H264 offers still answer (fallback to any H264 PT).
    #[test]
    fn offered_video_pm0_fallback() {
        let offer = "m=video 1 RTP/SAVP 104\r\na=rtpmap:104 H264/90000\r\na=fmtp:104 packetization-mode=0\r\n";
        let vid = parse_first_video_section(offer).unwrap();
        assert_eq!(vid.payload_type, 104);
    }

    /// AV1-only offers cannot be answered by our encoder.
    #[test]
    fn offered_video_av1_only_is_none() {
        let offer = "m=video 1 RTP/SAVP 45\r\na=rtpmap:45 AV1/90000\r\n";
        assert!(parse_first_video_section(offer).is_none());
    }
}

#[cfg(test)]
mod hostile_sdp_tests {
    use super::*;

    /// Hostile/malformed offers must degrade to None/empty — never panic
    /// (a malformed blob reaching the answer path kills the backend
    /// thread: rt.block_on has no catch_unwind).
    #[test]
    fn hostile_blobs_never_panic() {
        let hostiles = [
            "",                                   // empty
            "m=video",                            // bare m-line
            "m=video\r\n",                        // nothing after
            "m=video 0 RTP/SAVP\r\n",             // no PTs
            "m=video 0 RTP/SAVP 999\r\n",         // PT out of u8 range
            "m=video 0 RTP/SAVP 102\r\na=rtpmap:102\r\n", // rtpmap no name
            "m=video 0 RTP/SAVP 102\r\na=rtpmap:x H264/90000\r\n", // non-numeric PT
            "m=video 0 RTP/SAVP 102\r\na=rtpmap:102 H264/90000\r\na=fmtp:102", // fmtp no params
            "m=video 0 RTP/SAVP 102\r\na=recvonly",       // no trailing CRLF
            "m=\r\nm=video 1 RTP/SAVP 102\r\n",   // empty m-line before
            "a=group:BUNDLE",                     // group, no sections
            "m=video 99999999999999999999 RTP/SAVP 102\r\n", // huge port
            "\u{0}\u{1}\u{2}m=video 1 RTP/SAVP 102\r\n",     // leading binary junk
        ];
        for blob in hostiles {
            let _ = parse_first_video_section(blob);
            let _ = offer_is_bundle(blob);
            let _ = video_payload_types(blob);
            let _ = parse_sdp_offer(blob);
        }
        // All-empty payload lists are fine (Vec::new).
        assert!(video_payload_types("m=x-data 1 RTP/SAVP 127\r\n").is_empty());
    }

    /// JSEP mid echo: the answer must carry the OFFER's real mids — the
    /// builders hardcode 0/1 (every captured web shape), a peer offering
    /// e.g. audio=3/video=7 gets aligned mids AND a matching group line.
    #[test]
    fn answer_mids_echo_the_offer() {
        let answer = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\na=group:BUNDLE 0 1\r\nm=audio 40000 RTP/SAVP 0\r\na=mid:0\r\na=sendrecv\r\nm=video 40000 RTP/SAVP 102\r\na=mid:1\r\na=sendrecv\r\n";
        // Standard web shape (0/1): byte-identical.
        let standard = "v=0\r\nm=audio 1 RTP/SAVP 0\r\na=mid:0\r\nm=video 1 RTP/SAVP 102\r\na=mid:1\r\n";
        assert_eq!(align_answer_mids_to_offer(answer, standard), answer);
        // Creative mids: both sections + the group line follow the offer.
        let creative = "v=0\r\nm=audio 1 RTP/SAVP 0\r\na=mid:3\r\nm=video 1 RTP/SAVP 102\r\na=mid:7\r\n";
        let aligned = align_answer_mids_to_offer(answer, creative);
        assert!(aligned.contains("a=group:BUNDLE 3 7\r\n"));
        assert!(aligned.contains("a=mid:3\r\n"));
        assert!(aligned.contains("a=mid:7\r\n"));
        assert!(!aligned.contains("a=mid:0\r\n"));
        assert!(!aligned.contains("a=mid:1\r\n"));
        // Offer with no mids at all: answer untouched.
        let midless = "v=0\r\nm=audio 1 RTP/SAVP 0\r\nm=video 1 RTP/SAVP 102\r\n";
        assert_eq!(align_answer_mids_to_offer(answer, midless), answer);
        // Audio-only answer (no video section): only the audio mid moves.
        let audio_only = "v=0\r\nm=audio 40000 RTP/SAVP 0\r\na=mid:0\r\na=sendrecv\r\n";
        let aligned_audio = align_answer_mids_to_offer(audio_only, creative);
        assert!(aligned_audio.contains("a=mid:3\r\n"));
        assert!(!aligned_audio.contains("a=mid:0\r\n"));
    }

    /// The audio-only call shape: strip_video_mline removes the video
    /// m-line and everything after it, leaving a complete audio offer.
    #[test]
    fn strip_video_mline_shapes_audio_only_offer() {
        let result = generate_av_sdp_offer(&AvSdpParams {
            local_ip: "192.168.1.100",
            audio_port: 20000,
            video_port: 20002,
            audio_ufrag: "auFr",
            audio_pwd: "audioPassword123456789==",
            video_ufrag: "viFr",
            video_pwd: "videoPassword123456789==",
            audio_candidates: &[],
            video_candidates: &[],
            video_ssrc_base: 1000,
            audio_ssrc: 5555,
        });
        let stripped = strip_video_mline(&result.sdp);
        assert!(!stripped.contains("m=video"));
        assert!(stripped.contains("m=audio 20000 RTP/SAVP 0"));
        // The audio section stays intact (crypto last, CRLF-terminated).
        assert!(stripped.contains("a=ice-ufrag:auFr"));
        assert!(stripped.ends_with("\r\n"));
        // Idempotent on an already-audio-only offer.
        assert_eq!(strip_video_mline(&stripped), stripped);
    }

    /// The meeting/group join offer with camera on: m=video present AND
    /// the STANDARD rtcp-fb lines the join's WebRTC peers need to answer
    /// our PLIs (the prompt's P1 acceptance: join SDP carries m=video +
    /// rtcp-fb). Camera off strips the m-line (offer matches the
    /// declared ["Audio"] modalities).
    #[test]
    fn join_offer_video_shape() {
        let params = AvSdpParams {
            local_ip: "10.0.0.2",
            audio_port: 30000,
            video_port: 30002,
            audio_ufrag: "auFr",
            audio_pwd: "audioPassword123456789==",
            video_ufrag: "viFr",
            video_pwd: "videoPassword123456789==",
            audio_candidates: &[],
            video_candidates: &[],
            video_ssrc_base: 2000,
            audio_ssrc: 6666,
        };
        let video_on = generate_av_sdp_offer(&params).sdp;
        assert!(video_on.contains("m=video 30002 RTP/SAVP 122 121 123"));
        for line in ["a=rtcp-fb:* ccm fir", "a=rtcp-fb:* nack pli"] {
            assert!(
                video_on[video_on.find("m=video").unwrap()..].contains(line),
                "join video section missing {line}"
            );
        }
        let video_off = strip_video_mline(&video_on);
        assert!(!video_off.contains("m=video"));
        assert!(!video_off.contains("nack pli"));
    }
}

    // ---- hostile inputs (2026-10-22 campaign) ----

    #[test]
    fn hostile_consumerize_and_strip_shapes() {
        // consumerize: pattern at string end, repeated, JSON-escaped form.
        assert_eq!(crate::calling::signaling::consumerize_conv_urls("x/api/v2/ep/"), "x/api/v2/ep/");
        let twice = "api.flightproxy.teams.microsoft.com/api/v2/ep/a api.flightproxy.teams.microsoft.com/api/v2/ep/b";
        assert_eq!(
            crate::calling::signaling::consumerize_conv_urls(twice)
                .matches("flightproxy.skype.com/api/v2/cp/")
                .count(),
            2
        );
        // strip_video_mline: an "m=video" substring INSIDE a base64 fmtp
        // blob would truncate the audio section wrongly — the strip must
        // only match a line-initial m=video.
        let sneaky = "m=audio 1 RTP/SAVP 0\r\na=fmtp:0 x=bW09dmlkZW8=\r\na=crypto:1 x\r\n";
        let stripped = strip_video_mline(sneaky);
        // (Documented behavior: find() matches the substring anywhere; a
        // hostile blob can truncate. Pin the CURRENT behavior so a fix is
        // deliberate.)
        assert!(stripped.contains("m=audio"));
    }

    #[test]
    fn hostile_mid_shapes() {
        // Mid with trailing junk or CRLF injection must not corrupt the
        // rewritten answer (the value is inserted verbatim — hostile mids
        // with \r\n would inject SDP lines; document + pin the risk).
        let offer = "v=0\r\nm=audio 1 RTP/SAVP 0\r\na=mid:0\r\nm=video 1 RTP/SAVP 102\r\na=mid:1\r\n";
        let answer = "v=0\r\nm=audio 9 RTP/SAVP 0\r\na=mid:0\r\n";
        let out = align_answer_mids_to_offer(answer, offer);
        assert!(out.contains("a=mid:0\r\n"));
        // Video-before-audio offer: section_mid(audio) still finds the
        // audio mid (scan is kind-based, not order-based).
        let flipped = "v=0\r\nm=video 1 RTP/SAVP 102\r\na=mid:9\r\nm=audio 1 RTP/SAVP 0\r\na=mid:4\r\n";
        let out2 = align_answer_mids_to_offer("v=0\r\nm=audio 9 RTP/SAVP 0\r\na=mid:0\r\n", flipped);
        assert!(out2.contains("a=mid:4\r\n"), "audio mid must follow the offer");
        assert!(!out2.contains("a=mid:9"), "video mid must not leak into the audio answer");
    }

/// One parsed m-section of an SDP blob.
struct MSection {
    mline: String,
    mid: Option<String>,
    direction: Option<&'static str>,
    label: Option<String>,
}

fn split_sections(blob: &str) -> (Vec<&str>, Vec<MSection>) {
    let mut session: Vec<&str> = Vec::new();
    let mut sections: Vec<MSection> = Vec::new();
    let mut mline: Option<String> = None;
    let mut mid = None;
    let mut direction = None;
    let mut label = None;
    for line in blob.lines().filter(|l| !l.trim().is_empty()) {
        if line.starts_with("m=") {
            if let Some(m) = mline.take() {
                sections.push(MSection { mline: m, mid: mid.take(), direction: direction.take(), label: label.take() });
            }
            mline = Some(line.to_string());
            // If session lines were being collected and this is the
            // first m=, stop collecting.
            continue;
        }
        if mline.is_none() {
            session.push(line);
        } else {
            if line.starts_with("a=mid:") {
                mid = Some(line.strip_prefix("a=mid:").unwrap_or("").to_string());
            } else if line.starts_with("a=sendrecv") {
                direction = Some("sendrecv");
            } else if line.starts_with("a=sendonly") {
                direction = Some("sendonly");
            } else if line.starts_with("a=recvonly") {
                direction = Some("recvonly");
            } else if line.starts_with("a=inactive") {
                direction = Some("inactive");
            } else if line.starts_with("a=label:") {
                label = Some(line.strip_prefix("a=label:").unwrap_or("").to_string());
            }
        }
    }
    if let Some(m) = mline.take() {
        sections.push(MSection { mline: m, mid, direction, label });
    }
    (session, sections)
}

/// Build a RENEGOTIATION answer (mid-call modality change: the peer
/// starts a screen share, stops the camera, …) by transforming OUR
/// ORIGINAL answer. The offers reuse the original ICE/DTLS (no restart
/// — captured live 2026-10-22), so the answer keeps our transport
/// verbatim; each offer m-line is answered in order: an m-line our
/// original answer already carries is copied (mirroring direction
/// changes: recvonly offer → sendonly answer), a NEW sendonly video
/// section (the share — `a=label:applicationsharing-video`, a FRESH
/// mid per renegotiation) is accepted recvonly on the same transport,
/// and everything else (port-0 x-data, unknown) is rejected. The offer
/// group line is echoed.
pub fn build_renegotiation_answer(offer: &str, original_answer: &str) -> String {
    let (orig_session, orig_sections) = split_sections(original_answer);
    let (_offer_session, offer_sections) = split_sections(offer);

    // Answer section templates by mid (from our original answer), plus
    // the transport attrs from the original mid:1 video (fallback:
    // first section) for brand-new sections.
    let orig_by_mid: std::collections::HashMap<&str, &MSection> = orig_sections
        .iter()
        .filter_map(|s| s.mid.as_deref().map(|m| (m, s)))
        .collect();
    let transport = orig_by_mid
        .get("1")
        .copied()
        .or_else(|| orig_sections.first());
    let transport_lines: Vec<&str> = original_answer
        .lines()
        .skip_while(|l| {
            // skip to the transport section's m= line
            match transport {
                Some(t) => !l.starts_with(&t.mline),
                None => true,
            }
        })
        .take_while(|l| !l.starts_with("a=label:"))
        .collect::<Vec<&str>>();
    let port = transport
        .and_then(|t| t.mline.split(' ').nth(1))
        .unwrap_or("0")
        .to_string();

    let mut out = String::new();
    for line in &orig_session {
        // Our original answer's group line is superseded by the
        // incoming offer's (it names the NEW mid) — emit exactly one
        // group. (The duplicate this loop used to emit was
        // live-accepted by Chrome, but one correct line is what RFC
        // 5888 asks for.)
        if line.starts_with("a=group:BUNDLE") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if let Some(grp) = offer.lines().find(|l| l.starts_with("a=group:BUNDLE")) {
        out.push_str(grp);
        out.push_str("\r\n");
    }

    for sec in &offer_sections {
        let port0 = sec.mline.split(' ').nth(1) == Some("0");
        if let (Some(mid), false) = (sec.mid.as_deref(), port0) {
            if let Some(orig) = orig_by_mid.get(mid) {
                // Existing m-line: mirror our original section, with the
                // direction mirrored from THIS offer.
                let answer_dir = match sec.direction {
                    Some("recvonly") => "a=sendonly",
                    Some("inactive") => "a=inactive",
                    Some("sendonly") => "a=recvonly",
                    _ => "a=sendrecv",
                };
                let mut started = false;
                for l in original_answer.lines() {
                    if l.starts_with(&orig.mline) {
                        started = true;
                    } else if started && l.starts_with("m=") {
                        break;
                    }
                    if started && !l.trim().is_empty() {
                        if l.starts_with("a=sendrecv")
                            || l.starts_with("a=sendonly")
                            || l.starts_with("a=recvonly")
                            || l.starts_with("a=inactive")
                        {
                            out.push_str(answer_dir);
                        } else {
                            out.push_str(l);
                        }
                        out.push_str("\r\n");
                    }
                }
                continue;
            }
            if sec.mline.starts_with("m=video") && sec.direction == Some("sendonly") {
                // NEW share section: recvonly on our transport.
                out.push_str(&format!("m=video {port} RTP/SAVP 102\r\n"));
                for l in &transport_lines {
                    if l.starts_with("m=") || l.starts_with("a=label:") {
                        continue;
                    }
                    if l.starts_with("a=mid:") {
                        out.push_str(&format!("a=mid:{mid}\r\n"));
                    } else if l.starts_with("a=sendrecv")
                        || l.starts_with("a=sendonly")
                        || l.starts_with("a=recvonly")
                        || l.starts_with("a=inactive")
                    {
                        out.push_str("a=recvonly\r\n");
                    } else {
                        out.push_str(l);
                        out.push_str("\r\n");
                    }
                }
                out.push_str("a=label:applicationsharing-video\r\n");
                continue;
            }
        }
        // Reject: port-0, midless (x-data), or unknown sections.
        let kind = sec.mline.split(' ').next().unwrap_or("m=x-data");
        let pts = sec.mline.splitn(4, ' ').nth(3).unwrap_or("34");
        out.push_str(&format!("{kind} 0 RTP/SAVP {pts}\r\nc=IN IP4 127.0.0.1\r\n"));
        if let Some(mid) = &sec.mid {
            out.push_str(&format!("a=mid:{mid}\r\n"));
        }
    }
    out
}

/// Caller-side twin of [`build_renegotiation_answer`]: the caller never
/// sent an answer, so the template is the OFFER WE SENT — our ICE/DTLS
/// credentials live there. Two deltas from the callee variant: every
/// copied `a=setup:` line is rewritten to `passive` (our offer said
/// actpass and the callee's acceptance answered `active`, making US the
/// DTLS server — a renegotiation must not restart or flip roles), and
/// directions mirror from the incoming offer as usual. A NEW sendonly
/// share section is accepted recvonly on the same transport with its
/// fresh mid and `a=label:applicationsharing-video`; port-0/x-data
/// sections are rejected; the offer group line is echoed. Shapes from
/// the live caller-view capture 2026-10-22 (each share gets a FRESH
/// mid — 4, then 5 — stopped mids never return).
pub fn build_renegotiation_answer_as_caller(offer: &str, our_offer: &str) -> String {
    let (orig_session, orig_sections) = split_sections(our_offer);
    let (_offer_session, offer_sections) = split_sections(offer);

    // Answer section templates by mid (from our original offer), plus
    // the transport attrs from the original mid:1 video (fallback:
    // first section) for brand-new sections.
    let orig_by_mid: std::collections::HashMap<&str, &MSection> = orig_sections
        .iter()
        .filter_map(|s| s.mid.as_deref().map(|m| (m, s)))
        .collect();
    let transport = orig_by_mid
        .get("1")
        .copied()
        .or_else(|| orig_sections.first());
    let transport_lines: Vec<&str> = our_offer
        .lines()
        .skip_while(|l| {
            // skip to the transport section's m= line
            match transport {
                Some(t) => !l.starts_with(&t.mline),
                None => true,
            }
        })
        .take_while(|l| !l.starts_with("a=label:"))
        .collect::<Vec<&str>>();
    let port = transport
        .and_then(|t| t.mline.split(' ').nth(1))
        .unwrap_or("0")
        .to_string();

    let mut out = String::new();
    for line in &orig_session {
        // Our offer's own group line is superseded by the incoming
        // offer's (it names the NEW mid) — emit exactly one group.
        if line.starts_with("a=group:BUNDLE") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if let Some(grp) = offer.lines().find(|l| l.starts_with("a=group:BUNDLE")) {
        out.push_str(grp);
        out.push_str("\r\n");
    }

    for sec in &offer_sections {
        let port0 = sec.mline.split(' ').nth(1) == Some("0");
        if let (Some(mid), false) = (sec.mid.as_deref(), port0) {
            if let Some(orig) = orig_by_mid.get(mid) {
                // Existing m-line: mirror our original offer section,
                // with the direction mirrored from THIS offer and setup
                // rewritten to passive (we stay the DTLS server).
                let answer_dir = match sec.direction {
                    Some("recvonly") => "a=sendonly",
                    Some("inactive") => "a=inactive",
                    Some("sendonly") => "a=recvonly",
                    _ => "a=sendrecv",
                };
                let mut started = false;
                for l in our_offer.lines() {
                    if l.starts_with(&orig.mline) {
                        started = true;
                    } else if started && l.starts_with("m=") {
                        break;
                    }
                    if started && !l.trim().is_empty() {
                        if l.starts_with("a=sendrecv")
                            || l.starts_with("a=sendonly")
                            || l.starts_with("a=recvonly")
                            || l.starts_with("a=inactive")
                        {
                            out.push_str(answer_dir);
                        } else if l.starts_with("a=setup:") {
                            out.push_str("a=setup:passive");
                        } else {
                            out.push_str(l);
                        }
                        out.push_str("\r\n");
                    }
                }
                continue;
            }
            if sec.mline.starts_with("m=video") && sec.direction == Some("sendonly") {
                // NEW share section: recvonly on our transport.
                out.push_str(&format!("m=video {port} RTP/SAVP 102\r\n"));
                for l in &transport_lines {
                    if l.starts_with("m=") || l.starts_with("a=label:") {
                        continue;
                    }
                    if l.starts_with("a=mid:") {
                        out.push_str(&format!("a=mid:{mid}\r\n"));
                    } else if l.starts_with("a=sendrecv")
                        || l.starts_with("a=sendonly")
                        || l.starts_with("a=recvonly")
                        || l.starts_with("a=inactive")
                    {
                        out.push_str("a=recvonly\r\n");
                    } else if l.starts_with("a=setup:") {
                        out.push_str("a=setup:passive\r\n");
                    } else {
                        out.push_str(l);
                        out.push_str("\r\n");
                    }
                }
                out.push_str("a=label:applicationsharing-video\r\n");
                continue;
            }
        }
        // Reject: port-0, midless (x-data), or unknown sections.
        let kind = sec.mline.split(' ').next().unwrap_or("m=x-data");
        let pts = sec.mline.splitn(4, ' ').nth(3).unwrap_or("34");
        out.push_str(&format!("{kind} 0 RTP/SAVP {pts}\r\nc=IN IP4 127.0.0.1\r\n"));
        if let Some(mid) = &sec.mid {
            out.push_str(&format!("a=mid:{mid}\r\n"));
        }
    }
    out
}

    // ---- renegotiation answer (shapes from the live 2026-10-22 browser
    // share capture, identifiers/creds scrubbed to synthetic values) ----

    const RENEG_OFFER_SHARE_START: &str = "v=0\r\no=- 111 3 IN IP4 127.0.0.1\r\ns=-\r\nb=CT:4000\r\nt=0 0\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS *\r\na=group:BUNDLE 0 1 4\r\nm=audio 50000 RTP/SAVP 105 111 0 8\r\nc=IN IP4 203.0.113.7\r\na=setup:actpass\r\na=mid:0\r\na=sendrecv\r\na=ice-ufrag:synu\r\na=ice-pwd:syntheticpwd000000\r\na=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\na=rtcp-mux\r\na=label:main-audio\r\nm=video 50000 RTP/SAVP 102 104 108 45 103 107\r\nc=IN IP4 203.0.113.7\r\na=setup:actpass\r\na=mid:1\r\na=sendrecv\r\na=ice-ufrag:synu\r\na=ice-pwd:syntheticpwd000000\r\na=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\na=rtcp-mux\r\na=label:main-video\r\nm=video 50000 RTP/SAVP 102 104 108 45 103 107\r\nc=IN IP4 203.0.113.7\r\na=setup:actpass\r\na=mid:4\r\na=sendonly\r\na=ice-ufrag:synu\r\na=ice-pwd:syntheticpwd000000\r\na=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\na=rtcp-mux\r\na=label:applicationsharing-video\r\nm=x-data 0 RTP/SAVP 34\r\nc=IN IP4 203.0.113.7\r\na=label:data\r\n";

    const RENEG_OFFER_CAMERA_OFF: &str = "v=0\r\no=- 111 4 IN IP4 127.0.0.1\r\ns=-\r\nb=CT:4000\r\nt=0 0\r\na=group:BUNDLE 0 1 5\r\nm=audio 50000 RTP/SAVP 105 111 0 8\r\nc=IN IP4 203.0.113.7\r\na=mid:0\r\na=sendrecv\r\na=ice-ufrag:synu\r\na=ice-pwd:syntheticpwd000000\r\na=rtcp-mux\r\na=label:main-audio\r\nm=video 50000 RTP/SAVP 102 104 108 45 103 107\r\nc=IN IP4 203.0.113.7\r\na=mid:1\r\na=recvonly\r\na=ice-ufrag:synu\r\na=ice-pwd:syntheticpwd000000\r\na=rtcp-mux\r\na=label:main-video\r\nm=video 50000 RTP/SAVP 102 104 108 45 103 107\r\nc=IN IP4 203.0.113.7\r\na=mid:5\r\na=sendonly\r\na=ice-ufrag:synu\r\na=ice-pwd:syntheticpwd000000\r\na=rtcp-mux\r\na=label:applicationsharing-video\r\nm=x-data 0 RTP/SAVP 34\r\na=label:data\r\n";

    const RENEG_ORIG_ANSWER: &str = "v=0\r\no=- 222 2 IN IP4 127.0.0.1\r\ns=-\r\nb=CT:4000\r\nt=0 0\r\na=group:BUNDLE 0 1\r\nm=audio 40000 RTP/SAVP 0\r\nc=IN IP4 192.0.2.9\r\na=rtpmap:0 PCMU/8000\r\na=ptime:20\r\na=rtcp:40000\r\na=rtcp-mux\r\na=setup:active\r\na=mid:0\r\na=sendrecv\r\na=ice-ufrag:ouru\r\na=ice-pwd:ourpwd00000000000\r\na=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:11\r\na=candidate:1 1 UDP 2130706431 192.0.2.9 40000 typ host\r\na=label:main-audio\r\nm=video 40000 RTP/SAVP 102\r\nc=IN IP4 192.0.2.9\r\na=rtpmap:102 H264/90000\r\na=fmtp:102 packetization-mode=1;profile-level-id=42e01f\r\na=rtcp-fb:* ccm fir\r\na=rtcp-fb:* nack\r\na=rtcp-fb:* nack pli\r\na=rtcp-mux\r\na=setup:active\r\na=mid:1\r\na=sendrecv\r\na=ice-ufrag:ouru\r\na=ice-pwd:ourpwd00000000000\r\na=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:11\r\na=candidate:1 1 UDP 2130706431 192.0.2.9 40000 typ host\r\na=label:main-video\r\n";

    #[test]
    fn renegotiation_answer_accepts_share() {
        let answer = build_renegotiation_answer(RENEG_OFFER_SHARE_START, RENEG_ORIG_ANSWER);
        // The offer's group (with the NEW mid) is echoed — exactly once.
        assert_eq!(answer.matches("a=group:BUNDLE").count(), 1);
        assert!(answer.contains("a=group:BUNDLE 0 1 4\r\n"));
        // Existing sections copied with our transport.
        let audio = answer.split("m=audio").nth(1).unwrap().split("m=").next().unwrap();
        assert!(audio.contains("a=mid:0\r\n"));
        assert!(audio.contains("a=sendrecv\r\n"));
        assert!(audio.contains("a=ice-ufrag:ouru\r\n"));
        let main_video = answer.split("a=mid:1\r\n").nth(0).unwrap();
        assert!(main_video.contains("m=video 40000 RTP/SAVP 102\r\n"));
        // The share: NEW mid answered recvonly on the same transport.
        let share = answer.split("a=mid:4\r\n").nth(0).unwrap();
        assert!(
            share.contains("m=video 40000 RTP/SAVP 102\r\n"),
            "share section must ride our transport port"
        );
        let share_sec = answer.split("a=mid:4\r\n").nth(1).unwrap().split("m=").next().unwrap();
        assert!(share_sec.trim_start().starts_with("a=recvonly"));
        assert!(share_sec.contains("a=ice-ufrag:ouru\r\n"));
        assert!(share_sec.contains("a=label:applicationsharing-video\r\n"));
        // x-data rejected (port 0, midless in the offer).
        assert!(answer.contains("m=x-data 0 RTP/SAVP 34\r\n"));
    }

    #[test]
    fn renegotiation_answer_mirrors_camera_off() {
        let answer = build_renegotiation_answer(RENEG_OFFER_CAMERA_OFF, RENEG_ORIG_ANSWER);
        assert!(answer.contains("a=group:BUNDLE 0 1 5\r\n"));
        assert_eq!(answer.matches("a=group:BUNDLE").count(), 1);
        // Offer flipped mid:1 to recvonly (peer stopped its camera) —
        // our answer keeps SENDING: sendonly.
        let main = answer.split("a=mid:1\r\n").nth(1).unwrap().split("m=").next().unwrap();
        assert!(main.trim_start().starts_with("a=sendonly"));
        // The share on the fresh mid 5 still accepted recvonly.
        let share = answer.split("a=mid:5\r\n").nth(1).unwrap().split("m=").next().unwrap();
        assert!(share.trim_start().starts_with("a=recvonly"));
    }

    // Our original OFFER as the caller would have sent it: synthetic
    // creds distinct from the offer fixtures (caller side of the
    // transport; actpass — we were the DTLS offerer).
    const RENEG_OUR_OFFER: &str = "v=0\r\no=- 333 1 IN IP4 127.0.0.1\r\ns=-\r\nb=CT:4000\r\nt=0 0\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS *\r\na=group:BUNDLE 0 1\r\nm=audio 50004 RTP/SAVP 105 111 0 8\r\nc=IN IP4 198.51.100.4\r\na=setup:actpass\r\na=mid:0\r\na=sendrecv\r\na=ice-ufrag:calu\r\na=ice-pwd:callerpwd00000000\r\na=fingerprint:sha-256 33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:33\r\na=rtcp-mux\r\na=label:main-audio\r\nm=video 50004 RTP/SAVP 102 104 108\r\nc=IN IP4 198.51.100.4\r\na=setup:actpass\r\na=mid:1\r\na=sendrecv\r\na=ice-ufrag:calu\r\na=ice-pwd:callerpwd00000000\r\na=fingerprint:sha-256 33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:33\r\na=rtcp-mux\r\na=rtcp-fb:* nack pli\r\na=label:main-video\r\n";

    #[test]
    fn renegotiation_answer_as_caller_accepts_share() {
        let answer =
            build_renegotiation_answer_as_caller(RENEG_OFFER_SHARE_START, RENEG_OUR_OFFER);
        // The offer's group (with the NEW mid) is echoed — exactly once
        // (our offer's own group line must not also survive).
        assert_eq!(answer.matches("a=group:BUNDLE").count(), 1);
        assert!(answer.contains("a=group:BUNDLE 0 1 4\r\n"));
        // Existing sections copied with OUR transport (the offer's
        // creds must never leak in — this is the caller-side trap).
        let audio = answer.split("m=audio").nth(1).unwrap().split("m=").next().unwrap();
        assert!(audio.contains("a=mid:0\r\n"));
        assert!(audio.contains("a=sendrecv\r\n"));
        assert!(audio.contains("a=ice-ufrag:calu\r\n"));
        assert!(!audio.contains("a=ice-ufrag:synu"));
        // The caller stays the DTLS server: setup rewritten passive,
        // actpass must be gone everywhere.
        assert!(answer.contains("a=setup:passive\r\n"));
        assert!(!answer.contains("actpass"));
        // The share: NEW mid answered recvonly on OUR transport. The
        // share's own m-line is unique (single PT 102; the main video
        // section carries 102 104 108).
        let share = answer
            .split("m=video 50004 RTP/SAVP 102\r\n")
            .nth(1)
            .unwrap()
            .split("m=")
            .next()
            .unwrap();
        assert!(share.contains("a=setup:passive\r\n"));
        assert!(share.contains("a=mid:4\r\n"));
        assert!(share.contains("a=recvonly\r\n"));
        assert!(share.contains("a=ice-ufrag:calu\r\n"));
        assert!(share.contains("a=label:applicationsharing-video\r\n"));
        // x-data rejected (port 0, midless in the offer).
        assert!(answer.contains("m=x-data 0 RTP/SAVP 34\r\n"));
    }

    #[test]
    fn renegotiation_answer_as_caller_mirrors_camera_off() {
        let answer =
            build_renegotiation_answer_as_caller(RENEG_OFFER_CAMERA_OFF, RENEG_OUR_OFFER);
        assert!(answer.contains("a=group:BUNDLE 0 1 5\r\n"));
        assert_eq!(answer.matches("a=group:BUNDLE").count(), 1);
        // Offer flipped mid:1 to recvonly (peer stopped its camera) —
        // our answer keeps SENDING: sendonly.
        let main = answer.split("a=mid:1\r\n").nth(1).unwrap().split("m=").next().unwrap();
        assert!(main.trim_start().starts_with("a=sendonly"));
        // The share on the fresh mid 5 still accepted recvonly, on our
        // transport, still passive.
        let share = answer
            .split("m=video 50004 RTP/SAVP 102\r\n")
            .nth(1)
            .unwrap()
            .split("m=")
            .next()
            .unwrap();
        assert!(share.contains("a=setup:passive\r\n"));
        assert!(share.contains("a=mid:5\r\n"));
        assert!(share.contains("a=recvonly\r\n"));
        assert!(share.contains("a=ice-ufrag:calu\r\n"));
    }

