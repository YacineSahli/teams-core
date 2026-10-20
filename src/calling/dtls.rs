//! DTLS-SRTP (RFC 5764): certificate, SDP attributes, and the handshake
//! engine.
//!
//! Run-13 root cause: the consumer web client is a WebRTC stack
//! (calling-pluginless: 57 dtls references, zero SDES) — it cannot answer
//! an SDES-only offer, and the consumer fleet's call controller never
//! completes an all-SDES acceptance transaction (408/10056 at its 30s
//! deadline, connectTime null while raw RTP flows). Every offer/answer
//! therefore carries `a=fingerprint`+`a=setup` (stage 1) and the media
//! plane runs a real DTLS handshake when the remote declares a
//! fingerprint (stage 2), deriving SRTP keys via the
//! `EXTRACTOR-dtls_srtp` exporter. SDES (`a=crypto`) stays for SFB peers
//! (echo bot, work legs).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};

use super::srtp::{self, SrtpKeyingMaterial};

/// Shared queue of inbound DTLS-record datagrams. The socket's recv loop
/// (single reader) pushes RFC 5764-demuxed records here; the handshake
/// engine drains them — no reader races on the UDP socket.
pub type DtlsInbound = Mutex<VecDeque<Vec<u8>>>;

/// Is this datagram a DTLS record (RFC 5764 §5.1.2: first byte 20..=63)?
pub fn is_dtls_record(data: &[u8]) -> bool {
    !data.is_empty() && (20..=63).contains(&data[0])
}

/// Push a DTLS record into the shared queue (bounded; oldest dropped).
pub fn push_inbound(queue: &DtlsInbound, data: &[u8]) {
    if let Ok(mut q) = queue.lock() {
        if q.len() >= 64 {
            q.pop_front();
        }
        q.push_back(data.to_vec());
    }
}

/// The DTLS certificate (generated once per process; also the source of
/// the SDP fingerprint).
fn certificate() -> &'static dtls::crypto::Certificate {
    static CERT: OnceLock<dtls::crypto::Certificate> = OnceLock::new();
    CERT.get_or_init(|| {
        dtls::crypto::Certificate::generate_self_signed(vec!["teamsfast".to_string()])
            .expect("DTLS self-signed certificate")
    })
}

/// The colon-separated UPPERCASE sha-256 fingerprint of our DTLS
/// certificate (the exact `a=fingerprint:sha-256 …` value).
pub fn fingerprint_sha256() -> &'static str {
    static FP: OnceLock<String> = OnceLock::new();
    FP.get_or_init(|| {
        use sha2::Digest as _;
        let der = certificate()
            .certificate
            .first()
            .expect("certificate chain");
        let mut h = sha2::Sha256::new();
        h.update(der.as_ref());
        h.finalize()
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

/// SRTP keying material derived from a completed DTLS-SRTP handshake.
pub struct DtlsSrtpKeys {
    pub local: SrtpKeyingMaterial,
    pub remote: SrtpKeyingMaterial,
}

/// Run the DTLS-SRTP handshake over the (already ICE-connected) socket
/// and derive both sides' SRTP keying material.
///
/// `we_are_client`: we declared `a=setup:active` (answerer-initiator) or
/// the remote answered `active` against our `actpass` offer. Blocks until
/// the handshake completes or `timeout` elapses — callers run it in a
/// background task; the recv loop must already be routing records into
/// `inbound`.
pub async fn handshake_srtp(
    socket: Arc<tokio::net::UdpSocket>,
    remote: SocketAddr,
    we_are_client: bool,
    inbound: Arc<DtlsInbound>,
    timeout: Duration,
) -> Result<DtlsSrtpKeys> {
    let config = dtls::config::Config {
        certificates: vec![certificate().clone()],
        srtp_protection_profiles: vec![
            dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        ],
        // WebRTC DTLS uses self-signed certs authenticated by the SDP
        // fingerprint; chain verification is not applicable (fingerprint
        // pinning is a follow-up).
        insecure_skip_verify: true,
        ..Default::default()
    };

    let conn = Arc::new(QueueConn {
        socket,
        remote,
        inbound,
    });
    let dc = tokio::time::timeout(
        timeout,
        dtls::conn::DTLSConn::new(conn, config, we_are_client, None),
    )
    .await
    .context("DTLS handshake timed out")?
    .context("DTLS handshake failed")?;

    use webrtc_util::KeyingMaterialExporter as _;
    let state = dc.connection_state().await;
    let km = tokio::time::timeout(
        timeout,
        state.export_keying_material("EXTRACTOR-dtls_srtp", &[], 60),
    )
    .await
    .context("DTLS key export timed out")?
    .context("DTLS key export failed")?;
    let _ = dc.close().await;

    // RFC 5764 §4.2: client_key || server_key || client_salt || server_salt
    // (AES_CM_128_HMAC_SHA1_80: 16-byte keys, 14-byte salts).
    anyhow::ensure!(km.len() == 60, "bad exported key length {}", km.len());
    let (client_key, rest) = km.split_at(16);
    let (server_key, rest) = rest.split_at(16);
    let (client_salt, server_salt) = rest.split_at(14);

    let to_material = |key: &[u8], salt: &[u8]| SrtpKeyingMaterial {
        master_key: key.try_into().expect("key len"),
        master_salt: salt.try_into().expect("salt len"),
        tag: 2,
    };
    let client = to_material(client_key, client_salt);
    let server = to_material(server_key, server_salt);

    tracing::info!(
        "DTLS-SRTP handshake complete (role: {})",
        if we_are_client { "client" } else { "server" }
    );
    Ok(if we_are_client {
        DtlsSrtpKeys { local: client, remote: server }
    } else {
        DtlsSrtpKeys { local: server, remote: client }
    })
}

/// Build a full SRTP context from handshake-derived keys.
pub fn srtp_context(keys: &DtlsSrtpKeys) -> Result<srtp::SrtpContext> {
    srtp::create_context(&keys.local, &keys.remote)
}

/// A random SDES-shaped placeholder context (pre-handshake state; wrong
/// keys, replaced the moment the handshake delivers real ones).
pub fn placeholder_context() -> srtp::SrtpContext {
    fn random_material() -> SrtpKeyingMaterial {
        let mut key = [0u8; 16];
        let mut salt = [0u8; 14];
        getrandom::getrandom(&mut key).ok();
        getrandom::getrandom(&mut salt).ok();
        SrtpKeyingMaterial { master_key: key, master_salt: salt, tag: 2 }
    }
    srtp::create_context(&random_material(), &random_material())
        .expect("placeholder context")
}

/// [webrtc_util::Conn] feeding the DTLS engine from the shared inbound
/// queue and sending records to the fixed remote.
struct QueueConn {
    socket: Arc<tokio::net::UdpSocket>,
    remote: SocketAddr,
    inbound: Arc<DtlsInbound>,
}

#[async_trait::async_trait]
impl webrtc_util::Conn for QueueConn {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        loop {
            let packet = {
                let Ok(mut q) = self.inbound.lock() else {
                    return Err(webrtc_util::Error::Other(
                        "dtls inbound queue poisoned".to_string(),
                    ));
                };
                q.pop_front()
            };
            match packet {
                Some(p) => {
                    let n = p.len().min(buf.len());
                    buf[..n].copy_from_slice(&p[..n]);
                    return Ok(n);
                }
                None => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let n = webrtc_util::Conn::recv(self, buf).await?;
        Ok((n, self.remote))
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.socket
            .send_to(buf, self.remote)
            .await
            .map_err(webrtc_util::Error::from)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        self.socket
            .send_to(buf, target)
            .await
            .map_err(webrtc_util::Error::from)
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(webrtc_util::Error::from)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote)
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
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
        }
        assert_eq!(fp, fingerprint_sha256());
    }

    #[test]
    fn sdp_attributes_shape() {
        let attr = sdp_attributes(Setup::ActPass);
        assert!(attr.starts_with("a=fingerprint:sha-256 "));
        assert!(attr.ends_with("\r\na=setup:actpass\r\n"));
    }

    #[test]
    fn dtls_record_demux() {
        assert!(is_dtls_record(&[20, 0, 0]));
        assert!(is_dtls_record(&[63, 0]));
        assert!(!is_dtls_record(&[0x00, 0x01])); // STUN
        assert!(!is_dtls_record(&[0x80, 0x60])); // RTP
        assert!(!is_dtls_record(&[]));
    }

    #[tokio::test]
    async fn dtls_handshake_loopback() {
        // Client and server over loopback sockets through the queue
        // plumbing — proves the engine, exporter split and role mapping.
        use std::net::SocketAddr;
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ra: SocketAddr = a.local_addr().unwrap();
        let rb: SocketAddr = b.local_addr().unwrap();
        a.connect(rb).await.unwrap();
        b.connect(ra).await.unwrap();
        let (a, b) = (Arc::new(a), Arc::new(b));

        let qa = Arc::new(DtlsInbound::default());
        let qb = Arc::new(DtlsInbound::default());
        // Pump each socket into the peer's queue and its own (handshake
        // reads from its own queue; we simply bridge both directions).
        let pump = |sock: Arc<tokio::net::UdpSocket>,
                    own: Arc<DtlsInbound>|
         -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    match sock.recv_from(&mut buf).await {
                        Ok((n, _)) => push_inbound(&own, &buf[..n]),
                        Err(_) => return,
                    }
                }
            })
        };
        let pa = pump(a.clone(), qa.clone());
        let pb = pump(b.clone(), qb.clone());

        let server = handshake_srtp(
            a.clone(),
            rb,
            false,
            qa,
            Duration::from_secs(10),
        );
        let client = handshake_srtp(
            b.clone(),
            ra,
            true,
            qb,
            Duration::from_secs(10),
        );
        let (server_keys, client_keys) = tokio::join!(server, client);
        pa.abort();
        pb.abort();

        let sk = server_keys.expect("server handshake");
        let ck = client_keys.expect("client handshake");
        // Cross-check: server.local == client.remote and vice versa.
        assert_eq!(sk.local.master_key, ck.remote.master_key);
        assert_eq!(sk.remote.master_key, ck.local.master_key);
        assert_eq!(sk.local.master_salt, ck.remote.master_salt);
    }
}
