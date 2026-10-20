//! Media session orchestrator — binds UDP socket, sends/receives SRTP audio.
//!
//! The `MediaSession` ties together RTP encoding, SRTP encryption, and UDP
//! transport into a running audio stream. For now it sends silence (PCMU)
//! and logs received packet statistics.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time;

use super::{ice, rtp, srtp, video};

#[cfg(feature = "audio")]
use super::audio;

/// Statistics for received media packets.
#[derive(Debug, Default)]
pub struct MediaStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub last_seq: u16,
    pub last_timestamp: u32,
    /// BUNDLE video plane: packets/frames SENT (camera/share/black).
    pub video_packets_sent: u64,
    pub video_frames_sent: u64,
    /// BUNDLE video plane: packets/frames RECEIVED (decoded frames counted
    /// only when a decoder is available; packets always).
    pub video_packets_received: u64,
    pub video_frames_received: u64,
    /// Frames the decoder produced (what the UI can show).
    pub video_frames_decoded: u64,
}

/// A live-swappable video frame source (camera mid-call, screen share) —
/// the embedder swaps the receiver in/out; the send loop drains to the
/// latest frame every tick.
pub type VideoSourceSlot = Arc<std::sync::Mutex<Option<std::sync::mpsc::Receiver<video::VideoFrame>>>>;

/// Configuration for the BUNDLE video plane riding an audio
/// [`MediaSession`]'s transport (same socket, same SRTP keys — per-SSRC
/// rollover tracking in the context makes that sound).
#[derive(Default)]
pub struct VideoSessionConfig {
    /// Payload type we SEND with (the negotiated one, echoed from the
    /// offer).
    pub send_payload_type: u8,
    /// Payload types treated as video on receive (demux: everything else
    /// is audio).
    pub recv_payload_types: Vec<u8>,
    /// Camera gate (`false` → black keyframes, stream stays alive).
    pub camera_on: Option<tokio::sync::watch::Receiver<bool>>,
    /// Mid-call camera source slot (None = black keyframes).
    pub camera_source: Option<VideoSourceSlot>,
    /// Screen-share source slot (priority over camera while held).
    pub screen_source: Option<VideoSourceSlot>,
    /// Decoded remote video frames sink (latest-wins, drop-on-full).
    pub remote_frames: Option<std::sync::mpsc::SyncSender<video::VideoFrame>>,
    /// Local preview tee (frames we are about to encode).
    pub local_preview: Option<std::sync::mpsc::SyncSender<video::VideoFrame>>,
}

/// Receive-side video pipeline: RTP payload → NAL → optional H264 decode
/// → sink. Shared by the answerer's demuxed audio-socket loop.
pub struct VideoRecvPipeline {
    depacketizer: video::VideoDepacketizer,
    #[cfg(feature = "video-cam")]
    decoder: Option<super::codec::H264Decoder>,
    remote_tx: Option<std::sync::mpsc::SyncSender<video::VideoFrame>>,
    pub packets: u64,
    pub frames: u64,
    /// Frames the decoder actually produced (UI-visible video).
    pub decoded: u64,
}

impl VideoRecvPipeline {
    pub fn new(remote_tx: Option<std::sync::mpsc::SyncSender<video::VideoFrame>>) -> Self {
        #[cfg(feature = "video-cam")]
        let decoder = match super::codec::H264Decoder::new() {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::warn!("H.264 decoder init failed (frames counted, not decoded): {e:#}");
                None
            }
        };
        VideoRecvPipeline {
            depacketizer: video::VideoDepacketizer::new(),
            #[cfg(feature = "video-cam")]
            decoder,
            remote_tx,
            packets: 0,
            frames: 0,
            decoded: 0,
        }
    }

    /// Feed one decrypted RTP packet's payload; the marker bit frames NALs.
    pub fn on_rtp(&mut self, payload: &[u8], marker: bool) {
        self.packets += 1;
        match self.depacketizer.depacketize(payload, marker) {
            Ok(Some(nal)) => {
                self.frames = self.depacketizer.frames_received;
                if self.depacketizer.frames_received % 50 == 1 {
                    tracing::info!(
                        "Recv video NAL: type={}, size={} bytes (frames: {})",
                        nal[0] & 0x1F,
                        nal.len(),
                        self.depacketizer.frames_received
                    );
                }
                // Skip SVC container NALs (PACSI 30 / prefix 14): openh264
                // rejects them with bitstream errors that kill every
                // P-frame after the IDR (live-verified 2026-10-20).
                let nal_type = nal[0] & 0x1F;
                if matches!(nal_type, 14 | 30) {
                    return;
                }
                #[cfg(feature = "video-cam")]
                if let Some(ref mut dec) = self.decoder {
                    match dec.decode(&nal) {
                        Ok(Some(frame)) => {
                            self.decoded += 1;
                            if self.decoded % 25 == 1 {
                                tracing::info!(
                                    "Recv video frame decoded: {}x{} ({} decoded)",
                                    frame.width,
                                    frame.height,
                                    self.decoded
                                );
                            }
                            if let Some(ref tx) = self.remote_tx {
                                let _ = tx.try_send(video::VideoFrame {
                                    width: frame.width,
                                    height: frame.height,
                                    data: frame.data,
                                });
                            }
                        }
                        Ok(None) => {}
                        Err(e) => tracing::debug!("video decode error: {e:#}"),
                    }
                }
                #[cfg(not(feature = "video-cam"))]
                let _ = &self.remote_tx;
            }
            Ok(None) => {}
            Err(e) => tracing::debug!("video depacketize error: {e:#}"),
        }
    }
}

/// Pick the frame to encode this tick: screen share (sticky, latest-wins)
/// > camera (gate-aware, latest-wins) > None (black keyframes).
fn pick_source_frame(
    screen_source: &Option<VideoSourceSlot>,
    camera_source: &Option<VideoSourceSlot>,
    camera_on: &Option<tokio::sync::watch::Receiver<bool>>,
    last_screen: &mut Option<video::VideoFrame>,
) -> Option<video::VideoFrame> {
    // Screen share is STICKY: hold the last frame between capture ticks
    // (a slower source on a faster send tick must not flap to camera).
    if let Some(slot) = screen_source.as_ref() {
        if let Ok(mut guard) = slot.lock() {
            if let Some(rx) = guard.as_mut() {
                match rx.try_recv() {
                    Ok(mut latest) => {
                        while let Ok(newer) = rx.try_recv() {
                            latest = newer;
                        }
                        *last_screen = Some(latest.clone());
                        return Some(latest);
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        tracing::info!("screen share source disconnected");
                        *guard = None;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        return last_screen.clone();
                    }
                }
            }
        }
    }
    if let Some(gate) = camera_on.as_ref() {
        if !*gate.borrow() {
            return None;
        }
    }
    for slot in camera_source.as_ref().into_iter() {
        if let Ok(mut guard) = slot.lock() {
            if let Some(rx) = guard.as_mut() {
                match rx.try_recv() {
                    Ok(mut latest) => {
                        while let Ok(newer) = rx.try_recv() {
                            latest = newer;
                        }
                        return Some(latest);
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        tracing::info!("camera source disconnected");
                        *guard = None;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => return None,
                }
            }
        }
    }
    None
}

/// BUNDLE video send loop: one transport with audio, SHARED SRTP context
/// (per-SSRC rollover), own SSRC + payload type; sends gated until DTLS
/// keys land (same gate flag as audio).
#[allow(clippy::too_many_arguments)]
async fn video_send_loop_shared(
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    srtp_ctx: Arc<Mutex<srtp::SrtpContext>>,
    keys_ready: Arc<std::sync::atomic::AtomicBool>,
    stats: Arc<Mutex<MediaStats>>,
    ssrc: u32,
    cfg: VideoSessionConfig,
) {
    let mut packetizer = video::VideoPacketizer::new(ssrc);
    let mut interval = time::interval(Duration::from_millis(video::FRAME_INTERVAL_MS));
    let mut last_screen: Option<video::VideoFrame> = None;

    #[cfg(feature = "video-cam")]
    let mut encoder: Option<super::codec::H264Encoder> = None;
    #[cfg(feature = "video-cam")]
    let mut enc_dims = (0u32, 0u32);


    tracing::info!(
        "BUNDLE video send loop started (SSRC {:#010x}, PT {})",
        ssrc,
        cfg.send_payload_type
    );

    loop {
        interval.tick().await;

        if !keys_ready.load(std::sync::atomic::Ordering::SeqCst) {
            continue;
        }

        let frame = pick_source_frame(
            &cfg.screen_source,
            &cfg.camera_source,
            &cfg.camera_on,
            &mut last_screen,
        );

        #[cfg(feature = "video-cam")]
        let nal_units = match frame {
            Some(f) if f.width > 0 && f.height > 0 => {
                if enc_dims != (f.width, f.height) {
                    let kbps = (((f.width as u64 * f.height as u64) * 256) / (320 * 240))
                        .clamp(256, 3500) as u32;
                    match super::codec::H264Encoder::new(f.width, f.height, 15.0, kbps) {
                        Ok(enc) => {
                            tracing::info!(
                                "H.264 encoder initialized ({}x{}, {kbps}kbps)",
                                f.width,
                                f.height
                            );
                            encoder = Some(enc);
                        }
                        Err(e) => {
                            tracing::warn!("encoder {}x{} failed: {e:#} — black frames", f.width, f.height);
                            encoder = None;
                        }
                    }
                    enc_dims = (f.width, f.height);
                }
                if let Some(ref tx) = cfg.local_preview {
                    let _ = tx.try_send(f.clone());
                }
                match encoder.as_mut().map(|enc| enc.encode(&f.data)) {
                    Some(Ok(nals)) if !nals.is_empty() => nals,
                    _ => super::codec::encode_black_frame(&mut encoder),
                }
            }
            _ => {
                // The preview mirrors the ENCODE INPUT — black frames
                // included (a "camera…" placeholder implies initializing;
                // a black tile says the lens is off / no source).
                if let (Some(ref tx), Some(ref e)) = (&cfg.local_preview, encoder.as_ref()) {
                    let (ew, eh) = e.dimensions();
                    let _ = tx.try_send(video::VideoFrame {
                        width: ew,
                        height: eh,
                        data: super::codec::black_i420(ew, eh),
                    });
                }
                super::codec::encode_black_frame(&mut encoder)
            }
        };
        #[cfg(not(feature = "video-cam"))]
        let _ = (&frame, &cfg.local_preview);
        #[cfg(not(feature = "video-cam"))]
        let nal_units = video::generate_black_iframe();

        let rtp_packets = packetizer.packetize_frame(&nal_units);
        // The packetizer stamps its own payload type; rewrite to the
        // negotiated one before protection.
        let mut sent = 0u64;
        for mut rtp_pkt in rtp_packets {
            if rtp_pkt.len() >= 2 {
                rtp_pkt[1] = (rtp_pkt[1] & 0x80) | (cfg.send_payload_type & 0x7F);
            }
            let srtp_packet = {
                let mut ctx = srtp_ctx.lock().await;
                match srtp::protect(&mut ctx, &rtp_pkt) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("BUNDLE video SRTP protect: {e:#}");
                        continue;
                    }
                }
            };
            if socket.send_to(&srtp_packet, remote_addr).await.is_ok() {
                sent += 1;
            }
        }
        if sent > 0 {
            let mut s = stats.lock().await;
            s.video_packets_sent += sent;
            s.video_frames_sent += 1;
        }
    }
}

/// A running media session for a single audio stream.
pub struct MediaSession {
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    srtp_ctx: Arc<Mutex<srtp::SrtpContext>>,
    ssrc: u32,
    stats: Arc<Mutex<MediaStats>>,
    /// Handle to the send task (for shutdown).
    send_handle: Option<tokio::task::JoinHandle<()>>,
    /// Handle to the recv task (for shutdown).
    recv_handle: Option<tokio::task::JoinHandle<()>>,
    /// Audio capture handle (kept alive so the stream stays open).
    #[cfg(feature = "audio")]
    _audio_capture: Option<audio::AudioCapture>,
    /// Audio playback handle (kept alive so the stream stays open).
    #[cfg(feature = "audio")]
    _audio_playback: Option<audio::AudioPlayback>,
}

impl MediaSession {
    /// Create and start a new media session with ICE connectivity checks.
    ///
    /// Binds a UDP socket, runs ICE checks against remote candidates, then starts
    /// the send/recv loops to the verified remote address.
    pub async fn start_with_ice(
        local_port: u16,
        remote_candidates: &[ice::IceCandidate],
        local_creds: &ice::IceCredentials,
        remote_creds: &ice::IceCredentials,
        local_material: &srtp::SrtpKeyingMaterial,
        remote_material: &srtp::SrtpKeyingMaterial,
        dtls_client: Option<bool>,
    ) -> Result<Self> {
        Self::start_with_ice_video(
            local_port,
            remote_candidates,
            local_creds,
            remote_creds,
            local_material,
            remote_material,
            dtls_client,
            None,
        )
        .await
    }

    /// [`start_with_ice`] plus an optional BUNDLE video plane riding the
    /// same transport: video RTP is demuxed by payload type on receive and
    /// a send loop emits camera/share/black frames with the negotiated PT
    /// under the SHARED SRTP context (per-SSRC rollover tracking).
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_ice_video(
        local_port: u16,
        remote_candidates: &[ice::IceCandidate],
        local_creds: &ice::IceCredentials,
        remote_creds: &ice::IceCredentials,
        local_material: &srtp::SrtpKeyingMaterial,
        remote_material: &srtp::SrtpKeyingMaterial,
        dtls_client: Option<bool>,
        video: Option<VideoSessionConfig>,
    ) -> Result<Self> {
        let bind_addr = format!("0.0.0.0:{}", local_port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .with_context(|| format!("Failed to bind UDP socket on {}", bind_addr))?;

        let local_addr = socket.local_addr()?;
        tracing::info!("Media session bound to {} for ICE checks", local_addr);

        let socket = Arc::new(socket);

        // Run ICE connectivity checks
        let agent = ice::IceAgent::new(
            local_creds.clone(),
            remote_creds.clone(),
            false, // answerer = controlled
        );

        let ice_result = agent
            .check_connectivity(socket.clone(), remote_candidates)
            .await;

        let remote_addr = match ice_result {
            Ok(result) => {
                tracing::info!(
                    "ICE check succeeded: remote={}, mapped={}",
                    result.remote_addr,
                    result.mapped_addr
                );
                result.remote_addr
            }
            Err(e) => {
                tracing::warn!("ICE checks failed ({}), falling back to best candidate", e);
                ice::select_remote_candidate(remote_candidates)
                    .context("No candidate available for fallback")?
            }
        };

        let srtp_ctx = if dtls_client.is_some() {
            // DTLS-SRTP: wrong keys until the handshake task swaps in the
            // exported ones; sends are gated until then.
            super::dtls::placeholder_context()
        } else {
            srtp::create_context(local_material, remote_material)?
        };
        let ssrc = {
            let id = uuid::Uuid::new_v4();
            let bytes = id.as_bytes();
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        };

        let srtp_ctx = Arc::new(Mutex::new(srtp_ctx));
        let stats = Arc::new(Mutex::new(MediaStats::default()));

        // Initialize audio devices (optional — graceful fallback to silence).
        #[cfg(feature = "audio")]
        let (audio_capture, mic_rx) = match audio::AudioCapture::start() {
            Some((cap, rx)) => (Some(cap), Some(rx)),
            None => (None, None),
        };
        #[cfg(not(feature = "audio"))]
        let mic_rx: Option<std::sync::mpsc::Receiver<Vec<i16>>> = None;

        #[cfg(feature = "audio")]
        let (audio_playback, spk_tx) = match audio::AudioPlayback::start() {
            Some((pb, tx)) => (Some(pb), Some(tx)),
            None => (None, None),
        };
        #[cfg(not(feature = "audio"))]
        let spk_tx: Option<std::sync::mpsc::SyncSender<Vec<i16>>> = None;

        // DTLS-SRTP plumbing: the recv loop demuxes RFC 5764 records into
        // the shared queue; a background task runs the handshake and
        // swaps the SRTP context; sends are gated until keys land.
        let dtls_inbound = Arc::new(super::dtls::DtlsInbound::default());
        let keys_ready = Arc::new(std::sync::atomic::AtomicBool::new(dtls_client.is_none()));

        let send_handle = {
            let socket = socket.clone();
            let srtp_ctx = srtp_ctx.clone();
            let stats = stats.clone();
            let keys_ready = keys_ready.clone();
            tokio::spawn(send_loop(
                socket,
                remote_addr,
                srtp_ctx,
                ssrc,
                stats,
                mic_rx,
                Some(keys_ready),
            ))
        };

        let local_pwd = local_creds.pwd.clone();
        let recv_handle = {
            let socket = socket.clone();
            let srtp_ctx = srtp_ctx.clone();
            let stats = stats.clone();
            let dtls_inbound = dtls_inbound.clone();
            let video_demux = video.as_ref().map(|cfg| {
                (
                    cfg.recv_payload_types.clone(),
                    VideoRecvPipeline::new(cfg.remote_frames.clone()),
                )
            });
            tokio::spawn(recv_loop_with_stun(
                socket, srtp_ctx, stats, local_pwd, spk_tx, dtls_inbound, video_demux,
            ))
        };

        // BUNDLE video send loop (own SSRC + negotiated PT, shared context
        // and DTLS gate).
        if let Some(cfg) = video {
            let video_ssrc = {
                let id = uuid::Uuid::new_v4();
                let bytes = id.as_bytes();
                u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
            };
            let socket = socket.clone();
            let srtp_ctx = srtp_ctx.clone();
            let stats = stats.clone();
            let keys_ready = keys_ready.clone();
            tokio::spawn(video_send_loop_shared(
                socket,
                remote_addr,
                srtp_ctx,
                keys_ready,
                stats,
                video_ssrc,
                cfg,
            ));
        }

        if let Some(we_are_client) = dtls_client {
            let socket = socket.clone();
            let srtp_ctx = srtp_ctx.clone();
            let inbound = dtls_inbound.clone();
            let keys_ready = keys_ready.clone();
            tokio::spawn(async move {
                match super::dtls::handshake_srtp(
                    socket,
                    remote_addr,
                    we_are_client,
                    inbound,
                    Duration::from_secs(15),
                )
                .await
                {
                    Ok(keys) => match super::dtls::srtp_context(&keys) {
                        Ok(ctx) => {
                            *srtp_ctx.lock().await = ctx;
                            keys_ready.store(true, std::sync::atomic::Ordering::SeqCst);
                            tracing::info!("DTLS-SRTP keys installed; media ungated");
                        }
                        Err(e) => tracing::error!("DTLS key context build failed: {e:#}"),
                    },
                    Err(e) => tracing::error!("DTLS handshake failed (media stays gated): {e:#}"),
                }
            });
        }

        Ok(MediaSession {
            socket,
            remote_addr,
            srtp_ctx,
            ssrc,
            stats,
            send_handle: Some(send_handle),
            recv_handle: Some(recv_handle),
            #[cfg(feature = "audio")]
            _audio_capture: audio_capture,
            #[cfg(feature = "audio")]
            _audio_playback: audio_playback,
        })
    }

    /// Create and start a new media session (no ICE checks, direct send to remote).
    ///
    /// - `local_port`: UDP port to bind on (0 for auto-assign).
    /// - `remote_addr`: Remote peer's RTP address (from ICE candidate selection).
    /// - `local_material`: Our SRTP keying material (from our SDP answer).
    /// - `remote_material`: Remote SRTP keying material (from their SDP offer).
    pub async fn start(
        local_port: u16,
        remote_addr: SocketAddr,
        local_material: &srtp::SrtpKeyingMaterial,
        remote_material: &srtp::SrtpKeyingMaterial,
    ) -> Result<Self> {
        let bind_addr = format!("0.0.0.0:{}", local_port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .with_context(|| format!("Failed to bind UDP socket on {}", bind_addr))?;

        let local_addr = socket.local_addr()?;
        tracing::info!(
            "Media session bound to {}, remote: {}",
            local_addr,
            remote_addr
        );

        let srtp_ctx = srtp::create_context(local_material, remote_material)?;

        // Generate a random-ish SSRC from uuid
        let ssrc = {
            let id = uuid::Uuid::new_v4();
            let bytes = id.as_bytes();
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        };

        let socket = Arc::new(socket);
        let srtp_ctx = Arc::new(Mutex::new(srtp_ctx));
        let stats = Arc::new(Mutex::new(MediaStats::default()));

        // Initialize audio devices (optional — graceful fallback to silence).
        #[cfg(feature = "audio")]
        let (audio_capture, mic_rx) = match audio::AudioCapture::start() {
            Some((cap, rx)) => (Some(cap), Some(rx)),
            None => (None, None),
        };
        #[cfg(not(feature = "audio"))]
        let mic_rx: Option<std::sync::mpsc::Receiver<Vec<i16>>> = None;

        #[cfg(feature = "audio")]
        let (audio_playback, spk_tx) = match audio::AudioPlayback::start() {
            Some((pb, tx)) => (Some(pb), Some(tx)),
            None => (None, None),
        };
        #[cfg(not(feature = "audio"))]
        let spk_tx: Option<std::sync::mpsc::SyncSender<Vec<i16>>> = None;

        let send_handle = {
            let socket = socket.clone();
            let srtp_ctx = srtp_ctx.clone();
            let stats = stats.clone();
            tokio::spawn(send_loop(
                socket,
                remote_addr,
                srtp_ctx,
                ssrc,
                stats,
                mic_rx,
                None,
            ))
        };

        let recv_handle = {
            let socket = socket.clone();
            let srtp_ctx = srtp_ctx.clone();
            let stats = stats.clone();
            tokio::spawn(recv_loop(socket, srtp_ctx, stats, spk_tx))
        };

        Ok(MediaSession {
            socket,
            remote_addr,
            srtp_ctx,
            ssrc,
            stats,
            send_handle: Some(send_handle),
            recv_handle: Some(recv_handle),
            #[cfg(feature = "audio")]
            _audio_capture: audio_capture,
            #[cfg(feature = "audio")]
            _audio_playback: audio_playback,
        })
    }

    /// Get the local port this session is bound to.
    pub fn local_port(&self) -> Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }

    /// Get current media statistics.
    pub async fn stats(&self) -> MediaStats {
        let s = self.stats.lock().await;
        MediaStats {
            packets_sent: s.packets_sent,
            packets_received: s.packets_received,
            bytes_received: s.bytes_received,
            last_seq: s.last_seq,
            last_timestamp: s.last_timestamp,
            video_packets_sent: s.video_packets_sent,
            video_frames_sent: s.video_frames_sent,
            video_packets_received: s.video_packets_received,
            video_frames_received: s.video_frames_received,
            video_frames_decoded: s.video_frames_decoded,
        }
    }

    /// Stop the media session.
    pub async fn stop(&mut self) {
        if let Some(h) = self.send_handle.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.recv_handle.take() {
            h.abort();
            let _ = h.await;
        }
        let stats = self.stats.lock().await;
        tracing::info!(
            "Media session stopped. Sent: {}, Received: {} ({} bytes)",
            stats.packets_sent,
            stats.packets_received,
            stats.bytes_received
        );
    }
}

impl Drop for MediaSession {
    fn drop(&mut self) {
        if let Some(h) = self.send_handle.take() {
            h.abort();
        }
        if let Some(h) = self.recv_handle.take() {
            h.abort();
        }
    }
}

/// Send loop: every 20ms, encode audio (or silence) as PCMU, encrypt with SRTP, send.
async fn send_loop(
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    srtp_ctx: Arc<Mutex<srtp::SrtpContext>>,
    ssrc: u32,
    stats: Arc<Mutex<MediaStats>>,
    mic_rx: Option<std::sync::mpsc::Receiver<Vec<i16>>>,
    keys_ready: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) {
    let mut seq: u16 = 0;
    let mut timestamp: u32 = 0;
    let mut interval = time::interval(Duration::from_millis(rtp::PACKET_INTERVAL_MS));

    let has_mic = mic_rx.is_some();
    tracing::info!(
        "Media send loop started (SSRC: {:#010x}, mic: {})",
        ssrc,
        if has_mic { "live" } else { "silence" }
    );

    loop {
        interval.tick().await;

        // DTLS-SRTP: hold (silence, no RTP) until the handshake lands the
        // real keys — garbage-SRTP before that only wastes the peer's
        // replay window.
        if let Some(ref ready) = keys_ready {
            if !ready.load(std::sync::atomic::Ordering::SeqCst) {
                continue;
            }
        }

        // Try to get a frame from the microphone; fall back to silence.
        let payload = if let Some(ref rx) = mic_rx {
            match rx.try_recv() {
                Ok(samples) => {
                    let mut encoded = Vec::with_capacity(samples.len());
                    for &s in &samples {
                        encoded.push(rtp::linear_to_ulaw(s));
                    }
                    // Pad or truncate to exactly SAMPLES_PER_PACKET.
                    encoded.resize(rtp::SAMPLES_PER_PACKET, 0xFF);
                    encoded
                }
                Err(_) => rtp::silence_payload(),
            }
        } else {
            rtp::silence_payload()
        };
        let rtp_packet = rtp::encode(rtp::PT_PCMU, seq, timestamp, ssrc, &payload);

        let srtp_packet = {
            let mut ctx = srtp_ctx.lock().await;
            match srtp::protect(&mut ctx, &rtp_packet) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("SRTP protect failed: {:#}", e);
                    continue;
                }
            }
        };

        match socket.send_to(&srtp_packet, remote_addr).await {
            Ok(_) => {
                let mut s = stats.lock().await;
                s.packets_sent += 1;
            }
            Err(e) => {
                tracing::warn!("UDP send failed: {:#}", e);
            }
        }

        seq = seq.wrapping_add(1);
        timestamp = timestamp.wrapping_add(rtp::TIMESTAMP_INCREMENT);
    }
}

/// Statistics for received video packets.
#[derive(Debug, Default)]
pub struct VideoStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
}

/// A running media session for a video stream.
pub struct VideoMediaSession {
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    stats: Arc<Mutex<VideoStats>>,
    send_handle: Option<tokio::task::JoinHandle<()>>,
    recv_handle: Option<tokio::task::JoinHandle<()>>,
}

impl VideoMediaSession {
    /// Create and start a new video media session.
    pub async fn start(
        local_port: u16,
        remote_addr: SocketAddr,
        local_material: &srtp::SrtpKeyingMaterial,
        remote_material: &srtp::SrtpKeyingMaterial,
    ) -> Result<Self> {
        let bind_addr = format!("0.0.0.0:{}", local_port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .with_context(|| format!("Failed to bind video UDP socket on {}", bind_addr))?;

        let local_addr = socket.local_addr()?;
        tracing::info!(
            "Video session bound to {}, remote: {}",
            local_addr,
            remote_addr
        );

        let srtp_ctx = srtp::create_context(local_material, remote_material)?;

        let ssrc = {
            let id = uuid::Uuid::new_v4();
            let bytes = id.as_bytes();
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        };

        let socket = Arc::new(socket);
        let srtp_ctx = Arc::new(Mutex::new(srtp_ctx));
        let stats = Arc::new(Mutex::new(VideoStats::default()));

        let send_handle = {
            let socket = socket.clone();
            let srtp_ctx = srtp_ctx.clone();
            let stats = stats.clone();
            tokio::spawn(video_send_loop(socket, remote_addr, srtp_ctx, ssrc, stats))
        };

        let recv_handle = {
            let socket = socket.clone();
            let srtp_ctx = srtp_ctx.clone();
            let stats = stats.clone();
            tokio::spawn(video_recv_loop(socket, srtp_ctx, stats))
        };

        Ok(VideoMediaSession {
            socket,
            remote_addr,
            stats,
            send_handle: Some(send_handle),
            recv_handle: Some(recv_handle),
        })
    }

    /// Get the local port this session is bound to.
    pub fn local_port(&self) -> Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }

    /// Get current video statistics.
    pub async fn stats(&self) -> VideoStats {
        let s = self.stats.lock().await;
        VideoStats {
            packets_sent: s.packets_sent,
            packets_received: s.packets_received,
            bytes_received: s.bytes_received,
            frames_sent: s.frames_sent,
            frames_received: s.frames_received,
        }
    }

    /// Stop the video session.
    pub async fn stop(&mut self) {
        if let Some(h) = self.send_handle.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.recv_handle.take() {
            h.abort();
            let _ = h.await;
        }
        let stats = self.stats.lock().await;
        tracing::info!(
            "Video session stopped. Sent: {} pkts/{} frames, Received: {} pkts/{} frames ({} bytes)",
            stats.packets_sent,
            stats.frames_sent,
            stats.packets_received,
            stats.frames_received,
            stats.bytes_received
        );
    }
}

impl Drop for VideoMediaSession {
    fn drop(&mut self) {
        if let Some(h) = self.send_handle.take() {
            h.abort();
        }
        if let Some(h) = self.recv_handle.take() {
            h.abort();
        }
    }
}

/// Video send loop: periodically send black H.264 I-frames.
async fn video_send_loop(
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    srtp_ctx: Arc<Mutex<srtp::SrtpContext>>,
    ssrc: u32,
    stats: Arc<Mutex<VideoStats>>,
) {
    let mut packetizer = video::VideoPacketizer::new(ssrc);
    let mut interval = time::interval(Duration::from_millis(video::FRAME_INTERVAL_MS));

    tracing::info!(
        "Video send loop started (SSRC: {:#010x}, 15fps black frames)",
        ssrc
    );

    loop {
        interval.tick().await;

        let nal_units = video::generate_black_iframe();
        let rtp_packets = packetizer.packetize_frame(&nal_units);

        for rtp_pkt in &rtp_packets {
            let srtp_packet = {
                let mut ctx = srtp_ctx.lock().await;
                match srtp::protect(&mut ctx, rtp_pkt) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("Video SRTP protect failed: {:#}", e);
                        continue;
                    }
                }
            };

            match socket.send_to(&srtp_packet, remote_addr).await {
                Ok(_) => {
                    let mut s = stats.lock().await;
                    s.packets_sent += 1;
                }
                Err(e) => {
                    tracing::warn!("Video UDP send failed: {:#}", e);
                }
            }
        }

        let mut s = stats.lock().await;
        s.frames_sent += 1;
    }
}

/// Video receive loop: receive and depacketize H.264 NAL units.
async fn video_recv_loop(
    socket: Arc<UdpSocket>,
    srtp_ctx: Arc<Mutex<srtp::SrtpContext>>,
    stats: Arc<Mutex<VideoStats>>,
) {
    let mut buf = [0u8; 2048];
    let mut depacketizer = video::VideoDepacketizer::new();

    tracing::info!("Video recv loop started");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                let data = &buf[..len];

                if len >= 20 && super::ice::is_stun_response(data) {
                    tracing::debug!("Video: STUN response from {}", from);
                    continue;
                }

                let mut ctx = srtp_ctx.lock().await;
                match srtp::unprotect(&mut ctx, data) {
                    Ok(rtp_data) => {
                        if let Ok(pkt) = rtp::decode(&rtp_data) {
                            let mut s = stats.lock().await;
                            s.packets_received += 1;
                            s.bytes_received += rtp_data.len() as u64;

                            let marker = pkt.marker;
                            drop(s); // release lock before depacketize

                            match depacketizer.depacketize(&pkt.payload, marker) {
                                Ok(Some(nal)) => {
                                    let mut s = stats.lock().await;
                                    s.frames_received = depacketizer.frames_received;
                                    if depacketizer.frames_received % 50 == 1 {
                                        tracing::info!(
                                            "Recv video NAL: type={}, size={} bytes (frames: {})",
                                            nal[0] & 0x1F,
                                            nal.len(),
                                            depacketizer.frames_received
                                        );
                                    }
                                }
                                Ok(None) => {} // more fragments needed
                                Err(e) => {
                                    tracing::debug!("Video depacketize error: {:#}", e);
                                }
                            }
                        }
                    }
                    Err(_) => {
                        tracing::trace!(
                            "Could not decrypt video packet from {} ({} bytes)",
                            from,
                            len
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Video UDP recv error: {:#}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Receive loop: receive UDP packets, try to decrypt SRTP, decode and play audio.
async fn recv_loop(
    socket: Arc<UdpSocket>,
    srtp_ctx: Arc<Mutex<srtp::SrtpContext>>,
    stats: Arc<Mutex<MediaStats>>,
    spk_tx: Option<std::sync::mpsc::SyncSender<Vec<i16>>>,
) {
    let mut buf = [0u8; 2048];

    tracing::info!("Media recv loop started");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                let data = &buf[..len];

                // Skip STUN packets
                if len >= 20 && super::ice::is_stun_response(data) {
                    tracing::debug!("Received STUN response from {}", from);
                    continue;
                }

                // Try SRTP decrypt
                let mut ctx = srtp_ctx.lock().await;
                match srtp::unprotect(&mut ctx, data) {
                    Ok(rtp_data) => {
                        if let Ok(pkt) = rtp::decode(&rtp_data) {
                            let mut s = stats.lock().await;
                            s.packets_received += 1;
                            s.bytes_received += rtp_data.len() as u64;
                            s.last_seq = pkt.sequence_number;
                            s.last_timestamp = pkt.timestamp;

                            if s.packets_received % 250 == 1 {
                                tracing::info!(
                                    "Recv audio: seq={}, ts={}, pt={}, payload={} bytes (total: {} pkts)",
                                    pkt.sequence_number,
                                    pkt.timestamp,
                                    pkt.payload_type,
                                    pkt.payload.len(),
                                    s.packets_received
                                );
                            }
                            drop(s);

                            // Decode PCMU and send to speaker.
                            if let Some(ref tx) = spk_tx {
                                let samples: Vec<i16> = pkt
                                    .payload
                                    .iter()
                                    .map(|&b| rtp::ulaw_to_linear(b))
                                    .collect();
                                let _ = tx.try_send(samples);
                            }
                        }
                    }
                    Err(_) => {
                        tracing::trace!("Could not decrypt packet from {} ({} bytes)", from, len);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("UDP recv error: {:#}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Receive loop that also responds to incoming STUN binding requests.
///
/// This is used when ICE is active — the peer continues sending STUN checks
/// during the media session and expects responses to keep the path alive.
/// `video_demux` (BUNDLE): RTP packets whose payload type is in the set go
/// to the video pipeline instead of the speaker.
#[allow(clippy::too_many_arguments)]
async fn recv_loop_with_stun(
    socket: Arc<UdpSocket>,
    srtp_ctx: Arc<Mutex<srtp::SrtpContext>>,
    stats: Arc<Mutex<MediaStats>>,
    local_pwd: String,
    spk_tx: Option<std::sync::mpsc::SyncSender<Vec<i16>>>,
    dtls_inbound: Arc<super::dtls::DtlsInbound>,
    mut video_demux: Option<(Vec<u8>, VideoRecvPipeline)>,
) {
    let mut buf = [0u8; 2048];

    tracing::info!("Media recv loop started (STUN-aware)");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                let data = &buf[..len];

                // RFC 5764 demux: DTLS records feed the handshake engine.
                if super::dtls::is_dtls_record(data) {
                    super::dtls::push_inbound(&dtls_inbound, data);
                    continue;
                }

                // Handle STUN messages
                if len >= 20 && ice::is_stun_message(data) {
                    if ice::is_stun_request(data) {
                        // Respond to STUN binding request from peer
                        if let Some(txn_id) = ice::get_transaction_id(data) {
                            let response = ice::build_binding_response(
                                &txn_id,
                                from,
                                Some(local_pwd.as_bytes()),
                            );
                            let _ = socket.send_to(&response, from).await;
                            tracing::debug!("Responded to STUN request from {} during media", from);
                        }
                    } else {
                        tracing::debug!("Received STUN response from {}", from);
                    }
                    continue;
                }

                // Try SRTP decrypt
                let mut ctx = srtp_ctx.lock().await;
                match srtp::unprotect(&mut ctx, data) {
                    Ok(rtp_data) => {
                        if let Ok(pkt) = rtp::decode(&rtp_data) {
                            // BUNDLE video plane: demux by payload type.
                            if let Some((pts, pipeline)) = video_demux.as_mut() {
                                if pts.contains(&pkt.payload_type) {
                                    let marker = pkt.marker;
                                    let payload = pkt.payload.clone();
                                    drop(ctx);
                                    pipeline.on_rtp(&payload, marker);
                                    let mut s = stats.lock().await;
                                    s.video_packets_received = pipeline.packets;
                                    s.video_frames_received = pipeline.frames;
                                    s.video_frames_decoded = pipeline.decoded;
                                    continue;
                                }
                            }
                            let mut s = stats.lock().await;
                            s.packets_received += 1;
                            s.bytes_received += rtp_data.len() as u64;
                            s.last_seq = pkt.sequence_number;
                            s.last_timestamp = pkt.timestamp;

                            if s.packets_received % 250 == 1 {
                                tracing::info!(
                                    "Recv audio: seq={}, ts={}, pt={}, payload={} bytes (total: {} pkts)",
                                    pkt.sequence_number,
                                    pkt.timestamp,
                                    pkt.payload_type,
                                    pkt.payload.len(),
                                    s.packets_received
                                );
                            }
                            drop(s);

                            // Decode PCMU and send to speaker.
                            if let Some(ref tx) = spk_tx {
                                let samples: Vec<i16> = pkt
                                    .payload
                                    .iter()
                                    .map(|&b| rtp::ulaw_to_linear(b))
                                    .collect();
                                let _ = tx.try_send(samples);
                            }
                        }
                    }
                    Err(_) => {
                        tracing::trace!("Could not decrypt packet from {} ({} bytes)", from, len);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("UDP recv error: {:#}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_material() -> srtp::SrtpKeyingMaterial {
        let mut key = [0u8; 16];
        let mut salt = [0u8; 14];
        for i in 0..16 {
            key[i] = (i + 1) as u8;
        }
        for i in 0..14 {
            salt[i] = (i + 17) as u8;
        }
        srtp::SrtpKeyingMaterial {
            master_key: key,
            master_salt: salt,
            tag: 2,
        }
    }

    #[tokio::test]
    async fn test_media_session_binds() {
        // Use a non-routable address so send_loop just drops packets
        let remote: SocketAddr = "192.0.2.1:9999".parse().unwrap();
        let mat = test_material();

        let mut session = MediaSession::start(0, remote, &mat, &mat).await.unwrap();
        let port = session.local_port().unwrap();
        assert!(port > 0);

        // Let it run briefly
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stats = session.stats().await;
        // Should have sent at least 1 packet in 50ms (20ms interval)
        assert!(stats.packets_sent >= 1, "sent: {}", stats.packets_sent);

        session.stop().await;
    }
}
