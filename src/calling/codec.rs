//! H.264 encode/decode wrappers around the `openh264` crate (v0.9 API).
//!
//! Encoder: takes I420 YUV frames, produces H.264 NAL units.
//! Decoder: takes H.264 NAL units, produces I420 YUV frames.

use anyhow::{Context, Result};
use openh264::decoder::{Decoder, DecoderConfig};
use openh264::encoder::{BitRate, Encoder, EncoderConfig, FrameRate};
use openh264::formats::YUVSource;
use openh264::OpenH264API;

/// Wrapper to pass raw I420 data directly to openh264 encoder.
struct RawI420<'a> {
    data: &'a [u8],
    width: usize,
    height: usize,
}

impl<'a> YUVSource for RawI420<'a> {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    fn strides(&self) -> (usize, usize, usize) {
        (self.width, self.width / 2, self.width / 2)
    }
    fn y(&self) -> &[u8] {
        &self.data[..self.width * self.height]
    }
    fn u(&self) -> &[u8] {
        let y_size = self.width * self.height;
        let uv_size = (self.width / 2) * (self.height / 2);
        &self.data[y_size..y_size + uv_size]
    }
    fn v(&self) -> &[u8] {
        let y_size = self.width * self.height;
        let uv_size = (self.width / 2) * (self.height / 2);
        &self.data[y_size + uv_size..y_size + uv_size * 2]
    }
}

/// Decoded YUV frame ready for display.
pub struct DecodedFrame {
    pub width: u32,
    pub height: u32,
    /// I420 planar data: Y (w*h) + U (w*h/4) + V (w*h/4)
    pub data: Vec<u8>,
}

/// H.264 encoder wrapper.
pub struct H264Encoder {
    encoder: Encoder,
    width: u32,
    height: u32,
}

impl H264Encoder {
    /// Create a new encoder for the given resolution.
    pub fn new(width: u32, height: u32, fps: f32, bitrate_kbps: u32) -> Result<Self> {
        let api = OpenH264API::from_source();
        let config = EncoderConfig::new()
            .max_frame_rate(FrameRate::from_hz(fps))
            .bitrate(BitRate::from_bps(bitrate_kbps * 1000));

        let encoder =
            Encoder::with_api_config(api, config).context("Failed to create openh264 encoder")?;

        Ok(Self {
            encoder,
            width,
            height,
        })
    }

    /// Encode a raw I420 YUV frame into H.264 NAL units.
    ///
    /// Returns a Vec of NAL unit byte vectors (without start codes).
    /// The configured (width, height).
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    pub fn encode(&mut self, yuv_data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let expected_size = (self.width * self.height * 3 / 2) as usize;
        if yuv_data.len() < expected_size {
            anyhow::bail!(
                "YUV frame too small: {} bytes, expected {}",
                yuv_data.len(),
                expected_size
            );
        }

        let yuv = RawI420 {
            data: yuv_data,
            width: self.width as usize,
            height: self.height as usize,
        };

        let bitstream = self
            .encoder
            .encode(&yuv)
            .context("openh264 encode failed")?;

        // Extract NAL units from the encoded bitstream
        let mut nals = Vec::new();
        for layer_idx in 0..bitstream.num_layers() {
            let layer = bitstream.layer(layer_idx);
            if let Some(layer) = layer {
                for nal_idx in 0..layer.nal_count() {
                    if let Some(nal_data) = layer.nal_unit(nal_idx) {
                        // openh264 returns NAL units with start codes -- strip them
                        let nal = strip_start_code(nal_data);
                        if !nal.is_empty() {
                            nals.push(nal.to_vec());
                        }
                    }
                }
            }
        }

        Ok(nals)
    }
}

/// Encode one black access unit through the CALL'S encoder — the same
/// instance live content uses. Two independent encoders interleaving on
/// one SSRC produce two unrelated reference chains and the receiver's
/// decoder rejects every P-slice with dsRefLost (live rigs 2026-10-20:
/// 3 frames decoded then permanent errors). The encoder is initialized
/// on first use so a no-source stream still flows.
pub fn encode_black_frame(encoder: &mut Option<H264Encoder>) -> Vec<Vec<u8>> {
    // A live encoder keeps its own resolution (a 1080p share must not
    // flap the encoder back to 320p on a no-source tick); fresh streams
    // start at camera size.
    const DEFAULT_W: u32 = 320;
    const DEFAULT_H: u32 = 240;
    if encoder.is_none() {
        match H264Encoder::new(DEFAULT_W, DEFAULT_H, 15.0, 256) {
            Ok(e) => *encoder = Some(e),
            Err(e) => {
                tracing::warn!("black-frame encoder init failed: {e:#}");
                return Vec::new();
            }
        }
    }
    let (w, h) = encoder
        .as_ref()
        .map(|e| e.dimensions())
        .unwrap_or((DEFAULT_W, DEFAULT_H));
    match encoder.as_mut().map(|enc| enc.encode(&black_i420(w, h))) {
        Some(Ok(nals)) => nals,
        Some(Err(e)) => {
            tracing::debug!("black-frame encode error: {e:#}");
            Vec::new()
        }
        None => Vec::new(),
    }
}

/// A black I420 frame with CORRECT neutral chroma: Y=0, U=V=128. An
/// all-zero buffer is not video black — zero chroma converts to solid
/// RGB(0,135,0) GREEN on every YUV→RGB renderer (live-verified: the
/// caller's remote tile was a uniform green field).
pub fn black_i420(w: u32, h: u32) -> Vec<u8> {
    let mut buf = vec![0u8; (w * h * 3 / 2) as usize];
    let uv_off = (w * h) as usize;
    for b in &mut buf[uv_off..] {
        *b = 128;
    }
    buf
}

/// H.264 decoder wrapper.
pub struct H264Decoder {
    decoder: Decoder,
}

impl H264Decoder {
    pub fn new() -> Result<Self> {
        let api = OpenH264API::from_source();
        let decoder = Decoder::with_api_config(api, DecoderConfig::new())
            .context("Failed to create openh264 decoder")?;
        Ok(Self { decoder })
    }

    /// Decode a single H.264 NAL unit.
    ///
    /// Returns a decoded YUV frame if the decoder produced output, None if
    /// it needs more data (e.g., SPS/PPS before IDR).
    pub fn decode(&mut self, nal: &[u8]) -> Result<Option<DecodedFrame>> {
        // openh264 expects NAL units with Annex B start codes
        let mut annexb = vec![0x00, 0x00, 0x00, 0x01];
        annexb.extend_from_slice(nal);

        match self.decoder.decode(&annexb) {
            Ok(Some(yuv)) => {
                let (w, h) = yuv.dimensions();
                let (y_stride, u_stride, v_stride) = yuv.strides();

                // Extract I420 planes
                let y_size = w * h;
                let uv_size = (w / 2) * (h / 2);
                let mut data = vec![0u8; y_size + uv_size * 2];

                // Copy Y plane (stride may be wider than width due to padding)
                for row in 0..h {
                    let src_start = row * y_stride;
                    let dst_start = row * w;
                    data[dst_start..dst_start + w]
                        .copy_from_slice(&yuv.y()[src_start..src_start + w]);
                }

                // Copy U plane
                let half_w = w / 2;
                let half_h = h / 2;
                for row in 0..half_h {
                    let src_start = row * u_stride;
                    let dst_start = y_size + row * half_w;
                    data[dst_start..dst_start + half_w]
                        .copy_from_slice(&yuv.u()[src_start..src_start + half_w]);
                }

                // Copy V plane
                for row in 0..half_h {
                    let src_start = row * v_stride;
                    let dst_start = y_size + uv_size + row * half_w;
                    data[dst_start..dst_start + half_w]
                        .copy_from_slice(&yuv.v()[src_start..src_start + half_w]);
                }

                Ok(Some(DecodedFrame {
                    width: w as u32,
                    height: h as u32,
                    data,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                let ty = nal.first().map(|b| b & 0x1F).unwrap_or(99);
                tracing::debug!(
                    "openh264 decode error (NAL type {ty}, {} bytes): {:?}",
                    nal.len(),
                    e
                );
                Ok(None) // Don't bail -- decoder may recover on next NAL
            }
        }
    }
}

/// Strip Annex B start codes (0x00 0x00 0x01 or 0x00 0x00 0x00 0x01) from NAL data.
fn strip_start_code(data: &[u8]) -> &[u8] {
    if data.starts_with(&[0x00, 0x00, 0x00, 0x01]) {
        &data[4..]
    } else if data.starts_with(&[0x00, 0x00, 0x01]) {
        &data[3..]
    } else {
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full wire-path roundtrip: encode -> X-H264UC packetization ->
    /// depacketize -> decode. The packetizer injects PACSI (30) and
    /// prefix (14) SVC container NALs; openh264 REJECTS those with
    /// persistent bitstream errors that kill every P-frame after the
    /// IDR (live rigs 2026-10-20: ~5000 decode errors, zero rendered
    /// frames) — the receive path must skip them before decoding.
    #[test]
    fn encode_packetize_depacketize_decode_roundtrip() {
        let w = 320u32;
        let h = 240u32;
        let mut enc = H264Encoder::new(w, h, 15.0, 256).expect("encoder");
        let mut dec = H264Decoder::new().expect("decoder");
        let mut packetizer = crate::calling::video::VideoPacketizer::new(0x1234);
        let mut depacketizer = crate::calling::video::VideoDepacketizer::new();

        let mut decoded_frames = 0usize;
        for frame_idx in 0..4 {
            let mut yuv = vec![0u8; (w * h * 3 / 2) as usize];
            // Vary content per frame so P-frames carry data.
            yuv.iter_mut()
                .for_each(|b| *b = (frame_idx * 37 + *b as usize % 200) as u8);
            let nals = enc.encode(&yuv).expect("encode");
            assert!(!nals.is_empty(), "encoder produced no NALs");
            let packets = packetizer.packetize_frame(&nals);
            assert!(!packets.is_empty());
            for pkt in &packets {
                let marker = pkt[1] & 0x80 != 0;
                let payload = &pkt[crate::calling::rtp::RTP_HEADER_SIZE..];
                if let Ok(Some(nal)) = depacketizer.depacketize(payload, marker) {
                    let ty = nal[0] & 0x1F;
                    if matches!(ty, 14 | 30) {
                        continue;
                    }
                    if let Ok(Some(_frame)) = dec.decode(&nal) {
                        decoded_frames += 1;
                    }
                }
            }
        }
        assert!(
            decoded_frames >= 3,
            "expected >=3 decoded frames over 4 encoded (1-frame decoder latency), got {decoded_frames}"
        );
    }
}

#[cfg(test)]
mod black_stream_tests {
    use super::*;

    /// The black-frame fallback stream (all-IDR, no P-frames) through the
    /// packetizer — the rig shape when no camera source delivers. Live
    /// 2026-10-20: only the FIRST frame decoded, then dsNoParam|dsRefLost
    /// on every following IDR.
    #[test]
    fn black_iframe_stream_decodes() {
        let mut dec = H264Decoder::new().expect("decoder");
        let mut packetizer = crate::calling::video::VideoPacketizer::new(0x1234);
        let mut depacketizer = crate::calling::video::VideoDepacketizer::new();
        let mut decoded = 0usize;
        for _round in 0..6 {
            let nals = crate::calling::video::generate_black_iframe();
            for pkt in &packetizer.packetize_frame(&nals) {
                let marker = pkt[1] & 0x80 != 0;
                let payload = &pkt[crate::calling::rtp::RTP_HEADER_SIZE..];
                if let Ok(Some(nal)) = depacketizer.depacketize(payload, marker) {
                    if matches!(nal[0] & 0x1F, 14 | 30) {
                        continue;
                    }
                    if let Ok(Some(_f)) = dec.decode(&nal) {
                        decoded += 1;
                    }
                }
            }
        }
        // The hand-rolled bitstream is documented decoder-hostile here —
        // this asserts the SYMPTOM so a future regeneration that fixes it
        // updates the test. The encoder-backed source below is the fix.
        assert!(decoded == 0, "hand-rolled stream now decodes? {decoded}/6 — switch the fallback back");
    }

    /// The same-encoder fallback decodes frame after frame (one
    /// reference chain, no interleaving).
    #[test]
    fn encoder_backed_black_stream_decodes() {
        let mut dec = H264Decoder::new().expect("decoder");
        let mut packetizer = crate::calling::video::VideoPacketizer::new(0x1234);
        let mut depacketizer = crate::calling::video::VideoDepacketizer::new();
        let mut encoder: Option<H264Encoder> = None;
        let mut decoded = 0usize;
        for _round in 0..6 {
            let nals = encode_black_frame(&mut encoder);
            assert!(!nals.is_empty(), "fallback produced no NALs");
            for pkt in &packetizer.packetize_frame(&nals) {
                let marker = pkt[1] & 0x80 != 0;
                let payload = &pkt[crate::calling::rtp::RTP_HEADER_SIZE..];
                if let Ok(Some(nal)) = depacketizer.depacketize(payload, marker) {
                    if matches!(nal[0] & 0x1F, 14 | 30) {
                        continue;
                    }
                    if let Ok(Some(_f)) = dec.decode(&nal) {
                        decoded += 1;
                    }
                }
            }
        }
        assert!(decoded >= 4, "only {decoded}/6 black frames decoded");
    }
}
