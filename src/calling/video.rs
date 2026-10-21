//! H.264 RTP packetization (RFC 6184 + RFC 6190 SVC extensions) and black frame generation.
//!
//! Implements X-H264UC packetization per MS-H264PF:
//! - PACSI NAL unit (type 30) with Stream Layout SEI and Bitstream Info SEI
//! - Prefix NAL units (type 14) before coded slices
//! - Single NAL Unit mode and FU-A fragmentation

use anyhow::{bail, Result};

/// H.264 payload type (dynamic, matching our SDP).
pub const PT_H264: u8 = 122;

/// STAP-A aggregation NAL type (RFC 6184).
pub const NAL_TYPE_STAP_A: u8 = 24;

/// A raw I420 video frame handed across the embedder boundary (decoded
/// remote video, or the local camera preview). Deliberately feature-gate
/// free so call controls can reference it unconditionally.
#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub width: u32,
    pub height: u32,
    /// Planar I420: Y (w*h) + U (w*h/4) + V (w*h/4).
    pub data: Vec<u8>,
}

impl VideoFrame {
    /// Convert to packed RGBA8 (unmultiplied) for GPU textures / egui.
    pub fn to_rgba(&self) -> Vec<u8> {
        let w = self.width as usize;
        let h = self.height as usize;
        let y = &self.data[..w * h];
        let (u, v) = (&self.data[w * h..w * h + w * h / 4], &self.data[w * h + w * h / 4..]);
        let mut rgba = vec![0u8; w * h * 4];
        for row in 0..h {
            for col in 0..w {
                let yi = row * w + col;
                let ci = (row / 2) * (w / 2) + (col / 2);
                // ITU-R BT.601 full-range, standard integer form.
                let c = y[yi] as i32 - 16;
                let d = u[ci] as i32 - 128;
                let e = v[ci] as i32 - 128;
                let r = (298 * c + 409 * e + 128) >> 8;
                let g = (298 * c - 100 * d - 208 * e + 128) >> 8;
                let b = (298 * c + 516 * d + 128) >> 8;
                let o = yi * 4;
                rgba[o] = r.clamp(0, 255) as u8;
                rgba[o + 1] = g.clamp(0, 255) as u8;
                rgba[o + 2] = b.clamp(0, 255) as u8;
                rgba[o + 3] = 255;
            }
        }
        rgba
    }

    /// Box-filtered downscale so the UI never converts/uploads
    /// screen-sized frames (a 1280x720 share at 15 repaints/s is
    /// ~55MB/s of RGBA on software GL — the stage starves, live
    /// 2026-10-20). Integer factor chosen so the result is at most
    /// `max_w` wide; returns `self` (cheap clone) when already small
    /// enough or when the factor would not divide the frame evenly.
    pub fn downscaled(&self, max_w: u32) -> Self {
        if self.width == 0 || self.height == 0 || self.width <= max_w {
            return self.clone();
        }
        let mut f = 1u32;
        while self.width / (f * 2) >= max_w && self.width % (f * 2) == 0 && self.height % (f * 2) == 0 {
            f *= 2;
        }
        if f == 1 {
            // Odd dimensions (a 1921x1080 portal capture) never hit an
            // even factor — nearest-neighbor resample instead of
            // bypassing the cap (the bypass re-triggered the software-GL
            // starvation the cap shipped to fix).
            return self.resampled(max_w);
        }
        let (w, h) = (self.width as usize, self.height as usize);
        let (ow, oh) = (w / f as usize, h / f as usize);
        let (y, uv) = self.data.split_at(w * h);
        let (u, v) = uv.split_at(w * h / 4);
        let (uw, _uh) = (w / 2, h / 2);
        let mut out = vec![0u8; ow * oh * 3 / 2];
        let (oy_plane, ouv) = out.split_at_mut(ow * oh);
        let (ou, ov) = ouv.split_at_mut(ow * oh / 4);
        let fu = f as usize;
        for row in 0..oh {
            for col in 0..ow {
                let mut acc = 0u32;
                for dy in 0..fu {
                    for dx in 0..fu {
                        acc += y[(row * fu + dy) * w + col * fu + dx] as u32;
                    }
                }
                oy_plane[row * ow + col] = (acc / (fu * fu) as u32) as u8;
            }
        }
        // UV is half-resolution: the source block is (fu/2)^2 samples.
        let cu = fu / 2;
        let plane = |src: &[u8], dst: &mut [u8]| {
            for row in 0..oh / 2 {
                for col in 0..ow / 2 {
                    let mut acc = 0u32;
                    for dy in 0..cu {
                        for dx in 0..cu {
                            acc += src[(row * cu + dy) * uw + col * cu + dx] as u32;
                        }
                    }
                    dst[row * (ow / 2) + col] = (acc / (cu * cu) as u32) as u8;
                }
            }
        };
        plane(u, ou);
        plane(v, ov);
        VideoFrame {
            width: ow as u32,
            height: oh as u32,
            data: out,
        }
    }

    /// Nearest-neighbor resample to at most `max_w` wide (aspect kept).
    fn resampled(&self, max_w: u32) -> Self {
        let nw = max_w.min(self.width);
        let nh = ((self.height as u64 * nw as u64) / self.width as u64).max(1) as u32;
        let (w, h) = (self.width as usize, self.height as usize);
        let (ow, oh) = (nw as usize, nh as usize);
        let (y, uv) = self.data.split_at(w * h);
        let (u, v) = uv.split_at(w * h / 4);
        let mut out = vec![0u8; ow * oh * 3 / 2];
        let (oy, ouv) = out.split_at_mut(ow * oh);
        let (ou, ov) = ouv.split_at_mut(ow * oh / 4);
        for row in 0..oh {
            let sy = row * h / oh;
            for col in 0..ow {
                oy[row * ow + col] = y[sy * w + col * w / ow];
            }
        }
        for row in 0..oh / 2 {
            let su = row * (h / 2) / (oh / 2);
            for col in 0..ow / 2 {
                let i = su * (w / 2) + col * (w / 2) / (ow / 2);
                let d = row * (ow / 2) + col;
                ou[d] = u[i];
                ov[d] = v[i];
            }
        }
        VideoFrame {
            width: nw,
            height: nh,
            data: out,
        }
    }

    /// Flat gray frame of the given size (test/QA helper): Y = level,
    /// neutral chroma.
    pub fn gray(w: u32, h: u32, level: u8) -> Self {
        let y_size = (w * h) as usize;
        let mut data = vec![128u8; y_size + y_size / 2];
        data[..y_size].fill(level);
        Self { width: w, height: h, data }
    }
}

/// Video clock rate (90 kHz per RTP spec for video).
pub const CLOCK_RATE: u32 = 90000;

#[cfg(test)]
mod frame_tests {
    use super::VideoFrame;

    #[test]
    fn gray_to_rgba_matches_bt601() {
        // Neutral chroma (U=V=128) maps Y straight to RGB via BT.601.
        for level in [16u8, 64, 128, 235] {
            let f = VideoFrame::gray(8, 4, level);
            assert_eq!(f.data.len(), 8 * 4 + 8 * 4 / 2);
            let rgba = f.to_rgba();
            assert_eq!(rgba.len(), 8 * 4 * 4);
            let expected = {
                let c = level as i32 - 16;
                ((298 * c + 128) >> 8).clamp(0, 255) as u8
            };
            for px in rgba.chunks_exact(4) {
                assert_eq!(px[0], expected);
                assert_eq!(px[1], expected);
                assert_eq!(px[2], expected);
                assert_eq!(px[3], 255);
            }
        }
    }

    #[test]
    fn chroma_blue_tints_b_up() {
        // U=240 pulls blue up, red down (BT.601).
        let mut f = VideoFrame::gray(2, 2, 128);
        let uv_start = (2 * 2) as usize;
        for b in f.data[uv_start..uv_start + 1].iter_mut() {
            *b = 240;
        }
        let rgba = f.to_rgba();
        let (b_chan, r_chan) = (rgba[2], rgba[0]);
        assert!(b_chan > r_chan, "blue={} red={}", b_chan, r_chan);
    }
}

/// Maximum RTP payload size before fragmentation.
pub const MTU: usize = 1200;

/// Frame interval for 15 fps in clock ticks (90000 / 15 = 6000).
pub const FRAME_INTERVAL_TICKS: u32 = 6000;

/// Frame interval in milliseconds (1000 / 15 ~= 67ms).
pub const FRAME_INTERVAL_MS: u64 = 67;

/// X-H264UC reserves 100 SSRCs for temporal/spatial SVC layers (T0-T3, L0-L2).
pub const VIDEO_SSRC_RANGE_SIZE: u32 = 100;

/// Generate a random SSRC via OS CSPRNG.
pub fn generate_ssrc() -> u32 {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG failed");
    u32::from_be_bytes(buf)
}

// H.264 NAL unit types
const NAL_TYPE_SLICE: u8 = 1;
const NAL_TYPE_IDR: u8 = 5;
const NAL_TYPE_SPS: u8 = 7;
const NAL_TYPE_PPS: u8 = 8;
const NAL_TYPE_PREFIX: u8 = 14;
const NAL_TYPE_FU_A: u8 = 28;
const NAL_TYPE_PACSI: u8 = 30;

// FU-A header bits
const FU_START_BIT: u8 = 0x80;
const FU_END_BIT: u8 = 0x40;

/// Stream Layout SEI UUID: {139FB1A9-446A-4DEC-8CBF-65B1E12D2CFD}
const STREAM_LAYOUT_UUID: [u8; 16] = [
    0x13, 0x9F, 0xB1, 0xA9, 0x44, 0x6A, 0x4D, 0xEC, 0x8C, 0xBF, 0x65, 0xB1, 0xE1, 0x2D, 0x2C, 0xFD,
];

/// Bitstream Info SEI UUID: {05FBC6B9-5A80-40E5-A22A-AB4020267E26}
const BITSTREAM_INFO_UUID: [u8; 16] = [
    0x05, 0xFB, 0xC6, 0xB9, 0x5A, 0x80, 0x40, 0xE5, 0xA2, 0x2A, 0xAB, 0x40, 0x20, 0x26, 0x7E, 0x26,
];

/// Video stream configuration for PACSI generation.
#[derive(Clone, Debug)]
pub struct SvcConfig {
    pub coded_width: u16,
    pub coded_height: u16,
    pub display_width: u16,
    pub display_height: u16,
    pub bitrate: u32,
    pub fps_idx: u8, // 0=7.5, 1=12.5, 2=15, 3=25, 4=30
    pub constrained_baseline: bool,
}

impl Default for SvcConfig {
    fn default() -> Self {
        Self {
            coded_width: 320,
            coded_height: 240,
            display_width: 320,
            display_height: 240,
            bitrate: 256000,
            fps_idx: 2, // 15 fps
            constrained_baseline: true,
        }
    }
}

/// Build the Stream Layout SEI message payload (everything after the NAL header byte).
///
/// This is a User Data Unregistered SEI (payloadType=5) containing:
/// - 16-byte UUID
/// - 8-byte Layer Presence Bitmask (bit 0 set for PRID=0)
/// - 1-byte flags (R=0, P=1)
/// - 1-byte LDSize (16)
/// - 16-byte Layer Description
fn build_stream_layout_sei(cfg: &SvcConfig) -> Vec<u8> {
    // Layer Description: 16 bytes
    let mut layer_desc = Vec::with_capacity(16);
    layer_desc.extend_from_slice(&cfg.coded_width.to_be_bytes());
    layer_desc.extend_from_slice(&cfg.coded_height.to_be_bytes());
    layer_desc.extend_from_slice(&cfg.display_width.to_be_bytes());
    layer_desc.extend_from_slice(&cfg.display_height.to_be_bytes());
    layer_desc.extend_from_slice(&cfg.bitrate.to_be_bytes());
    // FPSIdx (5 bits) | LT (3 bits) | PRID (6 bits) | CB (1 bit) | R (1 bit) | R2 (2 bytes)
    let byte12 = (cfg.fps_idx << 3) | 0x00; // FPSIdx in top 5 bits, LT=0 (base) in bottom 3
    let byte13 = 0x00 | if cfg.constrained_baseline { 0x02 } else { 0x00 };
    // PRID=0 in top 6 bits, CB in bit 1, R=0 in bit 0
    layer_desc.push(byte12);
    layer_desc.push(byte13);
    layer_desc.push(0x00); // R2 byte 1
    layer_desc.push(0x00); // R2 byte 2

    // SEI payload = UUID(16) + LPB(8) + flags(1) + LDSize(1) + LayerDesc(16) = 42 bytes
    let payload_size: u8 = 16 + 8 + 1 + 1 + 16; // 42

    let mut sei = Vec::with_capacity(2 + payload_size as usize);
    sei.push(5u8); // payloadType = 5 (User Data Unregistered)
    sei.push(payload_size); // payloadSize
    sei.extend_from_slice(&STREAM_LAYOUT_UUID);
    // Layer Presence Bitmask: 8 bytes. LPB0 bit 0 = PRID 0 present
    sei.push(0x01); // LPB0: bit 0 set (PRID=0 present)
    sei.push(0x00); // LPB1
    sei.push(0x00); // LPB2
    sei.push(0x00); // LPB3
    sei.push(0x00); // LPB4
    sei.push(0x00); // LPB5
    sei.push(0x00); // LPB6
    sei.push(0x00); // LPB7
    sei.push(0x01); // R(7 bits)=0, P=1 (layer description present)
    sei.push(16u8); // LDSize = 16
    sei.extend_from_slice(&layer_desc);

    sei
}

/// Build the Bitstream Info SEI message payload (everything after the NAL header byte).
///
/// payloadType=5, UUID, ref_frm_cnt, num_of_nal_unit.
fn build_bitstream_info_sei(ref_frm_cnt: u8, num_nal_units: u8) -> Vec<u8> {
    let payload_size: u8 = 18; // UUID(16) + ref_frm_cnt(1) + num_of_nal_unit(1)

    let mut sei = Vec::with_capacity(2 + payload_size as usize);
    sei.push(5u8); // payloadType = 5
    sei.push(payload_size); // payloadSize
    sei.extend_from_slice(&BITSTREAM_INFO_UUID);
    sei.push(ref_frm_cnt);
    sei.push(num_nal_units);

    sei
}

/// Build the 3-byte SVC extension header per RFC 6190.
///
///   Byte 0: R(1)=1 | I(1)=idr_flag | PRID(6)=0
///   Byte 1: N(1)=1 | DID(3)=0 | QID(4)=0
///   Byte 2: TID(3)=0 | U(1)=0 | D(1)=0 | O(1)=1 | RR(2)=3
fn svc_extension_bytes(is_idr: bool) -> [u8; 3] {
    [
        0x80 | if is_idr { 0x40 } else { 0x00 }, // R=1, I=idr_flag, PRID=0
        0x80,                                    // N=1, DID=0, QID=0
        0x07,                                    // TID=0, U=0, D=0, O=1, RR=3
    ]
}

/// Build a complete PACSI NAL unit (type 30) containing Stream Layout and Bitstream Info SEIs.
///
/// Structure:
///   Byte 0:    NAL header (F=0, NRI=3, Type=30)
///   Bytes 1-3: SVC extension header (for base layer)
///   Remaining: SEI NAL unit (type 6) containing both SEI messages
///
/// The SEI messages are wrapped in a NAL type 6 unit embedded inside the PACSI.
/// Per MS-H264PF, no emulation prevention bytes are inserted.
fn build_pacsi_nal(cfg: &SvcConfig, ref_frm_cnt: u8, num_nal_units: u8, has_idr: bool) -> Vec<u8> {
    let mut pacsi = Vec::with_capacity(128);

    // PACSI NAL header: F=0, NRI=3 (high priority), Type=30
    pacsi.push(0x60 | NAL_TYPE_PACSI); // 0x7E

    // SVC extension header (3 bytes)
    pacsi.extend_from_slice(&svc_extension_bytes(has_idr));

    // Embedded SEI NAL unit: NAL header (type 6) + SEI messages
    // SEI NAL units have NRI=0 per H.264 spec (non-reference)
    pacsi.push(0x06); // F=0, NRI=0, Type=6

    // Stream Layout SEI message
    let stream_layout = build_stream_layout_sei(cfg);
    pacsi.extend_from_slice(&stream_layout);

    // Bitstream Info SEI message
    let bitstream_info = build_bitstream_info_sei(ref_frm_cnt, num_nal_units);
    pacsi.extend_from_slice(&bitstream_info);

    pacsi
}

/// Build a prefix NAL unit (type 14) to prepend before a coded slice NAL.
///
/// Structure (4 bytes total):
///   Byte 0:    NAL header: F=0, NRI=same as slice, Type=14
///   Bytes 1-3: SVC extension header
fn build_prefix_nal(slice_nal_header: u8, is_idr: bool) -> Vec<u8> {
    let nri = slice_nal_header & 0x60;

    let header = nri | NAL_TYPE_PREFIX;
    let svc = svc_extension_bytes(is_idr);
    vec![header, svc[0], svc[1], svc[2]]
}

/// Packetizes H.264 NAL units into RTP payloads with X-H264UC SVC wrapping.
///
/// For each frame:
/// 1. Sends a PACSI NAL unit (type 30) as the first RTP packet
/// 2. Sends SPS/PPS NAL units as-is (single NAL mode)
/// 3. Prepends a prefix NAL unit (type 14) before each coded slice, then
///    sends the slice via single NAL or FU-A fragmentation
#[cfg(test)]
mod downscale_tests {
    use super::*;

    #[test]
    fn downscale_720p_to_640_caps_and_preserves_color() {
        // Red frame (Y=82 U=90 V=240 BT.601 full-range) at 1280x720.
        let (w, h) = (1280u32, 720u32);
        let mut data = vec![0u8; (w * h * 3 / 2) as usize];
        for b in &mut data[..(w * h) as usize] {
            *b = 82;
        }
        let uv_off = (w * h) as usize;
        let uv_len = (w * h / 4) as usize;
        for i in 0..uv_len {
            data[uv_off + i] = 90;
            data[uv_off + uv_len + i] = 240;
        }
        let f = VideoFrame { width: w, height: h, data };
        let d = f.downscaled(640);
        assert_eq!((d.width, d.height), (640, 360));
        assert_eq!(d.data.len(), (640 * 360 * 3 / 2) as usize);
        // Flat input stays flat through the box filter.
        assert!(d.data[..(640 * 360) as usize].iter().all(|&b| b == 82));
        assert!(d.data[(640 * 360) as usize..].iter().all(|&b| b == 90 || b == 240));
        // Small frames pass through untouched (same dims).
        let small = VideoFrame { width: 320, height: 240, data: vec![16; 320 * 240 * 3 / 2] };
        assert_eq!(small.downscaled(640).width, 320);
        // Odd widths still cap (nearest-neighbor fallback — the even-
        // factor loop used to bypass the cap entirely).
        let odd = VideoFrame { width: 1921, height: 1080, data: vec![16; 1921 * 1080 * 3 / 2] };
        let d = odd.downscaled(640);
        assert_eq!(d.width, 640);
        let expect_h = ((1080u64 * 640) / 1921) as u32; // floor aspect
        assert_eq!(d.height, expect_h);
        assert_eq!(d.data.len(), (640 * expect_h as usize * 3 / 2));
    }
}

pub struct VideoPacketizer {
    ssrc: u32,
    seq: u16,
    timestamp: u32,
    ref_frm_cnt: u8,
    svc_config: SvcConfig,
}

impl VideoPacketizer {
    pub fn new(ssrc: u32) -> Self {
        let mut buf = [0u8; 1];
        getrandom::getrandom(&mut buf).expect("OS CSPRNG failed");
        Self {
            ssrc,
            seq: 0,
            timestamp: 0,
            ref_frm_cnt: buf[0], // MS-H264PF: initial value is random
            svc_config: SvcConfig::default(),
        }
    }

    pub fn with_config(ssrc: u32, config: SvcConfig) -> Self {
        let mut buf = [0u8; 1];
        getrandom::getrandom(&mut buf).expect("OS CSPRNG failed");
        Self {
            ssrc,
            seq: 0,
            timestamp: 0,
            ref_frm_cnt: buf[0], // MS-H264PF: initial value is random
            svc_config: config,
        }
    }

    /// Packetize a single H.264 access unit (frame) consisting of multiple NAL units.
    ///
    /// Wraps the frame in X-H264UC SVC containers:
    /// - PACSI NAL (type 30) sent first with Stream Layout + Bitstream Info SEIs
    /// - Prefix NAL (type 14) before each coded slice (types 1, 5)
    ///
    /// Returns a list of complete RTP packets (header + payload) ready for SRTP.
    /// The marker bit is set on the last packet of the access unit.
    pub fn packetize_frame(&mut self, nal_units: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        // Count NAL units and detect IDR for PACSI
        let has_idr = nal_units
            .iter()
            .any(|n| !n.is_empty() && (n[0] & 0x1F) == NAL_TYPE_IDR);

        // Count non-empty NAL units for bitstream info (empty NALs are skipped).
        let num_nal_units = nal_units.iter().filter(|n| !n.is_empty()).count().min(255) as u8;

        // Build and send PACSI as first packet (never marker, never last)
        let pacsi = build_pacsi_nal(&self.svc_config, self.ref_frm_cnt, num_nal_units, has_idr);
        packets.push(self.build_rtp_packet(&pacsi, false));

        // Process each NAL unit
        let total_nals = nal_units.len();
        for (i, nal) in nal_units.iter().enumerate() {
            if nal.is_empty() {
                continue;
            }
            let is_last_nal = i == total_nals - 1;
            let nal_type = nal[0] & 0x1F;

            match nal_type {
                NAL_TYPE_SLICE | NAL_TYPE_IDR => {
                    // Send prefix NAL (type 14) before the slice — never marker
                    let prefix = build_prefix_nal(nal[0], nal_type == NAL_TYPE_IDR);
                    packets.push(self.build_rtp_packet(&prefix, false));

                    // Send the slice itself
                    let mut slice_packets = self.packetize_nal(nal, is_last_nal);
                    packets.append(&mut slice_packets);
                }
                _ => {
                    // SPS, PPS, SEI, etc. — send as-is
                    let mut nal_packets = self.packetize_nal(nal, is_last_nal);
                    packets.append(&mut nal_packets);
                }
            }
        }

        // Increment ref_frm_cnt for reference frames (NRI != 0 on any NAL)
        // All IDR frames and most P-frames are reference frames.
        let is_reference = nal_units
            .iter()
            .any(|n| !n.is_empty() && (n[0] & 0x60) != 0);
        if is_reference {
            self.ref_frm_cnt = self.ref_frm_cnt.wrapping_add(1);
        }

        self.timestamp = self.timestamp.wrapping_add(FRAME_INTERVAL_TICKS);
        packets
    }

    /// Packetize a single NAL unit. If `is_last` is true, the marker bit is set
    /// on the final RTP packet.
    fn packetize_nal(&mut self, nal: &[u8], is_last: bool) -> Vec<Vec<u8>> {
        if nal.is_empty() {
            return Vec::new();
        }

        if nal.len() <= MTU {
            // Single NAL Unit mode
            let marker = is_last;
            let pkt = self.build_rtp_packet(nal, marker);
            vec![pkt]
        } else {
            // FU-A fragmentation
            self.fragment_nal(nal, is_last)
        }
    }

    /// Fragment a large NAL unit using FU-A.
    fn fragment_nal(&mut self, nal: &[u8], is_last_nal: bool) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let nal_header = nal[0];
        let nri = nal_header & 0x60; // NRI bits
        let nal_type = nal_header & 0x1F;

        // FU indicator: same NRI, type = 28 (FU-A)
        let fu_indicator = (nal_header & 0x80) | nri | NAL_TYPE_FU_A;

        let payload_data = &nal[1..]; // Skip the NAL header byte
        let max_fragment = MTU - 2; // 2 bytes for FU indicator + FU header
        let mut offset = 0;

        while offset < payload_data.len() {
            let remaining = payload_data.len() - offset;
            let chunk_size = remaining.min(max_fragment);
            let is_first = offset == 0;
            let is_last_fragment = offset + chunk_size >= payload_data.len();

            let mut fu_header = nal_type;
            if is_first {
                fu_header |= FU_START_BIT;
            }
            if is_last_fragment {
                fu_header |= FU_END_BIT;
            }

            let mut payload = Vec::with_capacity(2 + chunk_size);
            payload.push(fu_indicator);
            payload.push(fu_header);
            payload.extend_from_slice(&payload_data[offset..offset + chunk_size]);

            let marker = is_last_nal && is_last_fragment;
            packets.push(self.build_rtp_packet(&payload, marker));

            offset += chunk_size;
        }

        packets
    }

    fn build_rtp_packet(&mut self, payload: &[u8], marker: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(super::rtp::RTP_HEADER_SIZE + payload.len());

        // Byte 0: V=2, P=0, X=0, CC=0 -> 0x80
        buf.push(0x80);
        // Byte 1: M bit + PT
        let byte1 = if marker { 0x80 | PT_H264 } else { PT_H264 };
        buf.push(byte1);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.extend_from_slice(payload);

        self.seq = self.seq.wrapping_add(1);
        buf
    }
}

/// Reassembles H.264 NAL units from RTP packets.
pub struct VideoDepacketizer {
    /// Partial FU-A reassembly buffer.
    fu_buffer: Vec<u8>,
    /// Whether we are currently reassembling a FU-A NAL.
    fu_in_progress: bool,
    /// NALs decoded from a STAP-A aggregation, pending delivery (one
    /// NAL per depacketize call).
    pending: std::collections::VecDeque<Vec<u8>>,
    /// Stats
    pub frames_received: u64,
    pub nals_received: u64,
}

impl VideoDepacketizer {
    pub fn new() -> Self {
        Self {
            fu_buffer: Vec::new(),
            fu_in_progress: false,
            pending: std::collections::VecDeque::new(),
            frames_received: 0,
            nals_received: 0,
        }
    }

    /// Process an RTP payload and return a complete NAL unit if one is ready.
    ///
    /// Returns `Ok(Some(nal))` when a complete NAL unit is assembled,
    /// `Ok(None)` when more fragments are needed, or `Err` on protocol error.
    pub fn depacketize(&mut self, rtp_payload: &[u8], marker: bool) -> Result<Option<Vec<u8>>> {
        if rtp_payload.is_empty() {
            bail!("empty RTP payload");
        }

        // STAP-A aggregates several NALs in one packet — deliver them one
        // per call from the pending queue.
        if let Some(nal) = self.pending.pop_front() {
            self.nals_received += 1;
            if marker && self.pending.is_empty() {
                self.frames_received += 1;
            }
            return Ok(Some(nal));
        }

        let nal_type = rtp_payload[0] & 0x1F;

        match nal_type {
            1..=23 | NAL_TYPE_PACSI => {
                // Single NAL unit mode (including PACSI type 30 which we pass through)
                self.nals_received += 1;
                if marker {
                    self.frames_received += 1;
                }
                Ok(Some(rtp_payload.to_vec()))
            }
            NAL_TYPE_STAP_A => self.depacketize_stap_a(rtp_payload, marker),
            NAL_TYPE_FU_A => self.depacketize_fu_a(rtp_payload, marker),
            _ => {
                // STAP-B (25), MTAP (26,27), FU-B (29) — not implemented
                tracing::debug!("Unsupported NAL aggregation type: {}", nal_type);
                Ok(None)
            }
        }
    }

    /// STAP-A (RFC 6184 §5.7.1): payload is (16-bit NAL size || NAL byte
    /// string)* after the aggregation header. Chrome bundles SPS+PPS
    /// (and small SEIs) this way; dropping them starves the decoder of
    /// parameter sets (live 2026-10-21: browser video decrypted fine,
    /// 0 frames decoded).
    fn depacketize_stap_a(&mut self, rtp_payload: &[u8], marker: bool) -> Result<Option<Vec<u8>>> {
        let mut off = 1; // skip the STAP-A NAL header byte
        while off + 2 <= rtp_payload.len() {
            let len = u16::from_be_bytes([rtp_payload[off], rtp_payload[off + 1]]) as usize;
            off += 2;
            if len == 0 || off + len > rtp_payload.len() {
                bail!("malformed STAP-A size field");
            }
            self.pending.push_back(rtp_payload[off..off + len].to_vec());
            off += len;
        }
        let first = self.pending.pop_front();
        self.nals_received += 1;
        if marker && self.pending.is_empty() {
            self.frames_received += 1;
        }
        Ok(first)
    }

    fn depacketize_fu_a(&mut self, payload: &[u8], marker: bool) -> Result<Option<Vec<u8>>> {
        if payload.len() < 2 {
            bail!("FU-A packet too short");
        }

        let fu_indicator = payload[0];
        let fu_header = payload[1];
        let is_start = fu_header & FU_START_BIT != 0;
        let is_end = fu_header & FU_END_BIT != 0;
        let nal_type = fu_header & 0x1F;
        let nri = fu_indicator & 0x60;

        // FU-A forensics (debug): IDR slices are ALWAYS FU-A at these
        // sizes; a systematically-dropped start fragment is invisible
        // without this (silent Ok(None) discard path below).
        if nal_type == 5 || tracing::enabled!(tracing::Level::TRACE) {
            tracing::debug!(
                "FU-A: type={nal_type} start={is_start} end={is_end} in_progress={} len={}",
                self.fu_in_progress,
                payload.len()
            );
        }

        if is_start {
            // Reconstruct the NAL header byte
            let nal_header = (fu_indicator & 0x80) | nri | nal_type;
            self.fu_buffer.clear();
            self.fu_buffer.push(nal_header);
            self.fu_buffer.extend_from_slice(&payload[2..]);
            self.fu_in_progress = true;
        } else if self.fu_in_progress {
            self.fu_buffer.extend_from_slice(&payload[2..]);
        } else {
            // Middle/end fragment without a start — discard
            return Ok(None);
        }

        if is_end {
            self.fu_in_progress = false;
            self.nals_received += 1;
            if marker {
                self.frames_received += 1;
            }
            let nal = std::mem::take(&mut self.fu_buffer);
            Ok(Some(nal))
        } else {
            Ok(None)
        }
    }
}

/// Generate a minimal black H.264 I-frame at 176x144 resolution.
///
/// Returns a list of NAL units: [SPS, PPS, IDR slice].
/// The IDR slice contains all-zero macroblocks (black).
///
/// This is a hardcoded bitstream — not generated dynamically.
/// Resolution: 176x144 (11x9 macroblocks = 99 MBs), Baseline profile.
pub fn generate_black_iframe() -> Vec<Vec<u8>> {
    // SPS: Baseline profile, level 1.2, 176x144
    // nal_unit_type = 7 (SPS)
    // profile_idc = 66 (Baseline)
    // constraint_set0_flag = 1, constraint_set1_flag = 1
    // level_idc = 12
    // seq_parameter_set_id = 0
    // log2_max_frame_num_minus4 = 0 (max_frame_num = 16)
    // pic_order_cnt_type = 2
    // max_num_ref_frames = 0
    // gaps_in_frame_num_value_allowed_flag = 0
    // pic_width_in_mbs_minus1 = 10 (176/16 - 1)
    // pic_height_in_map_units_minus1 = 8 (144/16 - 1)
    // frame_mbs_only_flag = 1
    let sps: Vec<u8> = vec![
        0x67, // NAL header: type 7 (SPS), NRI=3
        0x42, // profile_idc = 66 (Baseline)
        0xC0, // constraint_set0_flag=1, constraint_set1_flag=1
        0x0C, // level_idc = 12
        0xDA, // seq_parameter_set_id=0, log2_max_frame_num=0, pic_order_cnt_type=2
        0x0F, // max_num_ref_frames=0, gaps=0, pic_width=10 (exp-golomb)
        0x0A, // pic_height=8, frame_mbs_only=1
        0x68, // direct_8x8=0, vui_present=0, rbsp_stop_bit
    ];

    // PPS: pic_parameter_set_id=0, seq_parameter_set_id=0, entropy_coding=CAVLC
    let pps: Vec<u8> = vec![
        0x68, // NAL header: type 8 (PPS), NRI=3
        0xCE, // pps_id=0, sps_id=0, entropy=0(CAVLC), bottom_field_pic_order=0
        0x38, // num_slice_groups=0, num_ref_idx=0, weighted_pred=0
        0x80, // pic_init_qp=25, pic_init_qs=25, chroma_qp_offset=0, flags, stop
    ];

    // IDR slice (type 5): All-skip macroblocks = black
    let mut idr: Vec<u8> = vec![
        0x65, // NAL header: type 5 (IDR), NRI=3
        0x88, // first_mb_in_slice=0, slice_type=7(I), pps_id=0, frame_num=0
        0x80, // idr_pic_id=0
        0x40, // slice_qp_delta=0, then mb data begins
    ];

    for _ in 0..25 {
        idr.push(0xFF); // packed bits: mb_type + prediction modes
    }
    idr.push(0x80); // RBSP stop bit

    vec![sps, pps, idr]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packetize_small_nal() {
        let mut p = VideoPacketizer::new(0xAABBCCDD);
        let nal = vec![0x65, 0x00, 0x01, 0x02]; // small IDR
        let packets = p.packetize_frame(&[nal.clone()]);

        // Should have: PACSI + prefix + IDR = 3 packets
        assert_eq!(packets.len(), 3);

        // First packet should be PACSI (type 30)
        let pacsi_type = packets[0][12] & 0x1F;
        assert_eq!(pacsi_type, NAL_TYPE_PACSI);
        // PACSI should not have marker bit
        assert_eq!(packets[0][1] & 0x80, 0);

        // Second packet should be prefix NAL (type 14)
        let prefix_type = packets[1][12] & 0x1F;
        assert_eq!(prefix_type, NAL_TYPE_PREFIX);
        // Prefix should not have marker bit
        assert_eq!(packets[1][1] & 0x80, 0);

        // Third packet should be the IDR with marker
        assert_eq!(&packets[2][12..], &nal[..]);
        assert_eq!(packets[2][1], 0x80 | PT_H264); // marker set
    }

    #[test]
    fn test_packetize_large_nal_fragments() {
        let mut p = VideoPacketizer::new(0x12345678);
        // Create a NAL larger than MTU
        let mut nal = vec![0x65]; // IDR NAL header
        nal.extend(vec![0xAB; MTU + 500]);
        let packets = p.packetize_frame(&[nal]);

        // Should have: PACSI + prefix + FU-A fragments
        assert!(
            packets.len() > 3,
            "should have PACSI + prefix + multiple fragments"
        );

        // First packet: PACSI
        assert_eq!(packets[0][12] & 0x1F, NAL_TYPE_PACSI);

        // Second packet: prefix NAL
        assert_eq!(packets[1][12] & 0x1F, NAL_TYPE_PREFIX);

        // Third packet onward: FU-A fragments
        let fu_indicator = packets[2][12];
        assert_eq!(fu_indicator & 0x1F, NAL_TYPE_FU_A);
        let fu_header = packets[2][13];
        assert!(fu_header & FU_START_BIT != 0);

        // Last fragment should have FU-A end bit and marker
        let last = packets.last().unwrap();
        let fu_header_last = last[13];
        assert!(fu_header_last & FU_END_BIT != 0);
        assert_eq!(last[1], 0x80 | PT_H264); // marker set
    }

    #[test]
    fn test_packetize_sps_pps_no_prefix() {
        let mut p = VideoPacketizer::new(0xAABBCCDD);
        let sps = vec![0x67, 0x42, 0xC0, 0x0C];
        let pps = vec![0x68, 0xCE, 0x38, 0x80];
        let idr = vec![0x65, 0x88, 0x80, 0x40];
        let packets = p.packetize_frame(&[sps.clone(), pps.clone(), idr.clone()]);

        // PACSI + SPS + PPS + prefix + IDR = 5 packets
        assert_eq!(packets.len(), 5);

        // Packet 0: PACSI
        assert_eq!(packets[0][12] & 0x1F, NAL_TYPE_PACSI);
        // Packet 1: SPS (no prefix needed for type 7)
        assert_eq!(packets[1][12] & 0x1F, NAL_TYPE_SPS);
        // Packet 2: PPS (no prefix needed for type 8)
        assert_eq!(packets[2][12] & 0x1F, NAL_TYPE_PPS);
        // Packet 3: Prefix NAL before IDR
        assert_eq!(packets[3][12] & 0x1F, NAL_TYPE_PREFIX);
        // Packet 4: IDR with marker
        assert_eq!(packets[4][12] & 0x1F, NAL_TYPE_IDR);
        assert_eq!(packets[4][1], 0x80 | PT_H264);
    }

    #[test]
    fn test_depacketize_single_nal() {
        let mut d = VideoDepacketizer::new();
        let nal = vec![0x67, 0x42, 0xC0]; // SPS
        let result = d.depacketize(&nal, true).unwrap();
        assert_eq!(result.unwrap(), nal);
        assert_eq!(d.nals_received, 1);
        assert_eq!(d.frames_received, 1);
    }

    #[test]
    fn test_packetize_depacketize_roundtrip() {
        let mut p = VideoPacketizer::new(0x11223344);
        let mut d = VideoDepacketizer::new();

        // Create a large NAL that requires fragmentation
        let mut original_nal = vec![0x65]; // IDR
        original_nal.extend(vec![0x42; MTU + 100]);

        let packets = p.packetize_frame(&[original_nal.clone()]);
        // Skip PACSI (packet 0) and prefix (packet 1), depacketize FU-A fragments
        assert!(packets.len() > 3);

        let mut reassembled = None;
        for pkt in &packets[2..] {
            let marker = pkt[1] & 0x80 != 0;
            let payload = &pkt[12..]; // skip RTP header
            if let Some(nal) = d.depacketize(payload, marker).unwrap() {
                reassembled = Some(nal);
            }
        }

        assert_eq!(reassembled.unwrap(), original_nal);
    }

    #[test]
    fn test_generate_black_iframe() {
        let nals = generate_black_iframe();
        assert_eq!(nals.len(), 3);
        // SPS
        assert_eq!(nals[0][0] & 0x1F, NAL_TYPE_SPS);
        // PPS
        assert_eq!(nals[1][0] & 0x1F, NAL_TYPE_PPS);
        // IDR
        assert_eq!(nals[2][0] & 0x1F, NAL_TYPE_IDR);
    }

    #[test]
    fn test_sequence_numbers_increment() {
        let mut p = VideoPacketizer::new(0x00000001);
        let nal = vec![0x67, 0x42];
        let pkts1 = p.packetize_frame(&[nal.clone()]);
        let pkts2 = p.packetize_frame(&[nal.clone()]);

        // First frame: PACSI (seq 0) + SPS (seq 1) -> 2 packets
        // Second frame: PACSI (seq 2) + SPS (seq 3) -> 2 packets
        let seq_first = u16::from_be_bytes([pkts1[0][2], pkts1[0][3]]);
        let seq_last_frame1 =
            u16::from_be_bytes([pkts1.last().unwrap()[2], pkts1.last().unwrap()[3]]);
        let seq_first_frame2 = u16::from_be_bytes([pkts2[0][2], pkts2[0][3]]);
        assert_eq!(seq_first_frame2, seq_last_frame1 + 1);
        assert_eq!(seq_first, 0);
    }

    #[test]
    fn test_timestamp_increments_per_frame() {
        let mut p = VideoPacketizer::new(0x00000001);
        let nal = vec![0x67, 0x42];
        let pkts1 = p.packetize_frame(&[nal.clone()]);
        let pkts2 = p.packetize_frame(&[nal.clone()]);

        let ts1 = u32::from_be_bytes([pkts1[0][4], pkts1[0][5], pkts1[0][6], pkts1[0][7]]);
        let ts2 = u32::from_be_bytes([pkts2[0][4], pkts2[0][5], pkts2[0][6], pkts2[0][7]]);
        assert_eq!(ts2 - ts1, FRAME_INTERVAL_TICKS);
    }

    #[test]
    fn test_pacsi_nal_structure() {
        let cfg = SvcConfig::default();
        let pacsi = build_pacsi_nal(&cfg, 42, 3, true);

        // Byte 0: F=0, NRI=3, Type=30 -> 0x7E
        assert_eq!(pacsi[0], 0x7E);

        // Byte 1: R=1, I=1 (IDR), PRID=0 -> 0xC0
        assert_eq!(pacsi[1], 0xC0);

        // Byte 2: N=1, DID=0, QID=0 -> 0x80
        assert_eq!(pacsi[2], 0x80);

        // Byte 3: TID=0, U=0, D=0, O=1, RR=3 -> 0x07
        assert_eq!(pacsi[3], 0x07);

        // Byte 4: Embedded SEI NAL header: F=0, NRI=0, Type=6 -> 0x06
        assert_eq!(pacsi[4], 0x06);

        // Byte 5: Stream Layout payloadType=5
        assert_eq!(pacsi[5], 5);

        // Byte 6: Stream Layout payloadSize=42
        assert_eq!(pacsi[6], 42);

        // Bytes 7-22: Stream Layout UUID
        assert_eq!(&pacsi[7..23], &STREAM_LAYOUT_UUID);

        // After Stream Layout SEI: Bitstream Info SEI
        // Stream Layout SEI is 2 + 42 = 44 bytes (payloadType + payloadSize + payload)
        // Offset: 4 (PACSI hdr+ext) + 1 (SEI NAL hdr) + 44 = 49
        let bi_offset = 4 + 1 + 44;
        assert_eq!(pacsi[bi_offset], 5); // payloadType=5
        assert_eq!(pacsi[bi_offset + 1], 18); // payloadSize=18
        assert_eq!(&pacsi[bi_offset + 2..bi_offset + 18], &BITSTREAM_INFO_UUID);
        assert_eq!(pacsi[bi_offset + 18], 42); // ref_frm_cnt
        assert_eq!(pacsi[bi_offset + 19], 3); // num_of_nal_unit
    }

    #[test]
    fn test_pacsi_non_idr() {
        let cfg = SvcConfig::default();
        let pacsi = build_pacsi_nal(&cfg, 0, 1, false);

        // Byte 1: R=1, I=0 (non-IDR), PRID=0 -> 0x80
        assert_eq!(pacsi[1], 0x80);
    }

    #[test]
    fn test_prefix_nal_structure() {
        // IDR slice with NRI=3
        let prefix = build_prefix_nal(0x65, true);
        assert_eq!(prefix.len(), 4);
        // NAL header: F=0, NRI=3, Type=14 -> 0x6E
        assert_eq!(prefix[0], 0x6E);
        // SVC ext: R=1, I=1, PRID=0 -> 0xC0
        assert_eq!(prefix[1], 0xC0);
        // N=1, DID=0, QID=0 -> 0x80
        assert_eq!(prefix[2], 0x80);
        // TID=0, U=0, D=0, O=1, RR=3 -> 0x07
        assert_eq!(prefix[3], 0x07);
    }

    #[test]
    fn test_prefix_nal_non_idr() {
        // Non-IDR slice (type 1) with NRI=2
        let prefix = build_prefix_nal(0x41, false);
        // NAL header: F=0, NRI=2, Type=14 -> 0x4E
        assert_eq!(prefix[0], 0x4E);
        // SVC ext: R=1, I=0, PRID=0 -> 0x80
        assert_eq!(prefix[1], 0x80);
    }

    #[test]
    fn test_ref_frm_cnt_increments() {
        let mut p = VideoPacketizer::new(0xAABBCCDD);
        // IDR has NRI=3 (reference frame)
        let idr = vec![0x65, 0x88, 0x80, 0x40];

        let pkts1 = p.packetize_frame(&[idr.clone()]);
        let pacsi1 = &pkts1[0][12..]; // skip RTP header
        let bi_offset = 4 + 1 + 44;
        let cnt1 = pacsi1[bi_offset + 18]; // initial random value

        let pkts2 = p.packetize_frame(&[idr.clone()]);
        let pacsi2 = &pkts2[0][12..];
        let cnt2 = pacsi2[bi_offset + 18];
        assert_eq!(cnt2, cnt1.wrapping_add(1)); // incremented by 1
    }

    #[test]
    fn test_stream_layout_layer_description() {
        let cfg = SvcConfig {
            coded_width: 320,
            coded_height: 240,
            display_width: 320,
            display_height: 240,
            bitrate: 256000,
            fps_idx: 2,
            constrained_baseline: true,
        };
        let sei = build_stream_layout_sei(&cfg);

        // payloadType=5, payloadSize=42
        assert_eq!(sei[0], 5);
        assert_eq!(sei[1], 42);

        // UUID at bytes 2..18
        assert_eq!(&sei[2..18], &STREAM_LAYOUT_UUID);

        // LPB0=0x01 at byte 18
        assert_eq!(sei[18], 0x01);

        // P=1 at byte 26 (offset 18 + 8 = 26)
        assert_eq!(sei[26], 0x01);

        // LDSize=16 at byte 27
        assert_eq!(sei[27], 16);

        // Layer Description starts at byte 28
        // Coded Width = 320 = 0x0140
        assert_eq!(sei[28], 0x01);
        assert_eq!(sei[29], 0x40);
        // Coded Height = 240 = 0x00F0
        assert_eq!(sei[30], 0x00);
        assert_eq!(sei[31], 0xF0);

        // Bitrate = 256000 at bytes 36..40
        let bitrate = u32::from_be_bytes([sei[36], sei[37], sei[38], sei[39]]);
        assert_eq!(bitrate, 256000);

        // FPSIdx=2 (top 5 bits), LT=0 (bottom 3 bits) -> byte = 0x10
        assert_eq!(sei[40], 0x10); // 2 << 3 = 16 = 0x10

        // PRID=0, CB=1 -> byte = 0x02
        assert_eq!(sei[41], 0x02);
    }
}

#[cfg(test)]
mod stap_a_tests {
    use super::*;

    /// Chrome bundles SPS+PPS (and small SEIs) into STAP-A; the
    /// depacketizer must yield them one per call (live 2026-10-21: 0
    /// frames decoded from browser video until this existed).
    #[test]
    fn stap_a_yields_each_embedded_nal() {
        let sps = vec![0x67u8, 0x42, 0xC0, 0x1F];
        let pps = vec![0x68u8, 0xCE, 0x3C, 0x80];
        let mut payload = vec![24u8]; // STAP-A header (NAL type 24)
        for nal in [&sps, &pps] {
            payload.extend_from_slice(&(nal.len() as u16).to_be_bytes());
            payload.extend_from_slice(nal);
        }
        let mut d = VideoDepacketizer::new();
        let first = d.depacketize(&payload, false).unwrap().expect("first NAL");
        assert_eq!(first, sps);
        let second = d.depacketize(&payload, true).unwrap().expect("second NAL");
        assert_eq!(second, pps);
        // A frame completes only on the marker-bearing NAL delivery.
        assert_eq!(d.frames_received, 1);
        assert_eq!(d.nals_received, 2);
    }

    #[test]
    fn stap_a_malformed_size_does_not_panic() {
        let payload = vec![24u8, 0x00, 0xFF, 0x01]; // size 255 > remaining
        let mut d = VideoDepacketizer::new();
        assert!(d.depacketize(&payload, false).is_err());
    }
}

#[cfg(all(test, feature = "video-cam"))]
mod i420_color_tests {
    use super::*;

    /// I420 black is Y=0/UV=128 — NOT all-zero. Zero chroma converts to
    /// solid RGB(0,135,0) GREEN on every YUV→RGB renderer (live
    /// 2026-10-21: the caller's remote tile was a uniform green field).
    #[test]
    fn black_i420_renders_dark_not_green() {
        let f = VideoFrame {
            width: 8,
            height: 8,
            data: crate::calling::codec::black_i420(8, 8),
        };
        let rgba = f.to_rgba();
        // Every pixel near-black in ALL channels — no green channel spike.
        for px in rgba.chunks(4) {
            assert!(px[1] <= 8, "green channel spiked: {}", px[1]);
            assert!(px[0] <= 8 && px[2] <= 8, "not dark: {:?}", px);
        }
        // The all-zero buffer this replaced would be exactly (0,135,0).
        let zeroed = VideoFrame {
            width: 8,
            height: 8,
            data: vec![0u8; 8 * 8 * 3 / 2],
        };
        let zr = zeroed.to_rgba();
        assert_eq!(&zr[0..3], &[0, 135, 0]);
    }
}
