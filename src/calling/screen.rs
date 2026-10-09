//! Screen capture for screenshare on Linux via xdg-desktop-portal
//! ScreenCast + PipeWire (works on Wayland and X11 sessions that run a
//! portal). The user picks a monitor/window in the compositor dialog; this
//! module consumes the portal's PipeWire stream and emits planar I420
//! [`VideoFrame`]s for the video send loop.
//!
//! SPIKE NOTES (honest): stop is cooperative — the capture thread parks in
//! the PipeWire main loop until the app exits after `stop()` (frames cease
//! within one frame; the thread itself is left to the OS). Clean main-loop
//! teardown needs a quit handle threaded into the listener.

use crate::calling::video::VideoFrame;
use anyhow::{anyhow, Context, Result};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

/// A running screen-capture session. Frames cease within ~1 frame of
/// `stop()`/drop.
pub struct ScreenShareSession {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ScreenShareSession {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for ScreenShareSession {
    fn drop(&mut self) {
        self.stop();
        // The pw thread parks in its main loop; leak it (bounded, one per
        // share) rather than join a loop that never returns. See module doc.
        let _ = self.thread.take();
    }
}

/// Open the portal (blocks on the compositor picker dialog), then consume
/// the capture stream, pushing I420 frames to `tx`.
pub fn start_screen_capture(
    tx: SyncSender<VideoFrame>,
    with_cursor: bool,
) -> Result<ScreenShareSession> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
    let thread = std::thread::Builder::new()
        .name("screenshare".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let res = rt
                .map_err(anyhow::Error::from)
                .and_then(|rt| rt.block_on(portal_setup(with_cursor, stop2.clone(), tx)));
            let _ = ready_tx.send(res);
        })
        .context("spawn screenshare thread")?;

    ready_rx
        .recv()
        .map_err(|e| anyhow!("screenshare thread died: {e}"))??;

    Ok(ScreenShareSession { stop, thread: Some(thread) })
}

async fn portal_setup(
    with_cursor: bool,
    stop: Arc<AtomicBool>,
    tx: SyncSender<VideoFrame>,
) -> Result<()> {
    use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};

    let proxy = Screencast::new()
        .await
        .context("connect to xdg-desktop-portal (is a desktop session running?)")?;
    let session = proxy.create_session(Default::default()).await?;
    let cursor = if with_cursor {
        CursorMode::Embedded
    } else {
        CursorMode::Hidden
    };
    proxy
        .select_sources(
            &session,
            SelectSourcesOptions::default()
                .set_cursor_mode(cursor)
                .set_sources(SourceType::Monitor | SourceType::Window)
                .set_multiple(false),
        )
        .await
        .context("select sources")?;
    let response = proxy
        .start(&session, None, Default::default())
        .await
        .context("start screencast (user cancelled?)")?
        .response()
        .context("screencast response")?;
    let stream = response
        .streams()
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("portal returned no streams"))?;
    let node_id = stream.pipe_wire_node_id();
    tracing::info!("screenshare: portal stream node {node_id}");

    // Own pw connection fd (independent of the session's transport fd).
    let fd: OwnedFd = proxy
        .open_pipe_wire_remote(&session, Default::default())
        .await
        .context("open pipewire remote")?;

    let (pw_ready_tx, pw_ready_rx) = std::sync::mpsc::channel::<Result<()>>();
    std::thread::Builder::new()
        .name("pipewire-consumer".into())
        .spawn(move || {
            let res = pipewire_consume(fd, node_id, stop, tx);
            let _ = pw_ready_tx.send(res);
        })
        .context("spawn pipewire thread")?;
    pw_ready_rx
        .recv()
        .map_err(|e| anyhow!("pipewire thread died: {e}"))??;
    Ok(())
}

struct PwData {
    format: libspa::param::video::VideoInfoRaw,
    tx: SyncSender<VideoFrame>,
    stop: Arc<AtomicBool>,
    seq: u64,
}

fn pipewire_consume(
    fd: OwnedFd,
    node_id: u32,
    stop: Arc<AtomicBool>,
    tx: SyncSender<VideoFrame>,
) -> Result<()> {
    use libspa::pod::Pod;
    use pipewire as pw;
    use pw::{properties::properties, spa};

    pw::init();
    let mainloop = pw::main_loop::MainLoopBox::new(None).context("pw main loop")?;
    let context = pw::context::ContextBox::new(mainloop.loop_(), None).context("pw context")?;
    let core = context.connect_fd(fd, None).context("pw connect_fd")?;

    let data = PwData { format: Default::default(), tx, stop, seq: 0 };

    let stream = pw::stream::StreamBox::new(
        &core,
        "teamsfast-screen",
        properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )
    .context("pw stream")?;

    let _listener = stream
        .add_local_listener_with_user_data(data)
        .param_changed(|_, user_data, id, param| {
            use pw::spa::param::format::{MediaSubtype, MediaType};
            use pw::spa::param::ParamType;
            let Some(param) = param else { return };
            if id != ParamType::Format.as_raw() {
                return;
            }
            let (media_type, media_subtype) =
                match pw::spa::param::format_utils::parse_format(param) {
                    Ok(v) => v,
                    Err(_) => return,
                };
            if media_type != MediaType::Video || media_subtype != MediaSubtype::Raw {
                return;
            }
            user_data.format.parse(param).expect("parse video format");
            tracing::info!(
                "screenshare: format {:?} {}x{}",
                user_data.format.format(),
                user_data.format.size().width,
                user_data.format.size().height
            );
        })
        .process(|stream, user_data| {
            if user_data.stop.load(Ordering::SeqCst) {
                return;
            }
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            let datas = buffer.datas_mut();
            if datas.is_empty() || datas[0].chunk().size() == 0 {
                return;
            }
            let w = user_data.format.size().width;
            let h = user_data.format.size().height;
            if w == 0 || h == 0 {
                return;
            }
            let fmt = user_data.format.format();
            let data = &mut datas[0];
            let size = data.chunk().size() as usize;
            let stride = data.chunk().stride() as usize;
            let Some(mem) = data.data() else { return };
            if mem.len() < size || size == 0 {
                return;
            }
            let bytes: &[u8] = &mem[..size];
            let frame = match fmt {
                pw::spa::param::video::VideoFormat::I420 => {
                    if size < w as usize * h as usize * 3 / 2 {
                        return;
                    }
                    VideoFrame { width: w, height: h, data: bytes.to_vec() }
                }
                pw::spa::param::video::VideoFormat::BGRx
                | pw::spa::param::video::VideoFormat::RGBx
                | pw::spa::param::video::VideoFormat::RGB
                | pw::spa::param::video::VideoFormat::RGBA => {
                    let swap_rb = matches!(
                        fmt,
                        pw::spa::param::video::VideoFormat::RGBx
                            | pw::spa::param::video::VideoFormat::RGB
                    );
                    bgra_to_i420(bytes, stride, w, h, swap_rb)
                }
                _ => return,
            };
            user_data.seq += 1;
            if user_data.seq % 100 == 1 {
                tracing::info!("screenshare: frame #{} {}x{}", user_data.seq, w, h);
            }
            let _ = user_data.tx.try_send(frame);
        })
        .register()
        .context("register listener")?;

    // Negotiate: BGRx first (compositor-native, cheap), I420 accepted.
    let obj = pw::spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        pw::spa::pod::property!(
            spa::param::format::FormatProperties::MediaType,
            Id,
            spa::param::format::MediaType::Video
        ),
        pw::spa::pod::property!(
            spa::param::format::FormatProperties::MediaSubtype,
            Id,
            spa::param::format::MediaSubtype::Raw
        ),
        pw::spa::pod::property!(
            spa::param::format::FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            spa::param::video::VideoFormat::BGRx,
            spa::param::video::VideoFormat::BGRx,
            spa::param::video::VideoFormat::I420,
            spa::param::video::VideoFormat::RGBx,
            spa::param::video::VideoFormat::RGB,
        ),
        pw::spa::pod::property!(
            spa::param::format::FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            spa::utils::Fraction { num: 30, denom: 1 },
            spa::utils::Fraction { num: 5, denom: 1 },
            spa::utils::Fraction { num: 60, denom: 1 }
        ),
    );
    let values: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )
    .context("serialize format pod")?
    .0
    .into_inner();

    let mut params = [Pod::from_bytes(&values).context("pod from bytes")?];
    stream
        .connect(
            spa::utils::Direction::Input,
            Some(node_id),
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .context("connect stream")?;

    mainloop.run();
    Ok(())
}

/// Packed BGRA/BGRx/RGB(A) → planar I420 (BT.601, matching the camera
/// path's convention). `swap_rb` flips R/B for the RGB variants.
fn bgra_to_i420(src: &[u8], stride: usize, w: u32, h: u32, swap_rb: bool) -> VideoFrame {
    let (w, h) = (w as usize, h as usize);
    let mut y = vec![0u8; w * h];
    let mut u = vec![0u8; w * h / 4];
    let mut v = vec![0u8; w * h / 4];
    for row in 0..h {
        let src_row = &src[row * stride..];
        let y_row = &mut y[row * w..];
        for col in 0..w {
            let px = &src_row[col * 4..col * 4 + 4];
            let (b, g, r) = if swap_rb { (px[2], px[1], px[0]) } else { (px[0], px[1], px[2]) };
            let yy = ((66 * r as i32 + 129 * g as i32 + 25 * b as i32 + 128) >> 8) + 16;
            y_row[col] = yy.clamp(0, 255) as u8;
            if row % 2 == 0 && col % 2 == 0 {
                let (b2, g2, r2) = (b as i32, g as i32, r as i32);
                let uu = ((-38 * r2 - 74 * g2 + 112 * b2 + 128) >> 8) + 128;
                let vv = ((112 * r2 - 94 * g2 - 18 * b2 + 128) >> 8) + 128;
                let (ux, vx) = (col / 2, row / 2);
                u[ux + vx * (w / 2)] = uu.clamp(0, 255) as u8;
                v[ux + vx * (w / 2)] = vv.clamp(0, 255) as u8;
            }
        }
    }
    let mut data = y;
    data.extend_from_slice(&u);
    data.extend_from_slice(&v);
    VideoFrame { width: w as u32, height: h as u32, data }
}
