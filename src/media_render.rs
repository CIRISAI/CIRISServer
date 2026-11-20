//! Image renditions: the node decodes, the client never does (CIRISServer#614,
//! CC 3.3.13 / CC 5.3.2.6; the client's `FSD/MEDIA_EDGE.md` §1, §7).
//!
//! **Why the node.** A client that decodes a stranger's image bytes runs a C
//! decoder on hostile input, the surface §1 of the brief is about. So the
//! client shows a stranger's image only as bytes its OWN node re-encoded,
//! here, in memory-safe Rust: `image` with exactly its pure-Rust codecs
//! (`zune-jpeg`, `png`, `image-webp`, `gif`), and no unsafe code in this module.
//!
//! **Two places, one decoder** (Eric, 2026-11-18):
//!
//! - [`canonicalize`] at the SENDER's node, when an image is written into a
//!   shared room. Turn it upright from its EXIF orientation, then re-encode.
//!   That drops every EXIF, GPS, XMP and ICC block, plus GIF comment and
//!   application extensions. The canonical bytes are what gets hashed, sealed
//!   and sent (CC 3.3.13: "sender canonicalises before hashing"). A photo's
//!   location never leaves the phone that took it.
//! - [`render`] at every READER's node: a display rendition (≤ 2048 px on its
//!   long edge) and a thumbnail (≤ 320 px), plus [`info`]'s dimensions and
//!   thumbhash `placeholder` (≤ 64 decoded bytes, CC 3.3.13).
//!
//! **Animation** (Eric, 2026-11-18): an animated GIF, WebP or APNG stays
//! animated, in the canonical bytes and in a rendition. A reader picks how it
//! plays ([`Play`]): on a loop, once and then stop, or as a still (its first
//! frame). Animated output is GIF, the one animated format `image` encodes.
//!
//! **Caps are the published policy's** ([`crate::media_gate::policy`]'s
//! `tier_a`): bytes and pixels per type. They are checked from the header
//! BEFORE any pixel is decoded, and `image`'s allocation limit backs them. An
//! image over a cap is refused, never partially decoded.
//!
//! HEIC, HEIF and AVIF stay Tier B (convert at sender): their decoders are C.

use std::io::Cursor;

use image::{AnimationDecoder, DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};

/// The long edge of a display rendition.
pub const DISPLAY_MAX_EDGE: u32 = 2048;
/// The long edge of a thumbnail.
pub const THUMB_MAX_EDGE: u32 = 320;
/// JPEG quality of a rendition, and of a canonical JPEG.
const RENDITION_QUALITY: u8 = 85;
const CANONICAL_QUALITY: u8 = 90;
/// The decoder's allocation ceiling, behind the per-type pixel caps:
/// 33 MP × 4 bytes is 132 MB, so this is headroom, not the limit.
const MAX_ALLOC: u64 = 256 * 1024 * 1024;
/// An animation keeps at most this many frames.
pub const MAX_ANIMATED_FRAMES: usize = 500;

/// An image type this node decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Jpeg,
    Png,
    Webp,
    Gif,
}

impl Kind {
    /// The kind for an RFC 6838 essence the write gate already checked
    /// against the bytes, or `None` for a type this node does not render.
    pub fn of(essence: &str) -> Option<Kind> {
        match essence {
            "image/jpeg" => Some(Kind::Jpeg),
            "image/png" => Some(Kind::Png),
            "image/webp" => Some(Kind::Webp),
            "image/gif" => Some(Kind::Gif),
            _ => None,
        }
    }

    fn format(self) -> ImageFormat {
        match self {
            Kind::Jpeg => ImageFormat::Jpeg,
            Kind::Png => ImageFormat::Png,
            Kind::Webp => ImageFormat::WebP,
            Kind::Gif => ImageFormat::Gif,
        }
    }

    /// The published caps (`media_gate::policy().tier_a`): bytes, pixels.
    /// WebP publishes no pixel cap; it takes JPEG's.
    pub fn caps(self) -> (u64, u64) {
        const MB: u64 = 1_000_000;
        match self {
            Kind::Jpeg | Kind::Png => (16 * MB, 33_000_000),
            Kind::Webp => (10 * MB, 33_000_000),
            Kind::Gif => (25 * MB, 921_600),
        }
    }
}

/// Why an image was not decoded. Each maps to one refusal id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderRefusal {
    /// Not a type this node renders (`drive.no_rendition`).
    NotRenderable(String),
    /// Over the published byte or pixel cap (`drive.image_too_large`).
    TooLarge {
        what: &'static str,
        got: u64,
        cap: u64,
    },
    /// The bytes do not decode as the type they are (`drive.image_undecodable`).
    Undecodable(String),
}

impl RenderRefusal {
    pub fn reason_id(&self) -> &'static str {
        match self {
            RenderRefusal::NotRenderable(_) => "drive.no_rendition",
            RenderRefusal::TooLarge { .. } => "drive.image_too_large",
            RenderRefusal::Undecodable(_) => "drive.image_undecodable",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            RenderRefusal::NotRenderable(t) => format!(
                "{t} has no rendition on this node: only image/jpeg, image/png, image/webp and \
                 image/gif are decoded here (CC 5.3.2.6 Tier A)"
            ),
            RenderRefusal::TooLarge { what, got, cap } => {
                format!("the image is {got} {what}, over this node's published cap of {cap}")
            }
            RenderRefusal::Undecodable(why) => format!("the image does not decode: {why}"),
        }
    }
}

/// An encoded image: its bytes, the essence they are, and their size.
#[derive(Debug, Clone)]
pub struct Encoded {
    pub bytes: Vec<u8>,
    pub media_type: &'static str,
    pub width: u32,
    pub height: u32,
    /// True for an animated GIF (more than one frame).
    pub animated: bool,
}

/// Which rendition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Size {
    Display,
    Thumb,
}

impl Size {
    pub fn parse(s: &str) -> Option<Size> {
        match s {
            "display" => Some(Size::Display),
            "thumb" => Some(Size::Thumb),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Size::Display => "display",
            Size::Thumb => "thumb",
        }
    }
    fn max_edge(self) -> u32 {
        match self {
            Size::Display => DISPLAY_MAX_EDGE,
            Size::Thumb => THUMB_MAX_EDGE,
        }
    }
}

/// An image's dimensions and its thumbhash placeholder.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Info {
    pub width: u32,
    pub height: u32,
    /// Base64 (standard, padded) thumbhash of the first frame, upright, at
    /// most 25 bytes before encoding.
    pub placeholder: String,
    /// `Some` for an animated GIF, WebP or APNG.
    pub animation: Option<Animation>,
}

/// An animation's length.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Animation {
    pub frames: usize,
    /// One play through, the sum of the frame delays.
    pub duration_ms: u64,
}

fn limits() -> Limits {
    let mut l = Limits::default();
    l.max_alloc = Some(MAX_ALLOC);
    l.max_image_width = Some(16_384);
    l.max_image_height = Some(16_384);
    l
}

fn undecodable(e: impl std::fmt::Display) -> RenderRefusal {
    RenderRefusal::Undecodable(e.to_string())
}

/// The kind, after the byte cap.
fn admit(bytes: &[u8], essence: &str) -> Result<Kind, RenderRefusal> {
    let kind = Kind::of(essence).ok_or_else(|| RenderRefusal::NotRenderable(essence.into()))?;
    let (max_bytes, _) = kind.caps();
    if bytes.len() as u64 > max_bytes {
        return Err(RenderRefusal::TooLarge {
            what: "bytes",
            got: bytes.len() as u64,
            cap: max_bytes,
        });
    }
    Ok(kind)
}

/// Decode the first frame, upright, after the pixel cap is read off the
/// header. GIF and animated WebP yield their first frame.
fn decode_still(bytes: &[u8], kind: Kind) -> Result<DynamicImage, RenderRefusal> {
    let mut reader = ImageReader::with_format(Cursor::new(bytes), kind.format());
    reader.limits(limits());
    let mut decoder = reader.into_decoder().map_err(undecodable)?;
    let (w, h) = decoder.dimensions();
    let (_, max_pixels) = kind.caps();
    let pixels = u64::from(w) * u64::from(h);
    if pixels > max_pixels {
        return Err(RenderRefusal::TooLarge {
            what: "pixels",
            got: pixels,
            cap: max_pixels,
        });
    }
    let orientation = decoder.orientation().map_err(undecodable)?;
    let mut img = DynamicImage::from_decoder(decoder).map_err(undecodable)?;
    img.apply_orientation(orientation);
    Ok(img)
}

/// True when any pixel is not fully opaque.
fn has_transparency(img: &DynamicImage) -> bool {
    if !img.color().has_alpha() {
        return false;
    }
    img.to_rgba8().pixels().any(|p| p.0[3] != u8::MAX)
}

/// JPEG for an opaque image, PNG when any pixel is transparent.
fn encode_still(img: &DynamicImage, quality: u8) -> Result<Encoded, RenderRefusal> {
    let (width, height) = (img.width(), img.height());
    let mut out = Vec::new();
    let media_type = if has_transparency(img) {
        img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .map_err(undecodable)?;
        "image/png"
    } else {
        let rgb = img.to_rgb8();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality)
            .encode_image(&rgb)
            .map_err(undecodable)?;
        "image/jpeg"
    };
    Ok(Encoded {
        bytes: out,
        media_type,
        width,
        height,
        animated: false,
    })
}

/// How an animated image plays: on a loop, once and then stops on its last
/// frame, or not at all (its first frame, as a still).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Play {
    Loop,
    Once,
    Still,
}

impl Play {
    pub fn parse(s: &str) -> Option<Play> {
        match s {
            "loop" => Some(Play::Loop),
            "once" => Some(Play::Once),
            "still" => Some(Play::Still),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Play::Loop => "loop",
            Play::Once => "once",
            Play::Still => "still",
        }
    }
}

/// An animated image's frame canvas may be at most this many pixels, from
/// any of the three animated formats: the published GIF cap (`tier_a`).
pub const ANIMATED_MAX_PIXELS: u64 = 921_600;
/// The decoded frames of one animation, all together, stay under the
/// decoder's allocation ceiling: frames x width x height x 4 bytes.
const ANIMATED_MAX_DECODED: u64 = MAX_ALLOC;
/// GIF quantisation speed (1 slowest .. 30 fastest); 10 keeps a chat GIF's
/// colours and encodes in well under a second.
const GIF_SPEED: i32 = 10;

/// An animation's frames, composited to full canvases, or `None` when the
/// image is a still (one frame, or a format with no animation in it).
/// GIF, animated WebP and APNG. The canvas and the decoded total are capped
/// before and while decoding, so a long animation is refused, not truncated.
fn decode_frames(bytes: &[u8], kind: Kind) -> Result<Option<Vec<image::Frame>>, RenderRefusal> {
    use image::codecs::{gif::GifDecoder, png::PngDecoder, webp::WebPDecoder};
    let canvas = |w: u32, h: u32| -> Result<u64, RenderRefusal> {
        let pixels = u64::from(w) * u64::from(h);
        if pixels > ANIMATED_MAX_PIXELS {
            return Err(RenderRefusal::TooLarge {
                what: "pixels per animated frame",
                got: pixels,
                cap: ANIMATED_MAX_PIXELS,
            });
        }
        Ok(pixels)
    };
    let frames: image::Frames<'_> = match kind {
        Kind::Jpeg => return Ok(None),
        Kind::Gif => {
            let mut d = GifDecoder::new(Cursor::new(bytes)).map_err(undecodable)?;
            d.set_limits(limits()).map_err(undecodable)?;
            let (w, h) = d.dimensions();
            canvas(w, h)?;
            d.into_frames()
        }
        Kind::Webp => {
            let mut d = WebPDecoder::new(Cursor::new(bytes)).map_err(undecodable)?;
            if !d.has_animation() {
                return Ok(None);
            }
            d.set_limits(limits()).map_err(undecodable)?;
            let (w, h) = d.dimensions();
            canvas(w, h)?;
            d.into_frames()
        }
        Kind::Png => {
            let mut d = PngDecoder::new(Cursor::new(bytes)).map_err(undecodable)?;
            if !d.is_apng().map_err(undecodable)? {
                return Ok(None);
            }
            d.set_limits(limits()).map_err(undecodable)?;
            let (w, h) = d.dimensions();
            canvas(w, h)?;
            d.apng().map_err(undecodable)?.into_frames()
        }
    };
    let mut out = Vec::new();
    let mut decoded: u64 = 0;
    for frame in frames {
        let frame = frame.map_err(undecodable)?;
        if out.len() == MAX_ANIMATED_FRAMES {
            return Err(RenderRefusal::TooLarge {
                what: "frames",
                got: (MAX_ANIMATED_FRAMES + 1) as u64,
                cap: MAX_ANIMATED_FRAMES as u64,
            });
        }
        let buf = frame.buffer();
        decoded += u64::from(buf.width()) * u64::from(buf.height()) * 4;
        if decoded > ANIMATED_MAX_DECODED {
            return Err(RenderRefusal::TooLarge {
                what: "decoded bytes of animation",
                got: decoded,
                cap: ANIMATED_MAX_DECODED,
            });
        }
        out.push(frame);
    }
    Ok((out.len() > 1).then_some(out))
}

/// Frames as an animated GIF, the one animated format this node encodes.
/// `Loop` writes the loop-forever extension; `Once` writes none, so a viewer
/// plays the frames once and stops on the last. Frame delays are kept.
fn encode_animation(frames: Vec<image::Frame>, play: Play) -> Result<Encoded, RenderRefusal> {
    use image::codecs::gif::{GifEncoder, Repeat};
    let (width, height) = frames
        .first()
        .map(|f| (f.buffer().width(), f.buffer().height()))
        .unwrap_or((0, 0));
    let mut out = Vec::new();
    {
        let mut enc = GifEncoder::new_with_speed(&mut out, GIF_SPEED);
        if play == Play::Loop {
            enc.set_repeat(Repeat::Infinite).map_err(undecodable)?;
        }
        enc.encode_frames(frames).map_err(undecodable)?;
    }
    Ok(Encoded {
        bytes: out,
        media_type: "image/gif",
        width,
        height,
        animated: true,
    })
}

/// Each frame scaled to fit `edge` on its long side (never up), its delay
/// and offset kept.
fn scale_frames(frames: Vec<image::Frame>, edge: u32) -> Vec<image::Frame> {
    frames
        .into_iter()
        .map(|f| {
            let (w, h) = (f.buffer().width(), f.buffer().height());
            if w <= edge && h <= edge {
                return f;
            }
            let delay = f.delay();
            let img = DynamicImage::ImageRgba8(f.into_buffer())
                .resize(edge, edge, image::imageops::FilterType::Triangle)
                .to_rgba8();
            image::Frame::from_parts(img, 0, 0, delay)
        })
        .collect()
}

/// The sender's canonical form: upright and re-encoded, carrying no metadata,
/// at full resolution. A still is JPEG at quality 90 (PNG when any pixel is
/// transparent). An animation (GIF, animated WebP, APNG) stays animated: an
/// animated GIF that loops, its frames and delays kept, every extension
/// block dropped. GIF is the one animated format this node encodes, so an
/// animated WebP or APNG arrives in the room as a GIF.
pub fn canonicalize(bytes: &[u8], essence: &str) -> Result<Encoded, RenderRefusal> {
    let kind = admit(bytes, essence)?;
    if let Some(frames) = decode_frames(bytes, kind)? {
        return encode_animation(frames, Play::Loop);
    }
    let img = decode_still(bytes, kind)?;
    encode_still(&img, CANONICAL_QUALITY)
}

/// A rendition for a reader, scaled to fit `size`'s long edge (never up).
/// A still is JPEG at quality 85, or PNG when transparent. An animation
/// plays as `play` says: `Loop` and `Once` are an animated GIF, and `Still`
/// is its first frame encoded as a still.
pub fn render(
    bytes: &[u8],
    essence: &str,
    size: Size,
    play: Play,
) -> Result<Encoded, RenderRefusal> {
    let kind = admit(bytes, essence)?;
    if play != Play::Still {
        if let Some(frames) = decode_frames(bytes, kind)? {
            return encode_animation(scale_frames(frames, size.max_edge()), play);
        }
    }
    let img = decode_still(bytes, kind)?;
    let edge = size.max_edge();
    let img = if img.width() > edge || img.height() > edge {
        img.resize(edge, edge, image::imageops::FilterType::Triangle)
    } else {
        img
    };
    encode_still(&img, RENDITION_QUALITY)
}

/// The image's upright dimensions, whether it is animated (frame count and
/// one loop's length), and a thumbhash placeholder of its first frame.
pub fn info(bytes: &[u8], essence: &str) -> Result<Info, RenderRefusal> {
    let kind = admit(bytes, essence)?;
    let img = decode_still(bytes, kind)?;
    let (width, height) = (img.width(), img.height());
    let animation = decode_frames(bytes, kind)?.map(|frames| {
        let ms: u64 = frames
            .iter()
            .map(|f| {
                let (n, d) = f.delay().numer_denom_ms();
                u64::from(n) / u64::from(d.max(1))
            })
            .sum();
        Animation {
            frames: frames.len(),
            duration_ms: ms,
        }
    });
    // thumbhash takes at most 100 x 100.
    let small = img.thumbnail(100, 100).to_rgba8();
    let hash = thumbhash::rgba_to_thumb_hash(
        small.width() as usize,
        small.height() as usize,
        small.as_raw(),
    );
    use base64::Engine as _;
    Ok(Info {
        width,
        height,
        placeholder: base64::engine::general_purpose::STANDARD.encode(hash),
        animation,
    })
}

/// At most this many decodes run at once, node-wide. A decode is CPU and up
/// to [`MAX_ALLOC`] of memory; two bound a phone and keep a burst of chat
/// thumbnails from starving the node.
pub static DECODE_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// Run `f` (a decode) on the blocking pool, under [`DECODE_SLOTS`].
pub async fn decode_bounded<T, F>(f: F) -> Result<T, RenderRefusal>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, RenderRefusal> + Send + 'static,
{
    let _slot = DECODE_SLOTS
        .acquire()
        .await
        .map_err(|e| RenderRefusal::Undecodable(format!("decode slots closed: {e}")))?;
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| RenderRefusal::Undecodable(format!("the decode task failed: {e}")))?
}

/// A rendition or an info answer, cached.
#[derive(Clone)]
pub enum Cached {
    Image(std::sync::Arc<Encoded>),
    Info(std::sync::Arc<Info>),
}

impl Cached {
    fn weight(&self) -> usize {
        match self {
            Cached::Image(e) => e.bytes.len(),
            Cached::Info(i) => i.placeholder.len() + 16,
        }
    }
}

/// The rendition cache: IN MEMORY ONLY, keyed by the plaintext digest of the
/// original and the rendition asked for, bounded by bytes, oldest out first.
/// A rendition is plaintext of a file that may be sealed at rest, so it never
/// touches disk. A hit is served only AFTER the reader's access to the file
/// was checked again: the key names the bytes, not who may see them.
pub struct Cache {
    budget: usize,
    inner: std::sync::Mutex<CacheInner>,
}

#[derive(Default)]
struct CacheInner {
    map: std::collections::BTreeMap<(String, String), Cached>,
    order: std::collections::VecDeque<(String, String)>,
    used: usize,
}

impl Cache {
    pub const fn new(budget: usize) -> Self {
        Cache {
            budget,
            inner: std::sync::Mutex::new(CacheInner {
                map: std::collections::BTreeMap::new(),
                order: std::collections::VecDeque::new(),
                used: 0,
            }),
        }
    }

    pub fn get(&self, digest: &str, what: &str) -> Option<Cached> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .map
            .get(&(digest.to_owned(), what.to_owned()))
            .cloned()
    }

    pub fn put(&self, digest: &str, what: &str, value: Cached) {
        let w = value.weight();
        if w > self.budget {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let key = (digest.to_owned(), what.to_owned());
        if let Some(old) = inner.map.insert(key.clone(), value) {
            inner.used -= old.weight();
            inner.order.retain(|k| k != &key);
        }
        inner.used += w;
        inner.order.push_back(key);
        while inner.used > self.budget {
            let Some(k) = inner.order.pop_front() else {
                break;
            };
            if let Some(v) = inner.map.remove(&k) {
                inner.used -= v.weight();
            }
        }
    }
}

/// The node's one rendition cache: 48 MB, about 150 display renditions.
pub static CACHE: Cache = Cache::new(48 * 1024 * 1024);

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgb, RgbImage, Rgba, RgbaImage};

    #[test]
    fn the_cache_stays_inside_its_budget() {
        let c = Cache::new(100);
        let img = |n: usize| {
            Cached::Image(std::sync::Arc::new(Encoded {
                bytes: vec![0; n],
                media_type: "image/jpeg",
                width: 1,
                height: 1,
                animated: false,
            }))
        };
        c.put("a", "thumb", img(60));
        c.put("b", "thumb", img(60));
        assert!(c.get("a", "thumb").is_none(), "the oldest went out");
        assert!(c.get("b", "thumb").is_some());
        c.put("huge", "display", img(1000));
        assert!(
            c.get("huge", "display").is_none(),
            "over the budget alone: never cached"
        );
    }

    fn jpeg_of(w: u32, h: u32) -> Vec<u8> {
        let img = RgbImage::from_fn(w, h, |x, y| Rgb([(x % 256) as u8, (y % 256) as u8, 90]));
        let mut out = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 90)
            .encode_image(&img)
            .unwrap();
        out
    }

    /// A JPEG with an APP1 Exif block, carrying GPS-shaped bytes and
    /// orientation 6 (rotate 90° clockwise), spliced in after SOI.
    fn jpeg_with_exif(w: u32, h: u32) -> Vec<u8> {
        let base = jpeg_of(w, h);
        // TIFF header (little endian), IFD0 with one entry: Orientation = 6.
        let mut tiff = vec![b'I', b'I', 42, 0, 8, 0, 0, 0];
        tiff.extend_from_slice(&1u16.to_le_bytes()); // one entry
        tiff.extend_from_slice(&0x0112u16.to_le_bytes()); // Orientation
        tiff.extend_from_slice(&3u16.to_le_bytes()); // SHORT
        tiff.extend_from_slice(&1u32.to_le_bytes()); // count
        tiff.extend_from_slice(&6u16.to_le_bytes());
        tiff.extend_from_slice(&[0, 0]);
        tiff.extend_from_slice(&0u32.to_le_bytes()); // no next IFD
        tiff.extend_from_slice(b"GPSLatitude 40.7128 N GPSLongitude 74.0060 W");
        let mut app1 = b"Exif\0\0".to_vec();
        app1.extend_from_slice(&tiff);
        let len = (app1.len() + 2) as u16;
        let mut out = vec![0xFF, 0xD8, 0xFF, 0xE1];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&app1);
        out.extend_from_slice(&base[2..]);
        out
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn canonical_drops_exif_and_turns_the_photo_upright() {
        let src = jpeg_with_exif(64, 32);
        assert!(contains(&src, b"Exif"));
        assert!(contains(&src, b"GPSLatitude"));
        let c = canonicalize(&src, "image/jpeg").unwrap();
        assert_eq!(c.media_type, "image/jpeg");
        assert!(
            !contains(&c.bytes, b"Exif"),
            "the canonical bytes carry no Exif block"
        );
        assert!(!contains(&c.bytes, b"GPS"), "nor anything of the location");
        // Orientation 6 rotates a 64 x 32 landscape into a 32 x 64 portrait.
        assert_eq!((c.width, c.height), (32, 64));
        assert_eq!(image::load_from_memory(&c.bytes).unwrap().width(), 32);
    }

    #[test]
    fn a_transparent_png_stays_png_and_an_opaque_one_becomes_jpeg() {
        let clear = RgbaImage::from_fn(8, 8, |x, _| Rgba([255, 0, 0, if x < 4 { 0 } else { 255 }]));
        let mut png = Vec::new();
        DynamicImage::ImageRgba8(clear)
            .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
            .unwrap();
        assert_eq!(
            canonicalize(&png, "image/png").unwrap().media_type,
            "image/png"
        );

        let solid = RgbaImage::from_pixel(8, 8, Rgba([0, 0, 255, 255]));
        let mut png = Vec::new();
        DynamicImage::ImageRgba8(solid)
            .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
            .unwrap();
        assert_eq!(
            canonicalize(&png, "image/png").unwrap().media_type,
            "image/jpeg"
        );
    }

    #[test]
    fn renditions_fit_their_edge_and_never_upscale() {
        let big = jpeg_of(3000, 1000);
        let d = render(&big, "image/jpeg", Size::Display, Play::Loop).unwrap();
        assert_eq!((d.width, d.height), (2048, 683));
        let t = render(&big, "image/jpeg", Size::Thumb, Play::Loop).unwrap();
        assert_eq!(t.width, 320);
        let small = jpeg_of(100, 50);
        let d = render(&small, "image/jpeg", Size::Display, Play::Loop).unwrap();
        assert_eq!((d.width, d.height), (100, 50));
    }

    #[test]
    fn info_gives_dimensions_and_a_short_placeholder() {
        let i = info(&jpeg_with_exif(64, 32), "image/jpeg").unwrap();
        assert_eq!((i.width, i.height), (32, 64));
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&i.placeholder)
            .unwrap();
        assert!(
            !raw.is_empty() && raw.len() <= 64,
            "CC 3.3.13: placeholder <= 64 bytes"
        );
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for b in bytes {
            c ^= u32::from(*b);
            for _ in 0..8 {
                c = if c & 1 == 1 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    #[test]
    fn over_the_pixel_cap_is_refused_before_decoding() {
        // A PNG whose header claims 10000 x 10000 (100 MP > 33 MP), with no
        // pixel data at all: the cap is read off IHDR, so nothing decodes.
        let mut ihdr = b"IHDR".to_vec();
        ihdr.extend_from_slice(&10_000u32.to_be_bytes());
        ihdr.extend_from_slice(&10_000u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(&ihdr);
        png.extend_from_slice(&crc32(&ihdr).to_be_bytes());
        // An empty IDAT, then IEND: the decoder reads its header up to the
        // first data chunk, and the cap refuses there.
        for tag in [&b"IDAT"[..], &b"IEND"[..]] {
            png.extend_from_slice(&0u32.to_be_bytes());
            png.extend_from_slice(tag);
            png.extend_from_slice(&crc32(tag).to_be_bytes());
        }
        for f in [
            render(&png, "image/png", Size::Thumb, Play::Loop),
            canonicalize(&png, "image/png"),
        ] {
            match f {
                Err(RenderRefusal::TooLarge {
                    what: "pixels",
                    got,
                    cap,
                }) => {
                    assert_eq!((got, cap), (100_000_000, 33_000_000));
                }
                other => panic!("expected a pixel-cap refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn other_types_and_broken_bytes_are_named() {
        assert_eq!(
            render(b"<svg/>", "image/svg+xml", Size::Thumb, Play::Loop)
                .unwrap_err()
                .reason_id(),
            "drive.no_rendition"
        );
        let mut broken = jpeg_of(16, 16);
        broken.truncate(40);
        assert_eq!(
            render(&broken, "image/jpeg", Size::Thumb, Play::Loop)
                .unwrap_err()
                .reason_id(),
            "drive.image_undecodable"
        );
    }

    fn animated_gif(frames: u8, w: u32, h: u32) -> Vec<u8> {
        use image::{Delay, Frame};
        let frames: Vec<Frame> = (0..frames)
            .map(|i| {
                Frame::from_parts(
                    RgbaImage::from_pixel(w, h, Rgba([i.wrapping_mul(80), 40, 200, 255])),
                    0,
                    0,
                    Delay::from_numer_denom_ms(100, 1),
                )
            })
            .collect();
        let mut out = Vec::new();
        {
            let mut enc = image::codecs::gif::GifEncoder::new_with_speed(&mut out, 30);
            enc.set_repeat(image::codecs::gif::Repeat::Infinite)
                .unwrap();
            enc.encode_frames(frames).unwrap();
        }
        out
    }

    /// An APNG of `frames` frames, 4 x 4, 100 ms each, looping forever.
    fn apng(frames: u8) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, 4, 4);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            enc.set_animated(u32::from(frames), 0).unwrap();
            enc.set_frame_delay(1, 10).unwrap();
            let mut w = enc.write_header().unwrap();
            for i in 0..frames {
                w.write_image_data(&[i.wrapping_mul(60), 0, 0, 255].repeat(16))
                    .unwrap();
            }
            w.finish().unwrap();
        }
        out
    }

    fn frame_count(gif: &[u8]) -> usize {
        image::codecs::gif::GifDecoder::new(Cursor::new(gif))
            .unwrap()
            .into_frames()
            .count()
    }

    /// The NETSCAPE2.0 application extension is what makes a GIF loop.
    fn loops(gif: &[u8]) -> bool {
        contains(gif, b"NETSCAPE2.0")
    }

    #[test]
    fn an_animated_gif_stays_animated_and_loops_in_the_room() {
        let c = canonicalize(&animated_gif(3, 4, 4), "image/gif").unwrap();
        assert_eq!(c.media_type, "image/gif");
        assert_eq!(frame_count(&c.bytes), 3);
        assert!(loops(&c.bytes));
    }

    #[test]
    fn a_reader_picks_loop_once_or_still() {
        let src = animated_gif(3, 64, 32);
        let looping = render(&src, "image/gif", Size::Display, Play::Loop).unwrap();
        assert_eq!(
            (looping.media_type, frame_count(&looping.bytes)),
            ("image/gif", 3)
        );
        assert!(loops(&looping.bytes), "loop: the loop-forever extension");
        let once = render(&src, "image/gif", Size::Display, Play::Once).unwrap();
        assert_eq!(frame_count(&once.bytes), 3);
        assert!(
            !loops(&once.bytes),
            "once: no loop extension, so it stops on the last frame"
        );
        let still = render(&src, "image/gif", Size::Display, Play::Still).unwrap();
        assert_eq!(
            still.media_type, "image/jpeg",
            "still: the first frame, as a still"
        );
        // Frames scale like a still does.
        let thumb = render(
            &animated_gif(2, 640, 320),
            "image/gif",
            Size::Thumb,
            Play::Loop,
        )
        .unwrap();
        assert_eq!((thumb.width, thumb.height), (320, 160));
        assert_eq!(frame_count(&thumb.bytes), 2);
    }

    #[test]
    fn an_apng_animates_too() {
        let src = apng(4);
        let c = canonicalize(&src, "image/png").unwrap();
        assert_eq!(
            c.media_type, "image/gif",
            "GIF is the animated format this node encodes"
        );
        assert_eq!(frame_count(&c.bytes), 4);
        let r = render(&src, "image/png", Size::Thumb, Play::Once).unwrap();
        assert_eq!(frame_count(&r.bytes), 4);
        let i = info(&src, "image/png").unwrap();
        let a = i.animation.expect("animated");
        assert_eq!((a.frames, a.duration_ms), (4, 400));
        // A plain PNG is a still.
        assert!(info(&apng(1), "image/png").unwrap().animation.is_none());
    }

    #[test]
    fn info_says_whether_and_how_long_it_animates() {
        let a = info(&animated_gif(5, 8, 8), "image/gif")
            .unwrap()
            .animation
            .unwrap();
        assert_eq!((a.frames, a.duration_ms), (5, 500));
        assert!(info(&jpeg_of(8, 8), "image/jpeg")
            .unwrap()
            .animation
            .is_none());
    }

    #[test]
    fn a_long_animation_is_refused_not_truncated() {
        let src = animated_gif((MAX_ANIMATED_FRAMES + 1).min(255) as u8, 2, 2);
        // 255 frames is under the frame cap: it renders whole.
        assert_eq!(
            frame_count(
                &render(&src, "image/gif", Size::Thumb, Play::Loop)
                    .unwrap()
                    .bytes
            ),
            255
        );
        // At the canvas cap (960 x 960 = 921,600 px), 80 frames decode to
        // 80 x 921,600 x 4 bytes, about 295 MB: over the 256 MiB budget.
        let big = animated_gif(80, 960, 960);
        match render(&big, "image/gif", Size::Thumb, Play::Loop) {
            Err(RenderRefusal::TooLarge { .. }) => {}
            other => panic!("expected a refusal, got {:?}", other.map(|e| e.bytes.len())),
        }
    }
}
