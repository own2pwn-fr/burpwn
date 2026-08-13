//! WebSocket frame parsing, message reassembly and re-framing.
//!
//! Two consumers, one parser:
//!
//! - **Capture** ([`Scanner`]). The splice path forwards the two upgraded byte
//!   streams verbatim; this observes a COPY of each direction and turns the raw
//!   bytes into structured, complete WebSocket messages so the store gets real
//!   frames instead of the old in-band `ws-c2s:`/`ws-s2c:` marker hack.
//! - **Hooks** ([`Framer`]). A `ws-c2s`/`ws-s2c` hook has to act on a message
//!   BEFORE it is relayed, which means the pump can no longer forward bytes it
//!   has not yet interpreted. [`Framer`] is the same parse, except that it hands
//!   back the exact wire bytes alongside each message — so a message no hook
//!   touched is re-forwarded byte for byte (mask, fragmentation and all) rather
//!   than re-encoded, and only a payload a hook actually rewrote is rebuilt with
//!   [`encode_frame`].
//!
//! What the parse does:
//! - parses RFC6455 frames (FIN, opcode, MASK bit + masking-key, 7/16/64-bit
//!   payload length),
//! - unmasks masked frames (client→server frames are always masked),
//! - reassembles continuation-fragmented data messages,
//! - surfaces control frames (ping/pong/close) separately so they are never
//!   treated as data messages — and, on the hook path, never rewritten or
//!   refused: a dropped `close` leaks a socket and a rewritten `ping` breaks the
//!   pong echo RFC6455 §5.5.2 requires.
//!
//! Everything here is pure (no I/O), so the frame parser is unit-tested in
//! isolation and the async splice in `http.rs` just drives it.
//!
//! **RSV / extensions.** Nothing here interprets RSV1-3, so a payload
//! compressed by `permessage-deflate` is opaque to it: the capture stores the
//! compressed bytes, and the hook path REFUSES to run on such a socket at all
//! (see `http.rs`) rather than rewrite bytes it cannot read.

/// Continuation frame opcode.
pub const OP_CONTINUATION: u8 = 0x0;
/// Text frame opcode.
pub const OP_TEXT: u8 = 0x1;
/// Binary frame opcode.
pub const OP_BINARY: u8 = 0x2;
/// Close control frame opcode.
pub const OP_CLOSE: u8 = 0x8;
/// Ping control frame opcode.
pub const OP_PING: u8 = 0x9;
/// Pong control frame opcode.
pub const OP_PONG: u8 = 0xA;

/// Largest single frame payload we are willing to buffer for capture. A frame
/// declaring more than this is treated as a desync (we stop parsing that
/// direction and keep forwarding verbatim) so a hostile/garbage length can't
/// make us allocate without bound. Forwarding is unaffected — this only bounds
/// the observer's memory.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// Largest reassembled message we retain. Continuation fragments beyond this are
/// dropped from the captured copy (the message is still persisted, truncated).
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// A single parsed WebSocket frame with its payload already unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// FIN bit.
    pub fin: bool,
    /// 4-bit opcode.
    pub opcode: u8,
    /// Unmasked payload bytes.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Whether this frame is a control frame (close/ping/pong): opcode ≥ 0x8.
    pub fn is_control(&self) -> bool {
        self.opcode & 0x08 != 0
    }
}

/// Result of attempting to parse one frame off the front of a buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseOutcome {
    /// A complete frame was parsed; `consumed` bytes should be drained.
    Frame {
        /// The parsed frame.
        frame: Frame,
        /// Bytes consumed from the input.
        consumed: usize,
    },
    /// Not enough bytes yet; caller should read more and retry.
    Incomplete,
    /// The declared payload length exceeds [`MAX_FRAME_PAYLOAD`]; the stream is
    /// considered desynced for capture purposes.
    TooLarge,
}

/// Parse a single frame from the front of `buf`. Never panics on malformed
/// input; returns [`ParseOutcome::Incomplete`] when more bytes are required.
pub fn parse_frame(buf: &[u8]) -> ParseOutcome {
    if buf.len() < 2 {
        return ParseOutcome::Incomplete;
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0f;
    let masked = b1 & 0x80 != 0;
    let len7 = (b1 & 0x7f) as usize;

    // Resolve the extended payload length + the offset where it ends.
    let (payload_len, mut offset) = match len7 {
        126 => {
            if buf.len() < 4 {
                return ParseOutcome::Incomplete;
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
        }
        127 => {
            if buf.len() < 10 {
                return ParseOutcome::Incomplete;
            }
            let mut l = [0u8; 8];
            l.copy_from_slice(&buf[2..10]);
            let len = u64::from_be_bytes(l);
            // A length that doesn't fit usize (or exceeds our cap) is a desync.
            match usize::try_from(len) {
                Ok(v) => (v, 10),
                Err(_) => return ParseOutcome::TooLarge,
            }
        }
        n => (n, 2),
    };

    if payload_len > MAX_FRAME_PAYLOAD {
        return ParseOutcome::TooLarge;
    }

    // Masking key (client→server frames are masked; server→client are not).
    let mask_key = if masked {
        if buf.len() < offset + 4 {
            return ParseOutcome::Incomplete;
        }
        let key = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        offset += 4;
        Some(key)
    } else {
        None
    };

    let end = match offset.checked_add(payload_len) {
        Some(e) => e,
        None => return ParseOutcome::TooLarge,
    };
    if buf.len() < end {
        return ParseOutcome::Incomplete;
    }

    let mut payload = buf[offset..end].to_vec();
    if let Some(key) = mask_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i & 3];
        }
    }

    ParseOutcome::Frame {
        frame: Frame {
            fin,
            opcode,
            payload,
        },
        consumed: end,
    }
}

/// A complete WebSocket message emitted by the [`Reassembler`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Effective opcode (the opcode of the first frame for a fragmented data
    /// message, or the control opcode for a control frame).
    pub opcode: u8,
    /// Always `true` — a `Message` is only emitted once complete.
    pub fin: bool,
    /// Reassembled, unmasked payload.
    pub payload: Vec<u8>,
    /// Whether this is a control frame (ping/pong/close) rather than data.
    pub control: bool,
}

/// One thing a [`Framer`] produces, in the order the bytes arrived. Every byte
/// fed in comes back out in exactly one of these, which is what lets the hook
/// pump forward from the framer instead of from the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emit {
    /// A complete data message: reassembled and unmasked, plus the exact wire
    /// bytes that carried it (one frame, or the whole continuation chain).
    Data {
        /// Effective opcode (the first frame's, for a fragmented message).
        opcode: u8,
        /// Reassembled, unmasked payload.
        payload: Vec<u8>,
        /// The wire bytes this message arrived as, to re-forward verbatim.
        raw: Vec<u8>,
        /// Whether `payload` was cut at [`MAX_MESSAGE`] and is therefore NOT
        /// the whole message. Such a payload may be stored (truncated capture,
        /// as before) but must never be re-encoded onto the wire.
        truncated: bool,
    },
    /// A control frame (ping/pong/close): forwarded verbatim, never hooked.
    Control {
        /// Control opcode.
        opcode: u8,
        /// Unmasked control payload.
        payload: Vec<u8>,
        /// The wire bytes to re-forward.
        raw: Vec<u8>,
    },
    /// Bytes the framer cannot interpret as a message — a stray continuation, or
    /// everything it still holds when it desyncs. They must still reach the
    /// peer, so they come back out here rather than being swallowed.
    Passthrough(Vec<u8>),
}

/// Streaming frame parser + continuation reassembler for one direction, keeping
/// the wire bytes.
///
/// Control frames are surfaced immediately and never disturb an in-progress
/// fragmented data message. On a desync (an implausibly large declared length,
/// or garbage that never yields a frame) it hands back everything it holds as
/// [`Emit::Passthrough`] and degrades to a pipe: no more parsing, no more
/// capture, but not one byte lost.
#[derive(Default)]
pub struct Framer {
    buf: Vec<u8>,
    frag_opcode: Option<u8>,
    frag_payload: Vec<u8>,
    frag_raw: Vec<u8>,
    frag_truncated: bool,
    desynced: bool,
}

impl Framer {
    /// A fresh framer with no buffered bytes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the framer holds nothing: no partial frame, no fragmented
    /// message in progress. The only point at which a caller may switch between
    /// forwarding raw bytes and forwarding the framer's output without either
    /// duplicating or losing a byte.
    pub fn at_boundary(&self) -> bool {
        self.buf.is_empty() && self.frag_opcode.is_none()
    }

    /// Whether the framer has given up parsing this direction.
    pub fn desynced(&self) -> bool {
        self.desynced
    }

    /// Feed newly-read bytes and drain what they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Emit> {
        let mut out = Vec::new();
        if self.desynced {
            // A pipe from here on: the caller still has to forward.
            if !bytes.is_empty() {
                out.push(Emit::Passthrough(bytes.to_vec()));
            }
            return out;
        }
        self.buf.extend_from_slice(bytes);
        loop {
            match parse_frame(&self.buf) {
                ParseOutcome::Frame { frame, consumed } => {
                    let raw: Vec<u8> = self.buf.drain(..consumed).collect();
                    if let Some(emit) = self.absorb(frame, raw) {
                        out.push(emit);
                    }
                }
                ParseOutcome::Incomplete => break,
                ParseOutcome::TooLarge => {
                    // Can't reliably resynchronize a WS stream mid-frame; give up
                    // parsing this direction rather than risk unbounded memory —
                    // but hand back every byte still held, because the peer is
                    // waiting for them.
                    self.desynced = true;
                    let mut left = std::mem::take(&mut self.frag_raw);
                    left.append(&mut self.buf);
                    self.frag_payload = Vec::new();
                    self.frag_opcode = None;
                    if !left.is_empty() {
                        out.push(Emit::Passthrough(left));
                    }
                    break;
                }
            }
        }
        out
    }

    /// Fold one parsed frame into message state, returning what to emit.
    fn absorb(&mut self, frame: Frame, raw: Vec<u8>) -> Option<Emit> {
        if frame.is_control() {
            // Control frames are self-contained and must not interrupt an
            // in-progress fragmented DATA message (RFC6455 §5.4).
            return Some(Emit::Control {
                opcode: frame.opcode,
                payload: frame.payload,
                raw,
            });
        }
        match frame.opcode {
            OP_CONTINUATION => {
                // A continuation with no started message is a protocol error.
                // Not ours to fix: forward it and let the peer decide.
                if self.frag_opcode.is_none() {
                    return Some(Emit::Passthrough(raw));
                }
                self.frag_truncated |=
                    append_capped(&mut self.frag_payload, &frame.payload, MAX_MESSAGE);
                self.frag_raw.extend_from_slice(&raw);
                if !frame.fin {
                    return None;
                }
                let opcode = self.frag_opcode.take().unwrap_or(OP_BINARY);
                Some(Emit::Data {
                    opcode,
                    payload: std::mem::take(&mut self.frag_payload),
                    raw: std::mem::take(&mut self.frag_raw),
                    truncated: std::mem::take(&mut self.frag_truncated),
                })
            }
            op => {
                if frame.fin {
                    // Self-contained single-frame data message.
                    return Some(Emit::Data {
                        opcode: op,
                        payload: frame.payload,
                        raw,
                        truncated: false,
                    });
                }
                // Start of a fragmented message.
                self.frag_opcode = Some(op);
                self.frag_payload.clear();
                self.frag_raw.clear();
                self.frag_truncated =
                    append_capped(&mut self.frag_payload, &frame.payload, MAX_MESSAGE);
                self.frag_raw.extend_from_slice(&raw);
                None
            }
        }
    }
}

/// Streaming frame scanner + continuation reassembler for one direction.
///
/// Feed it raw bytes with [`Scanner::push`]; it returns every COMPLETE message
/// discovered so far. A thin view over [`Framer`] that drops the wire bytes:
/// the capture-only splice path never needs them.
#[derive(Default)]
pub struct Scanner {
    framer: Framer,
}

impl Scanner {
    /// A fresh scanner with no buffered bytes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed newly-forwarded bytes and drain any messages they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Message> {
        self.framer
            .push(bytes)
            .into_iter()
            .filter_map(message_of)
            .collect()
    }
}

/// The captured [`Message`] an emit carries, if any.
pub fn message_of(emit: Emit) -> Option<Message> {
    match emit {
        Emit::Data {
            opcode, payload, ..
        } => Some(Message {
            opcode,
            fin: true,
            payload,
            control: false,
        }),
        Emit::Control {
            opcode, payload, ..
        } => Some(Message {
            opcode,
            fin: true,
            payload,
            control: true,
        }),
        Emit::Passthrough(_) => None,
    }
}

/// Serialize one unfragmented frame. `mask` must be `Some` for a frame sent
/// TOWARD a server (RFC6455 §5.3 requires client→server frames to be masked) and
/// `None` for one sent toward a client.
///
/// Only ever used for a payload a hook rewrote: an untouched message is
/// re-forwarded as the bytes it arrived as, so nothing here can change the shape
/// of traffic nobody asked to modify.
pub fn encode_frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | (opcode & 0x0f)); // FIN, no RSV
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// A masking key for a re-encoded client→server frame.
///
/// RFC6455 wants it unpredictable to stop a hostile page steering intermediary
/// caches; here the "hostile page" would be the operator's own tooling, so this
/// is framing hygiene rather than a security boundary — a per-thread xorshift
/// seeded from the process's random hasher, and no dependency for it.
pub fn mask_key() -> [u8; 4] {
    use std::cell::Cell;
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0) };
    }
    STATE.with(|state| {
        let mut x = state.get();
        if x == 0 {
            x = RandomState::new().build_hasher().finish() | 1;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        (x as u32).to_ne_bytes()
    })
}

/// Append `src` to `dst` without letting `dst` exceed `cap` bytes. Returns
/// whether anything had to be dropped, which the caller needs: a payload that
/// lost bytes is no longer the message and must not be re-encoded onto the wire.
fn append_capped(dst: &mut Vec<u8>, src: &[u8], cap: usize) -> bool {
    if dst.len() >= cap {
        return !src.is_empty();
    }
    let take = src.len().min(cap - dst.len());
    dst.extend_from_slice(&src[..take]);
    take < src.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a WS frame on the wire. `mask` applies client-style masking.
    fn frame(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((if fin { 0x80 } else { 0 }) | (opcode & 0x0f));
        let len = payload.len();
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        if len < 126 {
            out.push(mask_bit | len as u8);
        } else if len <= u16::MAX as usize {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        match mask {
            Some(key) => {
                out.extend_from_slice(&key);
                for (i, b) in payload.iter().enumerate() {
                    out.push(b ^ key[i & 3]);
                }
            }
            None => out.extend_from_slice(payload),
        }
        out
    }

    #[test]
    fn parses_unmasked_text_frame() {
        let wire = frame(true, OP_TEXT, b"hello", None);
        match parse_frame(&wire) {
            ParseOutcome::Frame { frame, consumed } => {
                assert_eq!(consumed, wire.len());
                assert!(frame.fin);
                assert_eq!(frame.opcode, OP_TEXT);
                assert_eq!(frame.payload, b"hello");
            }
            other => panic!("expected frame, got {other:?}"),
        }
    }

    #[test]
    fn parses_and_unmasks_client_frame() {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let wire = frame(true, OP_BINARY, b"secret payload", Some(key));
        match parse_frame(&wire) {
            ParseOutcome::Frame { frame, .. } => {
                assert_eq!(frame.opcode, OP_BINARY);
                assert_eq!(frame.payload, b"secret payload");
            }
            other => panic!("expected frame, got {other:?}"),
        }
    }

    #[test]
    fn incomplete_frame_reports_incomplete() {
        let wire = frame(true, OP_TEXT, b"hello world", None);
        assert_eq!(parse_frame(&wire[..3]), ParseOutcome::Incomplete);
        assert_eq!(parse_frame(&[]), ParseOutcome::Incomplete);
        assert_eq!(parse_frame(&[0x81]), ParseOutcome::Incomplete);
    }

    #[test]
    fn parses_16bit_extended_length() {
        let payload = vec![0xABu8; 300]; // > 125 → 16-bit length
        let wire = frame(true, OP_BINARY, &payload, None);
        assert_eq!(wire[1] & 0x7f, 126, "must use 16-bit length");
        match parse_frame(&wire) {
            ParseOutcome::Frame { frame, consumed } => {
                assert_eq!(frame.payload, payload);
                assert_eq!(consumed, wire.len());
            }
            other => panic!("expected frame, got {other:?}"),
        }
    }

    #[test]
    fn parses_64bit_extended_length() {
        let payload = vec![0x5Au8; 70_000]; // > u16::MAX → 64-bit length
        let wire = frame(true, OP_BINARY, &payload, Some([1, 2, 3, 4]));
        assert_eq!(wire[1] & 0x7f, 127, "must use 64-bit length");
        match parse_frame(&wire) {
            ParseOutcome::Frame { frame, consumed } => {
                assert_eq!(frame.payload, payload);
                assert_eq!(consumed, wire.len());
            }
            other => panic!("expected frame, got {other:?}"),
        }
    }

    #[test]
    fn reassembles_fragmented_message() {
        // "Hel" (text, !fin) + "lo " (cont, !fin) + "world" (cont, fin).
        let mut scanner = Scanner::new();
        let f1 = frame(false, OP_TEXT, b"Hel", None);
        let f2 = frame(false, OP_CONTINUATION, b"lo ", None);
        let f3 = frame(true, OP_CONTINUATION, b"world", None);

        assert!(scanner.push(&f1).is_empty());
        assert!(scanner.push(&f2).is_empty());
        let msgs = scanner.push(&f3);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].opcode, OP_TEXT);
        assert_eq!(msgs[0].payload, b"Hello world");
        assert!(!msgs[0].control);
    }

    #[test]
    fn control_frame_does_not_break_fragmentation() {
        let mut scanner = Scanner::new();
        let start = frame(false, OP_TEXT, b"data-", None);
        let ping = frame(true, OP_PING, b"pingpayload", None);
        let end = frame(true, OP_CONTINUATION, b"more", None);

        assert!(scanner.push(&start).is_empty());
        // Interleaved ping must surface as a control message on its own.
        let mid = scanner.push(&ping);
        assert_eq!(mid.len(), 1);
        assert!(mid[0].control);
        assert_eq!(mid[0].opcode, OP_PING);
        // Then the fragmented data message completes intact.
        let done = scanner.push(&end);
        assert_eq!(done.len(), 1);
        assert!(!done[0].control);
        assert_eq!(done[0].payload, b"data-more");
    }

    #[test]
    fn scanner_splits_multiple_frames_in_one_push() {
        let mut scanner = Scanner::new();
        let mut wire = frame(true, OP_TEXT, b"one", None);
        wire.extend_from_slice(&frame(true, OP_TEXT, b"two", None));
        let msgs = scanner.push(&wire);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].payload, b"one");
        assert_eq!(msgs[1].payload, b"two");
    }

    // --- the framer (the hook path) -----------------------------------------

    /// The property the whole hook pump rests on: every byte fed in comes back
    /// out exactly once, and an untouched message comes back as the bytes it
    /// arrived as — mask and fragmentation included — so forwarding it is a
    /// copy, not a re-encode.
    #[test]
    fn the_framer_returns_the_exact_wire_bytes_of_every_message() {
        let mut wire = frame(true, OP_TEXT, b"hello", Some([1, 2, 3, 4]));
        let ping = frame(true, OP_PING, b"beat", Some([9, 9, 9, 9]));
        wire.extend_from_slice(&ping);
        let frag: Vec<u8> = [
            frame(false, OP_BINARY, b"AA", None),
            frame(false, OP_CONTINUATION, b"BB", None),
            frame(true, OP_CONTINUATION, b"CC", None),
        ]
        .concat();
        wire.extend_from_slice(&frag);

        let mut framer = Framer::new();
        let emits = framer.push(&wire);
        assert_eq!(emits.len(), 3, "{emits:?}");
        assert_eq!(
            emits[0],
            Emit::Data {
                opcode: OP_TEXT,
                payload: b"hello".to_vec(),
                raw: frame(true, OP_TEXT, b"hello", Some([1, 2, 3, 4])),
                truncated: false,
            }
        );
        assert_eq!(
            emits[1],
            Emit::Control {
                opcode: OP_PING,
                payload: b"beat".to_vec(),
                raw: ping,
            }
        );
        // The fragmented message: one payload, and the THREE frames as they
        // arrived (re-forwarding must not silently defragment).
        assert_eq!(
            emits[2],
            Emit::Data {
                opcode: OP_BINARY,
                payload: b"AABBCC".to_vec(),
                raw: frag,
                truncated: false,
            }
        );
        assert!(framer.at_boundary());
    }

    /// A boundary is only a boundary when nothing is held: a partial frame and
    /// an unfinished fragmented message both forbid the pump from switching
    /// between raw forwarding and framed forwarding.
    #[test]
    fn at_boundary_is_false_while_anything_is_held() {
        let mut framer = Framer::new();
        let wire = frame(true, OP_TEXT, b"hello world", None);
        assert!(framer.at_boundary());
        assert!(framer.push(&wire[..4]).is_empty());
        assert!(!framer.at_boundary(), "half a frame is not a boundary");
        framer.push(&wire[4..]);
        assert!(framer.at_boundary());

        framer.push(&frame(false, OP_TEXT, b"start", None));
        assert!(!framer.at_boundary(), "mid-message is not a boundary");
        framer.push(&frame(true, OP_CONTINUATION, b"end", None));
        assert!(framer.at_boundary());
    }

    /// A desync must not eat the bytes it was holding: the peer is waiting for
    /// them, and after it the framer is a pipe.
    #[test]
    fn a_desync_hands_back_everything_it_held_and_then_pipes() {
        let mut framer = Framer::new();
        // Start a fragmented message, then a frame claiming an absurd length.
        let start = frame(false, OP_BINARY, b"held", None);
        framer.push(&start);
        let mut huge = vec![0x82, 0xff];
        huge.extend_from_slice(&(u64::MAX).to_be_bytes());
        let emits = framer.push(&huge);
        assert!(framer.desynced());
        let mut expected = start.clone();
        expected.extend_from_slice(&huge);
        assert_eq!(emits, vec![Emit::Passthrough(expected)]);
        // …and from here on every byte is handed straight back.
        assert_eq!(
            framer.push(b"junk"),
            vec![Emit::Passthrough(b"junk".to_vec())]
        );
    }

    /// A continuation with nothing to continue is a peer protocol error, not
    /// ours to swallow: it has to reach the other side.
    #[test]
    fn a_stray_continuation_is_passed_through_not_dropped() {
        let mut framer = Framer::new();
        let stray = frame(true, OP_CONTINUATION, b"orphan", None);
        assert_eq!(
            framer.push(&stray),
            vec![Emit::Passthrough(stray.clone())],
            "the bytes must still reach the peer"
        );
        // The capture view still ignores it, exactly as before.
        let mut scanner = Scanner::new();
        assert!(scanner.push(&stray).is_empty());
    }

    #[test]
    fn encode_frame_round_trips_masked_and_unmasked() {
        for payload in [b"short".to_vec(), vec![7u8; 300], vec![3u8; 70_000]] {
            for mask in [None, Some([0x37, 0xfa, 0x21, 0x3d])] {
                let wire = encode_frame(OP_TEXT, &payload, mask);
                match parse_frame(&wire) {
                    ParseOutcome::Frame { frame, consumed } => {
                        assert_eq!(consumed, wire.len());
                        assert!(frame.fin);
                        assert_eq!(frame.opcode, OP_TEXT);
                        assert_eq!(frame.payload, payload);
                        assert_eq!(wire[1] & 0x80 != 0, mask.is_some());
                    }
                    other => panic!("expected frame, got {other:?}"),
                }
            }
        }
        // No RSV bit is ever set: an extension-negotiated socket is refused
        // upstream of here, so a re-encoded frame is always plain.
        assert_eq!(encode_frame(OP_BINARY, b"x", None)[0], 0x82);
    }

    #[test]
    fn mask_keys_are_not_all_the_same() {
        let first = mask_key();
        assert!(
            (0..8).any(|_| mask_key() != first),
            "a constant mask key would be a fixed XOR of the payload"
        );
    }

    #[test]
    fn scanner_handles_byte_at_a_time() {
        let wire = frame(true, OP_BINARY, b"streamed", Some([9, 8, 7, 6]));
        let mut scanner = Scanner::new();
        let mut got = Vec::new();
        for b in &wire {
            got.extend(scanner.push(&[*b]));
        }
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload, b"streamed");
    }
}
