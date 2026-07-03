//! WebSocket frame parsing + message reassembly for *capture*.
//!
//! The splice path forwards the two upgraded byte streams verbatim (it never
//! rewrites the wire); this module observes a COPY of each direction and turns
//! the raw bytes into structured, complete WebSocket messages so the store gets
//! real frames instead of the old in-band `ws-c2s:`/`ws-s2c:` marker hack.
//!
//! What it does:
//! - parses RFC6455 frames (FIN, opcode, MASK bit + masking-key, 7/16/64-bit
//!   payload length),
//! - unmasks masked frames (client→server frames are always masked),
//! - reassembles continuation-fragmented data messages,
//! - surfaces control frames (ping/pong/close) separately so they are never
//!   treated as data messages.
//!
//! Everything here is pure (no I/O), so the frame parser is unit-tested in
//! isolation and the async splice in `http.rs` just drives it.

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

/// Streaming frame scanner + continuation reassembler for one direction.
///
/// Feed it raw bytes with [`Scanner::push`]; it returns every COMPLETE message
/// discovered so far. Control frames are surfaced immediately and never disturb
/// an in-progress fragmented data message. On a desync (an implausibly large
/// declared length or garbage that never yields a frame past the buffer cap) it
/// stops parsing and silently ignores further bytes — forwarding is handled by
/// the caller and is unaffected.
#[derive(Default)]
pub struct Scanner {
    buf: Vec<u8>,
    frag_opcode: Option<u8>,
    frag_payload: Vec<u8>,
    desynced: bool,
}

impl Scanner {
    /// A fresh scanner with no buffered bytes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed newly-forwarded bytes and drain any messages they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Message> {
        let mut out = Vec::new();
        if self.desynced {
            return out;
        }
        self.buf.extend_from_slice(bytes);
        loop {
            match parse_frame(&self.buf) {
                ParseOutcome::Frame { frame, consumed } => {
                    self.buf.drain(..consumed);
                    if let Some(msg) = self.absorb(frame) {
                        out.push(msg);
                    }
                }
                ParseOutcome::Incomplete => break,
                ParseOutcome::TooLarge => {
                    // Can't reliably resynchronize a WS stream mid-frame; give up
                    // capturing this direction rather than risk unbounded memory.
                    self.desynced = true;
                    self.buf.clear();
                    self.frag_payload.clear();
                    self.frag_opcode = None;
                    break;
                }
            }
        }
        out
    }

    /// Fold one parsed frame into message state, returning a completed message.
    fn absorb(&mut self, frame: Frame) -> Option<Message> {
        if frame.is_control() {
            // Control frames are self-contained and must not interrupt an
            // in-progress fragmented DATA message (RFC6455 §5.4).
            return Some(Message {
                opcode: frame.opcode,
                fin: true,
                payload: frame.payload,
                control: true,
            });
        }
        match frame.opcode {
            OP_CONTINUATION => {
                // A continuation with no started message is a protocol error;
                // ignore it for capture purposes.
                self.frag_opcode?;
                append_capped(&mut self.frag_payload, &frame.payload, MAX_MESSAGE);
                if frame.fin {
                    let opcode = self.frag_opcode.take().unwrap_or(OP_BINARY);
                    let payload = std::mem::take(&mut self.frag_payload);
                    Some(Message {
                        opcode,
                        fin: true,
                        payload,
                        control: false,
                    })
                } else {
                    None
                }
            }
            op => {
                if frame.fin {
                    // Self-contained single-frame data message.
                    Some(Message {
                        opcode: op,
                        fin: true,
                        payload: frame.payload,
                        control: false,
                    })
                } else {
                    // Start of a fragmented message.
                    self.frag_opcode = Some(op);
                    self.frag_payload.clear();
                    append_capped(&mut self.frag_payload, &frame.payload, MAX_MESSAGE);
                    None
                }
            }
        }
    }
}

/// Append `src` to `dst` without letting `dst` exceed `cap` bytes.
fn append_capped(dst: &mut Vec<u8>, src: &[u8], cap: usize) {
    if dst.len() >= cap {
        return;
    }
    let take = src.len().min(cap - dst.len());
    dst.extend_from_slice(&src[..take]);
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
