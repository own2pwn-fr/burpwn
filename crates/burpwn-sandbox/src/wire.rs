//! Wire format for the SCM_RIGHTS connection hand-off between the in-netns
//! acceptor (sandbox side) and the host proxy.
//!
//! ## Why this contract exists
//!
//! The host (init userns, unprivileged) cannot `setns` into a child userns's
//! netns (EPERM, proven by the spike). So the listener/acceptor that binds
//! `127.0.0.1:<proxy_tcp_port>` and recovers `SO_ORIGINAL_DST` MUST live inside
//! the child userns. Once it has accepted a client connection and read the
//! original destination, it passes the **client socket fd** to the host proxy
//! (which has real connectivity) over a unix-domain socket using
//! `sendmsg(2)` with an `SCM_RIGHTS` control message. The host proxy then does
//! MITM/capture/egress and writes the response back over the passed fd.
//!
//! ## Exact wire format (THE CONTRACT — the proxy receiver must match this)
//!
//! For each handed-off connection the acceptor performs exactly one `sendmsg`
//! on the unix socket carrying:
//!
//! * **Control message**: a single `SCM_RIGHTS` cmsg carrying **exactly one**
//!   file descriptor — the accepted client TCP socket (or the in-netns UDP/53
//!   socket for the DNS hand-off).
//! * **Normal data (the metadata header)**: a fixed-layout little-endian prefix
//!   followed by a variable-length `exec_id`, so the proxy can stamp each
//!   captured flow with the originating `exec` and workspace AT CAPTURE TIME
//!   (no time-window guessing). Layout (all integers little-endian):
//!
//!   ```text
//!   offset  size  field
//!   0       4     magic         = 0x42_57_50_31  ("BWP1", as a LE u32)
//!   4       1     version       = 2
//!   5       1     l4            = 0x06 (TCP) | 0x11 (UDP)
//!   6       1     ip_family     = 4 (IPv4) | 6 (IPv6)
//!   7       1     reserved      = 0
//!   8       2     dst_port      (LE u16, host byte-order value)
//!   10      16    dst_ip        IPv4 = first 4 bytes used, rest 0; IPv6 = all 16
//!   26      8     workspace_id  (LE i64)
//!   34      2     exec_id_len   (LE u16, <= MAX_EXEC_ID)
//!   36      N     exec_id       UTF-8 bytes (N = exec_id_len)
//!   ```
//!
//!   Total: [`MIN_HEADER_LEN`] (36) + `exec_id_len` bytes, at most
//!   [`MAX_HEADER_LEN`]. The receiver reads up to [`MAX_HEADER_LEN`] bytes of
//!   normal data alongside the `SCM_RIGHTS` cmsg in a single `recvmsg`, then
//!   decodes the actual length from the header.
//!
//! The protocol *hint* (`l4`) is advisory: the proxy decides TLS-vs-plain etc.
//! from the destination port and the bytes on the fd; `l4` only tells it whether
//! the passed fd is a stream (TCP) or datagram (UDP) socket.

use std::net::IpAddr;

/// Magic prefix `"BWP1"` interpreted as a little-endian `u32`.
pub const MAGIC: u32 = 0x4257_5031;
/// Current wire version.
pub const VERSION: u8 = 2;
/// Minimum header length: the fixed prefix with an empty `exec_id`.
pub const MIN_HEADER_LEN: usize = 36;
/// Maximum accepted `exec_id` length (bytes).
pub const MAX_EXEC_ID: usize = 256;
/// Maximum header length the receiver must be prepared to read.
pub const MAX_HEADER_LEN: usize = MIN_HEADER_LEN + MAX_EXEC_ID;

const L4_TCP: u8 = 0x06;
const L4_UDP: u8 = 0x11;
const FAM_V4: u8 = 4;
const FAM_V6: u8 = 6;

/// Layer-4 protocol of the passed connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    /// TCP — the passed fd is a stream socket.
    Tcp,
    /// UDP — the passed fd is a datagram socket.
    Udp,
}

impl L4 {
    fn to_byte(self) -> u8 {
        match self {
            L4::Tcp => L4_TCP,
            L4::Udp => L4_UDP,
        }
    }

    fn from_byte(b: u8) -> Result<Self, WireError> {
        match b {
            L4_TCP => Ok(L4::Tcp),
            L4_UDP => Ok(L4::Udp),
            other => Err(WireError::BadL4(other)),
        }
    }
}

/// The metadata describing one handed-off connection.
///
/// Encodes/decodes to/from the header documented at the module level. This is
/// the side-channel that travels alongside the `SCM_RIGHTS` fd in the same
/// `sendmsg`. `exec_id` + `workspace_id` let the host proxy attribute every
/// captured flow to the originating `burpwn exec` directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassedConn {
    /// The pre-NAT destination IP recovered via `SO_ORIGINAL_DST`.
    pub dst_ip: IpAddr,
    /// The pre-NAT destination port.
    pub dst_port: u16,
    /// Layer-4 protocol of the passed socket.
    pub l4: L4,
    /// Workspace id the originating `exec` attributes captures to.
    pub workspace_id: i64,
    /// Correlation id of the originating `burpwn exec` (may be empty for the
    /// explicit-proxy test front-end, which synthesizes a `PassedConn`).
    pub exec_id: String,
}

/// Errors decoding the metadata header.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// The buffer was shorter than the declared header.
    #[error("wire header too short: have {have} bytes, need {need}")]
    Short {
        /// Bytes available.
        have: usize,
        /// Bytes required.
        need: usize,
    },
    /// The magic prefix did not match [`MAGIC`].
    #[error("bad wire magic: {0:#010x}")]
    BadMagic(u32),
    /// Unsupported wire version.
    #[error("unsupported wire version: {0}")]
    BadVersion(u8),
    /// Unknown L4 protocol byte.
    #[error("unknown l4 protocol byte: {0:#04x}")]
    BadL4(u8),
    /// Unknown IP family byte.
    #[error("unknown ip family byte: {0}")]
    BadFamily(u8),
    /// `exec_id` exceeded [`MAX_EXEC_ID`].
    #[error("exec_id too long: {0} > {MAX_EXEC_ID}")]
    ExecIdTooLong(usize),
    /// `exec_id` was not valid UTF-8.
    #[error("exec_id is not valid UTF-8")]
    BadExecIdUtf8,
}

impl PassedConn {
    /// Encode to the little-endian header (variable length: [`MIN_HEADER_LEN`] +
    /// `exec_id.len()`). `exec_id` is truncated to [`MAX_EXEC_ID`] bytes.
    pub fn encode(&self) -> Vec<u8> {
        let exec = self.exec_id.as_bytes();
        let exec = &exec[..exec.len().min(MAX_EXEC_ID)];
        let mut buf = vec![0u8; MIN_HEADER_LEN + exec.len()];
        buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        buf[4] = VERSION;
        buf[5] = self.l4.to_byte();
        match self.dst_ip {
            IpAddr::V4(v4) => {
                buf[6] = FAM_V4;
                buf[10..14].copy_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf[6] = FAM_V6;
                buf[10..26].copy_from_slice(&v6.octets());
            }
        }
        // buf[7] reserved = 0
        buf[8..10].copy_from_slice(&self.dst_port.to_le_bytes());
        buf[26..34].copy_from_slice(&self.workspace_id.to_le_bytes());
        buf[34..36].copy_from_slice(&(exec.len() as u16).to_le_bytes());
        buf[36..36 + exec.len()].copy_from_slice(exec);
        buf
    }

    /// Decode from a received buffer (`buf` is the exact `recvmsg` data, which
    /// may be longer than the header if the sender over-allocated — only the
    /// declared bytes are read).
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < MIN_HEADER_LEN {
            return Err(WireError::Short {
                have: buf.len(),
                need: MIN_HEADER_LEN,
            });
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != MAGIC {
            return Err(WireError::BadMagic(magic));
        }
        if buf[4] != VERSION {
            return Err(WireError::BadVersion(buf[4]));
        }
        let l4 = L4::from_byte(buf[5])?;
        let dst_port = u16::from_le_bytes([buf[8], buf[9]]);
        let dst_ip = match buf[6] {
            FAM_V4 => IpAddr::from([buf[10], buf[11], buf[12], buf[13]]),
            FAM_V6 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[10..26]);
                IpAddr::from(octets)
            }
            other => return Err(WireError::BadFamily(other)),
        };
        let workspace_id = i64::from_le_bytes([
            buf[26], buf[27], buf[28], buf[29], buf[30], buf[31], buf[32], buf[33],
        ]);
        let exec_len = u16::from_le_bytes([buf[34], buf[35]]) as usize;
        if exec_len > MAX_EXEC_ID {
            return Err(WireError::ExecIdTooLong(exec_len));
        }
        let need = MIN_HEADER_LEN + exec_len;
        if buf.len() < need {
            return Err(WireError::Short {
                have: buf.len(),
                need,
            });
        }
        let exec_id = std::str::from_utf8(&buf[MIN_HEADER_LEN..need])
            .map_err(|_| WireError::BadExecIdUtf8)?
            .to_string();
        Ok(PassedConn {
            dst_ip,
            dst_port,
            l4,
            workspace_id,
            exec_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn pc(ip: IpAddr, port: u16, l4: L4, ws: i64, exec: &str) -> PassedConn {
        PassedConn {
            dst_ip: ip,
            dst_port: port,
            l4,
            workspace_id: ws,
            exec_id: exec.into(),
        }
    }

    #[test]
    fn round_trip_ipv4_tcp_with_exec() {
        let c = pc(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            L4::Tcp,
            7,
            "exec-123-0-999",
        );
        let buf = c.encode();
        assert_eq!(buf.len(), MIN_HEADER_LEN + "exec-123-0-999".len());
        assert_eq!(PassedConn::decode(&buf).unwrap(), c);
    }

    #[test]
    fn round_trip_ipv6_udp_empty_exec() {
        let c = pc(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
            53,
            L4::Udp,
            1,
            "",
        );
        let buf = c.encode();
        assert_eq!(buf.len(), MIN_HEADER_LEN);
        assert_eq!(PassedConn::decode(&buf).unwrap(), c);
    }

    #[test]
    fn decode_tolerates_overlong_buffer() {
        // The receiver hands `decode` the whole recv buffer; trailing bytes past
        // the declared exec_id must be ignored.
        let c = pc(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, L4::Tcp, 2, "e1");
        let mut buf = c.encode();
        buf.extend_from_slice(&[0xAA; 64]);
        assert_eq!(PassedConn::decode(&buf).unwrap(), c);
    }

    #[test]
    fn header_has_expected_magic_and_version() {
        let buf = pc(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, L4::Tcp, 1, "x").encode();
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), MAGIC);
        assert_eq!(buf[4], VERSION);
        assert_eq!(&buf[0..4], b"1PWB"); // little-endian of 0x42575031
    }

    #[test]
    fn port_and_workspace_are_little_endian() {
        let buf = pc(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x1234, L4::Tcp, 0x0102, "").encode();
        assert_eq!([buf[8], buf[9]], [0x34, 0x12]);
        assert_eq!([buf[26], buf[27]], [0x02, 0x01]);
    }

    #[test]
    fn decode_rejects_short_magic_version() {
        assert!(matches!(
            PassedConn::decode(&[0u8; 10]),
            Err(WireError::Short { .. })
        ));
        let mut buf = pc(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, L4::Tcp, 1, "x").encode();
        let good = buf.clone();
        buf[0] ^= 0xff;
        assert!(matches!(
            PassedConn::decode(&buf),
            Err(WireError::BadMagic(_))
        ));
        buf = good;
        buf[4] = 99;
        assert_eq!(PassedConn::decode(&buf), Err(WireError::BadVersion(99)));
    }

    #[test]
    fn decode_rejects_bad_l4_and_family() {
        let good = pc(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, L4::Tcp, 1, "x").encode();
        let mut buf = good.clone();
        buf[5] = 0x99;
        assert_eq!(PassedConn::decode(&buf), Err(WireError::BadL4(0x99)));
        buf = good;
        buf[6] = 0x07;
        assert_eq!(PassedConn::decode(&buf), Err(WireError::BadFamily(0x07)));
    }

    #[test]
    fn decode_rejects_truncated_exec_id() {
        // Declared exec_id longer than the buffer provides.
        let mut buf = pc(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, L4::Tcp, 1, "abcd").encode();
        // claim 200 bytes of exec_id but don't provide them
        buf[34..36].copy_from_slice(&200u16.to_le_bytes());
        assert!(matches!(
            PassedConn::decode(&buf),
            Err(WireError::Short { .. })
        ));
    }
}
