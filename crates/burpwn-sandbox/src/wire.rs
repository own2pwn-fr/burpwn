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
//!   file descriptor — the accepted client TCP socket.
//! * **Normal data (the metadata header)**: a length-prefixed, fixed-layout
//!   little-endian blob describing the recovered pre-NAT destination. `sendmsg`
//!   requires at least one byte of normal data to carry a control message, so
//!   the header doubles as that payload. Layout (all integers little-endian):
//!
//!   ```text
//!   offset  size  field
//!   0       4     magic         = 0x42_57_50_31  ("BWP1", as a LE u32)
//!   4       1     version       = 1
//!   5       1     l4            = 0x06 (TCP) | 0x11 (UDP)
//!   6       1     ip_family     = 4 (IPv4) | 6 (IPv6)
//!   7       1     reserved      = 0
//!   8       2     dst_port      (LE u16, host byte order value)
//!   10      16    dst_ip        IPv4 = first 4 bytes used, rest 0;
//!                               IPv6 = all 16 bytes
//!   ```
//!
//!   Total: a **fixed 26-byte** header. Because the size is fixed and known to
//!   both sides, the receiver reads exactly [`HEADER_LEN`] bytes of normal data
//!   alongside the `SCM_RIGHTS` cmsg in a single `recvmsg`.
//!
//! The protocol *hint* (`l4`) is advisory: the proxy decides TLS-vs-plain etc.
//! from the destination port and the bytes on the fd; `l4` only tells it whether
//! the passed fd is a stream (TCP) or datagram (UDP) socket.

use std::net::IpAddr;

/// Magic prefix `"BWP1"` interpreted as a little-endian `u32`.
pub const MAGIC: u32 = 0x4257_5031;
/// Current wire version.
pub const VERSION: u8 = 1;
/// Fixed length of the metadata header in bytes.
pub const HEADER_LEN: usize = 26;

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
/// Encodes/decodes to/from the fixed [`HEADER_LEN`]-byte header documented at
/// the module level. This is the side-channel that travels alongside the
/// `SCM_RIGHTS` fd in the same `sendmsg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassedConn {
    /// The pre-NAT destination IP recovered via `SO_ORIGINAL_DST`.
    pub dst_ip: IpAddr,
    /// The pre-NAT destination port.
    pub dst_port: u16,
    /// Layer-4 protocol of the passed socket.
    pub l4: L4,
}

/// Errors decoding the metadata header.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// The buffer was not exactly [`HEADER_LEN`] bytes.
    #[error("wire header must be {HEADER_LEN} bytes, got {0}")]
    BadLength(usize),
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
}

impl PassedConn {
    /// Encode to the fixed [`HEADER_LEN`]-byte little-endian header.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
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
        buf
    }

    /// Decode from a buffer that must be exactly [`HEADER_LEN`] bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() != HEADER_LEN {
            return Err(WireError::BadLength(buf.len()));
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
            FAM_V4 => {
                let octets: [u8; 4] = [buf[10], buf[11], buf[12], buf[13]];
                IpAddr::from(octets)
            }
            FAM_V6 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[10..26]);
                IpAddr::from(octets)
            }
            other => return Err(WireError::BadFamily(other)),
        };
        Ok(PassedConn {
            dst_ip,
            dst_port,
            l4,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn round_trip_ipv4_tcp() {
        let pc = PassedConn {
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            l4: L4::Tcp,
        };
        let buf = pc.encode();
        assert_eq!(buf.len(), HEADER_LEN);
        assert_eq!(PassedConn::decode(&buf).unwrap(), pc);
    }

    #[test]
    fn round_trip_ipv6_udp() {
        let pc = PassedConn {
            dst_ip: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
            dst_port: 53,
            l4: L4::Udp,
        };
        let buf = pc.encode();
        assert_eq!(PassedConn::decode(&buf).unwrap(), pc);
    }

    #[test]
    fn header_has_expected_magic_and_version() {
        let pc = PassedConn {
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: 80,
            l4: L4::Tcp,
        };
        let buf = pc.encode();
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), MAGIC);
        assert_eq!(buf[4], VERSION);
        // "BWP1" ASCII check on the magic bytes.
        assert_eq!(&buf[0..4], b"1PWB"); // little-endian of 0x42575031
    }

    #[test]
    fn port_is_little_endian_in_header() {
        let pc = PassedConn {
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: 0x1234,
            l4: L4::Tcp,
        };
        let buf = pc.encode();
        assert_eq!(buf[8], 0x34);
        assert_eq!(buf[9], 0x12);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(
            PassedConn::decode(&[0u8; 10]),
            Err(WireError::BadLength(10))
        );
        assert_eq!(
            PassedConn::decode(&[0u8; HEADER_LEN + 1]),
            Err(WireError::BadLength(HEADER_LEN + 1))
        );
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut buf = PassedConn {
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: 80,
            l4: L4::Tcp,
        }
        .encode();
        buf[0] ^= 0xff;
        assert!(matches!(
            PassedConn::decode(&buf),
            Err(WireError::BadMagic(_))
        ));
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut buf = PassedConn {
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: 80,
            l4: L4::Tcp,
        }
        .encode();
        buf[4] = 99;
        assert_eq!(PassedConn::decode(&buf), Err(WireError::BadVersion(99)));
    }

    #[test]
    fn decode_rejects_bad_l4_and_family() {
        let mut buf = PassedConn {
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: 80,
            l4: L4::Tcp,
        }
        .encode();
        let good = buf;
        buf[5] = 0x99;
        assert_eq!(PassedConn::decode(&buf), Err(WireError::BadL4(0x99)));
        buf = good;
        buf[6] = 0x07;
        assert_eq!(PassedConn::decode(&buf), Err(WireError::BadFamily(0x07)));
    }
}
