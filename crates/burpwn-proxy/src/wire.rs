//! The `SCM_RIGHTS` hand-off wire format.
//!
//! `burpwn-sandbox` owns the canonical [`PassedConn`] type and the fixed 26-byte
//! header layout (the contract between the in-netns acceptor and the host proxy).
//! This module simply re-exports it so there is a single source of truth — the
//! proxy receiver and the sandbox sender can never drift apart.

pub use burpwn_sandbox::wire::{PassedConn, WireError, HEADER_LEN, L4, MAGIC, VERSION};
