//! burpwn-proxy — the proxy core. Recovers the original destination of redirected connections,
//! peeks the first bytes to classify TLS / cleartext-HTTP / DNS / raw-TCP, and dispatches to the
//! right handler: HTTP/1.1 + HTTP/2 + WebSocket (with TLS-MITM), DNS decode, raw-TCP capture, and
//! TLS pass-through. Applies match/replace rules and blocking intercept, and tees captured flows
//! to `burpwn-store`.

// Implementation lands in M2 (explicit mode) then M3/M6.
