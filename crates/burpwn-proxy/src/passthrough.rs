//! TLS passthrough: when interception is skipped (host pinned) or fails, splice
//! the client straight to the origin without decrypting, logging only metadata.
//!
//! We connect to the real destination, replay any buffered ClientHello bytes
//! that we peeked (so the origin sees a complete handshake), then run a
//! bidirectional copy. A `Protocol::TlsPassthru` flow records the SNI, byte
//! counts and timing — never plaintext, since we never had it.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use burpwn_store::model::{FlowStart, Protocol};
use burpwn_store::WriteHandle;

use crate::util::now_millis;

/// Splice a client stream straight to `dst` (TLS passthrough), recording a
/// metadata-only flow. `client_prefix` is any already-read bytes (e.g. the
/// ClientHello) to replay to the origin before copying.
#[allow(clippy::too_many_arguments)]
pub async fn run<S>(
    mut client: S,
    client_prefix: Vec<u8>,
    dst_ip: IpAddr,
    dst_port: u16,
    sni: Option<String>,
    client_addr: String,
    writer: &WriteHandle,
    workspace_id: i64,
    exec_id: Option<String>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let flow_id = writer
        .flow_start(FlowStart {
            workspace_id,
            ts_start: now_millis(),
            exec_id,
            client_addr,
            dst_ip: dst_ip.to_string(),
            dst_port,
            sni: sni.clone(),
            scheme: "https".into(),
            protocol: Protocol::TlsPassthru,
            intercepted: false,
        })
        .await
        .map_err(to_io)?;

    let mut upstream = TcpStream::connect(SocketAddr::new(dst_ip, dst_port)).await?;
    if !client_prefix.is_empty() {
        upstream.write_all(&client_prefix).await?;
    }

    let copy = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    let (c2s, s2c) = copy.unwrap_or((0, 0));

    let _ = writer
        .add_note(
            flow_id,
            format!(
                "tls-passthru sni={} client->server={}B server->client={}B elapsed_ms={}",
                sni.as_deref().unwrap_or("?"),
                c2s,
                s2c,
                started.elapsed().as_millis(),
            ),
            now_millis(),
        )
        .await;
    let _ = writer.flow_end(flow_id, now_millis()).await;
    Ok(())
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
