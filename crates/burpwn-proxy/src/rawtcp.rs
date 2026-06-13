//! Raw-TCP capture: connect to the origin and splice bytes both ways, flushing
//! captured chunks (capped) to the store as a `Protocol::RawTcp` flow.
//!
//! Unlike `copy_bidirectional` we run our own pump so we can tee a bounded copy
//! of each direction into the store via `WriteOp::RawChunk` while still
//! forwarding everything unchanged.

use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use burpwn_store::model::{FlowStart, Protocol};
use burpwn_store::{WriteHandle, WriteOp};

use crate::util::now_millis;

/// Per-direction cap on bytes teed to the store (forwarding is uncapped).
const CAPTURE_CAP: usize = 256 * 1024;

/// Handle a redirected raw-TCP connection: log a flow, splice, capture.
#[allow(clippy::too_many_arguments)]
pub async fn run<S>(
    client: S,
    client_prefix: Vec<u8>,
    dst_ip: IpAddr,
    dst_port: u16,
    client_addr: String,
    writer: &WriteHandle,
    workspace_id: i64,
    exec_id: Option<String>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let flow_id = writer
        .flow_start(FlowStart {
            workspace_id,
            ts_start: now_millis(),
            exec_id,
            client_addr,
            dst_ip: dst_ip.to_string(),
            dst_port,
            sni: None,
            scheme: "tcp".into(),
            protocol: Protocol::RawTcp,
            intercepted: false,
        })
        .await
        .map_err(to_io)?;

    let upstream = TcpStream::connect(SocketAddr::new(dst_ip, dst_port)).await?;
    if !client_prefix.is_empty() {
        let mut up = upstream;
        up.write_all(&client_prefix).await?;
        let _ = writer
            .send(WriteOp::RawChunk {
                flow_id,
                bytes: cap(&client_prefix),
                reply: None,
            })
            .await;
        pump(client, up, writer.clone(), flow_id).await;
    } else {
        pump(client, upstream, writer.clone(), flow_id).await;
    }

    let _ = writer.flow_end(flow_id, now_millis()).await;
    Ok(())
}

/// Bidirectional splice that tees a capped copy of each direction to the store.
async fn pump<A, B>(client: A, upstream: B, writer: WriteHandle, flow_id: i64)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);

    let w1 = writer.clone();
    let c2s = tokio::spawn(async move { splice(cr, uw, w1, flow_id, "c2s").await });
    let w2 = writer.clone();
    let s2c = tokio::spawn(async move { splice(ur, cw, w2, flow_id, "s2c").await });

    let _ = c2s.await;
    let _ = s2c.await;
}

async fn splice<R, W>(
    mut r: R,
    mut w: W,
    writer: WriteHandle,
    flow_id: i64,
    dir: &'static str,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut captured = 0usize;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        if captured < CAPTURE_CAP {
            let take = n.min(CAPTURE_CAP - captured);
            captured += take;
            let mut bytes = Vec::with_capacity(take + dir.len() + 1);
            bytes.extend_from_slice(dir.as_bytes());
            bytes.push(b':');
            bytes.extend_from_slice(&buf[..take]);
            let _ = writer
                .send(WriteOp::RawChunk {
                    flow_id,
                    bytes,
                    reply: None,
                })
                .await;
        }
    }
    let _ = w.shutdown().await;
    Ok(())
}

fn cap(b: &[u8]) -> Vec<u8> {
    b[..b.len().min(CAPTURE_CAP)].to_vec()
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
