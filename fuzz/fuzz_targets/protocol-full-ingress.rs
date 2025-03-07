#![no_main]

use core::task::{Context, Poll};
use futures::StreamExt;
use libfuzzer_sys::fuzz_target;
use mms::protocol;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct MockTcp<'a> {
    recv: &'a [u8],
}

impl AsyncRead for MockTcp<'_> {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let len = std::cmp::min(self.recv.len(), buf.remaining());
        buf.put_slice(&self.recv[..len]);
        self.recv = &self.recv[len..];
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockTcp<'_> {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        // No-op
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|data: &[u8]| {
    let mut params = protocol::ProtocolParams::default();

    let tcp = MockTcp { recv: data };
    let framed = tokio_util::codec::Framed::new(tcp, protocol::tpkt::TpktCodec);
    let mut conn = protocol::transport::Connection::new(framed, params.transport.max_tpdu_size);

    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        while let Some(Ok(frame)) = conn.next().await {
            let _ = protocol::decode(frame, &mut params);
        }
    });
});
