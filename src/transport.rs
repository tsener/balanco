//! Raw duplex transport with backpressure, half-close handling and optional idle deadlines.
use std::{
    io::{self, Write},
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional_with_sizes},
    time::Instant,
};

struct Activity {
    started: Instant,
    last_ms: AtomicU64,
    enabled: bool,
}
pub fn dump(direction: &str, bytes: &[u8]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    let text: String = bytes
        .iter()
        .flat_map(|b| std::ascii::escape_default(*b))
        .map(char::from)
        .collect();
    writeln!(out, "{direction}: {text}")
}
impl Activity {
    fn touch(&self) {
        if !self.enabled {
            return;
        }
        self.last_ms
            .store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    async fn expire(&self, millis: u64) {
        loop {
            let last = self.last_ms.load(Ordering::Relaxed);
            tokio::time::sleep_until(self.started + Duration::from_millis(last + millis)).await;
            if self.started.elapsed().as_millis()
                >= u128::from(self.last_ms.load(Ordering::Relaxed) + millis)
            {
                return;
            }
        }
    }
}
struct Observed<'a, S> {
    stream: &'a mut S,
    activity: &'a Activity,
    dump: Option<&'static str>,
    written: &'a AtomicU64,
}
impl<S: AsyncRead + Unpin> AsyncRead for Observed<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut *this.stream).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.activity.touch();
            if let Some(direction) = this.dump
                && let Err(error) = dump(direction, &buf.filled()[before..])
            {
                return Poll::Ready(Err(error));
            }
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Observed<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.stream).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            this.activity.touch();
        }
        if let Poll::Ready(Ok(n)) = result {
            this.written.fetch_add(n as u64, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_shutdown(cx)
    }
}

// Called by raw TCP forwarding; counters track successful writes in each direction.
pub async fn copy<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    a: &mut A,
    b: &mut B,
    size: usize,
    idle_ms: Option<u64>,
    packet_dump: bool,
    counters: &crate::scheduler::Counters,
) -> io::Result<(u64, u64)> {
    let activity = Activity {
        started: Instant::now(),
        last_ms: AtomicU64::new(0),
        enabled: idle_ms.is_some(),
    };
    let mut a = Observed {
        stream: a,
        activity: &activity,
        dump: packet_dump.then_some("client->backend"),
        written: &counters.down,
    };
    let mut b = Observed {
        stream: b,
        activity: &activity,
        dump: packet_dump.then_some("backend->client"),
        written: &counters.up,
    };
    tokio::select! {
        result = copy_bidirectional_with_sizes(&mut a,&mut b,size,size) => result,
        _ = activity.expire(idle_ms.unwrap_or(0)), if idle_ms.is_some() => Err(io::Error::new(io::ErrorKind::TimedOut, "connection idle timeout")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn bounded_relay_preserves_half_close_backpressure_and_counters() {
        for idle in [None, Some(1000)] {
            let (mut client, mut front) = duplex(16);
            let (mut back, mut origin) = duplex(16);
            let counters = crate::scheduler::Counters::default();
            let payload = vec![b'x'; 4097];
            let exchange = async {
                client.write_all(&payload).await.unwrap();
                client.shutdown().await.unwrap();
                let mut reply = Vec::new();
                client.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"ack");
            };
            let workload = async {
                let mut received = Vec::new();
                origin.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, payload);
                origin.write_all(b"ack").await.unwrap();
                origin.shutdown().await.unwrap();
            };
            let (result, (), ()) = tokio::join!(
                copy(&mut front, &mut back, 32, idle, false, &counters),
                exchange,
                workload
            );
            assert_eq!(result.unwrap(), (4097, 3));
            assert_eq!(counters.up.load(Ordering::Relaxed), 4097);
            assert_eq!(counters.down.load(Ordering::Relaxed), 3);
        }
    }

    #[tokio::test]
    async fn quiet_open_sessions_expire_and_io_errors_propagate() {
        let (_client, mut front) = duplex(16);
        let (mut back, _origin) = duplex(16);
        let counters = crate::scheduler::Counters::default();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            copy(&mut front, &mut back, 16, Some(25), false, &counters),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let (mut client, mut front) = duplex(16);
        let (mut back, origin) = duplex(16);
        drop(origin);
        client.write_all(b"data").await.unwrap();
        assert!(
            copy(&mut front, &mut back, 16, None, false, &counters)
                .await
                .is_err()
        );
        dump("test", b"\n\0").unwrap();
    }
}
