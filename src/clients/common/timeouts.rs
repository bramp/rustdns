use std::future::Future;
use std::io;
use std::time::Duration;

/// Runs `future`, failing with [`io::ErrorKind::TimedOut`] if `timeout` elapses.
pub(crate) async fn with_timeout<F, T>(
    timeout: Duration,
    expired: &'static str,
    future: F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, expired))?
}
