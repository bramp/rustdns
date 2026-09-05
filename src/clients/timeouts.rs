use std::future::Future;
use std::io;
use std::time::Duration;

/// Runs `future`, failing with [`io::ErrorKind::TimedOut`] if `timeout` elapses.
///
/// A `None` timeout runs `future` without any additional bound.
pub(crate) async fn with_timeout<F, T>(
    timeout: Option<Duration>,
    expired: &'static str,
    future: F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    match timeout {
        None => future.await,
        Some(timeout) => tokio::time::timeout(timeout, future)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, expired))?,
    }
}
