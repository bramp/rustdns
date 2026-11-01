use crate::Message;
use crate::clients::WireResponseMeta;
use crate::types::{ChannelSecurity, SecurityStatus};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Resolver execution metadata attached to a [`Response`].
#[derive(Clone, Debug)]
pub struct ResponseMeta {
    /// The endpoint or identifier of the upstream that produced this response.
    pub upstream: Arc<str>,

    /// Number of attempts made across upstreams before this response was returned.
    pub attempts: u32,

    /// Total time spent resolving, including any retries against earlier attempts.
    pub elapsed: Duration,

    /// Timestamp when resolution started.
    pub when: SystemTime,

    /// DNSSEC security status evaluated for this response.
    pub security_status: SecurityStatus,

    /// Transport security classification of the channel that serviced this response.
    pub channel_security: ChannelSecurity,

    /// Low-level transport metadata and metrics from each attempt that produced a wire response,
    /// in chronological order. The last entry corresponds to the winning response.
    pub wire: Vec<WireResponseMeta>,
}

impl ResponseMeta {
    /// Returns the transport metadata of the winning attempt, if any wire response was received.
    pub fn winning_wire(&self) -> Option<&WireResponseMeta> {
        self.wire.last()
    }
}

impl fmt::Display for ResponseMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, ";; Query time: {} msec", self.elapsed.as_millis())?;
        writeln!(f, ";; UPSTREAM: {}", self.upstream)?;
        if let Some(winning) = self.wire.last() {
            if let Some(server) = winning.server {
                writeln!(f, ";; SERVER: {server}")?;
            }
        }
        let when: chrono::DateTime<chrono::Local> = self.when.into();
        writeln!(f, ";; WHEN: {}", when.format("%a %b %d %H:%M:%S %Z %Y"))?;

        if self.attempts > 1 {
            writeln!(f, ";; ATTEMPTS: {}", self.attempts)?;
        }
        if let Some(winning) = self.wire.last() {
            writeln!(
                f,
                ";; MSG SIZE sent: {} rcvd: {}",
                winning.bytes_sent, winning.bytes_received
            )?;
        }
        writeln!(f, ";; SECURITY: {}", self.security_status)?;
        writeln!(f, ";; CHANNEL: {}", self.channel_security)?;
        if let Some(winning) = self.wire.last() {
            if let Some(tls) = &winning.tls_info {
                write!(f, ";; TLS: {}", tls.version)?;
                if let Some(cs) = &tls.cipher_suite {
                    write!(f, ", {cs}")?;
                }
                if let Some(alpn) = &tls.alpn {
                    write!(f, ", alpn: {alpn}")?;
                }
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

/// A decoded DNS [`Message`] together with resolver execution metadata.
#[derive(Clone, Debug)]
pub struct Response {
    /// The decoded DNS message. Remains the source of truth for protocol contents.
    pub message: Message,

    /// Metadata describing how this response was obtained.
    pub meta: ResponseMeta,
}

impl Deref for Response {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl DerefMut for Response {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        write!(f, "{}", self.meta)
    }
}

/// An asynchronous resolver capable of dispatching DNS queries.
///
/// The default deadline type is [`Instant`]. Implementations using a different
/// runtime or clock can select another instant type without changing the
/// resolver response model.
#[async_trait::async_trait]
pub trait AsyncResolver<I = Instant>: Send + Sync
where
    I: Copy + Ord + Send + Sync + 'static,
{
    /// Exchanges a DNS query message, bounded by an overall resolution deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the query cannot be resolved or its deadline elapses.
    async fn exchange_with_deadline(
        &self,
        query: &Message,
        deadline: I,
    ) -> Result<Response, crate::Error>;
}

#[async_trait::async_trait]
impl<T, I> AsyncResolver<I> for &T
where
    T: AsyncResolver<I> + ?Sized,
    I: Copy + Ord + Send + Sync + 'static,
{
    async fn exchange_with_deadline(
        &self,
        query: &Message,
        deadline: I,
    ) -> Result<Response, crate::Error> {
        (**self).exchange_with_deadline(query, deadline).await
    }
}

#[async_trait::async_trait]
impl<T, I> AsyncResolver<I> for Arc<T>
where
    T: AsyncResolver<I> + ?Sized,
    I: Copy + Ord + Send + Sync + 'static,
{
    async fn exchange_with_deadline(
        &self,
        query: &Message,
        deadline: I,
    ) -> Result<Response, crate::Error> {
        (**self).exchange_with_deadline(query, deadline).await
    }
}

#[async_trait::async_trait]
impl<T, I> AsyncResolver<I> for Box<T>
where
    T: AsyncResolver<I> + ?Sized,
    I: Copy + Ord + Send + Sync + 'static,
{
    async fn exchange_with_deadline(
        &self,
        query: &Message,
        deadline: I,
    ) -> Result<Response, crate::Error> {
        (**self).exchange_with_deadline(query, deadline).await
    }
}
