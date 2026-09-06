//! Asynchronous DNS resolver with upstream failover, retries, and DNSSEC validation.

mod backoff;
pub use backoff::Backoff;

mod r#async;
pub use r#async::*;

mod builder;
pub use builder::ResolverBuilder;
