//! Asynchronous DNS resolver with upstream failover, retries, and DNSSEC validation.
// TODO Implement caching, query prioritization and cookies for the resolver.

mod backoff;
pub use backoff::Backoff;

mod r#async;
pub use r#async::*;

mod builder;
pub use builder::ResolverBuilder;
