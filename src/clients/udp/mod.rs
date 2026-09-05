//! DNS-over-UDP client.

mod r#async;
pub use r#async::*;

#[cfg(feature = "sync")]
pub mod sync;
