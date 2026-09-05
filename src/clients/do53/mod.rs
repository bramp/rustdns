//! Classic DNS ("Do53") client combining UDP with TCP retry on truncation.

mod r#async;
pub use r#async::*;

#[cfg(feature = "sync")]
pub mod sync;
