//! Synchronous (blocking) DNS clients.
//!
//! These mirror the asynchronous clients in [`crate::clients`] and are enabled
//! by the `sync` feature, alongside the protocol feature for each client.
//! Prefer the asynchronous clients unless you specifically need blocking I/O.

#[cfg(feature = "do53")]
pub use crate::clients::do53::sync as do53;

#[cfg(feature = "do53")]
pub use crate::clients::tcp::sync as tcp;

#[cfg(feature = "do53")]
pub use crate::clients::udp::sync as udp;

#[cfg(feature = "dot")]
pub use crate::clients::dot::sync as dot;
