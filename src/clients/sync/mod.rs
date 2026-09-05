//! Synchronous (blocking) DNS clients.
//!
//! These mirror the asynchronous clients in [`crate::clients`] and are enabled
//! by the `sync` feature, alongside the protocol feature for each client.
//! Prefer the asynchronous clients unless you specifically need blocking I/O.

#[cfg(feature = "do53")]
pub mod do53;

#[cfg(feature = "do53")]
pub mod tcp;

#[cfg(feature = "do53")]
pub mod udp;

#[cfg(feature = "dot")]
pub mod dot;
