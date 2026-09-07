#[cfg(any(feature = "do53", feature = "dot"))]
pub(crate) mod framing;

#[cfg(any(feature = "doh", feature = "doh-json"))]
pub(crate) mod http;

#[cfg(any(feature = "doh", feature = "doh-json"))]
pub(crate) mod mime;

pub(crate) mod stats;

#[cfg(any(
    feature = "do53",
    feature = "dot",
    feature = "doh",
    feature = "doh-json"
))]
pub(crate) mod timeouts;
