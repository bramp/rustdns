use crate::Type;
use crate::from_str::FromStrError;
use core::num::ParseIntError;
use std::net::AddrParseError;
use thiserror::Error;

/// Handy macro for returning a formatted [`std::io::Error`] message.
/// TODO Delete
///
/// ```rust
/// use rustdns::bail;
///
/// fn example(field: &str) -> std::io::Result<()> {
///     bail!(InvalidData, "unable to parse field '{}'", field);
/// }
/// ```
#[macro_export]
macro_rules! bail {
    ($kind:ident, $($arg:tt)*) => {
        // Construct the I/O error.
        return Err(
            ::std::io::Error::new(::std::io::ErrorKind::$kind, format!($($arg)*)).into()
        )
    };
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[cfg(feature = "http")]
    #[error(transparent)]
    HttpError(#[from] http::Error),

    #[cfg(feature = "hyper")]
    #[error(transparent)]
    HyperError(#[from] hyper::Error),

    #[cfg(feature = "http")]
    #[error(transparent)]
    InvalidUri(#[from] http::uri::InvalidUri),

    #[error(transparent)]
    ParseError(#[from] ParseError),

    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error(transparent)]
    IntError(#[from] ParseIntError),

    #[error(transparent)]
    AddrError(#[from] AddrParseError),

    /// Invalid JSON was parsed.
    #[cfg(feature = "serde_json")]
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error("invalid rcode status: '{0}'")]
    InvalidStatus(u32),

    #[error("invalid record type: '{0}'")]
    InvalidType(u16),

    #[error("invalid {0} resource: '{1}'")]
    InvalidResource(Type, FromStrError),

    #[error("invalid rname email address: '{0}'")]
    InvalidRname(String),
}
