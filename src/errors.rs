/// Handy macro for returning a formatted [`std::io::Error`] message.
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
            ::std::io::Error::new(::std::io::ErrorKind::$kind, format!($($arg)*))
        )
    };
}
