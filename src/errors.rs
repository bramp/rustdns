#[macro_export]
macro_rules! bail {
    ($kind:ident, $($arg:tt)*) => {
        // Construct the I/O error.
        return Err(
            ::std::io::Error::new(::std::io::ErrorKind::$kind, format!($($arg)*))
        )
    };
}
