use std::fmt;
use std::error::Error;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteError {
    pub msg: String, // TODO Remove the pub
}

impl Error for WriteError {}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub msg: String, // TODO Remove the pub
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}


#[macro_export]
macro_rules! parse_error {
    ($($arg:tt)*) => {{
        Err(ParseError{
            msg: fmt::format(format_args!($($arg)*)),
        })
    }}
}
