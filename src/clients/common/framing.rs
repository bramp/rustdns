use crate::limits;
use std::convert::TryFrom;

/// Prefixes `message` with its two-byte big-endian length, as used by DNS over
/// TCP and by the stream transports layered on it, such as DoT.
///
/// # Errors
///
/// Returns an error if `message` is longer than a DNS message may be.
pub(crate) fn encode_tcp_frame(message: &[u8]) -> std::io::Result<Vec<u8>> {
    limits::validate_message_len(message.len())?;
    let length = u16::try_from(message.len()).expect("validated DNS message length");
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(message);
    Ok(frame)
}
