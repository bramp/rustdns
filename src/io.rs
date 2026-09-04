//! Various traits to help parsing of DNS messages.

use crate::errors::DecodeError;
use crate::types::{Class, Type};
use byteorder::{BE, ReadBytesExt};
use num_traits::FromPrimitive;
use std::convert::TryFrom;
use std::io;
use std::io::Cursor;
use std::io::SeekFrom;

const MAX_QNAME_POINTER_DEPTH: usize = 255;

pub trait SeekExt: io::Seek {
    /// Returns the number of bytes remaining to be consumed.
    /// This is used as a way to check for malformed input.
    fn remaining(&mut self) -> io::Result<u64> {
        let pos = self.stream_position()?;
        let len = self.seek(SeekFrom::End(0))?;

        // reset position
        self.seek(SeekFrom::Start(pos))?;

        len.checked_sub(pos).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cursor position is past the end of the input",
            )
        })
    }
}

impl<'a> SeekExt for Cursor<&'a [u8]> {
    fn remaining(self: &mut std::io::Cursor<&'a [u8]>) -> io::Result<u64> {
        let pos = usize::try_from(self.position()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cursor position does not fit in a usize",
            )
        })?;
        let len = self.get_ref().len();

        len.checked_sub(pos)
            .map(|remaining| remaining as u64)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cursor position is past the end of the input",
                )
            })
    }
}

pub trait CursorExt<T> {
    /// Return a cursor that is bounded over the original cursor by start-end.
    ///
    /// The returned cursor contains all values with start <= x < end. It is empty if start >= end.
    ///
    /// Similar to `Take` but allows the start-end range to be specified, instead of just the next
    /// N values.
    fn sub_cursor(&mut self, start: usize, end: usize) -> io::Result<std::io::Cursor<T>>;
}

impl<'a> CursorExt<&'a [u8]> for Cursor<&'a [u8]> {
    fn sub_cursor(&mut self, start: usize, end: usize) -> io::Result<std::io::Cursor<&'a [u8]>> {
        let buf = self.get_ref();

        if start > end || end > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "requested cursor range is outside the input",
            ));
        }

        let record = Cursor::new(&buf[start..end]);
        Ok(record)
    }
}

/// All types that implement `Read` and `Seek` get methods defined
/// in `DNSReadExt` for free.
impl<R: io::Read + ?Sized + io::Seek> DNSReadExt for R {}

/// Extensions to io::Read to add some DNS specific types.
pub trait DNSReadExt: io::Read + io::Seek {
    /// Reads a puny encoded domain name from a byte array.
    ///
    /// Used for extracting a encoding ASCII domain name from a DNS message. Will
    /// returns the Unicode domain name, as well as the length of this name (ignoring
    /// any compressed pointers) in bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] when the name is malformed, uses unsupported
    /// compression, or runs past the end of the message.
    fn read_qname(&mut self) -> Result<String, DecodeError> {
        self.read_qname_at_depth(0)
    }

    fn read_qname_at_depth(&mut self, depth: usize) -> Result<String, DecodeError> {
        if depth > MAX_QNAME_POINTER_DEPTH {
            // TODO Write a test to ensure that exceeding the maximum pointer depth triggers this error.
            return Err(DecodeError::NamePointerDepthExceeded {
                max: MAX_QNAME_POINTER_DEPTH,
            });
        }

        let mut qname = String::new();
        let start = self.stream_position()?;

        // Read each label one at a time, to build up the full domain name.
        loop {
            // Length of the first label
            let len = self.read_u8()?;
            if len == 0 {
                if qname.is_empty() {
                    qname.push('.') // Root domain
                }
                break;
            }

            match len & 0xC0 {
                // No compression
                0x00 => {
                    let mut label = vec![0; len.into()];
                    self.read_exact(&mut label)?;

                    // Really this is meant to be ASCII, but we read as utf8
                    // (as that what Rust provides).
                    let label = match std::str::from_utf8(&label) {
                        Err(e) => return Err(DecodeError::LabelNotUtf8(e)),
                        Ok(s) => s,
                    };

                    if !label.is_ascii() {
                        return Err(DecodeError::LabelNotAscii {
                            label: label.to_string(),
                        });
                    }

                    // Now puny decode this label returning its original unicode.
                    let label = match idna::domain_to_unicode(label) {
                        (label, Err(_)) => return Err(DecodeError::LabelNotIdna { label }),
                        (label, Ok(_)) => label,
                    };

                    qname.push_str(&label);
                    qname.push('.');
                }

                // Compression
                0xC0 => {
                    // Read the 14 bit pointer.
                    let b2 = self.read_u8()? as u16;
                    let ptr = ((len as u16 & !0xC0) << 8 | b2) as u64;

                    // Make sure we don't get into a loop.
                    if ptr >= start {
                        return Err(DecodeError::NamePointerNotBackwards);
                    }

                    // We are going to jump backwards, so record where we
                    // currently are. So we can reset it later.
                    let current = self.stream_position()?;

                    // Jump and start reading the qname again.
                    self.seek(SeekFrom::Start(ptr))?;
                    qname.push_str(&self.read_qname_at_depth(depth + 1)?);

                    // Reset ourselves.
                    self.seek(SeekFrom::Start(current))?;

                    break;
                }

                // Unknown
                _ => {
                    return Err(DecodeError::UnsupportedNameCompression {
                        bits: (len & 0xC0) >> 6,
                    });
                }
            }
        }

        Ok(qname)
    }

    /// Reads a DNS Type.
    fn read_type(&mut self) -> Result<Type, DecodeError> {
        let r#type = self.read_u16::<BE>()?;
        let r#type = match FromPrimitive::from_u16(r#type) {
            Some(t) => t,
            None => return Err(DecodeError::InvalidType(r#type)),
        };

        Ok(r#type)
    }

    /// Reads a DNS Class.
    fn read_class(&mut self) -> Result<Class, DecodeError> {
        let class = self.read_u16::<BE>()?;
        let class = match FromPrimitive::from_u16(class) {
            Some(t) => t,
            None => return Err(DecodeError::InvalidClass(class)),
        };

        Ok(class)
    }
}

#[cfg(test)]
mod tests {
    use super::{DNSReadExt, SeekExt};
    use std::io::Cursor;

    #[test]
    fn remaining_rejects_cursor_past_input() {
        let input = [0_u8; 2];
        let mut cursor = Cursor::new(input.as_slice());
        cursor.set_position(3);

        let error = cursor
            .remaining()
            .expect_err("out-of-bounds cursor accepted");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn qname_rejects_excessive_pointer_depth() {
        let mut input = vec![0_u8; 515];
        for index in 1..=256 {
            let offset = index * 2;
            let pointer = (offset - 2) as u16;
            input[offset] = 0xc0 | (pointer >> 8) as u8;
            input[offset + 1] = pointer as u8;
        }

        let mut cursor = Cursor::new(input.as_slice());
        cursor.set_position(512);

        assert!(cursor.read_qname().is_err());
    }

    #[test]
    fn qname_rejects_invalid_pointer_forms() {
        let cases = [
            (&[0xc0, 0x02][..], "forward pointer"),
            (&[0xc0, 0xff][..], "out-of-range pointer"),
            (&[0x80, 0x00][..], "unsupported compression"),
        ];

        for (input, description) in cases {
            let mut cursor = Cursor::new(input);
            assert!(cursor.read_qname().is_err(), "accepted {}", description);
        }
    }

    #[test]
    fn qname_rejects_pointer_loop() {
        let input = [0xc0, 0x02, 0xc0, 0x00];
        let mut cursor = Cursor::new(&input);
        cursor.set_position(2);

        assert!(cursor.read_qname().is_err());
    }
}
