//! Various traits to help parsing of DNS messages.

use crate::errors::DecodeError;
use crate::names::Name;
use crate::types::{Class, Type};
use byteorder::{BE, ReadBytesExt};
use num_traits::FromPrimitive;
use std::convert::TryFrom;
use std::io;
use std::io::Cursor;
use std::io::SeekFrom;

const MAX_QNAME_POINTER_DEPTH: usize = 255;

pub(crate) trait SeekExt: io::Seek {
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
    fn remaining(self: &mut Cursor<&'a [u8]>) -> io::Result<u64> {
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

pub(crate) trait CursorExt<T> {
    /// Return a cursor that is bounded over the original cursor by start-end.
    ///
    /// The returned cursor contains all values with start <= x < end. It is empty if start >= end.
    ///
    /// Similar to `Take` but allows the start-end range to be specified, instead of just the next
    /// N values.
    fn sub_cursor(&mut self, start: usize, end: usize) -> io::Result<Cursor<T>>;
}

impl<'a> CursorExt<&'a [u8]> for Cursor<&'a [u8]> {
    fn sub_cursor(&mut self, start: usize, end: usize) -> io::Result<Cursor<&'a [u8]>> {
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
pub(crate) trait DNSReadExt: io::Read + io::Seek {
    /// Reads a puny encoded domain name from a byte array.
    ///
    /// Extracts an encoded ASCII domain name from a DNS message, returning a validated [`Name`].
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] when the name is malformed, uses unsupported
    /// compression, or runs past the end of the message.
    fn read_qname(&mut self) -> Result<Name, DecodeError> {
        let wire = read_qname_at_depth(self, 0)?;
        Ok(Name::from_wire(wire))
    }

    fn read_rname(&mut self) -> Result<crate::Rname, DecodeError> {
        let wire = read_qname_at_depth(self, 0)?;
        crate::Rname::from_wire(wire).map_err(DecodeError::InvalidRname)
    }

    /// Reads a DNS Type.
    fn read_type(&mut self) -> Result<Type, DecodeError> {
        let code = self.read_u16::<BE>()?;
        Ok(Type::from(code))
    }

    /// Reads a DNS Class.
    fn read_class(&mut self) -> Result<Class, DecodeError> {
        let class = self.read_u16::<BE>()?;
        let Some(class) = FromPrimitive::from_u16(class) else {
            return Err(DecodeError::InvalidClass(class));
        };

        Ok(class)
    }
}

fn read_qname_at_depth<R: io::Read + io::Seek + ?Sized>(
    reader: &mut R,
    depth: usize,
) -> Result<Vec<u8>, DecodeError> {
    if depth > MAX_QNAME_POINTER_DEPTH {
        return Err(DecodeError::NamePointerDepthExceeded {
            max: MAX_QNAME_POINTER_DEPTH,
        });
    }

    let mut qname = Vec::new();
    let start = reader.stream_position()?;

    // Read each label one at a time, to build up the full domain name.
    loop {
        // Length of the first label
        let len = reader.read_u8()?;
        if len == 0 {
            qname.push(0);
            break;
        }

        match len & 0xC0 {
            // No compression
            0x00 => {
                let mut label = vec![0; len.into()];
                reader.read_exact(&mut label)?;

                qname.push(len);
                qname.extend_from_slice(&label);
                if qname.len() >= crate::limits::MAX_DNS_NAME_WIRE_LEN {
                    return Err(DecodeError::NameTooLong {
                        max: crate::limits::MAX_DNS_NAME_WIRE_LEN,
                        len: qname.len() + 1,
                    });
                }
            }

            // Compression
            0xC0 => {
                // Read the 14 bit pointer.
                let b2 = reader.read_u8()? as u16;
                let ptr = ((len as u16 & !0xC0) << 8 | b2) as u64;

                // Make sure we don't get into a loop.
                if ptr >= start {
                    return Err(DecodeError::NamePointerNotBackwards);
                }

                // We are going to jump backwards, so record where we
                // currently are. So we can reset it later.
                let current = reader.stream_position()?;

                // Jump and start reading the qname again.
                reader.seek(SeekFrom::Start(ptr))?;
                let suffix = read_qname_at_depth(reader, depth + 1)?;
                qname.extend_from_slice(&suffix);

                // Reset ourselves.
                reader.seek(SeekFrom::Start(current))?;

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

    if qname.len() > crate::limits::MAX_DNS_NAME_WIRE_LEN {
        return Err(DecodeError::NameTooLong {
            max: crate::limits::MAX_DNS_NAME_WIRE_LEN,
            len: qname.len(),
        });
    }
    Ok(qname)
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
        cursor.set_position(512);
        assert!(cursor.read_rname().is_err());
    }

    #[test]
    fn compressed_names_enforce_expanded_wire_length() {
        for (last_label_length, valid) in [(59, true), (60, false)] {
            let mut input = Vec::new();
            for length in [63, 63, 63, last_label_length] {
                input.push(length);
                input.extend(std::iter::repeat_n(b'a', usize::from(length)));
            }
            input.push(0);
            let start = input.len() as u64;
            input.extend_from_slice(b"\x01x\xc0\x00");
            let mut cursor = Cursor::new(input.as_slice());
            cursor.set_position(start);
            let hostname = cursor.read_qname();
            cursor.set_position(start);
            let mailbox = cursor.read_rname();
            if valid {
                assert!(hostname.is_ok());
                assert!(mailbox.is_ok());
            } else {
                assert!(matches!(
                    hostname,
                    Err(crate::DecodeError::NameTooLong { .. })
                ));
                assert!(matches!(
                    mailbox,
                    Err(crate::DecodeError::NameTooLong { .. })
                ));
            }
        }
    }

    #[test]
    fn compressed_root_suffix_preserves_single_label_names() {
        let input = b"\0\x05local\xc0\x00";
        let mut cursor = Cursor::new(input.as_slice());
        cursor.set_position(1);
        assert_eq!(cursor.read_qname().unwrap().as_ascii(), "local.");
        cursor.set_position(1);
        assert_eq!(cursor.read_rname().unwrap().as_str(), "local.");
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
