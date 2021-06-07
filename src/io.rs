//! Various traits to help parsing of DNS messages.

use crate::bail;
use crate::types::{Class, Type};
use byteorder::{ReadBytesExt, BE};
use num_traits::FromPrimitive;
use std::convert::TryInto;
use std::io;
use std::io::Cursor;
use std::io::SeekFrom;

pub fn clamp<T: PartialOrd>(v: T, min: T, max: T) -> T {
    assert!(min < max);

    if v < min {
        min
    } else if v > max {
        max
    } else {
        v
    }
}

pub trait SeekExt: io::Seek {
    /// Returns the number of bytes remaining to be consumed.
    /// This is used as a way to check for malformed input.
    fn remaining(&mut self) -> io::Result<u64> {
        let pos = self.stream_position()?;
        let len = self.seek(SeekFrom::End(0))?;

        // reset position
        self.seek(SeekFrom::Start(pos))?;

        Ok(len - pos)
    }
}

impl<'a> SeekExt for Cursor<&'a [u8]> {
    fn remaining(self: &mut std::io::Cursor<&'a [u8]>) -> io::Result<u64> {
        let pos = self.position() as usize;
        let len = self.get_ref().len() as usize;

        Ok((len - pos).try_into().unwrap())
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

        let start = clamp(start, 0, buf.len());
        let end = clamp(end, start, buf.len());

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
    /// Will return a io::Error(InvalidData) if the read domain name is invalid, or
    /// a more general io::Error on any other read failure.
    fn read_qname(&mut self) -> io::Result<String> {
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
                        Err(e) => bail!(InvalidData, "invalid label: {}", e),
                        Ok(s) => s,
                    };

                    if !label.is_ascii() {
                        bail!(InvalidData, "invalid label '{:}': not valid ascii", label);
                    }

                    // Now puny decode this label returning its original unicode.
                    let label = match idna::domain_to_unicode(label) {
                        (label, Err(e)) => bail!(InvalidData, "invalid label '{:}': {}", label, e),
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
                        bail!(
                            InvalidData,
                            "invalid compressed pointer pointing to future bytes"
                        );
                    }

                    // We are going to jump backwards, so record where we
                    // currently are. So we can reset it later.
                    let current = self.stream_position()?;

                    // Jump and start reading the qname again.
                    self.seek(SeekFrom::Start(ptr))?;
                    qname.push_str(&self.read_qname()?);

                    // Reset ourselves.
                    self.seek(SeekFrom::Start(current))?;

                    break;
                }

                // Unknown
                _ => bail!(
                    InvalidData,
                    "unsupported compression type {0:b}",
                    len & 0xC0
                ),
            }
        }

        Ok(qname)
    }

    /// Reads a DNS Type.
    fn read_type(&mut self) -> io::Result<Type> {
        let r#type = self.read_u16::<BE>()?;
        let r#type = match FromPrimitive::from_u16(r#type) {
            Some(t) => t,
            None => bail!(InvalidData, "invalid Type({})", r#type),
        };

        Ok(r#type)
    }

    /// Reads a DNS Class.
    fn read_class(&mut self) -> io::Result<Class> {
        let class = self.read_u16::<BE>()?;
        let class = match FromPrimitive::from_u16(class) {
            Some(t) => t,
            None => bail!(InvalidData, "invalid Class({})", class),
        };

        Ok(class)
    }
}
