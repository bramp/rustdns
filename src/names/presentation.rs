use crate::limits;

pub(crate) fn parse(text: &str) -> Result<Vec<u8>, &'static str> {
    if text.is_empty() {
        return Err("empty name");
    }
    let mut wire = Vec::new();
    if text != "." {
        let mut chars = text.chars();
        let mut label = Vec::new();
        while let Some(character) = chars.next() {
            match character {
                '.' => {
                    push_label(&mut wire, &label)?;
                    label.clear();
                }
                '\\' => {
                    let escaped = chars.next().ok_or("trailing backslash")?;
                    if escaped.is_ascii_digit() {
                        let mut value = escaped as u16 - u16::from(b'0');
                        for _ in 0..2 {
                            let digit = chars
                                .next()
                                .filter(char::is_ascii_digit)
                                .ok_or("decimal escape requires three digits")?;
                            value = value * 10 + digit as u16 - u16::from(b'0');
                        }
                        label.push(u8::try_from(value).map_err(|_| "decimal escape exceeds 255")?);
                    } else {
                        label.extend_from_slice(escaped.encode_utf8(&mut [0; 4]).as_bytes());
                    }
                }
                c => label.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
            }
            if label.len() > limits::MAX_DNS_LABEL_WIRE_LEN {
                return Err("label exceeds 63 octets");
            }
        }
        if !label.is_empty() {
            push_label(&mut wire, &label)?;
        }
    }
    wire.push(0);
    if wire.len() > limits::MAX_DNS_NAME_WIRE_LEN {
        return Err("name exceeds 255 wire octets");
    }
    Ok(wire)
}

fn push_label(wire: &mut Vec<u8>, label: &[u8]) -> Result<(), &'static str> {
    if label.is_empty() {
        return Err("empty label");
    }
    let length = u8::try_from(label.len()).map_err(|_| "label exceeds 63 octets")?;
    wire.push(length);
    wire.extend_from_slice(label);
    if wire.len() >= limits::MAX_DNS_NAME_WIRE_LEN {
        return Err("name exceeds 255 wire octets");
    }
    Ok(())
}

// Only called with validated, uncompressed DNS names.
pub(crate) fn labels(mut wire: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let (&length, rest) = wire.split_first()?;
        if length == 0 {
            return None;
        }
        let (label, rest) = rest.split_at_checked(usize::from(length))?;
        wire = rest;
        Some(label)
    })
}

pub(crate) fn render(wire: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for label in labels(wire) {
        for &byte in label {
            match byte {
                b'.' | b'\\' | b'"' | b';' | b'(' | b')' | b'@' => {
                    text.push('\\');
                    text.push(char::from(byte));
                }
                0x21..=0x7e => text.push(char::from(byte)),
                _ => {
                    let _ = write!(text, "\\{byte:03}");
                }
            }
        }
        text.push('.');
    }
    if text.is_empty() {
        text.push('.');
    }
    text
}

#[cfg(feature = "zones")]
pub(crate) fn is_absolute(text: &str) -> bool {
    text.strip_suffix('.').is_some_and(|prefix| {
        prefix
            .bytes()
            .rev()
            .take_while(|&byte| byte == b'\\')
            .count()
            % 2
            == 0
    })
}
