use encoding8::ascii;

// Dumps out the slice in a pretty way
pub fn hexdump(slice: &[u8]) {
    const WIDTH: usize = 16;
    let mut offset = 0;

    for row in slice.chunks(WIDTH) {
        let row_hex: String = row.iter().map(|x| format!("{0:02X} ", x)).collect();

        // For each byte on this row, only print out the ascii printable ones.
        let row_str: String = row
            .iter()
            .map(|x| {
                if ascii::is_printable(*x) {
                    *x as char
                } else {
                    '.'
                }
            })
            .collect();

        println!("{0:>08x}: {1:<48} {2:}", offset, row_hex, row_str);

        offset += WIDTH
    }
}


// Converts a slice into a array (with a fixed length)
// if the array is not long enough a parse_error is returned
// This is inspired by array_ref!, but it returns the errors
// I care about.
#[macro_export]
macro_rules! as_array {
    ($slice:expr, $offset:expr, $len:expr) => {{
        {
            #[inline]
            fn as_array<T>(slice: &[T]) -> &[T; $len] {
                // unwrap should be safe here, due to the outer bounds check.
                slice.try_into().unwrap()
            }

            let offset = $offset;
            let len = $len;
            match $slice.get(offset..offset + len) {
                None => return parse_error!("buffer out of range buf[{}..{}] for slice of length {}", offset, len, $slice.len()),
                Some(slice) => as_array(slice)
            }
        }
    }}
}
