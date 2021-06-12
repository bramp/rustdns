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
