pub mod dns;
mod errors;
pub mod name;
pub mod resource;
pub mod types;

#[macro_use]
extern crate num_derive;

// Converts a slice into a array (with a fixed length)
// if the array is not long enough a parse_error is returned
// This is inspired by array_ref!, but it returns the errors
// I care about.
// TODO Should this be here, or another file?
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
                None => {
                    return parse_error!(
                        "buffer out of range buf[{}..{}] for slice of length {}",
                        offset,
                        len,
                        $slice.len()
                    )
                }
                Some(slice) => as_array(slice),
            }
        }
    }};
}
