use http::HeaderValue;
use mime::Mime;
use std::str::FromStr;

pub(crate) fn content_type_equal(content_type: &HeaderValue, expected: &str) -> bool {
    // Parse the content type, into it's "essence" which is just "type/subtype", instead of
    // "type/subtype+suffix; param=value..."
    let content_type = match content_type.to_str() {
        Ok(t) => t,
        Err(_err) => return false,
    };
    let content_type = match Mime::from_str(content_type) {
        Ok(t) => t,
        Err(_err) => return false,
    };

    content_type.essence_str() == expected
}
