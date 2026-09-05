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

#[cfg(test)]
mod tests {
    use super::content_type_equal;
    use http::HeaderValue;

    #[test]
    fn recognizes_content_type_essence_and_rejects_invalid_values() {
        assert!(content_type_equal(
            &HeaderValue::from_static("application/dns-message; charset=binary"),
            "application/dns-message"
        ));
        assert!(!content_type_equal(
            &HeaderValue::from_static("text/plain"),
            "application/dns-message"
        ));
        assert!(!content_type_equal(
            &HeaderValue::from_static("not a media type"),
            "application/dns-message"
        ));
    }
}
