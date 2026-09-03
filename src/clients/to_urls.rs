use std::io;
use std::iter;
use std::slice;
use std::vec;
use url::Url;

/// A trait for objects which can be converted or resolved to one or more
/// [`Url`] values. Heavily inspired by [`std::net::ToSocketAddrs`].
pub trait ToUrls {
    type Iter: Iterator<Item = Url>;

    fn to_urls(&self) -> io::Result<Self::Iter>;
}

impl ToUrls for &str {
    type Iter = vec::IntoIter<Url>;

    fn to_urls(&self) -> io::Result<vec::IntoIter<Url>> {
        let url = self
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(vec![url].into_iter())
    }
}

impl<'a> ToUrls for &'a [Url] {
    type Iter = iter::Cloned<slice::Iter<'a, Url>>;

    fn to_urls(&self) -> io::Result<Self::Iter> {
        Ok(self.iter().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::ToUrls;

    #[test]
    fn invalid_url_returns_error() {
        assert!("not a URL".to_urls().is_err());
    }
}
