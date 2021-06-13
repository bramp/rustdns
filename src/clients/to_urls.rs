use std::io;
use std::iter;
use std::slice;
use std::vec;
use url::Url;

/// A trait for objects which can be converted or resolved to one or more
/// [`Url`] values. Heavily inspired by [`ToSocketAddrs`].
pub trait ToUrls {
    type Iter: Iterator<Item = Url>;

    fn to_urls(&self) -> io::Result<Self::Iter>;
}

impl ToUrls for &str {
    type Iter = vec::IntoIter<Url>;

    fn to_urls(&self) -> io::Result<vec::IntoIter<Url>> {
        Ok(vec![self.parse().unwrap()].into_iter()) // TODO FIX THE PANIC!
    }
}

impl<'a> ToUrls for &'a [Url] {
    type Iter = iter::Cloned<slice::Iter<'a, Url>>;

    fn to_urls(&self) -> io::Result<Self::Iter> {
        Ok(self.iter().cloned())
    }
}
