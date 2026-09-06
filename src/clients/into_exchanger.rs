use super::AsyncExchanger;
use std::net::IpAddr;
use std::net::SocketAddr;

/// Conversion trait for values that can be converted into an [`AsyncExchanger`].
///
/// Implementations are provided for:
/// - Any transport already implementing [`AsyncExchanger`] (`+ Send + Sync + 'static`).
/// - [`SocketAddr`] and [`IpAddr`] (which default to classic DNS over UDP with TCP fallback).
/// - `&str` and [`String`], parsed as an address or URL with scheme:
///   - `"8.8.8.8"`, `"8.8.8.8:53"`, `"[::1]:53"` -> classic DNS (`dns://`, Do53: UDP with TCP retry)
///   - `"dns://8.8.8.8:53"` -> classic DNS (`dns://`, Do53: UDP with TCP retry)
///   - `"udp://8.8.8.8:53"` -> pure UDP client
///   - `"tcp://8.8.8.8:53"` -> pure TCP client
///   - `"tls://..."` or `"dot://..."` -> DoT client (if `dot` feature enabled)
///   - `"https://..."` -> DoH client (if `doh` feature enabled)
///   - `"json+https://..."` -> JSON DoH client (if `json` feature enabled, unofficial scheme)
pub trait IntoAsyncExchanger {
    /// Converts this value into a boxed [`AsyncExchanger`].
    ///
    /// # Errors
    ///
    /// Returns an error if string or URL parsing fails, or an address cannot be parsed.
    fn into_async_exchanger(self) -> Result<Box<dyn AsyncExchanger + Send + Sync>, crate::Error>;
}

impl<T> IntoAsyncExchanger for T
where
    T: AsyncExchanger + Send + Sync + 'static,
{
    fn into_async_exchanger(self) -> Result<Box<dyn AsyncExchanger + Send + Sync>, crate::Error> {
        Ok(Box::new(self))
    }
}

impl IntoAsyncExchanger for SocketAddr {
    fn into_async_exchanger(self) -> Result<Box<dyn AsyncExchanger + Send + Sync>, crate::Error> {
        #[cfg(feature = "do53")]
        {
            Ok(Box::new(crate::clients::do53::Client::new(self)))
        }
        #[cfg(not(feature = "do53"))]
        Err(crate::Error::InvalidArgument(
            "feature 'do53' is required for SocketAddr exchangers".to_string(),
        ))
    }
}

impl IntoAsyncExchanger for IpAddr {
    fn into_async_exchanger(self) -> Result<Box<dyn AsyncExchanger + Send + Sync>, crate::Error> {
        SocketAddr::new(self, 53).into_async_exchanger()
    }
}

#[cfg(feature = "doh")]
impl IntoAsyncExchanger for url::Url {
    fn into_async_exchanger(self) -> Result<Box<dyn AsyncExchanger + Send + Sync>, crate::Error> {
        let client = crate::clients::doh::Client::try_new(self, http::Method::GET)?;
        Ok(Box::new(client))
    }
}

impl IntoAsyncExchanger for &str {
    fn into_async_exchanger(self) -> Result<Box<dyn AsyncExchanger + Send + Sync>, crate::Error> {
        parse_async_exchanger_str(self)
    }
}

impl IntoAsyncExchanger for String {
    fn into_async_exchanger(self) -> Result<Box<dyn AsyncExchanger + Send + Sync>, crate::Error> {
        parse_async_exchanger_str(&self)
    }
}

impl IntoAsyncExchanger for &String {
    fn into_async_exchanger(self) -> Result<Box<dyn AsyncExchanger + Send + Sync>, crate::Error> {
        parse_async_exchanger_str(self)
    }
}

fn parse_socket_addr(s: &str, default_port: u16) -> Result<SocketAddr, crate::Error> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    let trimmed = s.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    use std::net::ToSocketAddrs;
    if let Ok(mut addrs) = (s, default_port).to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(addr);
        }
    }
    if let Ok(mut addrs) = s.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(addr);
        }
    }
    Err(crate::Error::InvalidArgument(format!(
        "cannot parse address '{s}'"
    )))
}

#[cfg(feature = "dot")]
fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16), crate::Error> {
    if let Some((host, port_str)) = s.rsplit_once(':') {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok((host.to_string(), port));
        }
    }
    let host = s.trim_start_matches('[').trim_end_matches(']');
    Ok((host.to_string(), default_port))
}

fn parse_async_exchanger_str(
    s: &str,
) -> Result<Box<dyn AsyncExchanger + Send + Sync>, crate::Error> {
    let s = s.trim();

    if let Some((scheme, rest)) = s.split_once("://") {
        match scheme.to_ascii_lowercase().as_str() {
            "dns" => {
                #[cfg(feature = "do53")]
                {
                    let addr = parse_socket_addr(rest, 53)?;
                    Ok(Box::new(crate::clients::do53::Client::new(addr)))
                }
                #[cfg(not(feature = "do53"))]
                Err(crate::Error::InvalidArgument(
                    "feature 'do53' is required for dns:// exchangers".to_string(),
                ))
            }
            "udp" => {
                #[cfg(feature = "do53")]
                {
                    let addr = parse_socket_addr(rest, 53)?;
                    Ok(Box::new(crate::clients::udp::Client::new(addr)))
                }
                #[cfg(not(feature = "do53"))]
                Err(crate::Error::InvalidArgument(
                    "feature 'do53' is required for udp:// exchangers".to_string(),
                ))
            }
            "tcp" => {
                #[cfg(feature = "do53")]
                {
                    let addr = parse_socket_addr(rest, 53)?;
                    Ok(Box::new(crate::clients::tcp::Client::new(addr)))
                }
                #[cfg(not(feature = "do53"))]
                Err(crate::Error::InvalidArgument(
                    "feature 'do53' is required for tcp:// exchangers".to_string(),
                ))
            }
            "tls" | "dot" => {
                #[cfg(feature = "dot")]
                {
                    let (host, port) = parse_host_port(rest, 853)?;
                    let host_port = format!("{host}:{port}");
                    let addr = if let Ok(ip) = host.parse::<IpAddr>() {
                        SocketAddr::new(ip, port)
                    } else {
                        use std::net::ToSocketAddrs;
                        (host.as_str(), port)
                            .to_socket_addrs()
                            .map_err(crate::Error::Io)?
                            .next()
                            .ok_or_else(|| {
                                crate::Error::InvalidArgument(format!(
                                    "no addresses found for '{host_port}'"
                                ))
                            })?
                    };
                    let client = crate::clients::dot::Client::try_new(&host, addr)?;
                    Ok(Box::new(client))
                }
                #[cfg(not(feature = "dot"))]
                Err(crate::Error::InvalidArgument(
                    "feature 'dot' is required for tls:// exchangers".to_string(),
                ))
            }
            "https" => {
                #[cfg(feature = "doh")]
                {
                    let url = s.parse::<url::Url>().map_err(|e| {
                        crate::Error::InvalidArgument(format!("invalid DoH URL '{s}': {e}"))
                    })?;
                    let client = crate::clients::doh::Client::try_new(url, http::Method::GET)?;
                    Ok(Box::new(client))
                }
                #[cfg(not(feature = "doh"))]
                Err(crate::Error::InvalidArgument(
                    "feature 'doh' is required for https:// exchangers".to_string(),
                ))
            }
            "json+https" => {
                #[cfg(feature = "json")]
                {
                    // json+https:// is an unofficial URI scheme to distinguish JSON DoH from binary DoH (RFC 8484).
                    let https_str = format!("https://{rest}");
                    let url = https_str.parse::<url::Url>().map_err(|e| {
                        crate::Error::InvalidArgument(format!("invalid JSON DoH URL '{s}': {e}"))
                    })?;
                    let client = crate::clients::json::Client::try_new(url)?;
                    Ok(Box::new(client))
                }
                #[cfg(not(feature = "json"))]
                Err(crate::Error::InvalidArgument(
                    "feature 'json' is required for json+https:// exchangers".to_string(),
                ))
            }
            "http" => Err(crate::Error::InvalidArgument(
                "HTTP is insecure; DoH requires HTTPS".to_string(),
            )),
            other => Err(crate::Error::InvalidArgument(format!(
                "unsupported exchanger scheme '{other}' in '{s}'"
            ))),
        }
    } else {
        #[cfg(feature = "do53")]
        {
            let addr = parse_socket_addr(s, 53)?;
            Ok(Box::new(crate::clients::do53::Client::new(addr)))
        }
        #[cfg(not(feature = "do53"))]
        Err(crate::Error::InvalidArgument(
            "feature 'do53' is required for IP exchangers".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchanger_endpoints_are_roundtrippable() {
        let inputs = [
            "dns://8.8.8.8:53",
            "udp://8.8.8.8:53",
            "tcp://8.8.8.8:53",
            #[cfg(feature = "dot")]
            "tls://dns.google:853",
            #[cfg(feature = "doh")]
            "https://dns.google/dns-query",
            #[cfg(feature = "json")]
            "json+https://dns.google/resolve",
        ];

        for &input in &inputs {
            let exchanger = input
                .into_async_exchanger()
                .unwrap_or_else(|e| panic!("failed into_async_exchanger for '{input}': {e}"));
            let endpoint = exchanger.endpoint();
            assert_eq!(
                &*endpoint, input,
                "endpoint for '{input}' did not match input"
            );

            // Round trip: feeding the endpoint back into into_async_exchanger must succeed
            // and produce an identical endpoint.
            let roundtripped = (&*endpoint).into_async_exchanger().unwrap_or_else(|e| {
                panic!("failed roundtrip into_async_exchanger for '{endpoint}': {e}")
            });
            assert_eq!(
                roundtripped.endpoint(),
                endpoint,
                "roundtripped endpoint did not match original"
            );
        }
    }

    #[test]
    fn bare_ip_assumes_do53_scheme() {
        let exchanger = "8.8.8.8:53".into_async_exchanger().expect("valid address");
        assert_eq!(&*exchanger.endpoint(), "dns://8.8.8.8:53");

        let exchanger_default_port = "8.8.8.8".into_async_exchanger().expect("valid IP");
        assert_eq!(&*exchanger_default_port.endpoint(), "dns://8.8.8.8:53");
    }

    #[test]
    fn rejects_invalid_exchanger_string() {
        assert!("invalid://foo".into_async_exchanger().is_err());
    }
}
