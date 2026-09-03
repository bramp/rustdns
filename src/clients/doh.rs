use crate::Message;
use crate::bail;
use crate::clients::AsyncExchanger;
use crate::clients::ToUrls;
use crate::clients::mime::content_type_equal;
use crate::clients::stats::StatsBuilder;
use crate::clients::validate_http_status;
use crate::clients::{BoxError, HttpClient, new_http_client};
use crate::limits::MAX_DNS_MESSAGE_LEN;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::header::*;
use http::{Method, Request};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::connect::HttpInfo;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use url::Url;

const MAX_DOH_BODY_SIZE: usize = MAX_DNS_MESSAGE_LEN;

pub const GOOGLE: &str = "https://dns.google/dns-query";

// For use in Content-type and Accept headers
const CONTENT_TYPE_APPLICATION_DNS_MESSAGE: &str = "application/dns-message";

// The param name that contains the DNS request.
const DNS_QUERY_PARAM: &str = "dns";

/// A DNS over HTTPS (DoH) Client (rfc8484).
///
/// # Example
///
/// ```rust
/// use crate::rustdns::clients::AsyncExchanger;
/// use http::method::Method;
/// use rustdns::clients::doh::Client;
/// use rustdns::types::*;
///
/// #[tokio::main]
/// async fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     let response = Client::new("https://dns.google/dns-query", Method::GET)?
///        .exchange(&query)
///        .await
///        .expect("could not exchange message");
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See <https://datatracker.ietf.org/doc/html/rfc8484>
pub struct Client {
    /// HTTPS endpoints used for DNS queries. The first endpoint is currently used for each exchange.
    servers: Vec<Url>,
    /// HTTP method used for DNS-over-HTTPS requests. Only `GET` and `POST` are accepted.
    method: Method,
    /// Hyper client whose connection pool is reused across exchanges.
    http_client: HttpClient,
}

impl std::panic::RefUnwindSafe for Client {}
impl std::panic::UnwindSafe for Client {}

impl Default for Client {
    fn default() -> Self {
        Client {
            servers: Vec::default(),
            method: Method::GET,
            http_client: new_http_client(),
        }
    }
}

impl Client {
    /// Creates a new Client bound to the specific servers.
    ///
    /// Be aware that the servers will typically be in the form of `https://domain_name/`. That
    /// `domain_name` will be resolved by the system's standard DNS library. I don't have a good
    /// work-around for this yet.
    ///
    /// # Errors
    ///
    /// Returns an error if no server is supplied, a URL cannot be parsed, a server
    /// does not use HTTPS, or `method` is not `GET` or `POST`.
    pub fn new<A: ToUrls>(servers: A, method: Method) -> Result<Self, crate::Error> {
        match method {
            Method::GET | Method::POST => (), // Nothing,
            _ => {
                return Err(crate::Error::InvalidArgument(
                    "only GET and POST allowed".to_string(),
                ));
            }
        }

        let servers: Vec<_> = servers.to_urls()?.collect();
        if servers.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "at least one DoH server is required".to_string(),
            ));
        }
        if servers.iter().any(|server| server.scheme() != "https") {
            return Err(crate::Error::InvalidArgument(
                "DoH servers must use HTTPS".to_string(),
            ));
        }

        Ok(Self {
            servers,
            method,
            http_client: new_http_client(),
        })
    }
}

#[async_trait]
impl AsyncExchanger for Client {
    /// Sends the [`Message`] to the `server` via HTTP and returns the result.
    ///
    /// # Errors
    ///
    /// Returns an error for request construction failures, unsuccessful HTTP
    /// responses, invalid content types, oversized bodies, or invalid DNS data.
    // TODO Decide if this should be async or not.
    // Can return ::std::io::Error
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        let server = self.servers.first().ok_or_else(|| {
            crate::Error::InvalidArgument("at least one DoH server is required".to_string())
        })?;
        let mut query = query.clone();
        query.id = 0;

        let p = query.to_vec()?;
        let dns_request_len = p.len();

        let client = &self.http_client;

        // Base request common to both GET and POST
        let req = Request::builder()
            .method(&self.method)
            .header(ACCEPT, CONTENT_TYPE_APPLICATION_DNS_MESSAGE);

        let mut request_target = server.to_string();
        let req = match self.method {
            Method::GET => {
                // Encode the message as a base64 string
                let mut buf = String::new();
                URL_SAFE_NO_PAD.encode_string(p, &mut buf);

                // and add to the query params.
                let mut url = server.clone(); // TODO Support more than one server
                url.query_pairs_mut().append_pair(DNS_QUERY_PARAM, &buf);
                request_target = url.to_string();

                // We have to do this wierd as_str().parse() thing because the
                // http::Uri doesn't provide a way to easily mutate or construct it.
                let uri: http::Uri = url.as_str().parse()?;
                req.uri(uri).body(
                    Full::new(Bytes::new())
                        .map_err(|error: std::convert::Infallible| -> BoxError { match error {} })
                        .boxed(),
                )?
            }
            Method::POST => {
                req.uri(server.as_str()) // TODO Support more than one server
                    .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_DNS_MESSAGE)
                    .body(
                        Full::new(Bytes::from(p))
                            .map_err(|error: std::convert::Infallible| -> BoxError {
                                match error {}
                            })
                            .boxed(),
                    )? // content-length header will be added.
            }
            _ => {
                return Err(crate::Error::InvalidArgument(
                    "only GET and POST allowed".to_string(),
                ));
            }
        };

        let stats = StatsBuilder::start(0);

        log::trace!(
            "DoH sending {} request to {request_target} with {dns_request_len} DNS bytes",
            self.method
        );
        let resp = client.request(req).await?;
        // TODO This media type restricts the maximum size of the DNS message to 65535 bytes

        // Get connection information (if available)
        let remote_addr = match resp.extensions().get::<HttpInfo>() {
            Some(http_info) => http_info.remote_addr(),

            // TODO Maybe remote_addr should be optional?
            None => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0), // Dummy address
        };
        log::trace!("DoH remote address: {remote_addr}");
        log::trace!("DoH HTTP status: {}", resp.status());

        let content_type = resp.headers().get(CONTENT_TYPE).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "response is missing content-type",
            )
        })?;
        log::trace!("DoH response content-type: {:?}", content_type);
        if !content_type_equal(content_type, CONTENT_TYPE_APPLICATION_DNS_MESSAGE) {
            bail!(
                InvalidData,
                "recevied invalid content-type: {:?} expected {}",
                content_type,
                CONTENT_TYPE_APPLICATION_DNS_MESSAGE,
            );
        }

        validate_http_status(resp.status())?;

        // TODO check Content-Length, but don't allow us to consume a body longer than 65535 bytes!

        // Read the full body
        let body = Limited::new(resp.into_body(), MAX_DOH_BODY_SIZE)
            .collect()
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .to_bytes();
        log::trace!(
            "DoH received {} DNS body bytes from {remote_addr}",
            body.len()
        );

        let mut m = Message::from_slice(&body)?;
        m.stats = Some(stats.end(remote_addr, body.len()));

        return Ok(m);
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, MAX_DOH_BODY_SIZE};
    use crate::clients::validate_http_status;
    use http::Method;
    use http::StatusCode;
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;

    #[test]
    fn rejects_plaintext_http_server() {
        assert!(Client::new("http://dns.example/dns-query", Method::GET).is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_response_body() {
        let body = Limited::new(
            Full::new(Bytes::from(vec![0; MAX_DOH_BODY_SIZE + 1])),
            MAX_DOH_BODY_SIZE,
        )
        .collect()
        .await;

        assert!(body.is_err());
    }

    #[test]
    fn validates_success_client_statuses() {
        assert!(validate_http_status(StatusCode::OK).is_ok());
        assert!(validate_http_status(StatusCode::BAD_REQUEST).is_err());
        assert!(validate_http_status(StatusCode::INTERNAL_SERVER_ERROR).is_err());
    }
}
