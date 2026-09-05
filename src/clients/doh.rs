use crate::Message;
use crate::clients::AsyncExchanger;
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
///     let response = Client::try_from_url("https://dns.google/dns-query", Method::GET)?
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
    /// HTTPS endpoint used for DNS queries.
    server: Url,
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
            server: Url::parse(GOOGLE).expect("valid Google DoH URL"),
            method: Method::GET,
            http_client: new_http_client(),
        }
    }
}

impl Client {
    /// Creates a new DoH client bound to the specified HTTPS URL.
    ///
    /// # Errors
    ///
    /// Returns an error if `server` does not use HTTPS, or `method` is not `GET` or `POST`.
    pub fn try_new(server: Url, method: Method) -> Result<Self, crate::Error> {
        match method {
            Method::GET | Method::POST => (),
            _ => {
                return Err(crate::Error::InvalidArgument(
                    "only GET and POST allowed".to_string(),
                ));
            }
        }

        if server.scheme() != "https" {
            return Err(crate::Error::InvalidArgument(
                "DoH servers must use HTTPS".to_string(),
            ));
        }

        Ok(Self {
            server,
            method,
            http_client: new_http_client(),
        })
    }

    /// Creates a new DoH client by parsing a URL string.
    ///
    /// # Errors
    ///
    /// Returns an error if `url` cannot be parsed, does not use HTTPS, or `method` is invalid.
    pub fn try_from_url(url: &str, method: Method) -> Result<Self, crate::Error> {
        let parsed = url
            .parse::<Url>()
            .map_err(|e| crate::Error::InvalidArgument(format!("invalid URL '{url}': {e}")))?;
        Self::try_new(parsed, method)
    }

    /// Compatibility constructor. Prefer [`Client::try_new`] or [`Client::try_from_url`].
    pub fn new(server: &str, method: Method) -> Result<Self, crate::Error> {
        Self::try_from_url(server, method)
    }

    /// Returns the HTTPS endpoint this client queries.
    pub fn server(&self) -> &Url {
        &self.server
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
        let mut query = query.clone();
        query.id = 0;

        let p = query.to_vec()?;
        let dns_request_len = p.len();

        let client = &self.http_client;

        // Base request common to both GET and POST
        let req = Request::builder()
            .method(&self.method)
            .header(ACCEPT, CONTENT_TYPE_APPLICATION_DNS_MESSAGE);

        let mut request_target = self.server.to_string();
        let req = match self.method {
            Method::GET => {
                // Encode the message as a base64 string
                let mut buf = String::new();
                URL_SAFE_NO_PAD.encode_string(p, &mut buf);

                // and add to the query params.
                let mut url = self.server.clone();
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
                req.uri(self.server.as_str())
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

        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .ok_or(crate::Error::MissingContentType)?;
        log::trace!("DoH response content-type: {:?}", content_type);
        if !content_type_equal(content_type, CONTENT_TYPE_APPLICATION_DNS_MESSAGE) {
            return Err(crate::Error::UnexpectedContentType {
                actual: format!("{content_type:?}"),
                expected: CONTENT_TYPE_APPLICATION_DNS_MESSAGE,
            });
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
