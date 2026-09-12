use crate::Message;
use crate::clients::common::http as client_http;
use crate::clients::common::http::{BoxError, HttpClient};
use crate::clients::common::mime::content_type_equal;
use crate::clients::common::stats::WireResponseBuilder;
use crate::clients::{AsyncExchanger, WireResponse};
use crate::limits::MAX_DNS_MESSAGE_LEN;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{Method, Request};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::connect::HttpInfo;
use std::fmt;
use std::io;
use std::time::Duration;
use url::Url;

use super::{CONTENT_TYPE_APPLICATION_DNS_MESSAGE, DNS_QUERY_PARAM, GOOGLE};

const MAX_DOH_BODY_SIZE: usize = MAX_DNS_MESSAGE_LEN;

/// A DNS over HTTPS (DoH) Client ([RFC 8484]).
///
/// # Example
///
/// ```rust,no_run
/// use http::method::Method;
/// use rustdns::clients::AsyncExchanger;
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
/// See [RFC 8484].
///
/// [RFC 8484]: https://datatracker.ietf.org/doc/html/rfc8484
pub struct Client {
    /// HTTPS endpoint used for DNS queries.
    server: Url,
    /// HTTP method used for DNS-over-HTTPS requests. Only `GET` and `POST` are accepted.
    method: Method,
    /// Maximum time allowed to establish connection before TLS starts. Defaults to five seconds.
    connect_timeout: Duration,
    /// Maximum time allowed for receiving the response body. Defaults to five seconds.
    read_timeout: Duration,
    /// Maximum time allowed for sending the request. Defaults to five seconds.
    write_timeout: Duration,
    /// Hyper client whose connection pool is reused across exchanges.
    http_client: HttpClient,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("server", &self.server)
            .field("method", &self.method)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .finish_non_exhaustive()
    }
}

impl std::panic::RefUnwindSafe for Client {}
impl std::panic::UnwindSafe for Client {}

impl Default for Client {
    fn default() -> Self {
        Client {
            server: Url::parse(GOOGLE).expect("valid Google DoH URL"),
            method: Method::GET,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            http_client: client_http::new_client(Duration::from_secs(5)),
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
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            http_client: client_http::new_client(Duration::from_secs(5)),
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

    /// Sets the maximum time allowed to establish a connection.
    pub fn set_connect_timeout(&mut self, timeout: Duration) {
        self.connect_timeout = timeout;
        self.http_client = client_http::new_client(timeout);
    }

    /// Sets the timeout for reading the response body.
    pub fn set_read_timeout(&mut self, timeout: Duration) {
        self.read_timeout = timeout;
    }

    /// Sets the timeout for writing the request.
    pub fn set_write_timeout(&mut self, timeout: Duration) {
        self.write_timeout = timeout;
    }
}

#[async_trait]
impl AsyncExchanger for Client {
    fn endpoint(&self) -> std::sync::Arc<str> {
        self.server.as_str().into()
    }

    fn channel_security(&self) -> crate::types::ChannelSecurity {
        crate::types::ChannelSecurity::Encrypted
    }

    /// Sends the [`Message`] to the `server` via HTTP and returns the result.
    ///
    /// # Errors
    ///
    /// Returns an error for request construction failures, unsuccessful HTTP
    /// responses, invalid content types, oversized bodies, or invalid DNS data.
    async fn exchange(&self, query: &Message) -> Result<WireResponse, crate::Error> {
        let mut query = query.clone();
        query.id = 0;

        let p = query.to_vec()?;
        let dns_request_len = p.len();

        let client = &self.http_client;

        // Base request common to both GET and POST
        let req = Request::builder()
            .method(&self.method)
            .header(ACCEPT, CONTENT_TYPE_APPLICATION_DNS_MESSAGE);

        let (req, request_target) = match self.method {
            Method::GET => {
                let encoded = URL_SAFE_NO_PAD.encode(&p);
                let mut url = self.server.clone();
                url.query_pairs_mut().append_pair(DNS_QUERY_PARAM, &encoded);
                let target = url.to_string();
                let req = req
                    .uri(url.as_str())
                    .body(Full::new(Bytes::new()).map_err(BoxError::from).boxed())?;
                (req, target)
            }
            Method::POST => {
                let target = self.server.to_string();
                let req = req
                    .uri(self.server.as_str())
                    .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_DNS_MESSAGE)
                    .body(Full::new(Bytes::from(p)).map_err(BoxError::from).boxed())?;
                (req, target)
            }
            _ => unreachable!("only GET and POST allowed"),
        };

        let builder = WireResponseBuilder::start(dns_request_len);

        log::trace!(
            "DoH sending {} request to {request_target} with {dns_request_len} DNS bytes",
            self.method
        );
        let resp = match tokio::time::timeout(self.write_timeout, client.request(req)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "DoH request timed out").into(),
                );
            }
        };
        // TODO This media type restricts the maximum size of the DNS message to 65535 bytes

        // Get connection information (if available)
        let remote_addr = resp
            .extensions()
            .get::<HttpInfo>()
            .map(HttpInfo::remote_addr);
        log::trace!("DoH remote address: {remote_addr:?}");
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

        client_http::validate_status(resp.status())?;
        client_http::validate_content_length(resp.headers(), MAX_DOH_BODY_SIZE)?;
        let tls_info = Some(client_http::tls_info_from_response(&self.server, &resp));

        // Read the full body
        let body = match tokio::time::timeout(
            self.read_timeout,
            Limited::new(resp.into_body(), MAX_DOH_BODY_SIZE).collect(),
        )
        .await
        {
            Ok(result) => result
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                .to_bytes(),
            Err(_) => {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "DoH response read timed out").into(),
                );
            }
        };
        log::trace!(
            "DoH received {} DNS body bytes from {remote_addr:?}",
            body.len()
        );

        let m = Message::from_slice(&body)?;
        Ok(builder.finish(
            m,
            remote_addr,
            body.len(),
            self.channel_security(),
            tls_info,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, MAX_DOH_BODY_SIZE};
    use crate::clients::AsyncExchanger;
    use crate::clients::common::http as client_http;
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
        assert!(client_http::validate_status(StatusCode::OK).is_ok());
        assert!(client_http::validate_status(StatusCode::BAD_REQUEST).is_err());
        assert!(client_http::validate_status(StatusCode::INTERNAL_SERVER_ERROR).is_err());
    }

    #[test]
    fn secure_channel_is_true() {
        let client = Client::new("https://dns.google/dns-query", Method::GET).expect("valid DoH");
        assert_eq!(
            client.channel_security(),
            crate::types::ChannelSecurity::Encrypted
        );
        assert!(client.is_secure_channel());
    }
}
