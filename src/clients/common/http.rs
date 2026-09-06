use http::StatusCode;
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::io;
use std::time::Duration;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type HttpClient = HyperClient<HttpsConnector<HttpConnector>, BoxBody<Bytes, BoxError>>;

pub(crate) fn new_client(connect_timeout: Duration) -> HttpClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    // TODO Are there other properties we should set on the connector? For example, `set_nodelay` or `set_keepalive`.
    http.set_connect_timeout(Some(connect_timeout));

    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);

    HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .http2_only(true)
        .build(https)
}

pub(crate) fn validate_status(status: StatusCode) -> io::Result<()> {
    if status.is_success() {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("received unexpected HTTP status code: {status}"),
    ))
}
