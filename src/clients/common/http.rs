use crate::types::TlsInfo;
use http::StatusCode;
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::io;
use std::time::Duration;
use url::Url;

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

pub(crate) fn validate_content_length(headers: &http::HeaderMap, max_len: usize) -> io::Result<()> {
    if let Some(val) = headers.get(http::header::CONTENT_LENGTH) {
        if let Ok(val_str) = val.to_str() {
            if let Ok(len) = val_str.parse::<usize>() {
                if len > max_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("response Content-Length ({len}) exceeds maximum size ({max_len})"),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Extracts or constructs [`TlsInfo`] from an HTTP response and server URL.
///
/// If the response extensions contain an explicit [`TlsInfo`], that value is
/// returned. Otherwise, protocol details are extracted from the actual HTTP
/// response:
/// - `version`: Formatted HTTP version (e.g. `"HTTP/2.0"`, `"HTTP/1.1"`).
/// - `alpn`: Negotiated ALPN identifier corresponding to the HTTP version
///   (`"h2"`, `"http/1.1"`, `"h3"`), if known.
/// - `server_name`: Hostname from `server`.
pub(crate) fn tls_info_from_response<B>(server: &Url, resp: &http::Response<B>) -> TlsInfo {
    if let Some(info) = resp.extensions().get::<TlsInfo>() {
        return info.clone();
    }

    let alpn = match resp.version() {
        http::Version::HTTP_2 => Some("h2".to_string()),
        http::Version::HTTP_11 => Some("http/1.1".to_string()),
        http::Version::HTTP_3 => Some("h3".to_string()),
        http::Version::HTTP_10 => Some("http/1.0".to_string()),
        http::Version::HTTP_09 => Some("http/0.9".to_string()),
        _ => None,
    };

    TlsInfo {
        version: format!("{:?}", resp.version()),
        // hyper-rustls does not expose the negotiated cipher suite through response extensions.
        cipher_suite: None,
        server_name: server.host_str().map(|s| s.to_string()),
        alpn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use http::header::CONTENT_LENGTH;

    #[test]
    fn validates_content_length() {
        let mut headers = HeaderMap::new();
        assert!(validate_content_length(&headers, 100).is_ok());

        headers.insert(CONTENT_LENGTH, "100".parse().unwrap());
        assert!(validate_content_length(&headers, 100).is_ok());

        headers.insert(CONTENT_LENGTH, "101".parse().unwrap());
        assert!(validate_content_length(&headers, 100).is_err());
    }

    #[test]
    fn extracts_tls_info_from_http_response() {
        let server = Url::parse("https://dns.google/dns-query").unwrap();

        let resp_h2 = http::Response::builder()
            .version(http::Version::HTTP_2)
            .body(())
            .unwrap();
        let info_h2 = tls_info_from_response(&server, &resp_h2);
        assert_eq!(info_h2.version, "HTTP/2.0");
        assert_eq!(info_h2.alpn.as_deref(), Some("h2"));
        assert_eq!(info_h2.server_name.as_deref(), Some("dns.google"));
        assert_eq!(info_h2.cipher_suite, None);

        let resp_h11 = http::Response::builder()
            .version(http::Version::HTTP_11)
            .body(())
            .unwrap();
        let info_h11 = tls_info_from_response(&server, &resp_h11);
        assert_eq!(info_h11.version, "HTTP/1.1");
        assert_eq!(info_h11.alpn.as_deref(), Some("http/1.1"));

        let mut resp_custom = http::Response::builder()
            .version(http::Version::HTTP_2)
            .body(())
            .unwrap();
        let custom_tls = TlsInfo {
            version: "TLSv1.3".to_string(),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            server_name: Some("custom.example".to_string()),
            alpn: Some("h2".to_string()),
        };
        resp_custom.extensions_mut().insert(custom_tls.clone());
        let info_custom = tls_info_from_response(&server, &resp_custom);
        assert_eq!(info_custom, custom_tls);
    }
}
