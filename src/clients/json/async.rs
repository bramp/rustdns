use crate::Class;
use crate::Error;
use crate::Message;
use crate::Question;
use crate::Record;
use crate::Resource;
use crate::clients::AsyncExchanger;
use crate::clients::common::http as client_http;
use crate::clients::common::http::{BoxError, HttpClient};
use crate::clients::common::mime::content_type_equal;
use crate::clients::common::stats::StatsBuilder;
use crate::errors::JsonError;
use async_trait::async_trait;
use core::convert::TryInto;
use http::Method;
use http::Request;
use http::header::*;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::connect::HttpInfo;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use serde_json;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;
use url::Url;

const MAX_JSON_BODY_SIZE: usize = 1024 * 1024;

pub const GOOGLE: &str = "https://dns.google/resolve";
pub const CLOUDFLARE: &str = "https://cloudflare-dns.com/dns-query";

// For use in Content-type and Accept headers
// Google actually uses "application/json", but Cloud Flare requires "application/dns-json".
// Since Google's API seems to accept either, we default to dns-json.
const CONTENT_TYPE_APPLICATION_DNS_JSON: &str = "application/dns-json";
const CONTENT_TYPE_APPLICATION_JSON: &str = "application/json";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MessageJson {
    pub status: u32, // NOERROR - Standard DNS response code (32 bit integer).

    #[serde(rename = "TC")]
    pub tc: bool, // Whether the response is truncated

    #[serde(rename = "RD")]
    pub rd: bool, // Always true for Google Public DNS

    #[serde(rename = "RA")]
    pub ra: bool, // Always true for Google Public DNS

    #[serde(rename = "AD")]
    pub ad: bool, // Whether all response data was validated with DNSSEC

    #[serde(rename = "CD")]
    pub cd: bool, // Whether the client asked to disable DNSSEC

    pub question: Vec<QuestionJson>,

    #[serde(default)] // Prefer empty Vec, over Optional
    pub answer: Vec<RecordJson>,

    pub comment: Option<String>,

    #[serde(rename = "edns_client_subnet")]
    pub edns_client_subnet: Option<String>, // IP address / scope prefix-length
}

impl TryInto<Message> for MessageJson {
    type Error = JsonError;

    fn try_into(self) -> Result<Message, Self::Error> {
        let rcode =
            FromPrimitive::from_u32(self.status).ok_or(JsonError::InvalidStatus(self.r#status))?;

        let mut m = Message {
            rcode,
            tc: self.tc,
            rd: self.rd,
            ra: self.ra,
            ad: self.ad,
            cd: self.cd,

            ..Default::default()
        };

        // TODO Do something with edns_client_subnet
        // TODO Do something with comment

        for question in self.question {
            m.questions.push(question.try_into()?)
        }

        for answer in self.answer {
            m.answers.push(answer.try_into()?)
        }

        Ok(m)
    }
}

// Basically a Question
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
struct QuestionJson {
    pub name: String, // FQDN with trailing dot
    pub r#type: u16,  // A - Standard DNS RR type
}

impl TryInto<Question> for QuestionJson {
    type Error = JsonError;

    fn try_into(self) -> Result<Question, Self::Error> {
        let r#type =
            FromPrimitive::from_u16(self.r#type).ok_or(JsonError::InvalidType(self.r#type))?;

        Ok(Question {
            name: self.name, // TODO Do I need to remove the trailing dot?
            r#type,
            class: Class::Internet,
        })
    }
}

// Basically a Record + Resource
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
struct RecordJson {
    pub name: String,
    pub r#type: u16, // A - Standard DNS RR type

    #[serde(rename = "TTL")]
    pub ttl: u32,
    pub data: String,
}

impl TryInto<Record> for RecordJson {
    type Error = JsonError;

    fn try_into(self) -> Result<Record, Self::Error> {
        let r#type =
            FromPrimitive::from_u16(self.r#type).ok_or(JsonError::InvalidType(self.r#type))?;

        let resource = Resource::parse_text(r#type, &self.data)
            .map_err(|x| JsonError::InvalidResource(r#type, x))?;

        Ok(Record {
            name: self.name, // TODO Do I need to remove the trailing dot?
            class: Class::Internet,
            ttl: Duration::from_secs(self.ttl.into()),
            resource,
        })
    }
}

/// A DNS over HTTPS client using the Google JSON API.
///
/// # Example
///
/// ```rust,no_run
/// use rustdns::clients::AsyncExchanger;
/// use rustdns::clients::json;
/// use rustdns::types::*;
///
/// #[tokio::main]
/// async fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     let response = json::Client::try_from_url("https://dns.google/resolve")?
///        .exchange(&query)
///        .await
///        .expect("could not exchange message");
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See <https://developers.google.com/speed/public-dns/docs/doh/json> and
/// <https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests/dns-json>
pub struct Client {
    /// HTTPS endpoint used for JSON DNS queries.
    server: Url,
    /// Maximum time allowed to establish connection before TLS starts. Defaults to five seconds.
    connect_timeout: Duration,
    /// Maximum time allowed for receiving the response body. Defaults to five seconds.
    read_timeout: Duration,
    /// Maximum time allowed for sending the request. Defaults to five seconds.
    write_timeout: Duration,
    /// Hyper client whose connection pool is reused across exchanges.
    http_client: HttpClient,
}

impl std::panic::RefUnwindSafe for Client {}
impl std::panic::UnwindSafe for Client {}

impl Default for Client {
    fn default() -> Self {
        Self {
            server: Url::parse(GOOGLE).expect("valid Google JSON URL"),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            http_client: client_http::new_client(Duration::from_secs(5)),
        }
    }
}

impl Client {
    /// Creates a new DoH JSON client bound to the specified HTTPS URL.
    ///
    /// # Errors
    ///
    /// Returns an error if `server` does not use HTTPS.
    pub fn try_new(server: Url) -> Result<Self, crate::Error> {
        if server.scheme() != "https" {
            return Err(crate::Error::InvalidArgument(
                "DoH JSON servers must use HTTPS".to_string(),
            ));
        }

        Ok(Self {
            server,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            http_client: client_http::new_client(Duration::from_secs(5)),
        })
    }

    /// Creates a new DoH JSON client by parsing a URL string.
    ///
    /// # Errors
    ///
    /// Returns an error if `url` cannot be parsed or does not use HTTPS.
    pub fn try_from_url(url: &str) -> Result<Self, crate::Error> {
        let parsed = url
            .parse::<Url>()
            .map_err(|e| crate::Error::InvalidArgument(format!("invalid URL '{url}': {e}")))?;
        Self::try_new(parsed)
    }

    /// Compatibility constructor. Prefer [`Client::try_new`] or [`Client::try_from_url`].
    pub fn new(server: &str) -> Result<Self, crate::Error> {
        Self::try_from_url(server)
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
        // Unofficial custom scheme to unambiguously differentiate JSON DoH from binary DoH (https://).
        let without_scheme = self
            .server
            .as_str()
            .strip_prefix("https://")
            .unwrap_or(self.server.as_str());
        format!("json+https://{without_scheme}").into()
    }

    fn channel_security(&self) -> crate::types::ChannelSecurity {
        crate::types::ChannelSecurity::Encrypted
    }

    /// Sends the [`Message`] to the `server` via HTTP and returns the result.
    ///
    /// # Errors
    ///
    /// Returns an error for request construction failures, unsuccessful HTTP
    /// responses, invalid content types, oversized bodies, or invalid JSON/DNS data.
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        if query.questions.len() != 1 {
            return Err(Error::InvalidArgument(
                "expected exactly one question must be provided".to_string(),
            ));
        }

        let client = &self.http_client;

        let question = query.questions.first().ok_or_else(|| {
            crate::Error::InvalidArgument("expected one DNS question".to_string())
        })?;

        let mut url = self.server.clone();
        url.query_pairs_mut().append_pair("name", &question.name);
        url.query_pairs_mut()
            .append_pair("type", &question.r#type.to_string());

        url.query_pairs_mut()
            .append_pair("cd", &query.cd.to_string());
        url.query_pairs_mut()
            .append_pair("ct", CONTENT_TYPE_APPLICATION_DNS_JSON);

        if let Some(extension) = &query.extension {
            url.query_pairs_mut()
                .append_pair("do", &extension.dnssec_ok.to_string());
        }

        // TODO Support the following
        // url.query_pairs_mut().append_pair("edns_client_subnet", );
        // url.query_pairs_mut().append_pair("random_padding", );

        let request_target = url.to_string();
        let req = Request::builder()
            .method(Method::GET)
            .uri(url.as_str())
            .header(ACCEPT, CONTENT_TYPE_APPLICATION_DNS_JSON)
            .body(Empty::<Bytes>::new().map_err(BoxError::from).boxed())?;

        let stats = StatsBuilder::start(0);
        log::trace!("DoH JSON sending GET request to {request_target}");
        let resp = match tokio::time::timeout(self.write_timeout, client.request(req)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "DoH JSON request timed out").into(),
                );
            }
        };

        // Get connection information (if available)
        let remote_addr = match resp.extensions().get::<HttpInfo>() {
            Some(http_info) => http_info.remote_addr(),

            // TODO Maybe remote_addr should be optional?
            None => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0), // Dummy address
        };
        log::trace!("DoH JSON remote address: {remote_addr}");
        log::trace!("DoH JSON HTTP status: {}", resp.status());

        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .ok_or(crate::Error::MissingContentType)?;
        log::trace!("DoH JSON response content-type: {:?}", content_type);
        if !content_type_equal(content_type, CONTENT_TYPE_APPLICATION_DNS_JSON)
            && !content_type_equal(content_type, CONTENT_TYPE_APPLICATION_JSON)
        {
            return Err(crate::Error::UnexpectedContentType {
                actual: format!("{content_type:?}"),
                expected: "application/dns-json or application/json",
            });
        }

        client_http::validate_status(resp.status())?;
        client_http::validate_content_length(resp.headers(), MAX_JSON_BODY_SIZE)?;

        // Read the full body
        let body = match tokio::time::timeout(
            self.read_timeout,
            Limited::new(resp.into_body(), MAX_JSON_BODY_SIZE).collect(),
        )
        .await
        {
            Ok(result) => result
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                .to_bytes(),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DoH JSON response read timed out",
                )
                .into());
            }
        };
        log::trace!(
            "DoH JSON received {} response body bytes from {remote_addr}",
            body.len()
        );

        let mut m = parse_response(&body)?;
        m.stats = Some(stats.end(remote_addr, body.len()));

        return Ok(m);
    }
}

fn parse_response(body: &[u8]) -> Result<Message, JsonError> {
    let m: MessageJson = serde_json::from_slice(body).map_err(JsonError::Serde)?;
    m.try_into()
}

/// Parses a DNS-over-HTTPS JSON response body into a [`Message`].
/// Internal helper for fuzzing and testing only.
#[doc(hidden)]
#[cfg(any(test, fuzzing))]
pub fn fuzz_parse_response(body: &[u8]) -> Result<Message, JsonError> {
    parse_response(body)
}

#[cfg(test)]
mod tests {
    use super::MAX_JSON_BODY_SIZE;
    use super::MessageJson;
    use crate::Message;
    use crate::clients::common::http as client_http;
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;
    use json_comments::StripComments;
    use std::convert::TryInto;
    use std::io::Read;

    #[test]
    fn test_parse_response() {
        // From https://developers.google.com/speed/public-dns/docs/doh/json
        let tests = [
            r#"{
          "Status": 0,  // NOERROR - Standard DNS response code (32 bit integer).
          "TC": false,  // Whether the response is truncated
          "RD": true,   // Always true for Google Public DNS
          "RA": true,   // Always true for Google Public DNS
          "AD": false,  // Whether all response data was validated with DNSSEC
          "CD": false,  // Whether the client asked to disable DNSSEC
          "Question":
          [
            {
              "name": "apple.com.",  // FQDN with trailing dot
              "type": 1              // A - Standard DNS RR type
            }
          ],
          "Answer":
          [
            {
              "name": "apple.com.",   // Always matches name in the Question section
              "type": 1,              // A - Standard DNS RR type
              "TTL": 3599,            // Record's time-to-live in seconds
              "data": "17.178.96.59"  // Data for A - IP address as text
            },
            {
              "name": "apple.com.",
              "type": 1,
              "TTL": 3599,
              "data": "17.172.224.47"
            },
            {
              "name": "apple.com.",
              "type": 1,
              "TTL": 3599,
              "data": "17.142.160.59"
            }
          ],
          "edns_client_subnet": "12.34.56.78/0"  // IP address / scope prefix-length
        }"#,
            r#"
        {
          "Status": 2,  // SERVFAIL - Standard DNS response code (32 bit integer).
          "TC": false,  // Whether the response is truncated
          "RD": true,   // Always true for Google Public DNS
          "RA": true,   // Always true for Google Public DNS
          "AD": false,  // Whether all response data was validated with DNSSEC
          "CD": false,  // Whether the client asked to disable DNSSEC
          "Question":
          [
            {
              "name": "dnssec-failed.org.",  // FQDN with trailing dot
              "type": 1                      // A - Standard DNS RR type
            }
          ],
          "Comment": "DNSSEC validation failure. Please check http://dnsviz.net/d/dnssec-failed.org/dnssec/."
        }
        "#,
            r#"
        {
          "Status": 0,  // NOERROR - Standard DNS response code (32 bit integer).
          "TC": false,  // Whether the response is truncated
          "RD": true,   // Always true for Google Public DNS
          "RA": true,   // Always true for Google Public DNS
          "AD": false,  // Whether all response data was validated with DNSSEC
          "CD": false,  // Whether the client asked to disable DNSSEC
          "Question": [
            {
              "name": "*.dns-example.info.",  // FQDN with trailing dot
              "type": 99                      // SPF - Standard DNS RR type
            }
          ],
          "Answer": [
            {
              "name": "*.dns-example.info.",   // Always matches name in Question
              "type": 99,                      // SPF - Standard DNS RR type
              "TTL": 21599,                    // Record's time-to-live in seconds
              "data": "\"v=spf1 -all\""        // Data for SPF - quoted string
            }
          ],
          "Comment": "Response from 216.239.38.110"
          // Uncached responses are attributed to the authoritative name server
        }"#,
            r#"{
          "Status": 0,  // NOERROR - Standard DNS response code (32 bit integer).
          "TC": false,  // Whether the response is truncated
          "RD": true,   // Always true for Google Public DNS
          "RA": true,   // Always true for Google Public DNS
          "AD": false,  // Whether all response data was validated with DNSSEC
          "CD": false,  // Whether the client asked to disable DNSSEC
          "Question": [
            {
              "name": "s1024._domainkey.yahoo.com.", // FQDN with trailing dot
              "type": 16                             // TXT - Standard DNS RR type
            }
          ],
          "Answer": [
            {
              "name": "s1024._domainkey.yahoo.com.", // Always matches Question name
              "type": 16,                            // TXT - Standard DNS RR type
              "TTL": 21599,                          // Record's time-to-live in seconds
              "data": "\"k=rsa;  p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrEee0Ri4Juz+QfiWYui/E9UGSXau/2P8LjnTD8V4Unn+2FAZVGE3kL23bzeoULYv4PeleB3gfm\"\"JiDJOKU3Ns5L4KJAUUHjFwDebt0NP+sBK0VKeTATL2Yr/S3bT/xhy+1xtj4RkdV7fVxTn56Lb4udUnwuxK4V5b5PdOKj/+XcwIDAQAB; n=A 1024 bit key;\""
              // Data for TXT - multiple quoted strings
            }
          ]
        }"#,
            // From https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests/dns-json
            r#"{
          "Status": 0,
          "TC": false,
          "RD": true,
          "RA": true,
          "AD": true,
          "CD": false,
          "Question": [
            {
              "name": "example.com.",
              "type": 28
            }
          ],
          "Answer": [
            {
              "name": "example.com.",
              "type": 28,
              "TTL": 1726,
              "data": "2606:2800:220:1:248:1893:25c8:1946"
            }
          ]
        }"#,
        ];

        for test in tests {
            // Strip comments in the test, as a easy way to keep this test data annotated.
            let mut stripped = String::new();
            StripComments::new(test.as_bytes())
                .read_to_string(&mut stripped)
                .unwrap();

            let m: MessageJson = match serde_json::from_str(&stripped) {
                Ok(m) => m,
                Err(err) => panic!("failed to parse JSON: {}\n{}", err, stripped),
            };
            let _m: Message = m
                .try_into()
                .expect("failed to turn MessageJson into a Message");
            // TODO Check this is what we expect
        }
    }

    #[tokio::test]
    async fn rejects_oversized_response_body() {
        let body = Limited::new(
            Full::new(Bytes::from(vec![0; MAX_JSON_BODY_SIZE + 1])),
            MAX_JSON_BODY_SIZE,
        )
        .collect()
        .await;

        assert!(body.is_err());
    }

    #[test]
    fn validates_success_client_statuses() {
        use http::StatusCode;

        assert!(client_http::validate_status(StatusCode::OK).is_ok());
        assert!(client_http::validate_status(StatusCode::BAD_REQUEST).is_err());
        assert!(client_http::validate_status(StatusCode::INTERNAL_SERVER_ERROR).is_err());
    }
}
