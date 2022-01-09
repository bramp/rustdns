use crate::bail;
use crate::clients::utils::content_type_equal;
use crate::clients::AsyncExchanger;
use crate::clients::ToUrls;
use crate::errors::ParseError;
use crate::Class;
use crate::Error;
use crate::Message;
use crate::Question;
use crate::Record;
use crate::Resource;
use crate::StatsBuilder;
use async_trait::async_trait;
use core::convert::TryInto;
use http::header::*;
use http::Method;
use http::Request;
use hyper::client::connect::HttpInfo;
use hyper::{Body, Client as HyperClient};
use hyper_alpn::AlpnConnector;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use serde_json;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;
use url::Url;

pub const GOOGLE: &str = "https://dns.google/resolve";
pub const CLOUDFLARE: &str = "https://cloudflare-dns.com/dns-query";

// For use in Content-type and Accept headers
// Google actually uses "application/x-javascript", but Cloud Flare requires "application/dns-json".
// Since Google's API seems to accept either, we default to dns-json.
const CONTENT_TYPE_APPLICATION_DNS_JSON: &str = "application/dns-json";
const CONTENT_TYPE_APPLICATION_X_JAVASCRIPT: &str = "application/x-javascript";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MessageJson {
    pub status: u32, // NOERROR - Standard DNS response code (32 bit integer).

    #[serde(rename = "TC")]
    pub tc: bool,    // Whether the response is truncated

    #[serde(rename = "RD")]
    pub rd: bool,    // Always true for Google Public DNS

    #[serde(rename = "RA")]
    pub ra: bool,    // Always true for Google Public DNS

    #[serde(rename = "AD")]
    pub ad: bool,    // Whether all response data was validated with DNSSEC

    #[serde(rename = "CD")]
    pub cd: bool,    // Whether the client asked to disable DNSSEC

    pub question: Vec<QuestionJson>,

    #[serde(default)] // Prefer empty Vec, over Optional
    pub answer: Vec<RecordJson>,

    pub comment: Option<String>,

    #[serde(rename = "edns_client_subnet")]
    pub edns_client_subnet: Option<String>, // IP address / scope prefix-length
}

impl TryInto<Message> for MessageJson {
    type Error = ParseError;

    fn try_into(self) -> Result<Message, Self::Error> {
        let rcode =
            FromPrimitive::from_u32(self.status).ok_or(ParseError::InvalidStatus(self.r#status))?;

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
    type Error = ParseError;

    fn try_into(self) -> Result<Question, Self::Error> {
        let r#type =
            FromPrimitive::from_u16(self.r#type).ok_or(ParseError::InvalidType(self.r#type))?;

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
    type Error = ParseError;

    fn try_into(self) -> Result<Record, Self::Error> {
        let r#type =
            FromPrimitive::from_u16(self.r#type).ok_or(ParseError::InvalidType(self.r#type))?;

        let resource =
            Resource::from_str(r#type, &self.data).map_err(|x| ParseError::InvalidResource(r#type, x))?;

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
/// ```rust
/// use rustdns::clients::AsyncExchanger;
/// use rustdns::clients::json;
/// use rustdns::types::*;
///
/// #[tokio::main]
/// async fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.add_question("bramp.net", Type::A, Class::Internet);
///
///     let response = json::Client::new("https://dns.google/resolve")?
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
// TODO Document all the options.
pub struct Client {
    servers: Vec<Url>,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            servers: Vec::default(),
        }
    }
}

impl Client {
    /// Creates a new Client bound to the specific servers.
    ///
    /// Be aware that the servers will typically be in the form of `https://domain_name/`. That
    /// `domain_name` will be resolved by the system's standard DNS library. I don't have a good
    /// work-around for this yet.
    // TODO Document how it fails.
    pub fn new<A: ToUrls>(servers: A) -> Result<Self, crate::Error> {
        Ok(Self {
            servers: servers.to_urls()?.collect(),
        })
    }
}

#[async_trait]
impl AsyncExchanger for Client {
    /// Sends the [`Message`] to the `server` via HTTP and returns the result.
    // TODO Decide if this should be async or not.
    // Can return ::std::io::Error
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        if query.questions.len() != 1 {
            return Err(Error::InvalidArgument(
                "expected exactly one question must be provided".to_string(),
            ));
        }

        // Create a Alpn client, so our connection will upgrade to HTTP/2.
        // TODO Move the client into the struct/new()
        // TODO Change the Connector Connect method to allow us to override the DNS
        // resolution in the connector!
        let alpn = AlpnConnector::new();

        let client = HyperClient::builder()
            .pool_idle_timeout(Duration::from_secs(30))
            .http2_only(true)
            .build::<_, hyper::Body>(alpn);

        let question = &query.questions[0];

        let mut url = self.servers[0].clone(); // TODO Support more than one server
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

        // We have to do this wierd as_str().parse() thing because the
        // http::Uri doesn't provide a way to easily mutate or construct it.
        let uri: hyper::Uri = url.as_str().parse()?;

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(ACCEPT, CONTENT_TYPE_APPLICATION_DNS_JSON)
            .body(Body::empty())?;

        let stats = StatsBuilder::start(0);
        let resp = client.request(req).await?;

        if let Some(content_type) = resp.headers().get(CONTENT_TYPE) {
            if !content_type_equal(content_type, CONTENT_TYPE_APPLICATION_DNS_JSON)
                && !content_type_equal(content_type, CONTENT_TYPE_APPLICATION_X_JAVASCRIPT)
            {
                bail!(
                    InvalidData,
                    "recevied invalid content-type: {:?} expected {} or {}",
                    content_type,
                    CONTENT_TYPE_APPLICATION_DNS_JSON,
                    CONTENT_TYPE_APPLICATION_X_JAVASCRIPT,
                );
            }
        }

        if resp.status().is_success() {
            // Get connection information (if available)
            let remote_addr = match resp.extensions().get::<HttpInfo>() {
                Some(http_info) => http_info.remote_addr(),

                // TODO Maybe remote_addr should be optional?
                None => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0), // Dummy address
            };

            // Read the full body
            let body = hyper::body::to_bytes(resp.into_body()).await?;

            println!("{:?}", body);

            let m: MessageJson = serde_json::from_slice(&body).map_err(ParseError::JsonError)?;
            let mut m: Message = m.try_into()?;
            m.stats = Some(stats.end(remote_addr, body.len()));

            return Ok(m);
        }

        // TODO Retry on 500s. If this is a 4xx we should not retry. Should we follow 3xx?
        bail!(
            InvalidInput,
            "recevied unexpected HTTP status code: {:}",
            resp.status()
        );
    }
}


#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::convert::TryInto;
    use crate::clients::json::MessageJson;
    use json_comments::StripComments;
    use crate::Message;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_response() {
        // From https://developers.google.com/speed/public-dns/docs/doh/json
        let tests = [r#"{
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
        }"#
        ,
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
        "#
        ,
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
        }"#
        ,
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
        }"#];

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
            let _m: Message = m.try_into().expect("failed to turn MessageJson into a Message");
            // TODO Check this is what we expect
        }
    }
}