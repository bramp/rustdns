use crate::bail;
use crate::clients::mime::content_type_equal;
use crate::clients::AsyncExchanger;
use crate::clients::ToUrls;
use crate::Message;
use crate::clients::stats::StatsBuilder;
use async_trait::async_trait;
use http::header::*;
use http::{Method, Request};
use hyper::client::connect::HttpInfo;
use hyper::{Body, Client as HyperClient};
use hyper_alpn::AlpnConnector;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;
use url::Url;

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
///     query.add_question("bramp.net", Type::A, Class::Internet);
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
// TODO Document all the options.
pub struct Client {
    servers: Vec<Url>,
    method: Method, // One of POST or GET
}

impl Default for Client {
    fn default() -> Self {
        Client {
            servers: Vec::default(),
            method: Method::GET,
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
    pub fn new<A: ToUrls>(servers: A, method: Method) -> Result<Self, crate::Error> {
        match method {
            Method::GET | Method::POST => (), // Nothing,
            _ => bail!(InvalidInput, "only GET and POST allowed"),
        }

        Ok(Self {
            servers: servers.to_urls()?.collect(),
            method,
        })
    }
}

#[async_trait]
impl AsyncExchanger for Client {
    /// Sends the [`Message`] to the `server` via HTTP and returns the result.
    // TODO Decide if this should be async or not.
    // Can return ::std::io::Error
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        let mut query = query.clone();
        query.id = 0;

        let p = query.to_vec()?;

        // Create a Alpn client, so our connection will upgrade to HTTP/2.
        // TODO Move the client into the struct/new()
        // TODO Change the Connector Connect method to allow us to override the DNS
        // resolution in the connector!
        let alpn = AlpnConnector::new();

        let client = HyperClient::builder()
            .pool_idle_timeout(Duration::from_secs(30))
            .http2_only(true) // TODO POST stop working when this is false. Figure that out.
            .build::<_, hyper::Body>(alpn);

        // Base request common to both GET and POST
        let req = Request::builder()
            .method(&self.method)
            .header(ACCEPT, CONTENT_TYPE_APPLICATION_DNS_MESSAGE);

        let req = match self.method {
            Method::GET => {
                // Encode the message as a base64 string
                let mut buf = String::new();
                base64::encode_config_buf(p, base64::URL_SAFE_NO_PAD, &mut buf);

                // and add to the query params.
                let mut url = self.servers[0].clone(); // TODO Support more than one server
                url.query_pairs_mut().append_pair(DNS_QUERY_PARAM, &buf);

                // We have to do this wierd as_str().parse() thing because the
                // http::Uri doesn't provide a way to easily mutate or construct it.
                let uri: hyper::Uri = url.as_str().parse()?;
                req.uri(uri).body(Body::empty())
            }
            Method::POST => {
                req.uri(self.servers[0].as_str()) // TODO Support more than one server
                    .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_DNS_MESSAGE)
                    .body(Body::from(p)) // content-length header will be added.
            }
            _ => bail!(InvalidInput, "only GET and POST allowed"),
        };

        let stats = StatsBuilder::start(0);

        let resp = client.request(req.unwrap()).await?;
        // TODO This media type restricts the maximum size of the DNS message to 65535 bytes

        if let Some(content_type) = resp.headers().get(CONTENT_TYPE) {
            if !content_type_equal(content_type, CONTENT_TYPE_APPLICATION_DNS_MESSAGE) {
                bail!(
                    InvalidData,
                    "recevied invalid content-type: {:?} expected {}",
                    content_type,
                    CONTENT_TYPE_APPLICATION_DNS_MESSAGE,
                );
            }
        }

        if resp.status().is_success() {
            // TODO check Content-Length, but don't allow us to consume a body longer than 65535 bytes!

            // Get connection information (if available)
            let remote_addr = match resp.extensions().get::<HttpInfo>() {
                Some(http_info) => http_info.remote_addr(),

                // TODO Maybe remote_addr should be optional?
                None => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0), // Dummy address
            };

            // Read the full body
            let body = hyper::body::to_bytes(resp.into_body()).await?;

            let mut m = Message::from_slice(&body)?;
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
