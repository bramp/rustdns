use crate::Message;
use hyper::{Body, Client};
use hyper_alpn::AlpnConnector;
use std::io;
use std::time::Duration;
use http::header::*;
use http::{Method, Request};
use url::Url;
use crate::bail;

// For use in Content-type and Accept headers
const CONTENT_TYPE_APPLICATION_DNS_MESSAGE: &str = "application/dns-message";

// The param name that contains the DNS request.
const DNS_QUERY_PARAM: &str = "dns";

/// A DNS over HTTPS (DoH) Client.
///
/// # Example
///
/// ```rust
/// use rustdns::types::*;
/// use rustdns::clients::DoHClient;
/// use std::io::Result;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let mut query = Message::default();
///     query.add_question("bramp.net", Type::A, Class::Internet);
///
///     let response = DoHClient::new("https://dns.google/dns-query")?
///        .exchange(&query)
///        .expect("could not exchange message");
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See <https://datatracker.ietf.org/doc/html/rfc8484>
// TODO Document all the options.
pub struct DoHClient {
    server: String,
    method: Method, // One of POST or GET
}

impl Default for DoHClient {
    fn default() -> Self {
        DoHClient {
            server: "".to_string(),
            method: Method::POST,
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl DoHClient {
    /// Creates a new DoHClient bound to the specific servers.
    // TODO Document how it fails.
    pub fn new(server: &str) -> io::Result<Self> {
        // https://dns.google/dns-query
        Ok(Self {
            server: server.to_string(),

            ..Default::default()
        })
    }

    /// Sends the [`Message`] to the `server` via TCP and returns the result.
    // TODO Decide if this should be async or not.
    // Can return ::std::io::Error
    pub async fn exchange(&self, query: &Message) -> Result<Message> {
        let mut query = query.clone();
        query.id = 0;

        let p = query.to_vec()?;

        //let https = HttpsConnector::new();
        //let https = hyper_rustls::HttpsConnector::with_native_roots();

        // Create a Alpn client, so our connection will upgrade to HTTP/2.
        // TODO Change the Connector Connect method to allow us to override the DNS
        // resolution in the connector!
        let alpn = AlpnConnector::new();

        let client = Client::builder()
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
                let mut url = Url::parse(&self.server)?;
                url.query_pairs_mut().append_pair(DNS_QUERY_PARAM, &buf);

                // We have to do this wierd as_str().parse() thing because the
                // http::Uri doesn't provide a way to easily mutate or construct it.
                let uri: hyper::Uri = url.as_str().parse()?;
                req.uri(uri).body(Body::empty())
            }
            Method::POST => {
                req.uri(&self.server)
                    .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_DNS_MESSAGE)
                    .body(Body::from(p)) // content-length header will be added.
            }
            _ => panic!("only GET and POST allowed"), // TODO Return a error!
        };

        let req = req.unwrap();
        // Await the response...
        let resp = client.request(req).await?;
        // TODO This media type restricts the maximum size of the DNS message to 65535 bytes

        if let Some(content_type) = resp.headers().get(CONTENT_TYPE) {
            if content_type != CONTENT_TYPE_APPLICATION_DNS_MESSAGE {
                bail!(InvalidInput, "recevied invalid content-type: {:?}", content_type);
            }
        }

        if resp.status().is_success() {
            // Read the full body
            let body = hyper::body::to_bytes(resp.into_body()).await?;

            let m = Message::from_slice(&body)?;
            return Ok(m)
        }

        // TODO Retry on 500s. If this is a 4xx we should not retry. Should we follow 3xx?
        bail!(InvalidInput, "recevied unexpected HTTP status code: {:}", resp.status());      
    }
}
