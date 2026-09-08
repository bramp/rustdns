use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustdns::Message;
use rustdns::clients::doh::{CONTENT_TYPE_APPLICATION_DNS_MESSAGE, DNS_QUERY_PARAM};
use rustdns::clients::json::CONTENT_TYPE_APPLICATION_DNS_JSON;
use rustdns::clients::{AsyncExchanger, WireResponse, WireResponseMeta};
use rustdns::types::ChannelSecurity;
use std::sync::Arc;
use std::time::Duration;

/// HTTP method used for DNS-over-HTTPS (DoH, RFC 8484) requests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DohMethod {
    /// HTTP POST with `application/dns-message` request body.
    #[default]
    Post,
    /// HTTP GET with base64url-encoded `?dns=...` query parameter per RFC 8484 §4.1.
    Get,
}

/// An in-browser DNS-over-HTTPS (DoH, RFC 8484) client implementing [`AsyncExchanger`].
pub struct BrowserDohClient {
    endpoint: Arc<str>,
    method: DohMethod,
}

impl BrowserDohClient {
    /// Creates a new [`BrowserDohClient`] targeting the given HTTPS endpoint URL using POST.
    pub fn new(url: impl Into<Arc<str>>) -> Self {
        Self {
            endpoint: url.into(),
            method: DohMethod::Post,
        }
    }

    /// Creates a new [`BrowserDohClient`] targeting the given HTTPS endpoint URL with the specified [`DohMethod`].
    pub fn new_with_method(url: impl Into<Arc<str>>, method: DohMethod) -> Self {
        Self {
            endpoint: url.into(),
            method,
        }
    }
}

#[async_trait]
impl AsyncExchanger for BrowserDohClient {
    async fn exchange(&self, query: &Message) -> Result<WireResponse, rustdns::Error> {
        let mut query = query.clone();
        // RFC 8484 §4.1: "In order to maximize HTTP cache friendliness, DoH clients using media
        // formats that include the ID field SHOULD use a query ID of 0, but in all cases MUST
        // be prepared to receive a response that contains a different ID."
        query.id = 0;

        let wire_query = query.to_vec()?;

        SendWrapper(async move {
            let start = now_millis();
            let (resp_bytes, bytes_sent) = match self.method {
                DohMethod::Post => {
                    let (bytes, _status) = crate::fetch::fetch_binary(
                        &self.endpoint,
                        &[
                            ("Content-Type", CONTENT_TYPE_APPLICATION_DNS_MESSAGE),
                            ("Accept", CONTENT_TYPE_APPLICATION_DNS_MESSAGE),
                        ],
                        Some(&wire_query),
                    )
                    .await
                    .map_err(|err| rustdns::Error::Io(std::io::Error::other(err)))?;
                    (bytes, wire_query.len())
                }
                DohMethod::Get => {
                    let encoded = URL_SAFE_NO_PAD.encode(&wire_query);
                    let separator = if self.endpoint.contains('?') {
                        '&'
                    } else {
                        '?'
                    };
                    let url = format!("{}{}{DNS_QUERY_PARAM}={encoded}", self.endpoint, separator);
                    let (bytes, _status) = crate::fetch::fetch_binary(
                        &url,
                        &[("Accept", CONTENT_TYPE_APPLICATION_DNS_MESSAGE)],
                        None,
                    )
                    .await
                    .map_err(|err| rustdns::Error::Io(std::io::Error::other(err)))?;
                    (bytes, url.len())
                }
            };

            let elapsed = Duration::from_secs_f64(((now_millis() - start).max(0.0)) / 1000.0);
            let message = Message::from_slice(&resp_bytes)?;

            let meta = WireResponseMeta {
                server: None,
                elapsed,
                bytes_sent,
                bytes_received: resp_bytes.len(),
                channel_security: ChannelSecurity::Encrypted,
                tls_info: None,
            };

            Ok(WireResponse::new(message, meta))
        })
        .await
    }

    fn endpoint(&self) -> Arc<str> {
        Arc::clone(&self.endpoint)
    }

    fn channel_security(&self) -> ChannelSecurity {
        ChannelSecurity::Encrypted
    }
}

/// An in-browser DNS-over-HTTPS JSON client implementing [`AsyncExchanger`].
///
/// Compatible with Google and Cloudflare DNS-over-HTTPS JSON APIs.
pub struct BrowserJsonClient {
    endpoint: Arc<str>,
}

impl BrowserJsonClient {
    /// Creates a new [`BrowserJsonClient`] targeting the given JSON endpoint URL.
    pub fn new(url: impl Into<Arc<str>>) -> Self {
        Self {
            endpoint: url.into(),
        }
    }
}

#[async_trait]
impl AsyncExchanger for BrowserJsonClient {
    async fn exchange(&self, query: &Message) -> Result<WireResponse, rustdns::Error> {
        if query.questions.len() != 1 {
            return Err(rustdns::Error::InvalidArgument(
                "expected exactly one question for JSON DoH".to_string(),
            ));
        }

        let question = query.questions.first().ok_or_else(|| {
            rustdns::Error::InvalidArgument("query must have a question".to_string())
        })?;

        let domain = question.ascii_name()?;
        let rtype = question.r#type.to_string();

        let separator = if self.endpoint.contains('?') {
            "&"
        } else {
            "?"
        };
        let mut url = format!(
            "{}{}name={}&type={}&cd={}&ct={CONTENT_TYPE_APPLICATION_DNS_JSON}",
            self.endpoint, separator, domain, rtype, query.cd
        );

        if let Some(extension) = &query.extension {
            url.push_str(&format!("&do={}", extension.dnssec_ok));
        }

        SendWrapper(async move {
            let start = now_millis();
            let (json_text, _status) =
                crate::fetch::fetch_text(&url, &[("Accept", CONTENT_TYPE_APPLICATION_DNS_JSON)])
                    .await
                    .map_err(|err| rustdns::Error::Io(std::io::Error::other(err)))?;

            let elapsed = Duration::from_secs_f64(((now_millis() - start).max(0.0)) / 1000.0);
            let message: Message = rustdns::json::from_str(&json_text)?;

            let meta = WireResponseMeta {
                server: None,
                elapsed,
                bytes_sent: url.len(),
                bytes_received: json_text.len(),
                channel_security: ChannelSecurity::Encrypted,
                tls_info: None,
            };

            Ok(WireResponse::new(message, meta))
        })
        .await
    }

    fn endpoint(&self) -> Arc<str> {
        Arc::clone(&self.endpoint)
    }

    fn channel_security(&self) -> ChannelSecurity {
        ChannelSecurity::Encrypted
    }
}

/// An enum representing the available in-browser DNS transports without dynamic dispatch.
pub enum BrowserClient {
    /// DNS-over-HTTPS (RFC 8484 binary wire format).
    Doh(BrowserDohClient),
    /// DNS-over-HTTPS JSON API format (Google / Cloudflare).
    Json(BrowserJsonClient),
}

impl BrowserClient {
    /// Creates a [`BrowserClient`] according to `protocol` ("doh", "doh-post", "doh-get", or "json") targeting `server`.
    pub fn try_new(protocol: &str, server: impl Into<Arc<str>>) -> Result<Self, String> {
        match protocol.to_lowercase().as_str() {
            "doh" | "doh-post" | "rfc8484" | "wire" => Ok(Self::Doh(BrowserDohClient::new(server))),
            "doh-get" => Ok(Self::Doh(BrowserDohClient::new_with_method(
                server,
                DohMethod::Get,
            ))),
            "json" | "doh-json" => Ok(Self::Json(BrowserJsonClient::new(server))),
            _ => Err(format!(
                "unsupported protocol '{protocol}': must be 'doh', 'doh-get', or 'json'"
            )),
        }
    }
}

#[async_trait]
impl AsyncExchanger for BrowserClient {
    async fn exchange(&self, query: &Message) -> Result<WireResponse, rustdns::Error> {
        match self {
            Self::Doh(client) => client.exchange(query).await,
            Self::Json(client) => client.exchange(query).await,
        }
    }

    fn endpoint(&self) -> Arc<str> {
        match self {
            Self::Doh(client) => client.endpoint(),
            Self::Json(client) => client.endpoint(),
        }
    }

    fn channel_security(&self) -> ChannelSecurity {
        match self {
            Self::Doh(client) => client.channel_security(),
            Self::Json(client) => client.channel_security(),
        }
    }
}

struct SendWrapper<F>(F);

unsafe impl<F> Send for SendWrapper<F> {}

impl<F: std::future::Future> std::future::Future for SendWrapper<F> {
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // SAFETY: Pin-projection to the inner future.
        unsafe { self.map_unchecked_mut(|s| &mut s.0).poll(cx) }
    }
}

fn now_millis() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0)
}
