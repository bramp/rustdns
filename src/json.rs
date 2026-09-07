//! DNS-over-HTTPS JSON parsing and serialization (Google / Cloudflare format).
//!
//! This module provides pure serialization and deserialization between DNS [`Message`]
//! instances and the JSON schema defined by public DoH providers (Google, Cloudflare).
//!
//! It has zero networking or asynchronous runtime dependencies and is fully compatible with
//! WebAssembly (`wasm32-unknown-unknown`, `wasm32-wasip1`).
//!
//! # Example
//!
//! ```rust
//! use rustdns::json;
//!
//! let response_json = r#"{
//!   "Status": 0,
//!   "TC": false,
//!   "RD": true,
//!   "RA": true,
//!   "AD": false,
//!   "CD": false,
//!   "Question": [
//!     {
//!       "name": "example.com.",
//!       "type": 1
//!     }
//!   ],
//!   "Answer": [
//!     {
//!       "name": "example.com.",
//!       "type": 1,
//!       "TTL": 300,
//!       "data": "93.184.216.34"
//!     }
//!   ]
//! }"#;
//!
//! let message = json::from_str(response_json).expect("valid DNS JSON");
//! assert_eq!(message.answers.len(), 1);
//! ```

use crate::Class;
use crate::Message;
use crate::Opcode;
use crate::QR;
use crate::Question;
use crate::Record;
use crate::Resource;
use crate::errors::JsonError;
use core::convert::TryInto;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Media type for DNS-over-HTTPS JSON API requests and responses (used by Cloudflare and other DoH providers).
pub const CONTENT_TYPE_APPLICATION_DNS_JSON: &str = "application/dns-json";

/// Media type for standard JSON responses (used by Google Public DNS).
pub const CONTENT_TYPE_APPLICATION_JSON: &str = "application/json";

/// An intermediate representation of a DNS message serialized as JSON.
///
/// See the specifications and documentation provided by:
/// - [Google Public DNS DoH JSON API](https://developers.google.com/speed/public-dns/docs/doh/json)
/// - [Cloudflare 1.1.1.1 DNS over HTTPS JSON API](https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests/dns-json/)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageJson {
    /// Standard DNS response code (32-bit integer).
    pub status: u32,

    /// Whether the response was truncated (`TC` bit).
    #[serde(rename = "TC", default)]
    pub tc: bool,

    /// Recursion Desired (`RD` bit).
    #[serde(rename = "RD", default)]
    pub rd: bool,

    /// Recursion Available (`RA` bit).
    #[serde(rename = "RA", default)]
    pub ra: bool,

    /// Authentic Data (`AD` bit, DNSSEC validated).
    #[serde(rename = "AD", default)]
    pub ad: bool,

    /// Checking Disabled (`CD` bit).
    #[serde(rename = "CD", default)]
    pub cd: bool,

    /// List of question entries.
    #[serde(default)]
    pub question: Vec<QuestionJson>,

    /// List of answer records.
    #[serde(default)]
    pub answer: Vec<RecordJson>,

    /// List of authority records.
    #[serde(default)]
    pub authority: Vec<RecordJson>,

    /// List of additional records.
    #[serde(default)]
    pub additional: Vec<RecordJson>,

    /// Optional comment returned by the upstream provider.
    #[serde(default)]
    pub comment: Option<String>,

    /// Optional EDNS client subnet address and scope prefix length.
    #[serde(rename = "edns_client_subnet", default)]
    pub edns_client_subnet: Option<String>,
}

impl TryFrom<MessageJson> for Message {
    type Error = JsonError;

    fn try_from(val: MessageJson) -> Result<Self, Self::Error> {
        let rcode =
            FromPrimitive::from_u32(val.status).ok_or(JsonError::InvalidStatus(val.status))?;

        // Note: Construct fields explicitly rather than using Default::default()
        // so we never invoke rand::rng() on bare wasm32-unknown-unknown targets.
        let mut m = Message {
            id: 0,
            qr: QR::Response,
            opcode: Opcode::Query,
            aa: false,
            tc: val.tc,
            rd: val.rd,
            ra: val.ra,
            z: false,
            ad: val.ad,
            cd: val.cd,
            rcode,

            questions: Vec::with_capacity(val.question.len()),
            answers: Vec::with_capacity(val.answer.len()),
            authoritys: Vec::with_capacity(val.authority.len()),
            additionals: Vec::with_capacity(val.additional.len()),
            extension: None,
        };

        for question in val.question {
            m.questions.push(question.try_into()?);
        }

        for answer in val.answer {
            m.answers.push(answer.try_into()?);
        }

        for authority in val.authority {
            m.authoritys.push(authority.try_into()?);
        }

        for additional in val.additional {
            m.additionals.push(additional.try_into()?);
        }

        Ok(m)
    }
}

impl TryFrom<&Message> for MessageJson {
    type Error = JsonError;

    fn try_from(msg: &Message) -> Result<Self, Self::Error> {
        let mut question = Vec::with_capacity(msg.questions.len());
        for q in &msg.questions {
            question.push(QuestionJson {
                name: q.name.clone(),
                r#type: q.r#type as u16,
            });
        }

        let mut answer = Vec::with_capacity(msg.answers.len());
        for a in &msg.answers {
            answer.push(RecordJson {
                name: a.name.clone(),
                r#type: a.resource.r#type() as u16,
                ttl: a.ttl.as_secs().min(u32::MAX as u64) as u32,
                data: a.resource.to_string(),
            });
        }

        let mut authority = Vec::with_capacity(msg.authoritys.len());
        for auth in &msg.authoritys {
            authority.push(RecordJson {
                name: auth.name.clone(),
                r#type: auth.resource.r#type() as u16,
                ttl: auth.ttl.as_secs().min(u32::MAX as u64) as u32,
                data: auth.resource.to_string(),
            });
        }

        let mut additional = Vec::with_capacity(msg.additionals.len());
        for add in &msg.additionals {
            additional.push(RecordJson {
                name: add.name.clone(),
                r#type: add.resource.r#type() as u16,
                ttl: add.ttl.as_secs().min(u32::MAX as u64) as u32,
                data: add.resource.to_string(),
            });
        }

        Ok(MessageJson {
            status: msg.rcode as u32,
            tc: msg.tc,
            rd: msg.rd,
            ra: msg.ra,
            ad: msg.ad,
            cd: msg.cd,
            question,
            answer,
            authority,
            additional,
            comment: None,
            edns_client_subnet: None,
        })
    }
}

/// A DNS question serialized in JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct QuestionJson {
    /// FQDN name.
    pub name: String,
    /// Standard DNS RR type integer code.
    pub r#type: u16,
}

impl TryInto<Question> for QuestionJson {
    type Error = JsonError;

    fn try_into(self) -> Result<Question, Self::Error> {
        let r#type =
            FromPrimitive::from_u16(self.r#type).ok_or(JsonError::InvalidType(self.r#type))?;

        Ok(Question {
            name: self.name,
            r#type,
            class: Class::Internet,
        })
    }
}

/// A DNS resource record serialized in JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct RecordJson {
    /// Owner domain name.
    pub name: String,
    /// Standard DNS RR type integer code.
    pub r#type: u16,

    /// Time to live in seconds.
    #[serde(rename = "TTL")]
    pub ttl: u32,

    /// Resource record data formatted as text.
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
            name: self.name,
            class: Class::Internet,
            ttl: Duration::from_secs(self.ttl.into()),
            resource,
        })
    }
}

/// Decodes a DNS-over-HTTPS JSON response body into a [`Message`].
///
/// Works on any platform, including WebAssembly (`wasm32-unknown-unknown`),
/// with zero network or asynchronous runtime dependencies.
///
/// # Errors
///
/// Returns [`JsonError`] if the data cannot be parsed as valid DNS JSON.
pub fn from_slice(body: &[u8]) -> Result<Message, JsonError> {
    let m: MessageJson = serde_json::from_slice(body)?;
    m.try_into()
}

/// Decodes a DNS-over-HTTPS JSON response string into a [`Message`].
///
/// # Errors
///
/// Returns [`JsonError`] if the data cannot be parsed as valid DNS JSON.
pub fn from_str(s: &str) -> Result<Message, JsonError> {
    let m: MessageJson = serde_json::from_str(s)?;
    m.try_into()
}

/// Encodes a [`Message`] into a DNS-over-HTTPS JSON string.
///
/// # Errors
///
/// Returns [`JsonError`] if serialization fails.
pub fn to_string(message: &Message) -> Result<String, JsonError> {
    let m = MessageJson::try_from(message)?;
    serde_json::to_string(&m).map_err(JsonError::Serde)
}

/// Encodes a [`Message`] into a pretty-printed DNS-over-HTTPS JSON string.
///
/// # Errors
///
/// Returns [`JsonError`] if serialization fails.
pub fn to_string_pretty(message: &Message) -> Result<String, JsonError> {
    let m = MessageJson::try_from(message)?;
    serde_json::to_string_pretty(&m).map_err(JsonError::Serde)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rcode;
    use crate::Type;
    use json_comments::StripComments;
    use std::io::Read;

    #[test]
    fn test_parse_response() {
        let tests = [
            r#"{
          "Status": 0,
          "TC": false,
          "RD": true,
          "RA": true,
          "AD": false,
          "CD": false,
          "Question":
          [
            {
              "name": "apple.com.",
              "type": 1
            }
          ],
          "Answer":
          [
            {
              "name": "apple.com.",
              "type": 1,
              "TTL": 3599,
              "data": "17.178.96.59"
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
          "edns_client_subnet": "12.34.56.78/0"
        }"#,
            r#"{
          "Status": 2,
          "TC": false,
          "RD": true,
          "RA": true,
          "AD": false,
          "CD": false,
          "Question":
          [
            {
              "name": "dnssec-failed.org.",
              "type": 1
            }
          ],
          "Comment": "DNSSEC validation failure."
        }"#,
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
            let mut stripped = String::new();
            StripComments::new(test.as_bytes())
                .read_to_string(&mut stripped)
                .unwrap();

            let m = from_str(&stripped).expect("valid DNS message from JSON");
            assert_eq!(m.questions.len(), 1);
        }
    }

    #[test]
    fn test_round_trip_json() {
        let original_json = r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"apple.com.","type":1}],"Answer":[{"name":"apple.com.","type":1,"TTL":300,"data":"17.178.96.59"}],"Authority":[],"Additional":[],"Comment":null,"edns_client_subnet":null}"#;

        let msg = from_str(original_json).unwrap();
        assert_eq!(msg.rcode, Rcode::NoError);
        assert_eq!(msg.questions[0].name, "apple.com.");
        assert_eq!(msg.questions[0].r#type, Type::A);
        assert_eq!(msg.answers.len(), 1);

        let serialized = to_string(&msg).unwrap();
        let re_decoded = from_str(&serialized).unwrap();
        assert_eq!(msg.questions.len(), re_decoded.questions.len());
        assert_eq!(msg.answers.len(), re_decoded.answers.len());
    }
}
