//! Records the DNS exchanges made while answering one dig request.

use rustdns::Message;
use rustdns::clients::Response;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;
use wasm_bindgen::prelude::*;

/// One DNS exchange made while answering a dig request.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq)]
pub struct TraceEntry {
    /// Question name, class, and type, e.g. `example.com. IN DNSKEY`.
    #[wasm_bindgen(getter_with_clone)]
    pub question: String,
    /// DNSSEC-related query flags in dig syntax, e.g. `+dnssec +cd`.
    #[wasm_bindgen(getter_with_clone)]
    pub flags: String,
    /// One-line outcome, e.g. `NoError · 4 answers`, or the error message.
    #[wasm_bindgen(getter_with_clone)]
    pub summary: String,
    /// Full dig-style response, or the error message.
    #[wasm_bindgen(getter_with_clone)]
    pub detail: String,
    /// Whether the exchange failed without a response.
    pub failed: bool,
    /// Milliseconds from the start of the first exchange to the start of this one.
    pub start_ms: f64,
    /// Duration of this exchange in milliseconds.
    pub elapsed_ms: f64,
}

/// Thread-safe recorder of [`TraceEntry`] values, ordered by start time.
#[derive(Debug, Default)]
pub struct QueryTrace {
    entries: Mutex<Vec<(Duration, TraceEntry)>>,
}

impl QueryTrace {
    /// Records the exchange of `query` that started at the monotonic offset
    /// `started` and took `elapsed`, with its `result`.
    pub fn record(
        &self,
        query: &Message,
        started: Duration,
        elapsed: Duration,
        result: Result<&Response, &rustdns::Error>,
    ) {
        let (summary, detail, failed) = match result {
            Ok(response) => (summarize(&response.message), response.to_string(), false),
            Err(error) => (error.to_string(), error.to_string(), true),
        };
        let entry = TraceEntry {
            question: describe_question(query),
            flags: describe_flags(query),
            summary,
            detail,
            failed,
            start_ms: 0.0,
            elapsed_ms: elapsed.as_secs_f64() * 1_000.0,
        };
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((started, entry));
    }

    /// Removes and returns the recorded entries in start order, with
    /// [`TraceEntry::start_ms`] relative to the earliest exchange.
    pub fn take(&self) -> Vec<TraceEntry> {
        let mut entries =
            std::mem::take(&mut *self.entries.lock().unwrap_or_else(PoisonError::into_inner));
        entries.sort_by_key(|(started, _)| *started);
        let origin = entries.first().map(|(started, _)| *started);
        entries
            .into_iter()
            .map(|(started, mut entry)| {
                let offset = origin.map_or(Duration::ZERO, |origin| started.saturating_sub(origin));
                entry.start_ms = offset.as_secs_f64() * 1_000.0;
                entry
            })
            .collect()
    }
}

fn describe_question(query: &Message) -> String {
    query
        .questions
        .iter()
        .map(|q| format!("{} {} {}", q.name, q.class, q.r#type))
        .collect::<Vec<_>>()
        .join(", ")
}

fn describe_flags(query: &Message) -> String {
    let dnssec_ok = query.extension.as_ref().is_some_and(|e| e.dnssec_ok);
    [
        (dnssec_ok, "+dnssec"),
        (query.cd, "+cd"),
        (query.ad, "+adflag"),
    ]
    .into_iter()
    .filter_map(|(set, flag)| set.then_some(flag))
    .collect::<Vec<_>>()
    .join(" ")
}

fn summarize(message: &Message) -> String {
    let mut parts = vec![message.rcode.to_string()];
    match message.answers.len() {
        0 => {}
        1 => parts.push("1 answer".into()),
        count => parts.push(format!("{count} answers")),
    }
    if !message.authoritys.is_empty() {
        parts.push(format!("{} authority", message.authoritys.len()));
    }
    if message.ad {
        parts.push("AD".into());
    }
    parts.join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdns::Record;
    use rustdns::clients::ResponseMeta;
    use rustdns::types::{ChannelSecurity, Class, Extension, QR, Resource, SecurityStatus, Type};
    use std::time::SystemTime;

    fn query(name: &str, rtype: Type) -> Message {
        let mut query = Message {
            ad: false,
            ..Message::default()
        };
        query
            .try_add_question(name, rtype, Class::Internet)
            .unwrap();
        query
    }

    fn response_to(query: &Message) -> Response {
        let mut message = query.clone();
        message.qr = QR::Response;
        Response {
            message,
            meta: ResponseMeta {
                upstream: "https://dns.example/dns-query".into(),
                attempts: 1,
                elapsed: Duration::from_millis(5),
                when: SystemTime::UNIX_EPOCH,
                security_status: SecurityStatus::Insecure,
                channel_security: ChannelSecurity::Encrypted,
                wire: Vec::new(),
            },
        }
    }

    #[test]
    fn records_question_flags_and_summary() {
        let mut query = query("example.com", Type::DNSKEY);
        query.cd = true;
        query.set_extension(Extension {
            dnssec_ok: true,
            ..Default::default()
        });
        let mut response = response_to(&query);
        response.message.ad = true;
        response.message.answers = vec![
            Record::try_new(
                "example.com",
                Class::Internet,
                Duration::from_secs(60),
                Resource::A("192.0.2.1".parse().unwrap()),
            )
            .unwrap(),
        ];

        let trace = QueryTrace::default();
        trace.record(
            &query,
            Duration::from_millis(100),
            Duration::from_millis(7),
            Ok(&response),
        );
        let entries = trace.take();

        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.question, "example.com. IN DNSKEY");
        assert_eq!(entry.flags, "+dnssec +cd");
        assert_eq!(entry.summary, "NoError · 1 answer · AD");
        assert!(entry.detail.contains("192.0.2.1"));
        assert!(!entry.failed);
        assert_eq!(entry.start_ms, 0.0);
        assert_eq!(entry.elapsed_ms, 7.0);
    }

    #[test]
    fn orders_by_start_and_reports_relative_offsets() {
        let trace = QueryTrace::default();
        let ds = query("example.com", Type::DS);
        let failed = query("com", Type::DNSKEY);
        let error = rustdns::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        ));

        // Completion order differs from start order.
        trace.record(
            &failed,
            Duration::from_millis(30),
            Duration::from_millis(1),
            Err(&error),
        );
        trace.record(
            &ds,
            Duration::from_millis(10),
            Duration::from_millis(50),
            Ok(&response_to(&ds)),
        );

        let entries = trace.take();
        assert_eq!(entries[0].question, "example.com. IN DS");
        assert_eq!(entries[0].summary, "NoError");
        assert_eq!(entries[0].flags, "");
        assert_eq!(entries[1].question, "com. IN DNSKEY");
        assert!(entries[1].failed);
        assert!(entries[1].summary.contains("timed out"));
        assert_eq!(entries[1].start_ms, 20.0);
        assert!(trace.take().is_empty());
    }
}
