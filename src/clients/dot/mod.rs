//! DNS-over-TLS (DoT) client.

use crate::types::TlsInfo;

mod r#async;
pub use r#async::*;

#[cfg(feature = "sync")]
pub mod sync;

/// Extracts [`TlsInfo`] from an active TLS client connection.
///
/// Verifies whether TLS was negotiated by inspecting [`rustls::ClientConnection::protocol_version`].
/// Returns `None` if the TLS version has not been negotiated (e.g. handshake incomplete).
pub(crate) fn tls_info_from_connection(
    conn: &rustls::ClientConnection,
    server_name: Option<&str>,
) -> Option<TlsInfo> {
    let version = conn.protocol_version()?;
    let version_str = match version {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_1 => "TLSv1.1".to_string(),
        rustls::ProtocolVersion::TLSv1_0 => "TLSv1.0".to_string(),
        rustls::ProtocolVersion::SSLv3 => "SSLv3".to_string(),
        other => format!("{other:?}"),
    };

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));

    let alpn = conn
        .alpn_protocol()
        .and_then(|p| std::str::from_utf8(p).ok().map(|s| s.to_string()));

    Some(TlsInfo {
        version: version_str,
        cipher_suite,
        server_name: server_name.map(ToString::to_string),
        alpn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    #[test]
    fn unnegotiated_connection_returns_none() {
        let config = new_tls_config();
        let name = ServerName::try_from("dns.google".to_string()).unwrap();
        let conn = rustls::ClientConnection::new(config, name).unwrap();
        assert_eq!(tls_info_from_connection(&conn, Some("dns.google")), None);
    }
}
