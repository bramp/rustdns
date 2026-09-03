#[cfg(any(
    feature = "doh",
    feature = "dot",
    feature = "json",
    feature = "tcp",
    feature = "udp"
))]
mod tests {
    #[cfg(feature = "doh")]
    use http::Method;
    use rustdns::Message;
    #[cfg(any(feature = "tcp", feature = "udp"))]
    use rustdns::clients::Exchanger;
    #[cfg(feature = "tcp")]
    use std::io::{Read, Write};
    #[cfg(feature = "tcp")]
    use std::net::TcpListener;
    #[cfg(feature = "udp")]
    use std::net::UdpSocket;
    #[cfg(feature = "tcp")]
    use std::thread;

    #[cfg(feature = "udp")]
    #[test]
    fn udp_client_rejects_malformed_response() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind UDP test server");
        let address = server.local_addr().expect("read UDP test server address");
        let handle = thread::spawn(move || {
            let mut request = [0; 512];
            let (_, peer) = server.recv_from(&mut request).expect("read UDP request");
            server
                .send_to(&[0; 11], peer)
                .expect("write malformed UDP response");
        });

        let client = rustdns::clients::udp::Client::new(address).expect("create UDP client");

        assert!(client.exchange(&Message::default()).is_err());
        handle.join().expect("join UDP test server");
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn tcp_client_rejects_malformed_response_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP test listener");
        let address = listener
            .local_addr()
            .expect("read TCP test listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept TCP test connection");
            let mut request_length = [0; 2];
            stream
                .read_exact(&mut request_length)
                .expect("read TCP request length");
            let request_length = u16::from_be_bytes(request_length) as usize;
            let mut request = vec![0; request_length];
            stream.read_exact(&mut request).expect("read TCP request");
            stream
                .write_all(&11_u16.to_be_bytes())
                .expect("write TCP response length");
            stream
                .write_all(&[0; 11])
                .expect("write malformed TCP response");
        });

        let client = rustdns::clients::tcp::Client::new(address).expect("create TCP client");

        assert!(client.exchange(&Message::default()).is_err());
        server.join().expect("join TCP test server");
    }

    #[cfg(feature = "dot")]
    #[test]
    fn dot_client_requires_tls_server_name_for_ip_addresses() {
        assert!(rustdns::clients::dot::Client::new("127.0.0.1:853").is_err());
        assert!(
            rustdns::clients::dot::Client::new_with_server_name("dns.google", "127.0.0.1:853")
                .is_ok()
        );
    }

    #[cfg(feature = "doh")]
    #[test]
    fn doh_client_rejects_plaintext_servers() {
        assert!(
            rustdns::clients::doh::Client::new("http://example.com/dns-query", Method::GET)
                .is_err()
        );
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_client_rejects_plaintext_servers() {
        assert!(rustdns::clients::json::Client::new("http://example.com/dns-query").is_err());
    }
}
