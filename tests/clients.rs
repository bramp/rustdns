#[cfg(any(
    feature = "doh",
    feature = "dot",
    feature = "doh-json",
    feature = "sync"
))]
mod tests {
    #[cfg(feature = "doh")]
    use http::Method;
    #[cfg(all(feature = "sync", feature = "do53"))]
    use rustdns::Message;
    #[cfg(all(feature = "sync", feature = "do53"))]
    use rustdns::clients::Exchanger;
    #[cfg(all(feature = "sync", feature = "do53"))]
    use std::io::{Read, Write};
    #[cfg(all(feature = "sync", feature = "do53"))]
    use std::net::TcpListener;
    #[cfg(all(feature = "sync", feature = "do53"))]
    use std::net::UdpSocket;
    #[cfg(all(feature = "sync", feature = "do53"))]
    use std::thread;

    #[cfg(all(feature = "sync", feature = "do53"))]
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

        let client = rustdns::clients::sync::udp::Client::new(address);

        assert!(client.exchange(&Message::default()).is_err());
        handle.join().expect("join UDP test server");
    }

    #[cfg(all(feature = "sync", feature = "do53"))]
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

        let client = rustdns::clients::sync::tcp::Client::new(address);

        assert!(client.exchange(&Message::default()).is_err());
        server.join().expect("join TCP test server");
    }

    #[cfg(all(feature = "sync", feature = "dot"))]
    #[test]
    fn dot_client_requires_tls_server_name_for_ip_addresses() {
        assert!(rustdns::clients::sync::dot::Client::try_from_host_port("127.0.0.1:853").is_err());
        assert!(
            rustdns::clients::sync::dot::Client::try_new(
                "dns.google",
                "127.0.0.1:853".parse().unwrap()
            )
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

    #[cfg(feature = "doh-json")]
    #[test]
    fn json_client_rejects_plaintext_servers() {
        assert!(rustdns::clients::json::Client::new("http://example.com/dns-query").is_err());
    }

    #[cfg(all(feature = "sync", feature = "do53"))]
    #[test]
    fn sync_clients_report_endpoints() {
        let addr = "127.0.0.1:53".parse().unwrap();
        let udp = rustdns::clients::sync::udp::Client::new(addr);
        assert_eq!(&*udp.endpoint(), "udp://127.0.0.1:53");

        let tcp = rustdns::clients::sync::tcp::Client::new(addr);
        assert_eq!(&*tcp.endpoint(), "tcp://127.0.0.1:53");

        let do53 = rustdns::clients::sync::do53::Client::new(addr);
        assert_eq!(&*do53.endpoint(), "dns://127.0.0.1:53");
    }

    #[cfg(all(feature = "sync", feature = "dot"))]
    #[test]
    fn sync_dot_client_reports_endpoint() {
        let addr = "127.0.0.1:853".parse().unwrap();
        let dot = rustdns::clients::sync::dot::Client::try_new("dns.google", addr).unwrap();
        assert_eq!(&*dot.endpoint(), "tls://dns.google:853");
    }

    #[test]
    fn channel_security_and_is_secure_channel_across_clients() {
        use rustdns::clients::AsyncExchanger;
        use rustdns::types::ChannelSecurity;

        let loopback_v4 = "127.0.0.1:53".parse().unwrap();
        let loopback_v6 = "[::1]:53".parse().unwrap();
        let remote_v4 = "8.8.8.8:53".parse().unwrap();
        let remote_v6 = "[2001:4860:4860::8888]:53".parse().unwrap();

        #[cfg(feature = "do53")]
        {
            // Async UDP
            let udp_local = rustdns::clients::udp::Client::new(loopback_v4);
            assert_eq!(udp_local.channel_security(), ChannelSecurity::Loopback);
            assert!(udp_local.is_secure_channel());

            let udp_remote = rustdns::clients::udp::Client::new(remote_v4);
            assert_eq!(udp_remote.channel_security(), ChannelSecurity::Insecure);
            assert!(!udp_remote.is_secure_channel());

            // Async TCP
            let tcp_local = rustdns::clients::tcp::Client::new(loopback_v6);
            assert_eq!(tcp_local.channel_security(), ChannelSecurity::Loopback);
            assert!(tcp_local.is_secure_channel());

            let tcp_remote = rustdns::clients::tcp::Client::new(remote_v6);
            assert_eq!(tcp_remote.channel_security(), ChannelSecurity::Insecure);
            assert!(!tcp_remote.is_secure_channel());

            // Async Do53
            let do53_local = rustdns::clients::do53::Client::new(loopback_v4);
            assert_eq!(do53_local.channel_security(), ChannelSecurity::Loopback);
            assert!(do53_local.is_secure_channel());

            let do53_remote = rustdns::clients::do53::Client::new(remote_v4);
            assert_eq!(do53_remote.channel_security(), ChannelSecurity::Insecure);
            assert!(!do53_remote.is_secure_channel());
        }

        #[cfg(all(feature = "sync", feature = "do53"))]
        {
            use rustdns::clients::Exchanger;

            // Sync UDP
            let sync_udp_local = rustdns::clients::sync::udp::Client::new(loopback_v4);
            assert_eq!(sync_udp_local.channel_security(), ChannelSecurity::Loopback);
            assert!(sync_udp_local.is_secure_channel());

            let sync_udp_remote = rustdns::clients::sync::udp::Client::new(remote_v4);
            assert_eq!(
                sync_udp_remote.channel_security(),
                ChannelSecurity::Insecure
            );
            assert!(!sync_udp_remote.is_secure_channel());

            // Sync TCP
            let sync_tcp_local = rustdns::clients::sync::tcp::Client::new(loopback_v6);
            assert_eq!(sync_tcp_local.channel_security(), ChannelSecurity::Loopback);
            assert!(sync_tcp_local.is_secure_channel());

            let sync_tcp_remote = rustdns::clients::sync::tcp::Client::new(remote_v6);
            assert_eq!(
                sync_tcp_remote.channel_security(),
                ChannelSecurity::Insecure
            );
            assert!(!sync_tcp_remote.is_secure_channel());

            // Sync Do53
            let sync_do53_local = rustdns::clients::sync::do53::Client::new(loopback_v4);
            assert_eq!(
                sync_do53_local.channel_security(),
                ChannelSecurity::Loopback
            );
            assert!(sync_do53_local.is_secure_channel());

            let sync_do53_remote = rustdns::clients::sync::do53::Client::new(remote_v4);
            assert_eq!(
                sync_do53_remote.channel_security(),
                ChannelSecurity::Insecure
            );
            assert!(!sync_do53_remote.is_secure_channel());
        }

        #[cfg(feature = "dot")]
        {
            let dot = rustdns::clients::dot::Client::try_new(
                "dns.google",
                "8.8.8.8:853".parse().unwrap(),
            )
            .unwrap();
            assert_eq!(dot.channel_security(), ChannelSecurity::Encrypted);
            assert!(dot.is_secure_channel());
        }

        #[cfg(all(feature = "sync", feature = "dot"))]
        {
            use rustdns::clients::Exchanger;
            let sync_dot = rustdns::clients::sync::dot::Client::try_new(
                "dns.google",
                "8.8.8.8:853".parse().unwrap(),
            )
            .unwrap();
            assert_eq!(sync_dot.channel_security(), ChannelSecurity::Encrypted);
            assert!(sync_dot.is_secure_channel());
        }

        #[cfg(feature = "doh")]
        {
            let doh =
                rustdns::clients::doh::Client::new("https://dns.google/dns-query", Method::POST)
                    .unwrap();
            assert_eq!(doh.channel_security(), ChannelSecurity::Encrypted);
            assert!(doh.is_secure_channel());
        }

        #[cfg(feature = "doh-json")]
        {
            let json = rustdns::clients::json::Client::new("https://dns.google/resolve").unwrap();
            assert_eq!(json.channel_security(), ChannelSecurity::Encrypted);
            assert!(json.is_secure_channel());
        }
    }
}
