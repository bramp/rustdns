// Simple dig style command line.
// rustdns {record} {domain}
mod util;

use http::method::Method;
use rustdns::clients::Exchanger;
use rustdns::clients::*;
use rustdns::types::*;
use std::env;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::process;
use std::str::FromStr;
use std::fmt;
use std::io;
use std::vec;
use strum_macros::{Display, EnumString};
use url::Url;

#[macro_use] extern crate pretty_assertions;

#[derive(Display, EnumString, PartialEq)]
enum Client {
    Udp,
    Tcp,
    DoH,
}

// A simple type alias so as to DRY.
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Args {
    client: Client,
    servers: Vec<String>,

    /// Query this types
    r#type: rustdns::Type,

    /// Across all these domains
    domains: Vec<String>,
}

#[derive(Debug)]
struct ArgParseError {
    details: String,
}

impl fmt::Display for ArgParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}", self.details)
    }
}

impl std::error::Error for ArgParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}



/// Parses a string into a SocketAddr allowing for the port to be missing.
fn sockaddr_parse_with_port(addr: &str, default_port: u16) -> io::Result<vec::IntoIter<SocketAddr>> {
    match addr.to_socket_addrs() {
        // Try parsing again, with the default port.
        Err(_e) => (addr, default_port).to_socket_addrs(),
        Ok(addrs) => Ok(addrs),
    }
}

impl Args {
    /// Helper function to return the list of servers as a `Vec[SocketAddr]`.
    fn servers_to_sockaddrs(
        &self,
        default_port: u16
    ) -> std::result::Result<Vec<SocketAddr>, ArgParseError> {
        Ok(self.servers.iter().map(|addr| {
            // Each address could be invalid, or return multiple SocketAddr.
            match sockaddr_parse_with_port(addr, default_port) {
                Err(e) => Err(ArgParseError{
                    details: format!("failed to parse '{}': {}", addr, e),
                }),
                Ok(addrs) => Ok(addrs),
            }
        }).collect::<std::result::Result<Vec<_>, _>>()?

        // We now have a collection of vec::IntoIter<SocketAddr>, flatten.
        // We would use .flat_map(), but it doesn't handle the Error case :(
        .into_iter()
        .flatten()
        .collect())
    }

    /// Helper function to return the list of servers as a `Vec[Url]`.
    fn servers_to_urls(&self) -> std::result::Result<Vec<Url>, url::ParseError> {
        self.servers.iter().map(|x| x.parse()).collect()
    }
}

impl Default for Args {
    fn default() -> Self {
        Args {
            client: Client::Udp,
            servers: Vec::new(),

            r#type: Type::A,
            domains: Vec::new(),
        }
    }
}


#[test]
fn test_servers_to_sockaddrs() {
    let mut a = Args::default();
    a.servers.push("1.2.3.4".to_string());         // This requires using the default port.
    a.servers.push("aaaaa.bramp.net".to_string()); // This resolves to two records.
    a.servers.push("5.6.7.8:453".to_string());     // This uses a different port.

    // This test may be flakly, if it is running in an environment that doesn't
    // have both IPv4 and IPv6, and has DNS queries that can fail.
    // TODO Figure out a way to make this more robust.
    let mut addrs = a.servers_to_sockaddrs(53).expect("resolution failed");
    let mut want = vec![
        "1.2.3.4:53".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        "[::1]:53".parse().unwrap(),
        "5.6.7.8:453".parse().unwrap(),
    ];

    // Sort because [::1]:53 or  127.0.0.1:53 may switch places.
    addrs.sort();
    want.sort();

    assert_eq!(addrs, want);
}


fn parse_args(args: impl Iterator<Item = String>) -> Result<Args> {
    let mut result = Args::default();
    let mut type_or_domain = Vec::<String>::new();

    for arg in args {
        match arg.as_str() {
            "+udp" => result.client = Client::Udp,
            "+tcp" => result.client = Client::Tcp,
            "+doh" => result.client = Client::DoH,

            _ => {
                if arg.starts_with('+') {
                    return Err(format!("Unknown flag: {}", arg).into());
                }

                if arg.starts_with('@') {
                    result
                        .servers
                        .push(arg.strip_prefix("@").unwrap().to_string()) // Unwrap should not panic
                } else {
                    type_or_domain.push(arg)
                }
            }
        }
    }

    let mut found_type = false;

    // To be useful, we allow users to say `dig A bramp.net` or `dig bramp.net A`
    for arg in type_or_domain {
        if !found_type {
            // Use the first type we found and assume the rest are domains.
            if let Ok(r#type) = Type::from_str(&arg) {
                result.r#type = r#type;
                found_type = true;
                continue;
            }
        }

        result.domains.push(arg)
    }

    if result.domains.is_empty() {
        // By default query the root domain
        result.domains.push(".".to_string());
        if !found_type {
            result.r#type = Type::NS;
        }
    }

    if result.servers.is_empty() {
        // TODO If no servers are provided determine the local server (from /etc/nslookup.conf for example)
        eprintln!(";; No servers specified, using Google's DNS servers");
        match result.client {
            Client::Udp | Client::Tcp => {
                result.servers.push("8.8.8.8".to_string());
                result.servers.push("8.8.4.4".to_string());
                result.servers.push("2001:4860:4860::8888".to_string());
                result.servers.push("2001:4860:4860::8844".to_string());
            }
            Client::DoH => result
                .servers
                .push("https://dns.google/dns-query".to_string()),
        }

        /*
        // TODO Create a function that returns the appropriate ones from this list:

        Cisco OpenDNS:
            208.67.222.222 and 208.67.220.220; TCP/UDP
            https://doh.opendns.com/dns-query

        Cloudflare:
            1.1.1.1 and 1.0.0.1;
            2606:4700:4700::1111
            2606:4700:4700::1001
            https://cloudflare-dns.com/dns-query

        Google Public DNS:
            8.8.8.8 and 8.8.4.4; and
            2001:4860:4860::8888
            2001:4860:4860::8844
            https://dns.google/dns-query

        Quad9: 9.9.9.9 and 149.112.112.112.
            2620:fe::fe
            2620:fe::9
            https://dns.quad9.net/dns-query
            tls://dns.quad9.net
        */
    }

    Ok(result)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = match parse_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!("Usage: dig [@server] {{domain}} {{type}}");
            process::exit(1);
        }
    };

    let mut query = Message::default();

    for domain in &args.domains {
        query.add_question(&domain, args.r#type, Class::Internet);
    }
    query.add_extension(Extension {
        payload_size: 4096,

        ..Default::default()
    });

    println!("query:");
    util::hexdump(&query.to_vec().expect("failed to encode the query"));
    println!();
    println!("{}", query);

    // TODO make all DNS client implement a Exchange trait
    let resp = match args.client {
        Client::Udp => UdpClient::new(args.servers_to_sockaddrs(53)?.as_slice())?
            .exchange(&query)
            .expect("could not exchange message"),

        Client::Tcp => TcpClient::new(args.servers_to_sockaddrs(53)?.as_slice())?
            .exchange(&query)
            .expect("could not exchange message"),

        Client::DoH => DoHClient::new(args.servers_to_urls()?.as_slice(), Method::GET)?
            .exchange(&query)
            .await
            .expect("could not exchange message"),
    };

    println!("response:");
    println!("{}", resp);

    Ok(())
}
