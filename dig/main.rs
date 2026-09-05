// Simple dig style command line.
// rustdns {record} {domain}
mod util;

use http::method::Method;
use rustdns::clients::AsyncExchanger;
use rustdns::clients::Exchanger;
use rustdns::clients::doh::Client as DohClient;
use rustdns::clients::json::Client as JsonClient;
use rustdns::clients::sync::dot::Client as DotClient;
use rustdns::clients::sync::tcp::Client as TcpClient;
use rustdns::clients::sync::udp::Client as UdpClient;
use rustdns::types::*;
use std::convert::TryInto;
use std::env;
use std::io;
use std::io::Write as _;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::process;
use std::str::FromStr;
use std::time::Duration;
use std::vec;
use strum_macros::{Display, EnumString};
use thiserror::Error;
use url::Url;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[derive(Display, EnumString, PartialEq)]
enum Client {
    #[strum(serialize = "UDP")]
    Udp,
    #[strum(serialize = "TCP")]
    Tcp,
    #[strum(serialize = "DoT")]
    DoT,
    #[strum(serialize = "DoH")]
    DoH,
    #[strum(serialize = "JSON")]
    Json,
}

#[derive(Error, Debug)]
enum DigError {
    // A command line argument was bad.
    // TODO Could I replace ArgParseError with rustdns::Error::IllegalArgument?
    #[error("{0}")]
    ArgParseError(String),

    #[error(transparent)]
    RustDnsError(#[from] rustdns::Error),
}

struct Args {
    client: Client,
    servers: Vec<String>,
    verbose: bool,

    /// Query this types
    r#type: rustdns::Type,

    /// Across all these domains
    domains: Vec<String>,

    /// EDNS(0) options to include in the query.
    edns_options: Vec<EdnsOption>,
}

/// Parses a string into a SocketAddr allowing for the port to be missing.
fn sockaddr_parse_with_port(
    addr: &str,
    default_port: u16,
) -> io::Result<vec::IntoIter<SocketAddr>> {
    match addr.to_socket_addrs() {
        // Try parsing again, with the default port.
        Err(_e) => (addr, default_port).to_socket_addrs(),
        Ok(addrs) => Ok(addrs),
    }
}

/// Helper function to take a vector of domain/port numbers, and return (a possibly larger) `Vec[SocketAddr]`.
fn to_sockaddrs(
    servers: &[String],
    default_port: u16,
) -> std::result::Result<Vec<SocketAddr>, DigError> {
    Ok(servers
        .iter()
        .map(|addr| {
            // Each address could be invalid, or return multiple SocketAddr.
            match sockaddr_parse_with_port(addr, default_port) {
                Err(e) => Err(DigError::ArgParseError(format!(
                    "failed to parse '{}': {}",
                    addr, e
                ))),
                Ok(addrs) => Ok(addrs),
            }
        })
        .collect::<std::result::Result<Vec<_>, _>>()?
        // We now have a collection of vec::IntoIter<SocketAddr>, flatten.
        // We would use .flat_map(), but it doesn't handle the Error case :(
        .into_iter()
        .flatten()
        .collect())
}

fn server_with_default_port(server: &str, default_port: u16) -> String {
    if server.rsplit_once(':').is_some() {
        server.to_string()
    } else {
        format!("{server}:{default_port}")
    }
}

fn trace_request(args: &Args, server: &str, query: &Message) -> Result<(), DigError> {
    if !args.verbose {
        return Ok(());
    }

    let message = query.to_vec().map_err(rustdns::Error::from)?;

    eprintln!("* transport: {}", args.client);
    eprintln!("* server: {server}");
    eprintln!("* query id: {}", query.id);
    if matches!(args.client, Client::Json) {
        eprintln!("* DNS query model hexdump follows; JSON transport sends query parameters");
    } else {
        eprintln!("* DNS query payload hexdump follows");
    }
    util::hexdump_to(&mut io::stderr(), &message).map_err(rustdns::Error::from)?;

    if matches!(args.client, Client::Tcp | Client::DoT) {
        eprintln!("* TCP DNS frame uses a 2-byte length prefix");
    }
    if matches!(args.client, Client::DoT) {
        eprintln!("* TLS: DNS payload is encrypted after this point");
    }

    Ok(())
}

fn init_verbose_logging() {
    let _ = env_logger::Builder::new()
        .filter_module("rustdns::clients", log::LevelFilter::Trace)
        .format(|buf, record| writeln!(buf, "* {}", record.args()))
        .try_init();
}

impl Args {
    /// Helper function to return the list of servers as a `Vec[Url]`.
    fn servers_to_urls(&self) -> std::result::Result<Vec<Url>, DigError> {
        self.servers
            .iter()
            .map(|url| match url.parse() {
                Err(e) => Err(DigError::ArgParseError(format!(
                    "failed to parse '{}': {}",
                    url, e
                ))),
                Ok(url) => Ok(url),
            })
            .collect()
    }
}

impl Default for Args {
    fn default() -> Self {
        Args {
            client: Client::Udp,
            servers: Vec::new(),
            verbose: false,

            r#type: Type::A,
            domains: Vec::new(),
            edns_options: Vec::new(),
        }
    }
}

fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    let input = input.strip_prefix("0x").unwrap_or(input);
    if input.len() % 2 != 0 {
        return Err("hex strings must contain an even number of digits".to_string());
    }

    let mut bytes = Vec::with_capacity(input.len() / 2);
    let mut index = 0;
    while index < input.len() {
        bytes.push(
            u8::from_str_radix(&input[index..index + 2], 16).map_err(|error| error.to_string())?,
        );
        index += 2;
    }
    Ok(bytes)
}

fn parse_cookie(input: &str) -> Result<EdnsOption, String> {
    let (client, server) = input.split_once(':').unwrap_or((input, ""));
    let client = parse_hex(client)?;
    let client: [u8; 8] = client
        .try_into()
        .map_err(|_| "COOKIE client cookie must be exactly 8 bytes".to_string())?;

    Ok(if server.is_empty() {
        EdnsOption::cookie(client)
    } else {
        EdnsOption::cookie_with_server(client, parse_hex(server)?)
    })
}

fn parse_subnet(input: &str) -> Result<EdnsOption, String> {
    let mut parts = input.split('/');
    let address = parts
        .next()
        .ok_or_else(|| "EDNS Client Subnet requires an address".to_string())?
        .parse::<IpAddr>()
        .map_err(|error| error.to_string())?;
    let source_prefix_len = parts
        .next()
        .ok_or_else(|| "EDNS Client Subnet requires a source prefix length".to_string())?
        .parse::<u8>()
        .map_err(|error| error.to_string())?;
    let scope_prefix_len = parts
        .next()
        .map(|scope| scope.parse::<u8>().map_err(|error| error.to_string()))
        .transpose()?
        .unwrap_or(0);
    if parts.next().is_some() {
        return Err("EDNS Client Subnet must be address/source[/scope]".to_string());
    }

    Ok(EdnsOption::client_subnet(
        address,
        source_prefix_len,
        scope_prefix_len,
    ))
}

fn parse_tcp_keepalive(input: Option<&str>) -> Result<EdnsOption, String> {
    match input {
        None => Ok(EdnsOption::tcp_keepalive(None)),
        Some(seconds) => seconds
            .parse::<u64>()
            .map(Duration::from_secs)
            .map(Some)
            .map(EdnsOption::tcp_keepalive)
            .map_err(|error| error.to_string()),
    }
}

fn parse_unknown_edns_option(input: &str) -> Result<EdnsOption, String> {
    let (code, data) = input
        .split_once(':')
        .ok_or_else(|| "unknown EDNS option must be code:hex-data".to_string())?;
    let code = code.parse::<u16>().map_err(|error| error.to_string())?;
    Ok(EdnsOption::unknown(code, parse_hex(data)?))
}

fn parse_edns_flag(arg: &str) -> Result<Option<EdnsOption>, String> {
    if arg == "+nsid" {
        return Ok(Some(EdnsOption::nsid(Vec::new())));
    }

    if let Some(value) = arg
        .strip_prefix("+subnet=")
        .or_else(|| arg.strip_prefix("+client-subnet="))
        .or_else(|| arg.strip_prefix("+edns-client-subnet="))
    {
        return parse_subnet(value).map(Some);
    }

    if let Some(value) = arg.strip_prefix("+cookie=") {
        return parse_cookie(value).map(Some);
    }

    if arg == "+cookie" {
        return Err("+cookie requires an 8-byte hex client cookie".to_string());
    }

    if arg == "+tcp-keepalive" || arg == "+keepalive" {
        return parse_tcp_keepalive(None).map(Some);
    }

    if let Some(value) = arg
        .strip_prefix("+tcp-keepalive=")
        .or_else(|| arg.strip_prefix("+keepalive="))
    {
        return parse_tcp_keepalive(Some(value)).map(Some);
    }

    if let Some(value) = arg.strip_prefix("+padding=") {
        return value
            .parse::<u16>()
            .map(EdnsOption::padding)
            .map(Some)
            .map_err(|error| error.to_string());
    }

    if let Some(value) = arg.strip_prefix("+ednsopt=") {
        return parse_unknown_edns_option(value).map(Some);
    }

    Ok(None)
}

// TODO Move into a integration test (due to the use of network)
#[test]
fn test_to_sockaddrs() {
    let servers = vec![
        "1.2.3.4".to_string(),         // This requires using the default port.
        "aaaaa.bramp.net".to_string(), // This resolves to two records.
        "5.6.7.8:453".to_string(),     // This uses a different port.
    ];

    // This test may be flakly, if it is running in an environment that doesn't
    // have both IPv4 and IPv6, and has DNS queries that can fail.
    // TODO Figure out a way to make this more robust.
    let mut addrs = to_sockaddrs(&servers, 53).expect("resolution failed");
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

#[test]
fn test_parse_edns_args() {
    let args = parse_args(
        [
            "+nsid",
            "+verbose",
            "+subnet=192.0.2.129/24",
            "+cookie=636c69656e743031:7365727665723031",
            "+tcp-keepalive=30",
            "+padding=4",
            "+ednsopt=65001:0102",
            "example.com",
        ]
        .iter()
        .map(|arg| arg.to_string()),
    )
    .expect("EDNS flags should parse");

    assert_eq!(args.edns_options.len(), 6);
    assert!(args.verbose);
    assert_eq!(args.domains, vec!["example.com"]);
}

#[test]
fn test_parse_edns_args_rejects_invalid_cookie() {
    assert!(parse_args(["+cookie=abcd"].iter().map(|arg| arg.to_string())).is_err());
}

#[test]
fn test_parse_dot_args() {
    let args = parse_args(
        ["+dot", "@dns.google", "example.com"]
            .iter()
            .map(|arg| arg.to_string()),
    )
    .expect("DoT args should parse");

    assert!(matches!(args.client, Client::DoT));
    assert_eq!(args.servers, vec!["dns.google"]);
    assert_eq!(args.domains, vec!["example.com"]);
    assert_eq!(
        server_with_default_port(&args.servers[0], 853),
        "dns.google:853"
    );
}

#[test]
fn test_parse_dot_args_use_google_dot_by_default() {
    let args = parse_args(["+dot", "example.com"].iter().map(|arg| arg.to_string()))
        .expect("DoT args should parse");

    assert!(matches!(args.client, Client::DoT));
    assert_eq!(args.servers, vec![rustdns::clients::dot::GOOGLE]);
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut result = Args::default();
    let mut type_or_domain = Vec::<String>::new();

    for arg in args {
        match arg.as_str() {
            "+udp" => result.client = Client::Udp,
            "+tcp" => result.client = Client::Tcp,
            "+dot" => result.client = Client::DoT,
            "+doh" => result.client = Client::DoH,
            "+json" => result.client = Client::Json,
            "+verbose" => result.verbose = true,

            _ => {
                if let Some(option) = parse_edns_flag(&arg)? {
                    result.edns_options.push(option);
                    continue;
                }

                if arg.starts_with('+') {
                    return Err(format!("Unknown flag: {}", arg));
                }

                if arg.starts_with('@') {
                    result
                        .servers
                        .push(arg.strip_prefix('@').unwrap().to_string()) // Unwrap should not panic
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
            Client::DoT => result
                .servers
                .push(rustdns::clients::dot::GOOGLE.to_string()),
            Client::DoH => result
                .servers
                .push(rustdns::clients::doh::GOOGLE.to_string()),

            Client::Json => result
                .servers
                .push(rustdns::clients::json::GOOGLE.to_string()),
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
async fn main() -> Result<(), DigError> {
    // TODO --help doesn't work

    let args = match parse_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!(
                "Usage: dig [@server] [+udp|+tcp|+dot|+doh|+json] [+verbose] [+nsid] [+subnet=addr/source[/scope]] [+cookie=hex[:hex]] [+tcp-keepalive[=seconds]] [+padding=bytes] [+ednsopt=code:hex] {{domain}} {{type}}"
            );
            process::exit(1);
        }
    };

    if args.verbose {
        init_verbose_logging();
    }

    let mut query = Message::default();
    for domain in &args.domains {
        query.try_add_question(domain, args.r#type, Class::Internet)?;
    }
    let mut extension = Extension {
        payload_size: 4096,

        ..Default::default()
    };
    for option in &args.edns_options {
        extension.add_option(option.clone());
    }
    query.set_extension(extension);

    // TODO Add this as a extra verbose flag
    // println!("query:");
    // util::hexdump(&query.to_vec().expect("failed to encode the query"));
    // println!();
    println!("{}", query);

    // TODO make all DNS client implement a Exchange trait
    let resp = match args.client {
        Client::Udp => {
            let servers = to_sockaddrs(&args.servers, 53)?;
            let server = servers.first().ok_or_else(|| {
                DigError::ArgParseError("at least one UDP server is required".to_string())
            })?;
            trace_request(&args, &server.to_string(), &query)?;
            UdpClient::new(*server)
                .exchange(&query)
                .expect("could not exchange message")
        }

        Client::Tcp => {
            let servers = to_sockaddrs(&args.servers, 53)?;
            let server = servers.first().ok_or_else(|| {
                DigError::ArgParseError("at least one TCP server is required".to_string())
            })?;
            trace_request(&args, &server.to_string(), &query)?;
            TcpClient::new(*server)
                .exchange(&query)
                .expect("could not exchange message")
        }

        Client::DoT => {
            let server = args.servers.first().ok_or_else(|| {
                DigError::ArgParseError("at least one DoT server is required".to_string())
            })?;
            let server = server_with_default_port(server, 853);
            trace_request(&args, &server, &query)?;
            DotClient::try_from_host_port(&server)?
                .exchange(&query)
                .expect("could not exchange message")
        }

        Client::DoH => {
            let servers = args.servers_to_urls()?;
            let server = servers.first().ok_or_else(|| {
                DigError::ArgParseError("at least one DoH server is required".to_string())
            })?;
            trace_request(&args, server.as_str(), &query)?;
            DohClient::new(servers.as_slice(), Method::GET)?
                .exchange(&query)
                .await
                .expect("could not exchange message")
        }

        Client::Json => {
            let servers = args.servers_to_urls()?;
            let server = servers.first().ok_or_else(|| {
                DigError::ArgParseError("at least one JSON DoH server is required".to_string())
            })?;
            trace_request(&args, server.as_str(), &query)?;
            JsonClient::new(servers.as_slice())?
                .exchange(&query)
                .await
                .expect("could not exchange message")
        }
    };

    println!("response:");
    println!("{}", resp);

    Ok(())
}
