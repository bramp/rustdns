// Simple nslookup style command line using rustdns Resolver::lookup.
// nslookup [options] {domain} [server]

use rustdns::clients::do53::{Client as Do53Client, GOOGLE};
use rustdns::clients::{Backoff, Resolver};
use std::env;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::process;
use std::time::Duration;
use std::vec;
use thiserror::Error;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[derive(Error, Debug)]
enum NslookupError {
    #[error("{0}")]
    ArgParseError(String),

    #[error(transparent)]
    RustDnsError(#[from] rustdns::Error),
}

const USAGE: &str = "Usage: nslookup [options] <domain> [server]\n\n\
Options:\n  \
  [+timeout=secs|-timeout=secs]  Query timeout in seconds (default: 5)\n  \
  [+verbose|-verbose|-v]         Enable verbose resolver logging\n  \
  [+help|-help|-h]               Show this help message";

#[derive(Debug, PartialEq)]
struct Args {
    help: bool,
    servers: Vec<String>,
    verbose: bool,
    timeout: Duration,
    domains: Vec<String>,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            help: false,
            servers: Vec::new(),
            verbose: false,
            timeout: Duration::from_secs(5),
            domains: Vec::new(),
        }
    }
}

fn sockaddr_parse_with_port(
    addr: &str,
    default_port: u16,
) -> io::Result<vec::IntoIter<SocketAddr>> {
    match addr.to_socket_addrs() {
        Err(_e) => (addr, default_port).to_socket_addrs(),
        Ok(addrs) => Ok(addrs),
    }
}

fn to_sockaddrs(servers: &[String], default_port: u16) -> Result<Vec<SocketAddr>, NslookupError> {
    Ok(servers
        .iter()
        .map(|addr| {
            sockaddr_parse_with_port(addr, default_port)
                .map_err(|e| NslookupError::ArgParseError(format!("failed to parse '{addr}': {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?
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

fn init_verbose_logging() {
    let _ = env_logger::Builder::new()
        .filter_module("rustdns::clients", log::LevelFilter::Trace)
        .format(|buf, record| writeln!(buf, "* {}", record.args()))
        .try_init();
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut result = Args::default();
    let mut positional = Vec::new();

    for arg in args {
        if let Some(server) = arg.strip_prefix('@') {
            result.servers.push(server.to_string());
        } else if arg.starts_with('+') || arg.starts_with('-') {
            let opt = arg.trim_start_matches('+').trim_start_matches('-');

            if opt == "h" || opt == "help" {
                result.help = true;
            } else if opt == "v" || opt == "verbose" {
                result.verbose = true;
            } else if let Some(val) = opt
                .strip_prefix("timeout=")
                .or_else(|| opt.strip_prefix("time="))
            {
                let secs: u64 = val
                    .parse()
                    .map_err(|e| format!("invalid timeout '{val}': {e}"))?;
                result.timeout = Duration::from_secs(secs);
            } else {
                return Err(format!("unknown option: {arg}"));
            }
        } else {
            positional.push(arg);
        }
    }

    if result.help {
        return Ok(result);
    }

    // Standard nslookup positional handling: nslookup <domain> [server]
    if result.servers.is_empty() && positional.len() == 2 {
        result.domains.push(positional.remove(0));
        result.servers.push(positional.remove(0));
    } else {
        result.domains = positional;
    }

    if result.domains.is_empty() {
        return Err("missing host operand".to_string());
    }

    if result.servers.is_empty() {
        eprintln!(";; No servers specified, using Google's DNS servers");
        result.servers.extend(GOOGLE.iter().map(|&s| s.to_string()));
    }

    Ok(result)
}

#[tokio::main]
async fn main() -> Result<(), NslookupError> {
    let args = match parse_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            eprintln!("{USAGE}");
            process::exit(1);
        }
    };

    if args.help {
        println!("{USAGE}");
        return Ok(());
    }

    if args.verbose {
        init_verbose_logging();
    }

    let mut builder = Resolver::builder()
        .timeout(args.timeout)
        .backoff(Backoff::None);

    let addrs = to_sockaddrs(&args.servers, 53)?;
    if addrs.is_empty() {
        return Err(NslookupError::ArgParseError(
            "at least one server is required".to_string(),
        ));
    }
    for addr in addrs {
        builder = builder.upstream(Do53Client::new(addr));
    }

    let resolver = builder.build()?;

    let primary_server = args
        .servers
        .first()
        .map(String::as_str)
        .unwrap_or("unknown");
    let display_addr = server_with_default_port(primary_server, 53);

    println!("Server:\t\t{primary_server}");
    println!("Address:\t{display_addr}\n");

    let mut exit_code = 0;
    for (i, domain) in args.domains.iter().enumerate() {
        if i > 0 {
            println!();
        }
        match resolver.lookup(domain).await {
            Ok(ips) => {
                println!("Non-authoritative answer:");
                println!("Name:\t{domain}");
                if ips.is_empty() {
                    println!("*** No address (A or AAAA) records found for {domain}");
                } else {
                    let mut sorted = ips;
                    sorted.sort();
                    for ip in sorted {
                        println!("Address: {ip}");
                    }
                }
            }
            Err(e) => {
                eprintln!("** server can't find {domain}: {e}");
                exit_code = 1;
            }
        }
    }

    if exit_code != 0 {
        process::exit(exit_code);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_basic() {
        let args = parse_args(["example.com"].into_iter().map(String::from))
            .expect("should parse basic domain");
        assert_eq!(args.domains, vec!["example.com"]);
        assert_eq!(
            args.servers,
            GOOGLE.iter().map(|&s| s.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_parse_args_with_server_positional() {
        let args = parse_args(["example.com", "1.1.1.1"].into_iter().map(String::from))
            .expect("should parse domain and server");
        assert_eq!(args.domains, vec!["example.com"]);
        assert_eq!(args.servers, vec!["1.1.1.1"]);
    }

    #[test]
    fn test_parse_args_at_server() {
        let args = parse_args(["@9.9.9.9", "example.com"].into_iter().map(String::from))
            .expect("should parse @server");
        assert_eq!(args.domains, vec!["example.com"]);
        assert_eq!(args.servers, vec!["9.9.9.9"]);
    }

    #[test]
    fn test_parse_timeout() {
        let args = parse_args(["-timeout=3", "example.com"].into_iter().map(String::from))
            .expect("timeout should parse");
        assert_eq!(args.timeout, Duration::from_secs(3));
    }

    #[test]
    fn test_parse_help() {
        for flag in ["-h", "--help", "+help", "-help"] {
            let args = parse_args([flag].into_iter().map(String::from)).expect("help should parse");
            assert!(args.help);
        }
    }

    #[test]
    fn test_missing_domain_error() {
        let err = parse_args(std::iter::empty()).unwrap_err();
        assert_eq!(err, "missing host operand");
    }
}
