// Simple dig style command line.
// rustdns {record} {domain}
mod util;

use rustdns::clients::*;
use rustdns::clients::Exchanger;
use rustdns::types::*;
use std::env;
use std::process;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

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

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args> {
    let mut result = Args {
        client: Client::Udp,
        servers: Vec::new(),

        r#type: Type::A,
        domains: Vec::new(),
    };

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
                        .push(arg.strip_prefix("@").unwrap().to_string())
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

    for domain in args.domains {
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
        Client::Udp => UdpClient::new("8.8.8.8:53")?
            .exchange(&query)
            .expect("could not exchange message"),
        Client::Tcp => TcpClient::new("8.8.8.8:53")?
            .exchange(&query)
            .expect("could not exchange message"),
        Client::DoH => DoHClient::new("https://dns.google/dns-query")?
            .exchange(&query)
            .await
            .expect("could not exchange message"),
    };

    println!("response:");
    println!("{}", resp);

    Ok(())
}
