// Simple dig style command line.
// rustdns {record} {domain}
mod util;

use rustdns::clients::*;
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

#[tokio::main]
async fn main() -> Result<()> {
    //fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: rustdns {{type}} {{domain}}");
        process::exit(1);
    }

    // TODO Better parsing
    let r#type = Type::from_str(&args[1]).expect("invalid type");
    let domain = &args[2];

    let mut query = Message::default();
    query.add_question(domain, r#type, Class::Internet);
    query.add_extension(Extension {
        payload_size: 4096,

        ..Default::default()
    });

    println!("query:");
    util::hexdump(&query.to_vec().expect("failed to encode the query"));
    println!();
    println!("{}", query);

    let client = Client::from_str("DoH").expect("invalid client");

    let resp = match client {
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
