// Simple dig style command line.
// rustdns {record} {domain}
mod util;

use std::env;
use std::net::UdpSocket;
use std::process;
use std::str::FromStr;
use std::time::Duration;

use rustdns::types::*;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: rustdns {{type}} {{domain}}");
        process::exit(1);
    }

    // TODO Better parsing
    let r#type = Type::from_str(&args[1]).expect("invalid type");
    let domain = &args[2];

    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    socket
        .set_read_timeout(Some(Duration::new(5, 0)))
        .expect("set_read_timeout call failed");

    let mut m = Message::default();

    m.add_question(domain, r#type, Class::Internet);

    m.add_extension(Extension {
        payload_size: 4096,

        ..Default::default()
    });

    let req = m.to_vec().expect("failed to write message");

    println!("request:");
    util::hexdump(&req);
    println!("{}", m);

    socket
        .send_to(&req, "8.8.8.8:53")
        .expect("could not send data");

    let mut resp = [0; 4096];
    let (amt, src) = socket.recv_from(&mut resp).expect("no response");

    println!("response: {0}", src);
    util::hexdump(&resp[0..amt]);

    let m = Message::from_slice(&resp[0..amt]).expect("invalid response");
    println!("{}", m);

    Ok(())
}
