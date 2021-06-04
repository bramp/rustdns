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
        eprintln!("Usage: rustdns {{qtype}} {{domain}}");
        process::exit(1);
    }

    // TODO Better parsing
    let qtype = QType::from_str(&args[1]).expect("invalid qtype");
    let domain = &args[2];

    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    socket
        .set_read_timeout(Some(Duration::new(5, 0)))
        .expect("set_read_timeout call failed");

    let mut packet = Packet {
        id: 0xeccb,
        qr: QR::Query,
        opcode: Opcode::Query,
        rd: true,
        ad: true,

        ..Default::default()
    };

    packet.add_question(domain, qtype, QClass::Internet);

    packet.add_extension(Extension {
        payload_size: 4096,

        ..Default::default()
    });

    let req = packet.as_vec().expect("failed to write packet");

    println!("request:");
    util::hexdump(&req);
    println!("{}", packet);

    socket
        .send_to(&req, "8.8.8.8:53")
        .expect("could not send data");

    let mut resp = [0; 4096];
    let (amt, src) = socket.recv_from(&mut resp).expect("no response");

    println!("response: {0}", src);
    util::hexdump(&resp[0..amt]);

    let packet = Packet::from_slice(&resp[0..amt]).expect("invalid response");
    println!("{}", packet);

    Ok(())
}
