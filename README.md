[![Crates.io](https://img.shields.io/crates/v/rustdns.svg)](https://crates.io/crates/rustdns)
[![Documentation](https://docs.rs/rustdns/badge.svg)](https://docs.rs/rustdns)
[![Build Status](https://github.com/bramp/rustdns/actions/workflows/rust.yml/badge.svg)](https://github.com/bramp/rustdns)

# rustdns

## rustdns

rustdns is a simple, fast, and fully fledged DNS library for interacting
with domain name services at a high or low level.

## Features
* Parsing and generating the following record types:
  * A,
  * AAAA,
  * CNAME,
  * MX,
  * NS,
  * SOA,
  * PTR,
  * TXT, and
  * SRV
* Extension Mechanisms for DNS ([EDNS(0)]).
* Support [International Domain Names (IDNA)](https://en.wikipedia.org/wiki/Internationalized_domain_name) - Different scripts, alphabets, anhd even emojis!
* Sample `dig` style [command line](#usage-cli).
* Fully [tested](#testing), and [fuzzed](#fuzzing).

## Usage (low-level library)

```rust
use rustdns::Message;
use rustdns::types::*;
use std::net::UdpSocket;
use std::time::Duration;

fn udp_example() -> std::io::Result<()> {
    // A DNS Message can be easily constructed
    let mut m = Message::default();
    m.add_question("bramp.net", Type::A, Class::Internet);
    m.add_extension(Extension {   // Optionally add a EDNS extension
        payload_size: 4096,       // which supports a larger payload size.
        ..Default::default()
    });

    // Setup a UDP socket for sending to a DNS server.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::new(5, 0)))?;
    socket.connect("8.8.8.8:53")?; // Google's Public DNS Servers

    // Encode the DNS Message as a Vec<u8>.
    let question = m.to_vec()?;

    // Send to the server.
    socket.send(&question)?;

    // Wait for a response from the DNS server.
    let mut resp = [0; 4096];
    let len = socket.recv(&mut resp)?;

    // Take the response bytes and turn it into another DNS Message.
    let answer = Message::from_slice(&resp[0..len])?;

    // Now do something with `answer`, in this case print it!
    println!("DNS Response:\n{}", answer);

    Ok(())
}
```

If successful something like the following will be printed:

```
;; ->>HEADER<<- opcode: Query, status: NoError, id: 44857
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
; bramp.net.              IN   A

; ANSWER SECTION:
bramp.net.            299 IN   A      104.21.62.200
bramp.net.            299 IN   A      172.67.138.196
```

## Features
The following optional features are available:

- `clients`: Enables the following clients:
  - `doh`: DNS over HTTPS (DoH) client (rfc8484).
  - `json`: DNS over HTTPS JSON client
  - `tcp`: Enables the DNS over TCP client
  - `udp`: Enables the DNS over UDP client
- `zones`: Enable a Zone File Parser

## Usage (cli)

To use the [demo CLI](https://github.com/bramp/rustdns/blob/main/src/rustdns/dig/main.rs):

```shell
$ cargo run -p dig -- A www.google.com
...
;; ->>HEADER<<- opcode: Query, status: NoError, id: 34327
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
; www.google.com.         IN   A

; ANSWER SECTION:
www.google.com.       110 IN   A      142.250.72.196

# More examples
$ cargo run -p dig -- AAAA www.google.com
$ cargo run -p dig -- ANY www.google.com
$ cargo run -p dig -- CNAME code.google.com
$ cargo run -p dig -- MX google.com
$ cargo run -p dig -- PTR 4.4.8.8.in-addr.arpa
$ cargo run -p dig -- SOA google.com
$ cargo run -p dig -- SRV _ldap._tcp.google.com
$ cargo run -p dig -- TXT google.com
```
## Testing

```shell
$ cargo test --all

# or the handy
$ cargo watch -- cargo test --all -- --nocapture
```

The test suite is full of stored real life examples, from querying real DNS records.
This was generated with `cargo run -p generate_tests`.

### Fuzzing

The library has been extensively fuzzed. Try for yourself:

```shell
$ cargo fuzz run from_slice
```

### Test Data

To aid in testing features, I have a set of pre-configured records setup:

| Domain                | Description |
| --------------------- | ----------- |
| a.bramp.net           | Single A record pointing at 127.0.0.1 |
| aaaa.bramp.net        | Single AAAA record pointing at ::1 |
| aaaaa.bramp.net       | One A record, and one AAAA record resolving to 127.0.0.1 and ::1 |
| cname.bramp.net       | Single CNAME record pointing at a.bramp.net |
| cname-loop1.bramp.net | Single CNAME record pointing at cname-loop2.bramp.net |
| cname-loop2.bramp.net | Single CNAME record pointing at cname-loop1.bramp.net |
| mx.bramp.net          | Single MX record pointing at a.bramp.net |
| ns.bramp.net          | Single NS record pointing at a.bramp.net |
| txt.bramp.net         | Single TXT Record "A TXT record!" |

## Releasing

```shell
# Bump version number
$ cargo test-all-features
$ cargo readme > README.md
$ cargo publish --dry-run
$ cargo publish
```

## TODO (in order of priority)
* [ ] Document UDP/TCP library
* [ ] Client side examples
* [ ] Server side examples
* [ ] DNSSEC: Signing, validating and key generation for DSA, RSA, ECDSA and Ed25519
* [ ] NSID, Cookies, AXFR/IXFR, TSIG, SIG(0)
* [ ] Runtime-independence
* [ ] Change the API to have getters and setters.
* [ ] Change hyper-alpn to support tokio-native-tls for people that want that.
* [ ] Implement more dig features, such as +trace
* [ ] Maybe convert the binary parsing to Nom format.
* [ ] Can I parse these https://www.iana.org/domains/root/files ?

### Reference

* [rfc1034]: DOMAIN NAMES - CONCEPTS AND FACILITIES
* [rfc1035]: DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
* [rfc6895]: Domain Name System (DNS) IANA Considerations
* [IANA Domain Name System (DNS) Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
* [Computer Networks CPS365 FALL 2016](https://courses.cs.duke.edu//fall16/compsci356/DNS/DNS-primer.pdf)
* [miekg's Go DNS Library](https://github.com/miekg/dns)

[EDNS(0)]: https://en.wikipedia.org/wiki/Extension_Mechanisms_for_DNS
[rfc1034]: https://datatracker.ietf.org/doc/html/rfc1034
[rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
[rfc6895]: https://datatracker.ietf.org/doc/html/rfc6895

## License: Apache-2.0

```
Copyright 2021 Andrew Brampton (bramp.net)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
