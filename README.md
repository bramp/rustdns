# rustdns

Simple native DNS client for rust.


## To use

```shell
cargo run A www.google.com
cargo run AAAA www.google.com
cargo run ANY www.google.com
cargo run CNAME code.google.com
cargo run MX google.com
cargo run PTR 4.4.8.8.in-addr.arpa
cargo run SOA google.com
cargo run SRV _ldap._tcp.google.com
cargo run TXT google.com # Doesn't work due to being tuncated

```

TODO add Library examples

## Testing

```shell
cargo test

# or the handy
cargo watch -- cargo test --lib -- --nocapture
```

The test suite is full of real life examples, from querying DNS servers online. This was generated withh `cargo run -p generate_tests`.

## Fuzzing

The library has been extensively fuzzed. Try for yourself:

```shell
cargo fuzz run from_slice
```


## Reference

* rfc1034 - DOMAIN NAMES - CONCEPTS AND FACILITIES
* rfc1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
* rfc6895 - Domain Name System (DNS) IANA Considerations

* https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
* https://courses.cs.duke.edu//fall16/compsci356/DNS/DNS-primer.pdf


