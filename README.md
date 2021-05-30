# rustdns

Simple native DNS client for rust.


## To run

```shell
cargo run 
```


## Examples

```shell
cargo run A www.google.com
cargo run AAAA www.google.com
cargo run ANY www.google.com
cargo run CNAME code.google.com
cargo run MX _ldap._tcp.google.com
cargo run PTR 4.4.8.8.in-addr.arpa
cargo run SOA google.com
cargo run SRV _ldap._tcp.google.com
cargo run TXT google.com # Doesn't work due to being tuncated

```

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
