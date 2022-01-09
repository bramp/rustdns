use crate::bail;
use crate::clients::udp::Client as UdpClient;
use crate::clients::Exchanger;
use crate::types::*;
use crate::Extension;
use crate::Message;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

// TODO https://docs.rs/hyper/0.14.9/src/hyper/client/connect/http.rs.html#32-35
// https://docs.rs/hyper/0.14.9/src/hyper/client/client.rs.html#26-31
// Lots of good example:
//   https://docs.rs/tower/0.4.8/src/tower/limit/concurrency/service.rs.html#26-55
pub struct Resolver<E = UdpClient> {
    client: E,
}

// TODO

//
// Should track the RA bit from remove servers (to know if they support recursion)
// Should track `batting stats`, distribution of delays, etc.
// 1. Host name to host address translation. (name -> ips)
// 2. Host address to host name translation. (ip -> name)
// 3. General lookup function. (name, type -> records)

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver {
    /// Creates a new Resolver using the system's default DNS server.
    pub fn new() -> Resolver<UdpClient> {
        let servers = crate::clients::udp::GOOGLE
            .iter()
            .flat_map(|a| a.to_socket_addrs())
            .flatten()
            .collect::<Vec<SocketAddr>>();

        let client = UdpClient::new(&servers[..]).unwrap(); // TODO Fix this
        Resolver::new_with_client(client)
    }
}

impl<E> Resolver<E>
where
    E: Exchanger,
{
    /// Creates a new Resolver using the system's default DNS server.
    pub fn new_with_client(client: E) -> Resolver<E> {
        Resolver { client }
    }

    //pub fn new_with_client(Exchanger)

    /// Resolves a name into one or more IP address.
    //
    /// See [rfc1035#section-7] and [rfc1034#section-5].
    ///
    /// [rfc1035#section-7]: https://datatracker.ietf.org/doc/html/rfc1035#section-7
    /// [rfc1034#section-5]: https://datatracker.ietf.org/doc/html/
    // TODO Should this return a Iterator, or a Vector? Check other APIs.
    // https://docs.rs/tokio/1.6.1/tokio/net/fn.lookup_host.html yield a iterator
    pub fn lookup(&self, name: &str) -> Result<Vec<IpAddr>, crate::Error> {
        let mut results = HashSet::new();

        // TODO Change this to make both DNS requests in parallel
        // If we returned a iterator, perhaps we could start to return entries
        // before they have all complete?

        // Send two queries, a A and a AAAA.
        for r#type in &[Type::A, Type::AAAA] {
            let mut query = Message::default();
            query.add_question(name, *r#type, Class::Internet);
            query.add_extension(Extension {
                payload_size: 4096, // Allow for bigger responses.

                ..Default::default()
            });

            let response = self.client.exchange(&query)?; // TODO Better error message

            println!(
                "{}: Trying {} and got {}",
                name,
                r#type,
                response.answers.len()
            );

            match response.rcode {
                Rcode::NoError => (), // Nothing
                _ => bail!(InvalidInput, "query failed with rcode: {}", response.rcode),
            };

            for answer in response.answers {
                // TODO Check the answer is for this question.
                match answer.resource {
                    Resource::A(ip4) => results.insert(IpAddr::V4(ip4)),
                    Resource::AAAA(ip6) => results.insert(IpAddr::V6(ip6)),
                    //Resource::A(ip4) => results.push(ip4),
                    _ => false, // Ignore other types
                };
            }
        }

        Ok(results.into_iter().collect())
    }
}
