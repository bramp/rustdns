Over 300 RFCs define, extend, or update the Domain Name System. The core, foundational, and most widely referenced RFCs across the protocol's architecture are grouped below by functional domain.

---

## Core Architecture & Protocol Fundamentals

* **RFC 1034** (*Domain Names - Concepts and Facilities*): Defines the foundational architectural concepts, hierarchical naming structure, and tree model of the DNS.
* **RFC 1035** (*Domain Names - Implementation and Specification*): Specifies the fundamental DNS packet format, message layout, core resource records, and transport mechanics.
* **RFC 1123** (*Requirements for Internet Hosts - Application and Support*): Updates DNS host requirements, clarification on mail routing, and resolver timeouts.
* **RFC 1982** (*Serial Number Arithmetic*): Defines 32-bit serial number modular arithmetic used for DNS zone versioning (`SOA.SERIAL`).
* **RFC 2181** (*Clarifications to the DNS Specification*): Resolves ambiguities across the original DNS specifications regarding RRset definitions, TTL handling, and server authority.
* **RFC 6895** (*Domain Name System (DNS) IANA Considerations*): Establishes the authoritative guidelines and procedures for IANA to assign DNS parameters, record types, and opcode values.

---

## Transport & Extensions

* **RFC 6891** (*Extension Mechanisms for DNS (EDNS(0))*): Extends the DNS protocol to support packet sizes greater than 512 bytes, extended RCODEs, and option flags.
* **RFC 7766** (*DNS over TCP - Implementation Requirements*): Mandates robust TCP support for DNS implementations and establishes guidelines for connection reuse and pipelining.
* **RFC 7828** (*The EDNS(0) Padding Option*): Introduces variable-length padding into EDNS to obscure message sizes against traffic analysis when using encrypted transports.
* **RFC 7871** (*Client Subnet in DNS Queries*): Defines the EDNS Client Subnet (ECS) option to pass client network prefixes to authoritative servers for geolocation routing.
* **RFC 8914** (*Extended DNS Errors*): Provides structured, extensible error codes in EDNS responses to diagnose why a query failed or was blocked.

---

## Encrypted Transports & Privacy

* **RFC 7858** (*Specification for DNS over Transport Layer Security (DoT)*): Defines the transport of DNS queries and responses over TLS using port 853.
* **RFC 8484** (*DNS Queries over HTTPS (DoH)*): Standardizes issuing DNS queries and receiving responses over HTTP/2 and HTTP/3 using HTTPS URI templates.
* **RFC 9076** (*DNS Privacy Considerations*): Analyzes DNS privacy threats across the query lifecycle and evaluates mitigating architectural techniques.
* **RFC 9198** (*DNS over Dedicated QUIC (DoQ)*): Specifies running DNS directly over QUIC on port 853 to reduce connection latency and head-of-line blocking.
* **RFC 9250** (*DNS over Dedicated QUIC (DoQ)*): Establishes the official standard track specification for transporting DNS traffic directly over QUIC.
* **RFC 9460** (*Service Binding and Parameter Specification via the DNS (SVCB and HTTPS RRs)*): Introduces SVCB and HTTPS resource records to streamline client connection setup, protocol negotiation, and encrypted DNS discovery.

---

## Zone Transfers & Dynamic Updates

* **RFC 1995** (*Incremental Zone Transfer in DNS (IXFR)*): Specifies an incremental transfer mechanism enabling secondary servers to request only zone deltas rather than full copies.
* **RFC 1996** (*A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)*): Introduces an active notification mechanism for primary servers to alert secondaries of zone changes.
* **RFC 2136** (*Dynamic Updates in the Domain Name System (DNS UPDATE)*): Defines dynamic insertion, modification, and deletion of resource records within a live zone without manual zone file edits.
* **RFC 3007** (*Secure Domain Name System (DNS) Dynamic Update*): Integrates cryptographic transaction signatures (TSIG/SIG(0)) to authenticate and authorize Dynamic DNS updates.
* **RFC 5936** (*DNS Zone Transfer Protocol (AXFR)*): Clarifies and details the end-to-end operation, error handling, and message framing of full zone transfers over TCP.

---

## Transaction & Server Security (TSIG / SIG(0))

* **RFC 2845** (*Secret Key Transaction Authentication for DNS (TSIG)*): Defines shared secret-key signatures using MD5/SHA algorithms to authenticate channel communication between DNS servers.
* **RFC 2930** (*Secret Key Establishment for DNS (TKEY RR)*): Establishes key-exchange mechanisms using DNS messages to dynamically negotiate shared TSIG keys.
* **RFC 2931** (*DNS Request and Transaction Signatures (SIG(0))*): Defines public-key digital signatures at the transaction level to secure DNS requests and responses without pre-shared keys.
* **RFC 8945** (*Secret Key Transaction Authentication for DNS (TSIG)*): Obsoletes RFC 2845, updating TSIG security considerations, deprecating MD5, and standardizing current HMAC practices.

---

## DNSSEC (DNS Security Extensions)

* **RFC 4033** (*DNS Security Introduction and Requirements*): Outlines the architecture, security model, and trust relationships introduced by DNSSEC.
* **RFC 4034** (*Resource Records for the DNS Security Extensions*): Defines core DNSSEC resource records, including `DNSKEY`, `RRSIG`, `NSEC`, and `DS`.
* **RFC 4035** (*Protocol Modifications for the DNS Security Extensions*): Details resolver validation workflows, authoritative server signing behavior, and message processing changes for DNSSEC.
* **RFC 5011** (*Automated Updates of DNS Security (DNSSEC) Trust Anchors*): Specifies a mechanism for resolvers to automatically track and update DNSSEC root or intermediate trust anchors.
* **RFC 5155** (*DNS Security (DNSSEC) Hashed Authenticated Denial of Existence*): Introduces the `NSEC3` and `NSEC3PARAM` records to provide authenticated denial of existence without permitting zone walking.
* **RFC 6840** (*Clarifications and Implementation Notes for DNS Security (DNSSEC)*): Collects operational experience and clarifies ambiguities in DNSSEC signature creation, validation, and negative caching.
* **RFC 7344** (*Automating DNSSEC Delegation Trust Maintenance*): Defines `CDS` (Child DS) and `CDNSKEY` records to automate the updating of parent DS records from the child zone.
* **RFC 9276** (*Guidance for NSEC3 Parameter Settings*): Provides guidance on choosing secure and performant iteration counts and salt lengths for NSEC3 deployments.

---

## Resolver Operation, Caching & Privacy

* **RFC 2308** (*Negative Caching of DNS Queries (DNS NCACHE)*): Specifies standard rules for caching negative answers (NXDOMAIN and NODATA) using the zone SOA record.
* **RFC 7816** (*DNS Query Name Minimisation to Improve Privacy*): Defines the QNAME minimisation technique where resolvers send only the minimal label necessary to discover the next nameserver.
* **RFC 8198** (*Aggressive Use of DNSSEC-Validated Cache*): Enables validating resolvers to synthesize negative responses and answers directly from cached NSEC/NSEC3 records without querying authoritative servers.
* **RFC 8767** (*Serving Stale Data to Improve DNS Resiliency*): Standardizes serving expired cached DNS records as stale fallback data when authoritative servers are unreachable.
* **RFC 9156** (*DNS Query Name Minimisation to Improve Privacy*): Obsoletes RFC 7816 with updated operational experience and recommendations for QNAME minimisation deployments.

---

## Internationalized Domain Names (IDNA)

* **RFC 3492** (*Punycode: A Bootstring encoding of Unicode for IDNA*): Specifies the Punycode algorithm used to encode Unicode domain labels into ASCII-compatible strings (`xn--`).
* **RFC 5890** (*Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework*): Establishes the terminology and architectural model for the updated IDNA2008 standard.
* **RFC 5891** (*Internationalized Domain Names in Applications (IDNA): Protocol*): Defines the protocol algorithms for encoding, resolving, and validating internationalized domain labels in applications.
* **RFC 5892** (*The Unicode Code Points and Internationalized Domain Names for Applications (IDNA)*): Classifies Unicode code points into categories determining their validity in IDN labels.
* **RFC 5893** (*Right-to-Left Scripts for Internationalized Domain Names for Applications (IDNA)*): Specifies the Bidi rule ensuring correct processing and display of Right-to-Left scripts (such as Arabic and Hebrew) in domain names.

---

## Key Specialized Resource Records & Applications

* **RFC 2782** (*A DNS RR for specifying the location of services (DNS SRV)*): Defines the `SRV` record to locate internet services by hostname and port with priority and weight weighting.
* **RFC 3596** (*DNS Extensions to Support IP Version 6*): Defines the `AAAA` record format and reverse lookup domain (`ip6.arpa`) for IPv6 resolution.
* **RFC 4255** (*Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints*): Defines the `SSHFP` record to publish verified SSH host key fingerprints via DNSSEC.
* **RFC 6698** (*The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA*): Specifies the `TLSA` record to associate TLS certificates or public keys with domain names using DNSSEC.
* **RFC 7208** (*Sender Policy Framework (SPF) for Authorizing Use of Domains in Email*): Defines the usage of DNS `TXT` records to authorize outbound email senders.
* **RFC 8555** (*Automatic Certificate Management Environment (ACME)*): Standardizes automated TLS issuance workflows, including the `_acme-challenge` DNS-01 verification record.

---

## Operational Practices & Special-Use Names

* **RFC 2606** (*Reserved Top Level DNS Names*): Reserves `.test`, `.example`, `.invalid`, and `.localhost` to prevent conflicts in testing and documentation.
* **RFC 6761** (*Special-Use Domain Names*): Defines policies for reserving domain names requiring special handling across applications, resolvers, and registries.
* **RFC 6762** (*Multicast DNS*): Standardizes peer-to-peer multicast DNS (mDNS) resolution over local-link networks without a centralized server (`.local`).
* **RFC 6763** (*DNS-Based Service Discovery*): Defines DNS-SD mechanisms for browsing and discovering network services using standard DNS queries.
* **RFC 7720** (*DNS Root Name Service Protocol and Deployment Requirements*): Establishes service requirements and protocol profiles for root nameserver operators.
* **RFC 8499** (*DNS Terminology*): Compiles and standardizes formal, consensus definitions for terms, actors, and mechanisms across the DNS ecosystem.

