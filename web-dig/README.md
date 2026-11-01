# Web Dig

An in-browser DNS lookup tool powered by [rustdns](https://github.com/bramp/rustdns) compiled to WebAssembly.

Live demo: <https://dig.bramp.net>

## Features

- **Direct In-Browser Resolution**: Queries DNS-over-HTTPS (DoH, RFC 8484) and DNS-over-HTTPS JSON endpoints directly from the browser without needing a backend server or proxy.
- **AsyncExchanger Integration**: Implements the `rustdns::clients::AsyncExchanger` trait for both binary DoH (`BrowserDohClient`) and JSON DoH (`BrowserJsonClient`).
- **Authentic Dig Output**: Formats DNS query responses using `rustdns`'s built-in `Display` implementation.
- **DNSSEC Demonstration**: Compare an upstream resolver's `AD` assertion with local cryptographic chain validation to IANA root trust anchors.
- **Validation Trace**: In local-validation mode, a trace pane lists every DNSKEY and DS query made to build the chain of trust, with flags, results, timing, and the full responses.
- **Bounded Browser Resolution**: DNSKEY and DS dependency queries use the selected DoH endpoint, a shared deadline, and abortable fetches.
- **Provider Support**: Pre-configured for Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9), and custom HTTPS endpoints.
- **Zero-Bundler Web Setup**: Generates standard ES modules using `wasm-pack --target web`.

The app's [DNSSEC guide](www/dnssec.html) explains the distinction between
upstream trust and local validation, and includes signed and intentionally
broken test domains.
DNSSEC status and validation errors appear in the metadata footer only when
DNSSEC is enabled. Issue badges do not replace the elapsed query time.

## Prerequisites

- Rust 1.87+ and `wasm32-unknown-unknown` target:
  ```shell
  rustup target add wasm32-unknown-unknown
  ```
- `wasm-pack`:
  ```shell
  brew install wasm-pack
  # or
  cargo install wasm-pack
  ```

## Building

From the `web-dig` directory:

```shell
wasm-pack build --target web --out-dir www/pkg
```

## Testing

Run the native Rust unit tests:

```shell
cargo test -p web-dig
```

## Running Locally

Serve the `www` folder using any static web server:

```shell
python3 -m http.server --directory www 8000
```

Then open `http://localhost:8000` in your browser.
