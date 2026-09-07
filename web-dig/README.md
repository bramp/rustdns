# Web Dig

An in-browser DNS lookup tool powered by [rustdns](https://github.com/bramp/rustdns) compiled to WebAssembly.

## Features

- **Direct In-Browser Resolution**: Queries DNS-over-HTTPS (DoH, RFC 8484) and DNS-over-HTTPS JSON endpoints directly from the browser without needing a backend server or proxy.
- **AsyncExchanger Integration**: Implements the `rustdns::clients::AsyncExchanger` trait for both binary DoH (`BrowserDohClient`) and JSON DoH (`BrowserJsonClient`).
- **Authentic Dig Output**: Formats DNS query responses using `rustdns`'s built-in `Display` implementation.
- **Provider Support**: Pre-configured for Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9), and custom HTTPS endpoints.
- **Zero-Bundler Web Setup**: Generates standard ES modules using `wasm-pack --target web`.

## Prerequisites

- Rust 1.85+ and `wasm32-unknown-unknown` target:
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
