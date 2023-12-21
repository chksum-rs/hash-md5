# chksum-hash-md5

[![crates.io](https://img.shields.io/crates/v/chksum-hash-md5?style=flat-square&logo=rust "crates.io")](https://crates.io/crates/chksum-hash-md5)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/hash-md5/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/hash-md5/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-hash-md5?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-hash-md5/)
[![MSRV](https://img.shields.io/badge/MSRV-1.63.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/hash-md5/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-hash-md5/0.0.0/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-hash-md5/0.0.0)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/hash-md5?style=flat-square "LICENSE")](https://github.com/chksum-rs/hash-md5/blob/master/LICENSE)

An implementation of MD5 hash algorithm for batch and stream computation.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-hash-md5 = "0.0.0"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-hash-md5
```

## Usage

Use the `hash` function for batch digest calculation.

```rust
use chksum_hash_md5 as md5;

let digest = md5::hash(b"example data");
assert_eq!(
    digest.to_hex_lowercase(),
    "5c71dbb287630d65ca93764c34d9aa0d"
);
```

Use the `default` function to create a hash instance for stream digest calculation.

```rust
use chksum_hash_md5 as md5;

let digest = md5::default()
    .update("example")
    .update(b"data")
    .update([0, 1, 2, 3])
    .digest();
assert_eq!(
    digest.to_hex_lowercase(),
    "a1a9f435f547ec4cffd8050c454f632a"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-hash-md5/).

## License

This crate is licensed under the MIT License.
