[![CI](https://github.com/spacescale/nftables-nl/actions/workflows/ci.yaml/badge.svg)](https://github.com/spacescale/nftables-nl/actions/workflows/ci.yaml)
![Rust version](https://img.shields.io/badge/rust-1.99%2B-orange)
![Platform](https://img.shields.io/badge/platform-Linux-blue)

> [!IMPORTANT]
> The library is under active development. More documentation and API usage will be added as the implementation matures.

# nftables-nl

nftables-nl is can be used to interact with Linux nftables.This library does not wrap the nft command-line tool,
libnftables or its JSON API. The project aims to provide safe idiomatic Rust types and APIs for nftables concepts such
as
tables, chains, rules and sets while keeping the
underlying behavior aligned with the Linux kernel interface.

The library is under active development. More documentation and API usage will be added as the implementation matures.
