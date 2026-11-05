[![CI](https://github.com/spacescale/nftables-nl/actions/workflows/ci.yaml/badge.svg)](https://github.com/spacescale/nftables-nl/actions/workflows/ci.yaml)
[![Coverage](https://codecov.io/gh/spacescale/nftables-nl/branch/main/graph/badge.svg)](https://app.codecov.io/gh/spacescale/nftables-nl)
![Rust version](https://img.shields.io/badge/rust-1.99%2B-orange)
![Platform](https://img.shields.io/badge/platform-Linux-blue)

> [!IMPORTANT]
> The library is under active development. More documentation and API usage will be added as the implementation matures.

# nftables-nl

nftables-nl can be used to interact with Linux nftables.This library does not wrap the nft command-line tool,
libnftables or its JSON API. This project aims to provide safe idiomatic Rust types and APIs for nftables concepts such
as tables, chains, rules and sets while keeping the underlying behavior aligned with the Linux kernel interface.

## Installation

Add the published crate to your project:

```sh
cargo add nftables-nl
```

## Quick start

> Requires Rust 1.99.1+ and Linux for socket operations. Querying and modifying nftables requires `CAP_NET_ADMIN`,
> typically provided by
> running the program with sudo

```rs
use nftables_nl::{Conn, TableFamily};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = Conn::new()?;

    // List tables in the combined IPv4/IPv6 (inet) family.
    let tables = conn.list_tables_of_family(TableFamily::INET)?;

    for table in tables {
        println!("{}", table.name);
    }

    Ok(())
}
```

### Add a table

Queue an inactive INET table, then commit the batch to apply the change:

```rust
use nftables_nl::{Conn, ConnError, Table, TableFamily, TableFlags};

fn main() -> Result<(), ConnError> {
    let mut conn = Conn::new()?;
    let table = Table {
        name: "filter".into(),
        family: TableFamily::INET,
        flags: TableFlags::DORMANT, // Disable packet processing for this table.
        use_count: 0,
        owner: None,
    };

    let mut batch = conn.batch();
    batch.add_table(&table)?; // Validate and queue the operation.
    batch.commit()?;          // Send the transaction and check kernel replies.

    Ok(())
}
```

For more usage examples, see the [examples directory](examples).

Integration tests run on GitHub-hosted Ubuntu 24.04 and 26.04 runners on x86-64 and ARM64,
plus `ubuntu-latest` on x86-64. Tests use GitHub's provided kernels. Each CI run logs the

kernel version, architecture and `nft` version. See the [integration workflow](.github/workflows/integration.yaml).

## Contributing

Contributions are welcome! Feel free to [open an issue](https://github.com/spacescale/nftables-nl/issues)
or [submit a pull request](https://github.com/spacescale/nftables-nl/pulls).

## Credits

The Netlink crates from the [rust-netlink](https://github.com/rust-netlink) project were used for socket operations.
The [Google nftables](https://github.com/google/nftables) API was a design reference for modeling the APIs,
closely alongside the Linux kernel UAPI headers.
Massive thanks to both projects!

## Maintainer

Developed and maintained by [Tobi Ogundiyan](https://github.com/t0gun)
at [Spacescale Systems](https://github.com/spacescale).

## License

nftables-nl is licensed under MIT license. See [License](LICENSE) for more details.
