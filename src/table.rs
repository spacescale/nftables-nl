use crate::types::{NfGenMsg, NftMessage};
use netlink_packet_core::{NlasIterator, parse_string, parse_u32_be};
use std;

#[derive(Debug, thiserror::Error)]
pub enum TableDecodeError {
    #[error("short table header: {0} bytes")]
    ShortHeader(usize),

    #[error("missing table name")]
    MissingName,

    #[error("invalid attribute: {0}")]
    Attribute(#[source] netlink_packet_core::DecodeError),
}

pub struct Table {
    pub name: String,
    pub use_count: u32,
    pub flags: TableFlags,
    pub owner: Option<u32>,
    pub family: TableFamily,
}

impl Table {
    /// Decodes an nftables table from a Netfilter Netlink message.
    ///
    /// Expects the message payload to contain a four-byte `nfgenmsg` header,
    /// followed by Netlink attributes describing the table.
    ///
    /// The table family is extracted from `nfgenmsg`, while the name, flags,
    /// use count, and optional owner are decoded from `NFTA_TABLE_*` attributes.
    /// Unrecognized attributes are ignored.
    ///
    /// Missing flags and use count default to zero, and an absent owner
    /// is represented as `None`.
    ///
    /// # Errors
    ///
    /// Returns [`TableDecodeError`] if:
    /// - The payload is shorter than the `nfgenmsg` header.
    /// - An attribute is malformed or cannot be decoded.
    /// - The required `NFTA_TABLE_NAME` attribute is missing.
    ///
    /// # References
    ///
    /// - [Netfilter generic message header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink.h)
    /// - [nftables table attributes](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_tables.h)
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn from_message(message: &NftMessage) -> Result<Self, TableDecodeError> {
        let data = &message.data[..];

        // The payload starts with the four-byte nfgenmsg header.
        if data.len() < NfGenMsg::LEN {
            return Err(TableDecodeError::ShortHeader(data.len()));
        }

        // The first byte of nfgenmsg identifies the tables family
        let family = TableFamily(data[0]);

        let mut name = None;
        let mut flags = TableFlags(0);
        let mut use_count = 0;
        let mut owner = None;

        // attributes begin immediately after nfgenmsg
        for attribute in NlasIterator::new(&data[NfGenMsg::LEN..]) {
            let attribute = attribute.map_err(TableDecodeError::Attribute)?;

            // kind returns the attribute type identifier.
            // see https: <github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_tables.h#L207>
            let kind = attribute.kind();
            let value = attribute.value();

            // kernel constants and their meaning. this is a summarization from the above link. the kernel nftables UAPI
            // 1 NFT_TABLE_NAME Table Name
            // 2 NFTA_TABLE_FLAGS Table Flags
            // 3 NFT-TABLE_USE Number of Chains
            // 4 NFTA_TABLE_HANDLE table handle
            // 7 NFTA-TABLE_OWNER owning netlink portID
            match kind {
                1 => {
                    // NFTA_TABLE_NAME
                    name = Some(parse_string(value).map_err(TableDecodeError::Attribute)?);
                }

                2 => {
                    // NFTA_TABLE_FLAGS
                    let raw = parse_u32_be(value).map_err(TableDecodeError::Attribute)?;
                    flags = TableFlags(raw)
                }

                3 => {
                    // NFTA_TABLE_USE
                    use_count = parse_u32_be(value).map_err(TableDecodeError::Attribute)?
                }

                7 => {
                    owner = Some(parse_u32_be(value).map_err(TableDecodeError::Attribute)?);
                }

                // Ignore unsupported attributes.
                _ => {}
            }
        }

        let name = name.ok_or(TableDecodeError::MissingName)?;

        Ok(Self {
            name,
            use_count,
            flags,
            owner,
            family,
        })
    }
}

/// Netfilter protocol family used by a nftables table.
///
/// These values come from the Linux UAPI Netfilter definitions:
/// <https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter.h>
///
/// In the kernel, they are defined as `NFPROTO_*` constants.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TableFamily(u8);

impl TableFamily {
    /// Unspecified protocol family (`NFPROTO_UNSPEC`).
    pub const UNSPEC: Self = Self(0);

    /// Combined IPv4 and IPv6 family (`NFPROTO_INET`).
    pub const INET: Self = Self(1);

    /// IPv4 family (`NFPROTO_IPV4`).
    pub const IPV4: Self = Self(2);

    /// ARP family (`NFPROTO_ARP`).
    pub const ARP: Self = Self(3);

    /// Network device ingress/egress family (`NFPROTO_NETDEV`).
    pub const NETDEV: Self = Self(5);

    /// Ethernet bridge family (`NFPROTO_BRIDGE`).
    pub const BRIDGE: Self = Self(7);

    /// IPv6 family (`NFPROTO_IPV6`).
    pub const IPV6: Self = Self(10);

    pub const fn as_raw(&self) -> u8 {
        self.0
    }
}

/// Flags controlling the state and lifetime of a nftables table.
///
/// These values come from the Linux UAPI nftables definitions:
/// <https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_tables.h>
///
/// In the kernel UAPI, they are defined by `enum nft_table_flags` and are
/// encoded as a bitmask in the `NFTA_TABLE_FLAGS` Netlink attribute.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TableFlags(u32);

impl TableFlags {
    /// The table is inactive and does not process packets.
    /// (`NFT_TABLE_F_DORMANT`).
    pub const DORMANT: Self = Self(0x1);

    /// The table is owned by the creating Netlink connection.
    ///  (`NFT_TABLE_F_OWNER`).
    pub const OWNER: Self = Self(0x2);

    /// The table persists after its owner connection closes.
    /// (`NFT_TABLE_F_PERSIST`).
    pub const PERSIST: Self = Self(0x4);

    /// Returns the raw `u32` bitmask used by the Linux nftables UAPI.
    pub const fn as_raw(&self) -> u32 {
        self.0
    }
}

impl std::ops::BitOr for TableFlags {
    type Output = Self; // result should also be a table flag

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
