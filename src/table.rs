use std;

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

/// Flags controlling the state and lifetime of an nftables table.
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

pub struct Table {
    pub name: String,
    pub use_count: u32,
    pub flags: TableFlags,
    pub owner: Option<u32>,
    pub family: TableFamily,
}
