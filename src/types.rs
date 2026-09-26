//! nftables Netlink message type definitions and header encoding.
//!
//! This module defines the nftables Netfilter subsystem identifier and the
//! operation numbers used in Netlink `nlmsg_type` fields.
//!
//! Netfilter splits `nlmsg_type` into two 8-bit components:
//!
//!
//!  15              8 7               0
//! +-----------------+-----------------+
//! |    subsystem    |    operation    |
//! +-----------------+-----------------+
//!
//!
//! For nftables, the subsystem is [`NFNL_SUBSYS_NFTABLES`]. [`NftMsgType`]
//! represents the operation in the low byte and provides helpers for composing
//! and decoding the complete Netlink message type.
//!
//! The numeric values in this module follow the Linux UAPI definitions in
//! `nfnetlink.h` and `nf_tables.h`. Their ordering is part of the kernel ABI and
//! must not be changed independently of the kernel definitions.

use std::fmt;
use std::fmt::Formatter;

/// The nftables subsystem number, ported from the kernel's nfnetlink.h.
/// The kernel splits nlmsg_type into "8 bit subsystem, 8 bit operation";
/// compose the full type as `NFNL_SUBSYS_NFTABLES << 8 | msg`.
/// See: <https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink.h#L61>
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;

/// Why a received envelope could not be decoded into a message type.
///
/// The two variants mirror the two rejection guards in the kernel's message
/// dispatcher: unknown subsystem `nfnetlink_get_subsys` and unknown operation `nfnetlink_find_client`.
/// See: <https://github.com/torvalds/linux/blob/master/net/netfilter/nfnetlink.c#L144-L163>
#[derive(Debug, PartialEq, Eq)]
pub enum NftMsgTypeError {
    /// The envelope is addressed to a different netfilter subsystem.
    /// u8: the subsystem number lives in the high byte of the type field.
    WrongSubsystem(u8),
    /// The operation number is not a known nftables message type (>= MAX).
    UnknownType(u8),
}

impl fmt::Display for NftMsgTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSubsystem(s) => write!(f, "not an nftables subsystem: {s}"),
            Self::UnknownType(m) => write!(f, "unknown nftables message type: {m}"),
        }
    }
}

/// nftables netlink message types, ported in order from the kernel enum
///
/// nf_tables_msg_types, which also matches google/nftables types.go.
/// Values are positional, verified from the kernel source.
/// Do not renumber. Do not reorder.
///
/// See: <https://github.com/torvalds/linux/blob/cbd2257dc96e3e46217540fcb095a757ffa20d96/include/uapi/linux/netfilter/nf_tables.h#L110>
///
/// See: <https://github.com/google/nftables/blob/f9b52ed2ba653815684ff3e19a4d087ff0b87332/types.go#L13>
///
/// Naming: kernel abbreviations are expanded to idiomatic Rust
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NftMsgType(u16);

impl NftMsgType {
    pub const NEW_TABLE: Self = Self(0);
    pub const GET_TABLE: Self = Self(1);
    pub const DELETE_TABLE: Self = Self(2);
    pub const NEW_CHAIN: Self = Self(3);
    pub const GET_CHAIN: Self = Self(4);
    pub const DELETE_CHAIN: Self = Self(5);
    pub const NEW_RULE: Self = Self(6);
    pub const GET_RULE: Self = Self(7);
    pub const DELETE_RULE: Self = Self(8);
    pub const NEW_SET: Self = Self(9);
    pub const GET_SET: Self = Self(10);
    pub const DELETE_SET: Self = Self(11);
    pub const NEW_SET_ELEM: Self = Self(12);
    pub const GET_SET_ELEM: Self = Self(13);
    pub const DELETE_SET_ELEM: Self = Self(14);
    pub const NEW_GEN: Self = Self(15);
    pub const GET_GEN: Self = Self(16);
    pub const TRACE: Self = Self(17);
    pub const NEW_OBJ: Self = Self(18);
    pub const GET_OBJ: Self = Self(19);
    pub const DELETE_OBJ: Self = Self(20);
    pub const GET_OBJ_RESET: Self = Self(21);
    pub const NEW_FLOW_TABLE: Self = Self(22);
    pub const GET_FLOW_TABLE: Self = Self(23);
    pub const DELETE_FLOW_TABLE: Self = Self(24);
    pub const GET_RULE_RESET: Self = Self(25);
    pub const DESTROY_TABLE: Self = Self(26);
    pub const DESTROY_CHAIN: Self = Self(27);
    pub const DESTROY_RULE: Self = Self(28);
    pub const DESTROY_SET: Self = Self(29);
    pub const DESTROY_SET_ELEM: Self = Self(30);
    pub const DESTROY_OBJ: Self = Self(31);
    pub const DESTROY_FLOW_TABLE: Self = Self(32);
    pub const GET_SET_ELEM_RESET: Self = Self(33);
    /// one past the last known type, use to reject unknown message types when parsing
    const MAX: Self = Self(34);

    /// Returns the bare operation number; the low 8 bits of the address.
    /// This does not include the netfilter subsystem identifier.
    ///
    /// ##### Examples
    ///
    /// ```
    /// use spacenft::types::NftMsgType;
    ///
    /// assert_eq!(NftMsgType::NEW_RULE.as_raw(), 6);
    /// ```
    pub const fn as_raw(&self) -> u16 {
        self.0
    }

    /// The full envelope type field: subsystem << 8 | operation.
    /// Mirrors the kernel's own helper:
    /// <https://github.com/torvalds/linux/blob/master/include/linux/netfilter/nfnetlink.h#L62-L65>
    /// This is the value that goes into the `nlmsg_type` field of the header.
    /// ##### Examples
    ///
    /// ```
    /// use spacenft::types::NftMsgType;
    ///
    /// assert_eq!(NftMsgType::NEW_TABLE.header_type(), 0x0a00);
    /// assert_eq!(NftMsgType::NEW_RULE.header_type(), 0x0a06);
    /// ```
    pub const fn header_type(&self) -> u16 {
        (NFNL_SUBSYS_NFTABLES << 8) | self.0
    }

    /// Decodes the envelope's type field into a message type — the inverse of [`NftMsgType::header_type`].
    /// The decode formulas are the kernel's own macros `NFNL_SUBSYS_ID` and `NFNL_MSG_TYPE` uapi nfnetlink.h,
    ///
    /// See: <https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink.h#L46-L47>
    ///
    /// Both rejection guards mirror the kernel's message dispatcher, which rejects unknown subsystems and unknown operations the same way
    /// See: <https://github.com/torvalds/linux/blob/master/net/netfilter/nfnetlink.c#L144-L163>
    ///
    /// Also See: <https://github.com/google/nftables/blob/master/types.go#L134-L146>
    ///
    /// ##### Examples
    /// ```
    /// use spacenft::types::{NftMsgType, NftMsgTypeError};
    ///
    /// // round trip: decode is the inverse of encode
    /// assert_eq!(
    ///     NftMsgType::parse_header_type(NftMsgType::NEW_RULE.header_type()),
    ///     Ok(NftMsgType::NEW_RULE)
    /// );
    ///
    /// // subsystem 0x0b (11) is nft_compat, not nftables
    /// assert_eq!(
    ///     NftMsgType::parse_header_type(0x0b06),
    ///     Err(NftMsgTypeError::WrongSubsystem(11))
    /// );
    ///
    /// // nftables subsystem, but operation 0x99 (153) is not a known type
    /// assert_eq!(
    ///     NftMsgType::parse_header_type(0x0a99),
    ///     Err(NftMsgTypeError::UnknownType(0x99))
    /// );
    /// ```
    pub fn parse_header_type(header_type: u16) -> Result<Self, NftMsgTypeError> {
        let subsys = (header_type >> 8) & 0xff;
        if subsys != NFNL_SUBSYS_NFTABLES {
            return Err(NftMsgTypeError::WrongSubsystem(subsys as u8));
        }
        let msg = header_type & 0xff;
        if msg >= Self::MAX.0 {
            return Err(NftMsgTypeError::UnknownType(msg as u8));
        }

        Ok(Self(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_known_types_round_trip() {
        let all = [
            NftMsgType::NEW_TABLE,
            NftMsgType::GET_TABLE,
            NftMsgType::DELETE_TABLE,
            NftMsgType::NEW_CHAIN,
            NftMsgType::GET_CHAIN,
            NftMsgType::DELETE_CHAIN,
            NftMsgType::NEW_RULE,
            NftMsgType::GET_RULE,
            NftMsgType::DELETE_RULE,
            NftMsgType::NEW_SET,
            NftMsgType::GET_SET,
            NftMsgType::DELETE_SET,
            NftMsgType::NEW_SET_ELEM,
            NftMsgType::GET_SET_ELEM,
            NftMsgType::DELETE_SET_ELEM,
            NftMsgType::NEW_GEN,
            NftMsgType::GET_GEN,
            NftMsgType::TRACE,
            NftMsgType::NEW_OBJ,
            NftMsgType::GET_OBJ,
            NftMsgType::DELETE_OBJ,
            NftMsgType::GET_OBJ_RESET,
            NftMsgType::NEW_FLOW_TABLE,
            NftMsgType::GET_FLOW_TABLE,
            NftMsgType::DELETE_FLOW_TABLE,
            NftMsgType::GET_RULE_RESET,
            NftMsgType::DESTROY_TABLE,
            NftMsgType::DESTROY_CHAIN,
            NftMsgType::DESTROY_RULE,
            NftMsgType::DESTROY_SET,
            NftMsgType::DESTROY_SET_ELEM,
            NftMsgType::DESTROY_OBJ,
            NftMsgType::DESTROY_FLOW_TABLE,
            NftMsgType::GET_SET_ELEM_RESET,
        ];

        for msg in all {
            assert_eq!(NftMsgType::parse_header_type(msg.header_type()), Ok(msg))
        }
    }

    /// The exact off-by-one boundary: 33 (0x21) is the last known type,
    /// 34 (MAX) must be rejected.
    #[test]
    fn max_is_the_reject_boundary() {
        assert_eq!(
            NftMsgType::parse_header_type(0x0a21),
            Ok(NftMsgType::GET_SET_ELEM_RESET)
        );
        assert_eq!(
            NftMsgType::parse_header_type(0x0a22),
            Err(NftMsgTypeError::UnknownType(34))
        );
    }

    /// External pin, from real kernel output: the NEWGEN reply in the
    /// original strace capture of the nft binary showed nlmsg_type 0x0a0f.
    /// If this fails, a constant's VALUE is wrong, round trips cannot catch that
    #[test]
    fn values_match_the_strace_capture() {
        assert_eq!(NftMsgType::NEW_GEN.header_type(), 0x0a0f);
    }
}
