//! Internal helpers for working with generic Netlink messages.
//!
//! The actual Netlink socket and packet formats are provided by
//! `netlink-sys` and `netlink-packet-core`. This module only contains
//! the small amount of glue needed by `nftables-nl`.
//!

use crate::types::NftMessage;
use netlink_packet_core::{DecodeError, NetlinkMessage};

const NETLINK_HEADER_LEN: usize = 16;
const NETLINK_ALIGN_TO: usize = 4;

/// Decodes every Netlink message contained in a single received datagram.
///
/// A Netlink datagram may contain more than one `nlmsghdr` message. Each
/// message carries its own length and is padded to a 4-byte boundary.
///
/// This helper walks those message boundaries and lets
/// `netlink-packet-core` deserialize each individual message.
pub(crate) fn decode_messages(data: &[u8]) -> Result<Vec<NetlinkMessage<NftMessage>>, DecodeError> {
    let mut messages = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let remaining = &data[offset..];

        // check that remaining message is enough for  a header
        if remaining.len() < NETLINK_HEADER_LEN {
            return Err(DecodeError::invalid_buffer(
                "netlink header",
                remaining.len(),
                NETLINK_HEADER_LEN,
            ));
        }

        // The kernel explicitly stores the total message length in the
        // first four bytes: `nlmsg_len`, the first field of `struct nlmsghdr`.
        // It is not computed from the contents; it is a number the kernel
        // wrote there. It counts the WHOLE message: these 4 length bytes,
        // the rest of the header, and the payload.
        let message_len = u32::from_ne_bytes(
            remaining[..4]
                .try_into()
                .expect("slice length checked above"),
        ) as usize;

        // The declared message length must be at least large enough
        // to contain the Netlink header itself.
        if message_len < NETLINK_HEADER_LEN {
            return Err(format!("invalid netlink message length: {message_len}").into());
        }
        // message len from first 4 bytes shouldn't be more than total bytes
        if message_len > remaining.len() {
            return Err(DecodeError::invalid_buffer(
                "netlink message",
                remaining.len(),
                message_len,
            ));
        }
        let message = NetlinkMessage::<NftMessage>::deserialize(&remaining[..message_len])?;
        messages.push(message);

        offset += align(message_len);
    }

    Ok(messages)
}

/// Rounds a Netlink message length up to its required 4-byte boundary.
///
/// Includes padding when advancing to the next message: 21 becomes 24,
/// while 24 stays 24. Adding 3 then clearing the lowest two bits rounds up.
const fn align(len: usize) -> usize {
    (len + NETLINK_ALIGN_TO - 1) & !(NETLINK_ALIGN_TO - 1)
}
