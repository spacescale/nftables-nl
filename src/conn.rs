//! Netlink connection handling for the kernel's nftables subsystem.
//!
//! This module is responsible for opening and owning a
//! `NETLINK_NETFILTER` socket used to communicate with nftables.
//!
//! It provides:
//!
//! - `Conn` (Linux only), which owns the netlink socket.
//! - [`ConnError`], which reports socket, kernel, and decoding failures.
//!
//! The connection is bound with an automatically assigned netlink port ID and
//! no multicast group subscriptions.
//!
//! The connection is only available on Linux because nftables and
//! `NETLINK_NETFILTER` are Linux kernel interfaces. Error types are portable.

#[cfg(target_os = "linux")]
use crate::netlink::decode_messages;
#[cfg(target_os = "linux")]
use crate::table::{Table, TableFamily};
#[cfg(target_os = "linux")]
use crate::types::{NfGenMsg, NftMessage, NftMsgType};
#[cfg(target_os = "linux")]
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
#[cfg(target_os = "linux")]
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    #[error(transparent)]
    Socket(io::Error),

    #[error(transparent)]
    Bind(io::Error),

    #[error(transparent)]
    Send(io::Error),

    #[error(transparent)]
    Recv(io::Error),

    #[error(transparent)]
    Decode(netlink_packet_core::DecodeError),

    #[error(transparent)]
    Kernel(io::Error),

    #[error(transparent)]
    TableDecode(#[from] crate::table::TableDecodeError),

    #[error("netlink data was lost during the table dump")]
    Overrun,

    #[error("table dump was interrupted")]
    DumpInterrupted,

    #[error("unexpected nftables message type: {0:?}")]
    UnexpectedMessageType(u16),
}

/// A netlink connection to the kernel's nftables subsystem.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Conn {
    socket: Socket,
}

#[cfg(target_os = "linux")]
impl Conn {
    /// Opens a NETLINK_NETFILTER socket and binds it, letting the kernel
    /// assign our port ID.
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// # {
    /// use nftables_nl::Conn;
    ///
    /// let conn = Conn::new()?;
    /// # let _ = conn;
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new() -> Result<Self, ConnError> {
        let mut socket = Socket::new(NETLINK_NETFILTER).map_err(ConnError::Socket)?;

        socket.bind_auto().map_err(ConnError::Bind)?;

        Ok(Self { socket })
    }

    /// Returns all currently configured nftables.
    pub fn list_tables(&mut self) -> Result<Vec<Table>, ConnError> {
        self.list_tables_of_family(TableFamily::UNSPEC)
    }

    pub fn list_tables_of_family(&mut self, family: TableFamily) -> Result<Vec<Table>, ConnError> {
        let nfgen = NfGenMsg {
            nfgen_family: family.as_raw(),
            version: 0,
            res_id: 0,
        };

        let payload = NftMessage {
            message_type: NftMsgType::GET_TABLE.header_type(),
            data: nfgen.encode().to_vec(),
        };

        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        let mut message = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(payload));

        message.finalize(); // copies nft message header into the netlink header struct header field

        // magic where header type is copied into the netlink header
        let mut buf = vec![0u8; message.buffer_len()];
        message.serialize(&mut buf[..]);

        let kernel = SocketAddr::new(0, 0);
        self.socket
            .send_to(&buf, &kernel, 0)
            .map_err(ConnError::Send)?;

        let mut tables = Vec::new();

        // Outer loop: receive datagrams until the kernel says the dump is done.
        loop {
            let (reply, _) = self.socket.recv_from_full().map_err(ConnError::Recv)?;
            let messages = decode_messages(&reply).map_err(ConnError::Decode)?;
            for message in messages {
                // Check the reply header before handling its payload.
                if message.header.flags & NLM_F_DUMP_INTR != 0 {
                    return Err(ConnError::DumpInterrupted);
                }

                match message.payload {
                    NetlinkPayload::InnerMessage(nft_message) => {
                        // kernel treats all retuned table as new table
                        if nft_message.message_type != NftMsgType::NEW_TABLE.header_type() {
                            return Err(ConnError::UnexpectedMessageType(nft_message.message_type));
                        }

                        let table = Table::from_message(&nft_message)?;
                        tables.push(table);
                    }

                    NetlinkPayload::Done(done) if done.code == 0 => return Ok(tables),

                    NetlinkPayload::Overrun(_) => return Err(ConnError::Overrun),

                    // other exit code should fail
                    NetlinkPayload::Done(done) => {
                        return Err(ConnError::Kernel(io::Error::from_raw_os_error(-done.code)));
                    }

                    NetlinkPayload::Error(error) if error.code.is_some() => {
                        return Err(ConnError::Kernel(error.to_io()));
                    }

                    _ => {}
                }
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod test {
    use super::*;

    #[test]
    fn open_and_bind() {
        let conn = Conn::new();
        assert!(conn.is_ok(), "{conn:?}");
    }
}
