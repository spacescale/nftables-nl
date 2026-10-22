//! Netlink connection handling for the kernel's nftables subsystem.
//!
//! This module is responsible for opening and owning a
//! `NETLINK_NETFILTER` socket used to communicate with nftables.
//!
//! It provides:
//!
//! - [`Conn`], which owns the netlink socket.
//! - [`ConnError`], which reports socket, kernel, and decoding failures.
//!
//! The connection is bound with an automatically assigned netlink port ID and
//! no multicast group subscriptions.
//!
//! This module is only available on Linux because nftables and
//! `NETLINK_NETFILTER` are Linux kernel interfaces.

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use std::io;

mod tables;

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

/// Socket operations needed for nftables
///
/// Production uses a real Socket, Unit tests supplies a fake transport
trait Transport {
    fn send_request(&mut self, bytes: &[u8]) -> io::Result<usize>;

    fn receive_reply(&mut self) -> io::Result<(Vec<u8>, SocketAddr)>;
}

impl Transport for Socket {
    fn send_request(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let kernel = SocketAddr::new(0, 0);
        self.send_to(bytes, &kernel, 0)
    }

    fn receive_reply(&mut self) -> io::Result<(Vec<u8>, SocketAddr)> {
        self.recv_from_full()
    }
}

/// A netlink connection to the kernel's nftables subsystem.
#[derive(Debug)]
pub struct Conn {
    socket: Socket,
}

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_bind() {
        let conn = Conn::new();
        assert!(conn.is_ok(), "{conn:?}");
    }
}
