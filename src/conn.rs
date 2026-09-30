//! Netlink connection handling for the kernel's nftables subsystem.
//!
//! This module is responsible for opening and owning a
//! `NETLINK_NETFILTER` socket used to communicate with nftables.
//!
//! It provides:
//!
//! - [`Conn`], which owns the netlink socket.
//! - [`ConnError`], which reports failures while creating or binding the socket.
//!
//! The connection is bound with an automatically assigned netlink port ID and
//! no multicast group subscriptions.
//!
//! This module is only available on Linux because nftables and
//! `NETLINK_NETFILTER` are Linux kernel interfaces.

#[cfg(target_os = "linux")]
use netlink_sys::{Socket, protocols::NETLINK_NETFILTER};
use std::fmt;
use std::fmt::Formatter;
use std::io;

use crate::table::{Table, TableFamily};
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub enum ConnError {
    Socket(io::Error),
    Bind(io::Error),
}

impl fmt::Display for ConnError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(e) => write!(f, "netlink socket creation failed: {e}"),
            Self::Bind(e) => write!(f, "netlink bind failed: {e}"),
        }
    }
}

impl std::error::Error for ConnError {}

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
        todo!()
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
