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


use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::socket::{
    AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, socket,
};
use std::fmt;
use std::fmt::Formatter;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};

#[derive(Debug)]
pub enum ConnError {
    /// socket(AF_NETLINK, ...) failed.
    Socket(Errno),
    /// bind() to the netlink address failed.
    Bind(Errno),
}

impl fmt::Display for ConnError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(e) => write!(f, "netlink socket creation failed: {e}"),
            Self::Bind(e) => write!(f, "netlink bind failed: {e}"),
        }
    }
}

// Integrates ConnError with Rust's standard error trait ecosystem
impl std::error::Error for ConnError {}

/// A netlink connection to the kernel's nftables subsystem.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Conn {
    socket: OwnedFd,
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
    /// use spacenft::Conn;
    ///
    /// let conn = Conn::new()?;
    /// # let _ = conn;
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new() -> Result<Self, ConnError> {
        // see socket syscall info: <https://man7.org/linux/man-pages/man2/socket.2.html>
        // see netlink ma7 <https://man7.org/linux/man-pages/man7/netlink.7.html>
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC, // prevent the socket fd from leaking into exec'd programs
            SockProtocol::NetlinkNetFilter,
        )
        .map_err(|e| ConnError::Socket(e))?;

        // bind(2): https://man7.org/linux/man-pages/man2/bind.2.html
        //
        // Binding assigns a local netlink address to this socket.
        // port_id = 0 lets the kernel assign one; groups = 0 subscribes to no multicast groups.
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0)).map_err(|e| ConnError::Bind(e))?;

        Ok(Self { socket: fd })
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
