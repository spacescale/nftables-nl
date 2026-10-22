pub mod chain;
// Packet parsing is portable, but the socket consumer only exists on Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod netlink;
pub mod table;
pub mod types;

#[cfg(target_os = "linux")]
pub mod conn;

#[cfg(target_os = "linux")]
pub use conn::{Conn, ConnError};

// Cross-platform types
pub use table::{Table, TableFamily, TableFlags};
