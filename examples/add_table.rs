//! Adds a dormant INET table through an explicit batch transaction.

#[cfg(target_os = "linux")]
fn main() -> Result<(), nftables_nl::ConnError> {
    use nftables_nl::{Conn, Table, TableFamily, TableFlags};

    let mut conn = Conn::new()?;
    let table = Table::new("nftables_nl_example", TableFamily::INET).with_flags(TableFlags::DORMANT);

    let mut batch = conn.batch();
    batch.add_table(&table)?; // Validate and queue without sending.
    batch.commit()?; // Send the transaction and check kernel replies.

    println!("Committed addition of INET table {:?}.", table.name);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux to access nftables.");
}
