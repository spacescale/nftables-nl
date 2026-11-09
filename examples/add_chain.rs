//! Adds a base chain and a regular chain in one batch transaction.

#[cfg(target_os = "linux")]
use nftables_nl::ConnError;

#[cfg(target_os = "linux")]
fn main() -> Result<(), ConnError> {
    use nftables_nl::chain::{Chain, ChainHook, ChainPolicy, ChainPriority, ChainType};
    use nftables_nl::{Conn, Table, TableFamily, TableFlags};

    let mut conn = Conn::new()?;

    let table = Table {
        name: "nftables_nl_chain_example".into(),
        family: TableFamily::INET,
        flags: TableFlags::DORMANT, // Disable packet processing for this table.
        use_count: 0,
        owner: None,
    };

    // A base chain attached to the INPUT hook
    let input = Chain {
        name: "input".into(),
        table: table.clone(),
        hooknum: Some(ChainHook::INPUT),
        priority: Some(ChainPriority::FILTER),
        chain_type: Some(ChainType::FILTER),
        policy: Some(ChainPolicy::ACCEPT),
        device: None,
    };

    // A regular chain, with no hook attachment.
    let services = Chain {
        name: "services".into(),
        table: table.clone(),
        hooknum: None,
        priority: None,
        chain_type: None,
        policy: None,
        device: None,
    };

    let mut batch = conn.batch();
    // Queue the table before the chains that belong to it.
    batch.add_table(&table)?;
    batch.add_chain(&input)?;
    batch.add_chain(&services)?;

    // Apply all three operations as one transaction.
    batch.commit()?;

    println!(
        "Created chains {:?} and {:?} in INET table {:?}.",
        input.name, services.name, table.name
    );

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux to access nftables.");
}
