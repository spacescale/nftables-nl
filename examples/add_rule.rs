//! Adds a counter and accept rule in one batch transaction.

#[cfg(target_os = "linux")]
fn main() -> Result<(), nftables_nl::ConnError> {
    use nftables_nl::chain::Chain;
    use nftables_nl::rule::{Rule, Verdict};
    use nftables_nl::{Conn, Table, TableFamily, TableFlags};

    let mut conn = Conn::new()?;
    let table = Table::new("nftables_nl_rule_example", TableFamily::INET).with_flags(TableFlags::DORMANT);

    let chain = Chain::new("services", &table);
    let rule = Rule::new(&chain).counter().verdict(Verdict::Accept);

    let mut batch = conn.batch();
    batch.add_table(&table)?;
    batch.add_chain(&chain)?;
    batch.add_rule(&rule)?;
    batch.commit()?;

    println!(
        "Added a counter and accept rule to dormant INET table {:?}.",
        table.name
    );
    println!("Inspect: sudo nft list table inet {}", table.name);
    println!("Cleanup: sudo nft delete table inet {}", table.name);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux to access nftables.");
}
