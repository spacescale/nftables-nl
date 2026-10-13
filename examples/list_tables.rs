#[cfg(target_os = "linux")]
use nftables_nl::Conn;
#[cfg(target_os = "linux")]
use nftables_nl::TableFamily;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nftables_nl::Conn;
    use nftables_nl::TableFamily;

    let mut conn = Conn::new()?;

    for table in conn.list_tables_of_family(TableFamily::INET)? {
        println!(
            "name={} family={} flags={} use_count={} owner={:?}",
            table.name,
            table.family.as_raw(),
            table.flags.as_raw(),
            table.use_count,
            table.owner
        )
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux to access nftables.");
}
