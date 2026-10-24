#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nftables_nl::{Conn, TableFamily};

    let mut conn = Conn::new()?;

    // List tables across all Netfilter families.
    println!("All tables:");
    for table in conn.list_tables()? {
        println!("{table:#?}");
    }

    // List only tables in the combined IPv4/IPv6 (inet) family.
    println!("INET tables:");
    for table in conn.list_tables_of_family(TableFamily::INET)? {
        println!("{table:#?}");
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux to access nftables.");
}
