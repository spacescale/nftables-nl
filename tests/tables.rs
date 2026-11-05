#![cfg(target_os = "linux")]

use nftables_nl::{Conn, ConnError, Table, TableFamily, TableFlags};
use std::env;
use std::process::Command;

/// Run a test body in a child process with its own network namespace/
#[allow(clippy::expect_used)]
fn in_network_namespace(test_name: &str, test_body: impl FnOnce()) {
    const CHILD_TEST: &str = "NFTABLES_NL_NAMESPACE_TEST";

    // The isolated child re-enters this test . Run its body instead of spawning another child
    if env::var(CHILD_TEST).ok().as_deref() == Some(test_name) {
        test_body();
        return;
    }

    let executable = env::current_exe().expect("find the integration test executable");

    // Start this same test executable ina  fresh network namespace
    // Inherit stdout/err so the child failures are visible in CI.
    let status = Command::new("timeout")
        .args([
            "--kill-after=5s",
            "30s",
            "sudo",
            "-n",
            "--preserve-env=NFTABLES_NL_NAMESPACE_TEST",
            "unshare",
            "--net",
        ])
        .arg(executable)
        .args(["--exact", test_name, "--ignored", "--nocapture"])
        .env(CHILD_TEST, test_name)
        .status()
        .expect("start timeout command");

    assert!(
        status.success(),
        "isolated test {test_name} failed or timed out: {status}"
    );
}

fn test_table(name: &str, family: TableFamily) -> Table {
    Table {
        name: name.into(),
        family,
        flags: TableFlags::DORMANT,
        use_count: 0,
        owner: None,
    }
}

// Runs nft inside the test's isolated network namespace.
fn nft(args: &[&str]) -> String {
    let output = Command::new("nft").args(args).output().expect("run nft");

    assert!(
        output.status.success(),
        "nft {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    String::from_utf8(output.stdout).expect("nft output is UTF-8")
}

#[test]
#[ignore = "requires namespace privileges, unshare, and timeout"]
fn list_tables_returns_empty_in_empty_namespace() {
    in_network_namespace("list_tables_returns_empty_in_empty_namespace", || {
        // Created after entering the namespace, so this socket queries
        // that namespace's nftables ruleset.
        let mut conn = Conn::new().expect("open Netlink connection");

        let tables = conn.list_tables().expect("list tables");

        assert!(
            tables.is_empty(),
            "a fresh namespace should have no tables: {tables:#?}",
        );
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn list_tables_of_family_returns_only_matching_tables() {
    in_network_namespace("list_tables_of_family_returns_only_matching_tables", || {
        // Fixtures exist only inside this test's network namespace.
        for family in ["inet", "ip"] {
            let output = Command::new("nft")
                .args(["add", "table", family, "family_test"])
                .output()
                .expect("run nft; nftables must be installed");

            assert!(
                output.status.success(),
                "create {family} table: {}",
                String::from_utf8_lossy(&output.stderr),
            );
        }

        let mut conn = Conn::new().expect("open Netlink connection");

        // Query both families using the same connection.
        for family in [TableFamily::INET, TableFamily::IPV4] {
            let tables = conn
                .list_tables_of_family(family)
                .expect("list tables of requested family");

            assert_eq!(
                tables.len(),
                1,
                "expected exactly one table for {family:?}: {tables:#?}",
            );
            assert_eq!(tables[0].name, "family_test");
            assert_eq!(tables[0].family, family);
        }
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_table_creates_table() {
    in_network_namespace("add_table_creates_table", || {
        let mut conn = Conn::new().expect("open connection");
        let table = test_table("creation_test", TableFamily::INET);

        let mut batch = conn.batch();
        batch.add_table(&table).expect("queue table");
        batch.commit().expect("commit table");

        let mut observer = Conn::new().expect("open observer");
        let tables = observer.list_tables().expect("list tables");

        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].name, table.name);
        assert_eq!(tables[0].family, table.family);
        assert_eq!(tables[0].flags, table.flags);
        assert_eq!(tables[0].use_count, 0);
        assert_eq!(tables[0].owner, None);

        // Independent confirmation through the nft CLI.
        nft(&["list", "table", "inet", "creation_test"]);
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_existing_table_preserves_contents() {
    in_network_namespace("add_existing_table_preserves_contents", || {
        let mut conn = Conn::new().expect("open connection");
        let table = test_table("repeat_test", TableFamily::INET);

        let mut batch = conn.batch();
        batch.add_table(&table).expect("queue table");
        batch.commit().expect("create table");

        nft(&["add", "chain", "inet", "repeat_test", "keep_chain"]);
        nft(&["add", "rule", "inet", "repeat_test", "keep_chain", "counter"]);

        let before = nft(&["list", "table", "inet", "repeat_test"]);

        let mut batch = conn.batch();
        batch.add_table(&table).expect("queue existing table");
        batch.commit().expect("adding existing table succeeds");

        let after = nft(&["list", "table", "inet", "repeat_test"]);
        assert_eq!(after, before, "existing contents must be preserved");

        let tables = conn.list_tables().expect("list after repeated addition");
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].name, table.name);
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn batch_creates_multiple_tables() {
    in_network_namespace("batch_creates_multiple_tables", || {
        let mut conn = Conn::new().expect("open connection");

        // The same name is allowed in different families.
        let inet = test_table("batch_test", TableFamily::INET);
        let ipv4 = test_table("batch_test", TableFamily::IPV4);

        let mut batch = conn.batch();
        batch.add_table(&inet).expect("queue INET table");
        batch.add_table(&ipv4).expect("queue IPv4 table");
        batch.commit().expect("commit both tables");

        let mut observer = Conn::new().expect("open observer");
        let tables = observer.list_tables().expect("list tables");

        assert_eq!(tables.len(), 2);

        for expected in [&inet, &ipv4] {
            assert!(
                tables.iter().any(|actual| {
                    actual.name == expected.name && actual.family == expected.family && actual.flags == expected.flags
                }),
                "missing table {expected:?}: {tables:#?}",
            );
        }

        nft(&["list", "table", "inet", "batch_test"]);
        nft(&["list", "table", "ip", "batch_test"]);
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn rejected_batch_rolls_back_and_connection_remains_usable() {
    in_network_namespace("rejected_batch_rolls_back_and_connection_remains_usable", || {
        // Keep this connection alive so it retains table ownership.
        let mut owner = Conn::new().expect("open owner connection");
        let mut protected = test_table("owned_table", TableFamily::INET);
        protected.flags = TableFlags::DORMANT | TableFlags::OWNER;

        let mut batch = owner.batch();
        batch.add_table(&protected).expect("queue owned table");
        batch.commit().expect("create owned table");

        let mut conn = Conn::new().expect("open second connection");
        let first = test_table("must_roll_back", TableFamily::INET);
        let forbidden = test_table("owned_table", TableFamily::INET);

        let mut batch = conn.batch();
        batch.add_table(&first).expect("queue valid operation");
        batch.add_table(&forbidden).expect("ownership is checked by the kernel");

        match batch.commit() {
            Err(ConnError::Kernel(error)) => {
                assert_eq!(error.raw_os_error(), Some(1)); // EPERM.
            }
            other => panic!("expected kernel EPERM, got {other:?}"),
        }

        // The first operation must also have been rolled back.
        let tables = owner.list_tables().expect("inspect rollback");
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].name, "owned_table");

        // Reuse the connection that received the transaction error.
        let recovery = test_table("after_failure", TableFamily::INET);
        let mut batch = conn.batch();
        batch.add_table(&recovery).expect("queue recovery table");
        batch.commit().expect("commit after rejected transaction");

        let tables = conn.list_tables().expect("read after recovery");
        assert_eq!(tables.len(), 2);
        assert!(tables.iter().any(|table| table.name == "after_failure"));
        assert!(!tables.iter().any(|table| table.name == "must_roll_back"));

        nft(&["list", "table", "inet", "after_failure"]);
    });
}
