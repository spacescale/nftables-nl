#![cfg(target_os = "linux")]

use nftables_nl::{Conn, TableFamily};
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
