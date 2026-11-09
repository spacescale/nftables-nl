#![cfg(target_os = "linux")]

mod common;

use common::{in_network_namespace, nft, test_table};
use nftables_nl::chain::{Chain, ChainHook, ChainPolicy, ChainPriority, ChainType};
use nftables_nl::{Conn, ConnError, Table, TableFamily};

fn regular_chain(name: &str, table: &Table) -> Chain {
    Chain {
        name: name.into(),
        table: table.clone(),
        hooknum: None,
        priority: None,
        chain_type: None,
        policy: None,
        device: None,
    }
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_chain_creates_regular_chain() {
    in_network_namespace("add_chain_creates_regular_chain", || {
        // Prepare an existing table independently of our library.
        nft(&["add", "table", "inet", "chain_test"]);

        let table = test_table("chain_test", TableFamily::INET);
        let chain = regular_chain("services", &table);

        let mut conn = Conn::new().expect("open connection");
        let mut batch = conn.batch();
        batch.add_chain(&chain).expect("queue regular chain");

        // Queueing alone must not change the kernel's ruleset.
        let before = nft(&["list", "table", "inet", "chain_test"]);
        assert!(
            !before.contains("chain services"),
            "chain exists before commit: {before}"
        );

        batch.commit().expect("commit regular chain");

        // Listing this exact chain fails if it was not created in this table.
        let after = nft(&["list", "chain", "inet", "chain_test", "services"]);
        assert!(after.contains("chain services {"), "missing chain: {after}");
        assert!(!after.contains("hook "), "regular chain must not have a hook: {after}");
        assert!(
            !after.contains("policy "),
            "regular chain must not have a policy: {after}"
        );
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_chain_creates_base_chain() {
    in_network_namespace("add_chain_creates_base_chain", || {
        nft(&["add", "table", "inet", "base_chain_test"]);
        let table = test_table("base_chain_test", TableFamily::INET);
        let mut conn = Conn::new().expect("open connection");

        for (name, hook, priority, chain_type, policy, expected) in [
            (
                "filter_input",
                ChainHook::INPUT,
                ChainPriority::RAW,
                ChainType::FILTER,
                Some(ChainPolicy::DROP),
                "type filter hook input priority -300; policy drop;",
            ),
            (
                "route_output",
                ChainHook::OUTPUT,
                ChainPriority::FILTER,
                ChainType::ROUTE,
                None, // The kernel defaults an omitted policy to ACCEPT.
                "type route hook output priority 0; policy accept;",
            ),
            (
                "nat_prerouting",
                ChainHook::PRE_ROUTING,
                ChainPriority::NAT_DEST,
                ChainType::NAT,
                Some(ChainPolicy::ACCEPT),
                "type nat hook prerouting priority -100; policy accept;",
            ),
        ] {
            let chain = Chain {
                hooknum: Some(hook),
                priority: Some(priority),
                chain_type: Some(chain_type),
                policy,
                ..regular_chain(name, &table)
            };
            let mut batch = conn.batch();
            batch.add_chain(&chain).expect("queue base chain");
            batch.commit().expect("commit base chain");

            // -y prints numeric priorities instead of names such as 'raw'.
            let actual = nft(&["-y", "list", "chain", "inet", &table.name, name]);
            assert!(actual.contains(expected), "unexpected base chain: {actual}");
        }
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_chain_creates_device_bound_chain() {
    in_network_namespace("add_chain_creates_device_bound_chain", || {
        // Every fresh network namespace has its own loopback interface.
        for (family, family_name, hook, hook_name) in [
            (TableFamily::NETDEV, "netdev", ChainHook::INGRESS, "ingress"),
            (TableFamily::NETDEV, "netdev", ChainHook::EGRESS, "egress"),
            (TableFamily::INET, "inet", ChainHook::INET_INGRESS, "ingress"),
        ] {
            let table_name = format!("device_{family_name}_{hook_name}");
            nft(&["add", "table", family_name, &table_name]);
            let table = test_table(&table_name, family);
            let chain = Chain {
                hooknum: Some(hook),
                priority: Some(ChainPriority::FILTER),
                chain_type: Some(ChainType::FILTER),
                policy: Some(ChainPolicy::ACCEPT),
                device: Some("lo".into()),
                ..regular_chain("device_chain", &table)
            };

            let mut conn = Conn::new().expect("open connection");
            let mut batch = conn.batch();
            batch.add_chain(&chain).expect("queue device-bound chain");
            batch.commit().expect("commit device-bound chain");

            let actual = nft(&["-y", "list", "chain", family_name, &table_name, &chain.name]);
            assert!(actual.contains(&format!("type filter hook {hook_name}")), "{actual}");
            assert!(
                actual.contains("device lo") || actual.contains("device \"lo\""),
                "{actual}"
            );
            assert!(actual.contains("priority 0; policy accept;"), "{actual}");
        }
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_chain_creates_table_and_chain_in_one_batch() {
    in_network_namespace("add_chain_creates_table_and_chain_in_one_batch", || {
        let table = test_table("table_and_chains", TableFamily::INET);
        let regular = regular_chain("services", &table);
        let base = Chain {
            hooknum: Some(ChainHook::INPUT),
            priority: Some(ChainPriority::FILTER),
            chain_type: Some(ChainType::FILTER),
            policy: Some(ChainPolicy::ACCEPT),
            ..regular_chain("input", &table)
        };

        let mut conn = Conn::new().expect("open connection");
        let mut batch = conn.batch();
        batch.add_table(&table).expect("queue table first");
        batch.add_chain(&regular).expect("queue regular chain");
        batch.add_chain(&base).expect("queue base chain");
        assert!(
            nft(&["list", "tables"]).is_empty(),
            "queueing must not create the table"
        );
        batch.commit().expect("create table and both chains atomically");

        let actual = nft(&["-y", "list", "table", "inet", &table.name]);
        assert!(actual.contains("flags dormant"), "{actual}");
        assert!(actual.contains("chain services {"), "{actual}");
        assert!(actual.contains("chain input {"), "{actual}");
        assert!(
            actual.contains("type filter hook input priority 0; policy accept;"),
            "{actual}"
        );
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_chain_preserves_existing_rules() {
    in_network_namespace("add_chain_preserves_existing_rules", || {
        nft(&["add", "table", "inet", "repeat_chain_test"]);
        let table = test_table("repeat_chain_test", TableFamily::INET);
        let regular = regular_chain("services", &table);
        let base = Chain {
            hooknum: Some(ChainHook::INPUT),
            priority: Some(ChainPriority::FILTER),
            chain_type: Some(ChainType::FILTER),
            policy: Some(ChainPolicy::ACCEPT),
            ..regular_chain("input", &table)
        };
        let mut conn = Conn::new().expect("open connection");

        for chain in [regular, base] {
            let mut batch = conn.batch();
            batch.add_chain(&chain).expect("queue chain");
            batch.commit().expect("create chain");
            nft(&["add", "rule", "inet", &table.name, &chain.name, "counter", "accept"]);

            let before = nft(&["list", "chain", "inet", &table.name, &chain.name]);
            assert!(
                before.contains("counter packets 0 bytes 0 accept"),
                "missing fixture rule: {before}"
            );
            let mut batch = conn.batch();
            batch.add_chain(&chain).expect("queue existing chain");
            batch.commit().expect("adding an existing chain succeeds");
            let after = nft(&["list", "chain", "inet", &table.name, &chain.name]);
            assert_eq!(after, before, "repeated addition must preserve the chain and its rules");
        }
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_chain_reports_missing_table() {
    in_network_namespace("add_chain_reports_missing_table", || {
        let table = test_table("missing_table", TableFamily::INET);
        let chain = regular_chain("services", &table);
        let mut conn = Conn::new().expect("open connection");
        let mut batch = conn.batch();
        // Local validation does not query the kernel for the table.
        batch.add_chain(&chain).expect("queue chain for a missing table");
        match batch.commit() {
            Err(ConnError::Kernel(error)) => assert_eq!(error.raw_os_error(), Some(2)), // ENOENT.
            other => panic!("expected kernel ENOENT, got {other:?}"),
        }
        assert!(
            nft(&["list", "tables"]).is_empty(),
            "the table must not be created implicitly"
        );
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_chain_failure_rolls_back_transaction_and_connection_remains_usable() {
    in_network_namespace(
        "add_chain_failure_rolls_back_transaction_and_connection_remains_usable",
        || {
            let table = test_table("must_roll_back", TableFamily::INET);
            let valid = regular_chain("services", &table);
            let missing = test_table("missing_table", TableFamily::INET);
            let invalid = regular_chain("cannot_create", &missing);
            let mut conn = Conn::new().expect("open connection");
            let mut batch = conn.batch();
            batch.add_table(&table).expect("queue table");
            batch.add_chain(&valid).expect("queue chain for the new table");
            batch.add_chain(&invalid).expect("queue chain for the missing table");
            match batch.commit() {
                Err(ConnError::Kernel(error)) => assert_eq!(error.raw_os_error(), Some(2)), // ENOENT.
                other => panic!("expected kernel ENOENT, got {other:?}"),
            }

            // The earlier valid table and chain must both have been rolled back.
            assert!(
                nft(&["list", "tables"]).is_empty(),
                "failed transaction left a table behind"
            );

            // Reuse the same connection after the failed transaction.
            let mut batch = conn.batch();
            batch.add_table(&table).expect("queue recovery table");
            batch.add_chain(&valid).expect("queue recovery chain");
            batch.commit().expect("commit after rejected transaction");
            let actual = nft(&["list", "chain", "inet", &table.name, &valid.name]);
            assert!(actual.contains("chain services {"), "{actual}");
        },
    );
}
