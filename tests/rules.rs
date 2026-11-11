#![cfg(target_os = "linux")]

mod common;

use common::{in_network_namespace, nft, test_table};
use nftables_nl::chain::Chain;
use nftables_nl::rule::{Expression, Rule, Verdict};
use nftables_nl::{Conn, ConnError, TableFamily};

fn regular_chain(table: &str, name: &str) -> Chain {
    Chain::new(name, &test_table(table, TableFamily::INET))
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_rule_appends_expressions_in_order() {
    in_network_namespace("add_rule_appends_expressions_in_order", || {
        nft(&["add", "table", "inet", "rule_test"]);
        nft(&["add", "chain", "inet", "rule_test", "test_chain"]);
        nft(&["add", "rule", "inet", "rule_test", "test_chain", "counter"]);

        let mut conn = Conn::new().expect("open connection");
        let chain = regular_chain("rule_test", "test_chain");
        let mut batch = conn.batch();
        for verdict in [Verdict::Accept, Verdict::Drop] {
            let rule = Rule::new(&chain).counter().verdict(verdict);
            batch.add_rule(&rule).expect("queue rule");
        }

        let before = nft(&["list", "chain", "inet", "rule_test", "test_chain"]);
        assert!(!before.contains("accept") && !before.contains("drop"), "{before}");
        batch
            .commit()
            .expect("commit rules after local rule values were dropped");

        let after = nft(&["list", "chain", "inet", "rule_test", "test_chain"]);
        let rules: Vec<_> = after
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("counter "))
            .collect();
        assert_eq!(
            rules,
            [
                "counter packets 0 bytes 0",
                "counter packets 0 bytes 0 accept",
                "counter packets 0 bytes 0 drop",
            ],
            "{after}"
        );
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_rule_creates_parents_and_preserves_batch_on_validation_error() {
    in_network_namespace(
        "add_rule_creates_parents_and_preserves_batch_on_validation_error",
        || {
            let mut conn = Conn::new().expect("open connection");
            let chain = regular_chain("rule_batch", "test_chain");
            let mut batch = conn.batch();
            batch.add_table(&chain.table).expect("queue table");
            batch.add_chain(&chain).expect("queue chain");

            let mut invalid = chain.clone();
            invalid.name = "bad\0name".into();
            let rule = Rule {
                chain: &invalid,
                expressions: vec![Expression::Verdict(Verdict::Drop)],
            };
            assert!(matches!(batch.add_rule(&rule), Err(ConnError::InvalidRule(_))));

            let rule = Rule {
                chain: &chain,
                expressions: vec![Expression::Verdict(Verdict::Accept)],
            };
            batch.add_rule(&rule).expect("queue valid rule");
            batch.commit().expect("commit parents and valid rule");

            let after = nft(&["list", "chain", "inet", "rule_batch", "test_chain"]);
            assert!(after.lines().any(|line| line.trim() == "accept"), "{after}");
            assert!(!after.contains("drop"), "{after}");
        },
    );
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_rule_repeated_additions_create_separate_rules() {
    in_network_namespace("add_rule_repeated_additions_create_separate_rules", || {
        nft(&["add", "table", "inet", "repeat_rule_test"]);
        nft(&["add", "chain", "inet", "repeat_rule_test", "test_chain"]);
        let chain = regular_chain("repeat_rule_test", "test_chain");
        let rule = Rule::new(&chain).counter().verdict(Verdict::Accept);
        let mut conn = Conn::new().expect("open connection");

        let mut batch = conn.batch();
        batch.add_rule(&rule).expect("queue first copy");
        batch.add_rule(&rule).expect("queue second copy");
        batch.commit().expect("commit two copies in one transaction");

        let after = nft(&["list", "chain", "inet", "repeat_rule_test", "test_chain"]);
        assert_eq!(
            after
                .lines()
                .filter(|line| line.trim() == "counter packets 0 bytes 0 accept")
                .count(),
            2,
            "repeated additions in one batch must create two rules: {after}",
        );

        let mut batch = conn.batch();
        batch
            .add_rule(&rule)
            .expect("queue another copy in a later transaction");
        batch.commit().expect("append another copy");
        let after = nft(&["list", "chain", "inet", "repeat_rule_test", "test_chain"]);
        assert_eq!(
            after
                .lines()
                .filter(|line| line.trim() == "counter packets 0 bytes 0 accept")
                .count(),
            3,
            "a later transaction must append without replacing existing rules: {after}",
        );
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_rule_reports_missing_parents_without_creating_them() {
    in_network_namespace("add_rule_reports_missing_parents_without_creating_them", || {
        let mut conn = Conn::new().expect("open connection");
        for table_exists in [false, true] {
            let table = if table_exists {
                "existing_parent"
            } else {
                "missing_parent"
            };
            if table_exists {
                nft(&["add", "table", "inet", table]);
            }
            let before = nft(&["list", "ruleset"]);
            let chain = regular_chain(table, "missing_chain");
            let rule = Rule::new(&chain).verdict(Verdict::Drop);
            let mut batch = conn.batch();
            // Parent existence is checked by the kernel, not by local validation.
            batch.add_rule(&rule).expect("queue rule referencing a missing parent");
            match batch.commit() {
                Err(ConnError::Kernel(error)) => assert_eq!(error.raw_os_error(), Some(2)), // ENOENT.
                other => panic!("expected kernel ENOENT, got {other:?}"),
            }
            assert_eq!(
                nft(&["list", "ruleset"]),
                before,
                "failed addition must not implicitly create a table or chain",
            );
        }
    });
}

#[test]
#[ignore = "requires namespace privileges, nft, unshare, and timeout"]
fn add_rule_kernel_failure_rolls_back_transaction_and_connection_remains_usable() {
    in_network_namespace(
        "add_rule_kernel_failure_rolls_back_transaction_and_connection_remains_usable",
        || {
            nft(&["add", "table", "inet", "existing_rule_table"]);
            nft(&["add", "chain", "inet", "existing_rule_table", "test_chain"]);
            nft(&[
                "add",
                "rule",
                "inet",
                "existing_rule_table",
                "test_chain",
                "counter",
                "accept",
            ]);
            let before = nft(&["list", "ruleset"]);

            let existing = regular_chain("existing_rule_table", "test_chain");
            let created = regular_chain("must_roll_back", "new_chain");
            let missing = regular_chain("existing_rule_table", "missing_chain");
            let mut conn = Conn::new().expect("open connection");
            let mut batch = conn.batch();
            batch
                .add_rule(&Rule::new(&existing).verdict(Verdict::Drop))
                .expect("queue valid addition to existing chain");
            batch.add_table(&created.table).expect("queue new table");
            batch.add_chain(&created).expect("queue new chain");
            batch
                .add_rule(&Rule::new(&created).counter().verdict(Verdict::Accept))
                .expect("queue valid rule for new chain");
            batch
                .add_rule(&Rule::new(&missing).verdict(Verdict::Drop))
                .expect("queue rule whose missing parent will cause kernel rejection");

            match batch.commit() {
                Err(ConnError::Kernel(error)) => assert_eq!(error.raw_os_error(), Some(2)), // ENOENT.
                other => panic!("expected kernel ENOENT, got {other:?}"),
            }
            assert_eq!(
                nft(&["list", "ruleset"]),
                before,
                "kernel rejection must undo earlier rules, chains, and tables while preserving existing state",
            );

            // Reuse the same connection after the kernel-rejected transaction.
            let mut batch = conn.batch();
            batch
                .add_rule(&Rule::new(&existing).verdict(Verdict::Drop))
                .expect("queue recovery rule");
            batch.commit().expect("commit recovery rule on the same connection");
            let after = nft(&["list", "chain", "inet", "existing_rule_table", "test_chain"]);
            let rules: Vec<_> = after
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("counter ") || *line == "drop")
                .collect();
            assert_eq!(rules, ["counter packets 0 bytes 0 accept", "drop"], "{after}");
        },
    );
}
