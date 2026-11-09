use nftables_nl::{Table, TableFamily, TableFlags};
use std::env;
use std::process::Command;

/// Runs a test body in a child process with its own network namespace.
#[allow(clippy::expect_used)]
pub(super) fn in_network_namespace(test_name: &str, test_body: impl FnOnce()) {
    const CHILD_TEST: &str = "NFTABLES_NL_NAMESPACE_TEST";

    // The isolated child re-enters this test. Run its body instead of spawning another child.
    if env::var(CHILD_TEST).ok().as_deref() == Some(test_name) {
        test_body();
        return;
    }

    let executable = env::current_exe().expect("find the integration test executable");

    // Start this same test executable in a fresh network namespace.
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

pub(super) fn test_table(name: &str, family: TableFamily) -> Table {
    Table {
        name: name.into(),
        family,
        flags: TableFlags::DORMANT,
        use_count: 0,
        owner: None,
    }
}

// Runs nft inside the test's isolated network namespace.
#[allow(clippy::expect_used)]
pub(super) fn nft(args: &[&str]) -> String {
    let output = Command::new("nft").args(args).output().expect("run nft");

    assert!(
        output.status.success(),
        "nft {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    String::from_utf8(output.stdout).expect("nft output is UTF-8")
}
