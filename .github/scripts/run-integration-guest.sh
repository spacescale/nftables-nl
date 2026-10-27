#!/usr/bin/env bash
# vmtest runs this script inside the VM. No Cargo build or unit tests run here.
set -euo pipefail

expected_kernel=${1:?provide the expected kernel release}
test_executable=${2:?provide the integration test executable}

actual_kernel=$(uname -r)
echo "Guest kernel: $actual_kernel (expected $expected_kernel)"
test "$actual_kernel" = "$expected_kernel"
nft --version
export RUST_BACKTRACE=1

# This binary contains only tests/tables.rs. --ignored runs its privileged tests.
exec "$test_executable" --ignored --nocapture
