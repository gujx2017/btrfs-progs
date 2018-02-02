#!/bin/bash
# test commands of btrfs

source "$TOP/tests/common"

check_prereq btrfs

# returns 1
run_mayfail $EXEC/btrfs || true
run_check "$EXEC/btrfs" version
run_check "$EXEC/btrfs" version --
run_check "$EXEC/btrfs" help
run_check "$EXEC/btrfs" help --
run_check "$EXEC/btrfs" help --full
run_check "$EXEC/btrfs" --help
run_check "$EXEC/btrfs" --help --full
run_check "$EXEC/btrfs" --version
run_check "$EXEC/btrfs" --version --help
