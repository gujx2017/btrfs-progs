#!/bin/bash
#
# qgroup show behaviour when quotas are not enabled

source "$TOP/tests/common"

check_prereq mkfs.btrfs
check_prereq btrfs

setup_root_helper
prepare_test_dev

run_check "$EXEC/mkfs.btrfs" -f "$TEST_DEV"
run_check_mount_test_dev
run_mayfail "$EXEC/btrfs" qgroup show "$TEST_MNT"
run_mayfail $SUDO_HELPER "$EXEC/btrfs" qgroup show "$TEST_MNT"
run_check $SUDO_HELPER "$EXEC/btrfs" quota enable "$TEST_MNT"
run_mayfail "$EXEC/btrfs" qgroup show "$TEST_MNT"
run_check $SUDO_HELPER "$EXEC/btrfs" qgroup show "$TEST_MNT"
run_check $SUDO_HELPER "$EXEC/btrfs" quota disable "$TEST_MNT"
run_check_umount_test_dev
