#!/bin/bash
#
# coverage of balance --full-balance

source "$TOP/tests/common"

check_prereq mkfs.btrfs
check_prereq btrfs

setup_root_helper
prepare_test_dev

run_check "$EXEC/mkfs.btrfs" -f "$TEST_DEV"
run_check_mount_test_dev

run_check $SUDO_HELPER "$EXEC/btrfs" balance start --full-balance "$TEST_MNT"
run_check $SUDO_HELPER "$EXEC/btrfs" balance start "$TEST_MNT"
run_check $SUDO_HELPER "$EXEC/btrfs" balance --full-balance "$TEST_MNT"
run_check $SUDO_HELPER "$EXEC/btrfs" balance "$TEST_MNT"

run_check_umount_test_dev
