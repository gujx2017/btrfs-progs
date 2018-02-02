#!/bin/bash
# a long device name must pass the SSD test

source $TOP/tests/common

check_prereq mkfs.btrfs

setup_root_helper
prepare_test_dev

# prep device
dmname=\
btrfs-test-with-very-long-name-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
dmdev=/dev/mapper/$dmname

run_check truncate -s0 img
chmod a+w img
run_check truncate -s2g img

loopdev=`run_check_stdout $SUDO_HELPER losetup --find --show img`
run_check $SUDO_HELPER dmsetup create $dmname --table "0 1048576 linear $loopdev 0"

dmbase=`readlink -f $dmdev`
base=`basename "$dmbase"`
rot=/sys/class/block/$base/queue/rotational

# switch rotational
run_check cat $rot
echo 0 | run_check $SUDO_HELPER tee $rot
run_check cat $rot

# test
run_check_stdout $SUDO_HELPER $EXEC/mkfs.btrfs -f $@ $dmdev |
	grep -q 'SSD detected:.*yes' || _fail 'SSD not detected'
run_check $SUDO_HELPER $EXEC/btrfs inspect-internal dump-super $dmdev

# cleanup
run_check $SUDO_HELPER dmsetup remove $dmname
run_mayfail $SUDO_HELPER losetup -d $loopdev
run_check truncate -s0 img
rm img
