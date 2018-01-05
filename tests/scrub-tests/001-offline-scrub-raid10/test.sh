#!/bin/bash

source $TOP/tests/common

check_prereq mkfs.btrfs
check_prereq btrfs
check_prereq btrfs-debug-tree
check_prereq btrfs-map-logical

setup_root_helper

setup_loopdevs 4
prepare_loopdevs

dev1=${loopdevs[1]}
file=$TEST_MNT/file

mkfs_multi()
{
	run_check $SUDO_HELPER $TOP/mkfs.btrfs -f $@ ${loopdevs[@]}
}

#create filesystem
mkfs_multi -d raid10 -m raid10
run_check $SUDO_HELPER mount -t btrfs $dev1 "$TEST_MNT"

#write some data
run_check $SUDO_HELPER touch $file
run_check $SUDO_HELPER dd if=/dev/zero of=$file bs=64K count=1
run_check sync -f $file

#get the extent data's logical address of $file
logical=$($SUDO_HELPER $TOP/btrfs-debug-tree -t 5 $dev1 | grep -oP '(?<=byte\s)\d+')

#get the first physical address and device of $file's data
read physical dev< <($SUDO_HELPER $TOP/btrfs-map-logical -l $logical $dev1| head -1 |cut -d ' ' -f6,8)

#then modify the data
run_check $SUDO_HELPER dd if=/dev/random of=$dev seek=$(($physical/65536)) bs=64K count=1
run_check sync -f $file

run_check $SUDO_HELPER umount "$TEST_MNT"
log=$(run_check_stdout $SUDO_HELPER $TOP/btrfs scrub start --offline $dev1)
cleanup_loopdevs

#check result
result=$(echo $log | grep 'len 65536 REPARIED: has corrupted mirror, repaired')
if [[ -z "$result" ]] ;then
	_fail "scrub repair faild"
fi
