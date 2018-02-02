#!/bin/bash

# iterate over all fuzzed images and run 'btrfs check', try various options to
# get more code coverage

source $TOP/tests/common

setup_root_helper
check_prereq btrfs

# redefine the one provided by common
check_image() {
	local image

	image=$1
	run_mayfail $EXEC/btrfs check -s 1 "$image"
	run_mayfail $EXEC/btrfs check --init-csum-tree "$image"
	run_mayfail $EXEC/btrfs check --init-extent-tree "$image"
	run_mayfail $EXEC/btrfs check --check-data-csum "$image"
	run_mayfail $EXEC/btrfs check --subvol-extents "$image"
	run_mayfail $EXEC/btrfs check --repair "$image"
}

check_all_images $TOP/tests/fuzz-tests/images

exit 0
