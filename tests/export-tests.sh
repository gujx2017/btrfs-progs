#!/bin/bash
# export the testsuite files to a separate tar

SCRIPT_DIR=$(dirname $(readlink -f "$0"))
TESTDIR=$(basename $SCRIPT_DIR)
FSSUM=fssum
CORRUPT=btrfs-corrupt-block
DESTNAME="tests.tar.gz"
DESTDIR="."

test -n "$EXPORT" && DESTDIR=$(realpath "$EXPORT")
if [ ! -d $DESTDIR ]; then
	echo "dest directory is not exsit."
	exit 1
fi

DEST=$DESTDIR/$DESTNAME

if [ -f $DEST ];then
	echo "remove exsit package: " $DEST
	rm $DEST
fi

echo "begin create tar:  " $DEST
tar --exclude-vcs-ignores -zScf $DEST $TESTDIR $FSSUM $CORRUPT
if [ $? -eq 0 ]; then
	echo "create tar successfully."
fi
