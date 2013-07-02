#!/bin/bash
if [ -z "$1" -o -z "$2" -o -z "$3" ]; then
	echo "$(basename $0) <kversion> <version> <redhat path>" >&2;
	exit 1;
fi

KVERSION="$1";
RELEASE="$2";
NEW_RELEASE="$[RELEASE + 1]";
RHPATH="$3";

if [ -s "$RHPATH/linux-kernel-test.patch" ]; then
	echo "linux-kernel-test.patch is not empty, aborting" >&2;
	exit 1;
fi
sed -i -e "s/BUILD:=$RELEASE/BUILD:=$NEW_RELEASE/" $RHPATH/Makefile.common;

# update top Makefile
sed -i -e "s/RHEL_RELEASE\ =.*/RHEL_RELEASE\ =\ $NEW_RELEASE/" $RHPATH/../Makefile;

