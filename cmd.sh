#!/bin/bash
cmd=$1
shift

topdir=`pwd`
for lib in nvpair uutil zpool zfs; do
	export DYLD_LIBRARY_PATH=$topdir/lib/lib${lib}/.libs:$DYLD_LIBRARY_PATH
done
for c in zdb zfs zpool ztest; do
	export PATH=${topdir}/cmd/${c}/.libs:$PATH
done

#echo PATH=$PATH
#echo DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH
exec ./cmd/$cmd/.libs/$cmd $*
