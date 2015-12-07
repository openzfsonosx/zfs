#!/bin/bash
#
# $0 $commit --dry-run
#
# lundman

# Assume people run this from top of 'zfs', and ../openzfs is upstream
OPENZFS=../openzfs
MAP=scripts/zfs2osx-patch.sed

(cd $OPENZFS && git format-patch -1 $1 --stdout) > /tmp/patch.zfs
$MAP < /tmp/patch.zfs > /tmp/patch.o3x
git apply --check --ignore-space-change --ignore-whitespace --reject /tmp/patch.o3x

if [ $? = 0 ]; then

  if [ x"$2" = x"--apply" ]; then
	  git am --ignore-space-change --ignore-whitespace --reject /tmp/patch.o3x
	  exit $?
  fi
  echo "Re-run command with --apply to commit"
fi

