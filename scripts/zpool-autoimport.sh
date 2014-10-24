#!/bin/bash

export ZFS_DEV=/dev/zfs
export ZED_PROG_NAME=zed
export ZED_PATH=/usr/local/sbin/${ZED_PROG_NAME}
export ERRNO_PATH=/usr/include/sys/errno.h
export ZFS=/usr/local/sbin/zfs
export ZPOOL=/usr/local/sbin/zpool
export ZPOOL_CACHE=/etc/zfs/zpool.cache

[ -f "$ZPOOL_CACHE" ] && cp "$ZPOOL_CACHE" "$ZPOOL_CACHE".bak

syslog_echo()
{
	/usr/bin/syslog -s -l notice "$1"
}

errno_exit()
{
	str_error=$1
	numeric_val=$(awk -v pat=$str_error '$0 ~ pat{print $3}' "$ERRNO_PATH")
	exit "$numeric_val"
}

if [ ! -c "$ZFS_DEV" -o x"$(pgrep "$ZED_PROG_NAME")" = x ] ; then
	sleep 2
	if [ ! -c "$ZFS_DEV" ] ; then
		if [ -d /Library/Extensions/spl.kext\
		    -a -d /Library/Extensions/zfs.kext ] ; then
			/sbin/kextload /Library/Extensions/spl.kext
			/sbin/kextload -d /Library/Extensions/spl.kext\
			    /Library/Extensions/zfs.kext
		elif [ -d /System/Library/Extensions/spl.kext\
		    -a -d /System/Library/Extensions/zfs.kext ] ; then
			/sbin/kextload /System/Library/Extensions/spl.kext
			/sbin/kextload -d /System/Library/Extensions/spl.kext\
			    /System/Library/Extensions/zfs.kext
		fi
		sleep 2
		if [ ! -c "$ZFS_DEV" ] ; then
			syslog_echo "/dev/zfs does not exist"
			errno_exit ENOENT
		fi
	fi
	if [ x"$(pgrep "$ZED_PROG_NAME")" = x ] ; then
		sleep 2
		if [ x"$(pgrep "$ZED_PROG_NAME")" = x ] ; then
			"$ZED_PATH"
		fi
		if [ x"$(pgrep "$ZED_PROG_NAME")" = x ] ; then
			syslog_echo "zed not started yet"
			errno_exit ESRCH
		fi
	fi
fi

"$ZPOOL" list -H | awk -F '\t' -v faulted=FAULTED '$7 == faulted{print $1;}' |\
while read p ; do
	reimport_msg=$(printf "Trying to reimport %s\n" "$p")
	syslog_echo "$reimport_msg"
	"$ZPOOL" export "$p"
	rc=$?
	if [ $rc -ne 0 ] ; then
		msg=$(printf "Failed to export %s : error %s\n" "$p" "$rc")
		syslog_echo "$msg"
	else
		"$ZPOOL" import -N "$p"
		rc=$?
		if [ $rc -ne 0 ] ; then
			msg=$(printf "Failed to re-import %s : error %s\n" "$p" "$rc")
			syslog_echo "$msg"
		fi
	fi
done

"$ZFS" mount -a
rc=$?
if [ $rc -ne 0 ] ; then
	msg=$(printf "Trouble during 'zfs mount -a' : error %s\n" "$rc")
	syslog_echo "$msg"
fi
