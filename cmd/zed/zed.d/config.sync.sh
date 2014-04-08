#!/bin/sh
#
# Log the zevent via syslog.
#
if [ -d /etc/zfs ]; then

    if [ -f /etc/zfs/zpool.cache.tmp ]; then

	rm -qf /etc/zfs/zpool.cache
	mv /etc/zfs/zpool.cache.tmp /etc/zfs/zpool.cache

	logger -t "${ZED_SYSLOG_TAG:=zed}" -p "${ZED_SYSLOG_PRIORITY:=daemon.notice}" \
	    eid="${ZEVENT_EID}" class="${ZEVENT_SUBCLASS}" \
	    "${ZEVENT_POOL:+pool=$ZEVENT_POOL}"

    fi

fi
echo 0
