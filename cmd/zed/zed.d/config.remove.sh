#!/bin/sh
#
# Log the zevent via syslog.
#


if [ -d /etc/zfs ]; then

	rm -f /etc/zfs/zpool.cache

	logger -t "${ZED_SYSLOG_TAG:=zed}" -p "${ZED_SYSLOG_PRIORITY:=daemon.notice}" \
	    eid="${ZEVENT_EID}" class="${ZEVENT_SUBCLASS}" \
	    "${ZEVENT_POOL:+pool=$ZEVENT_POOL}"

	fi

fi
echo 0
