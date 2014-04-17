#!/bin/sh
#
# Log the zevent via syslog.
#

# OS X notification script.
function notify {
	/usr/bin/osascript -e 'display notification "'"$1"'" with title "'"$2"'"'
}


if [ -d /etc/zfs ]; then

	rm -f /etc/zfs/zpool.cache

	logger -t "${ZED_SYSLOG_TAG:=zed}" -p "${ZED_SYSLOG_PRIORITY:=daemon.notice}" \
	    eid="${ZEVENT_EID}" class="${ZEVENT_SUBCLASS}" \
	    "${ZEVENT_POOL:+pool=$ZEVENT_POOL}"

	notify "zpool.cache file has been removed" "config.sync"

	fi

fi
echo 0
