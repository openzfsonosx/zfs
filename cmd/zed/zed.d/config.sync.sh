#!/bin/sh
#
# Log the zevent via syslog.
#

# OS X notification script.
function notify {
	sudo -u "$(stat -f '%Su' /dev/console)" /usr/bin/osascript -e 'display notification "'"$1"'" with title "'"$2"'"'
}


if [ -d /etc/zfs ]; then

	if [ -f /etc/zfs/zpool.cache.tmp ]; then

	rm -f /etc/zfs/zpool.cache
	mv /etc/zfs/zpool.cache.tmp /etc/zfs/zpool.cache

	logger -t "${ZED_SYSLOG_TAG:=zed}" -p "${ZED_SYSLOG_PRIORITY:=daemon.notice}" \
	    eid="${ZEVENT_EID}" class="${ZEVENT_SUBCLASS}" \
	    "${ZEVENT_POOL:+pool=$ZEVENT_POOL}"

	notify "zpool.cache file has been renamed" "config.sync"

	fi
else
	mkdir -p /etc/zfs
fi

if [ -d /etc/zfs/caches ]; then
    for p in homepool Dual
    do
	if [ -f /etc/zfs/caches/${p}.cache.tmp ]
	then
	    rm -f /etc/zfs/caches/${p}.cache
	    mv /etc/zfs/caches/${p}.cache.tmp /etc/zfs/caches/${p}.cache

	    logger -t "${ZED_SYSLOG_TAG:=zed}" -p "${ZED_SYSLOG_PRIORITY:=daemon.notice}" \
		   eid="${ZEVENT_EID}" class="${ZEVENT_SUBCLASS}" \
		   "${ZEVENT_POOL:+pool=$ZEVENT_POOL}"

	    notify "${i} file has been renamed" "config.sync"

	fi
    done
else
    mkdir -p /etc/zfs/caches
fi
echo 0
