#!/bin/sh
#
# Log the zevent via syslog.
#

# OS X notification script.
function notify {
	sudo -u "$(stat -f '%Su' /dev/console)" /usr/bin/osascript -e 'display notification "'"$1"'" with title "'"$2"'"'
}

logger -t "${ZED_SYSLOG_TAG:=zed}" \
       -p "${ZED_SYSLOG_PRIORITY:=daemon.notice}" \
       eid="${ZEVENT_EID}" class="${ZEVENT_SUBCLASS}" \
       "${ZEVENT_POOL:+pool=$ZEVENT_POOL} ${CACHEFILE}"

notify "{$CACHEFILE} file has been renamed" "config.sync"

echo 0
