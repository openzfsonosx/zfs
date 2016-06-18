#!/bin/sh
#
# Log the zevent via syslog.
#

# OS X notification script.
function notify {
	sudo -u "$(stat -f '%Su' /dev/console)" /usr/bin/osascript -e 'display notification "'"$1"'" with title "'"$2"'"'
}

test -f "${ZED_ZEDLET_DIR}/zed.rc" && . "${ZED_ZEDLET_DIR}/zed.rc"

test -n "${ZEVENT_POOL}" || exit 5
test -n "${ZEVENT_SUBCLASS}" || exit 5

if [ "${ZEVENT_SUBCLASS}" = "zpool.import" ]; then
	cmd="import"
else
	cmd="export"
    rm -f "/var/run/zfs/zvol/dsk/${ZEVENT_POOL}/*"
    rm -f "/var/run/zfs/zvol/rdsk/${ZEVENT_POOL}/*"
fi

logger -t "${ZED_SYSLOG_TAG:=zed}" \
	-p "${ZED_SYSLOG_PRIORITY:=daemon.warning}" \
	"Pool $cmd ${ZEVENT_POOL}"
notify "Pool ${ZEVENT_POOL} ${cmd}ed." "Pool ${cmd}"

echo 0
