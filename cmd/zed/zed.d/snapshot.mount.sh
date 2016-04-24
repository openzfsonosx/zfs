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

${ZFS} mount "${ZEVENT_SNAPSHOT_NAME}"

if [ $? == 0 ]; then
	logger -t "${ZED_SYSLOG_TAG:=zed}" \
		-p "${ZED_SYSLOG_PRIORITY:=daemon.warning}" \
		"Snapshot mount ${ZEVENT_SNAPSHOT_NAME}"
	notify "Snapshot ${ZEVENT_SNAPSHOT_NAME} mounted." "Snapshot mount"
else
	code=$?
	logger -t "${ZED_SYSLOG_TAG:=zed}" \
		-p "${ZED_SYSLOG_PRIORITY:=daemon.warning}" \
		"Snapshot failed mount ${ZEVENT_SNAPSHOT_NAME} reason $code"
	notify "Snapshot ${ZEVENT_SNAPSHOT_NAME} failed to mount. (${code})" "Snapshot mount failed"
fi
echo 0
