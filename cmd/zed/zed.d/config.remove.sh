#!/bin/sh
#
# Log the zevent via syslog.
#

# ZEVENT_CACHEFILE=/etc/zfs/zpool.cache
CACHEFILE="${ZEVENT_CACHEFILE}"

if [ -d /etc/zfs ]; then

    if [[ x"${CACHEFILE:0:9}" == x"/etc/zfs/" ||
			  x"${CACHEFILE:0:9}" == x"/var/tmp/" ||
			  x"${CACHEFILE:0:5}" == x"/tmp/" ]]; then
		rm -f "${CACHEFILE}"
	fi
fi
echo 0
