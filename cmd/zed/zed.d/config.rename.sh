#!/bin/sh
#
# Log the zevent via syslog.
#
# Rename a newly kernel created cachefile (/etc/zfs/zpool.cache.tmp) to
# its intended name (/etc/zfs/zpool.cache).

# ZEVENT_CACHEFILE=/etc/zfs/zpool.cache
CACHEFILE="${ZEVENT_CACHEFILE}"

# We only handle filenames starting with /etc/zfs/
# (and /var/tmp /tmp for zfs-tester)
if [ -d /etc/zfs ]; then

    if [[ x"${CACHEFILE:0:9}" == x"/etc/zfs/" ||
			  x"${CACHEFILE:0:9}" == x"/var/tmp/" ||
			  x"${CACHEFILE:0:5}" == x"/tmp/" ]]; then

        if [ -f "${CACHEFILE}.tmp" ]; then

            mv -f "${CACHEFILE}.tmp" "${CACHEFILE}"

        fi
    fi
else
    mkdir -p /etc/zfs
fi
echo 0
