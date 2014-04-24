#!/bin/sh
#
# Log the zevent via syslog.
#

# Given POOL and DATASET name for ZVOL
# BSD_disk  for /dev/disk*
# BSD_rdisk for /dev/rdisk*
# Create symlink in
# /var/run/zfs/zvol/dsk/POOL/DATASET -> /dev/disk*
# /var/run/zfs/zvol/rdsk/POOL/DATASET -> /dev/rdisk*

ZVOL_ROOT="/var/run/zfs/zvol"

mkdir -p "${ZVOL_ROOT}/dsk/${ZEVENT_POOL}"
mkdir -p "${ZVOL_ROOT}/rdsk/${ZEVENT_POOL}"
# Remove them if they already exist. (ln -f is not portable)
rm -f "${ZVOL_ROOT}/dsk/${ZEVENT_POOL}/${ZEVENT_DATASET}"
rm -f "${ZVOL_ROOT}/rdsk/${ZEVENT_POOL}/${ZEVENT_DATASET}"
ln -s "/dev/${ZEVENT_BSD_DISK}" "${ZVOL_ROOT}/dsk/${ZEVENT_POOL}/${ZEVENT_DATASET}"
ln -s "/dev/${ZEVENT_BSD_RDISK}" "${ZVOL_ROOT}/rdsk/${ZEVENT_POOL}/${ZEVENT_DATASET}"

logger -t "${ZED_SYSLOG_TAG:=zed}" -p "${ZED_SYSLOG_PRIORITY:=daemon.notice}" \
	eid="${ZEVENT_EID}" class="${ZEVENT_SUBCLASS}" \
	"${ZEVENT_POOL:+pool=$ZEVENT_POOL}/${ZEVENT_DATASET} symlinked ${ZEVENT_BSD_DISK}"

echo 0
