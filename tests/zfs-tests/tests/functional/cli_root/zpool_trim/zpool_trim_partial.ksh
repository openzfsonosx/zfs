#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2017 by Tim Chase. All rights reserved.
# Copyright (c) 2017 Lawrence Livermore National Security, LLC.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zpool_trim/zpool_trim.kshlib

#
# DESCRIPTION:
#	Verify 'zpool trim -p' partial trim.
#
# STRATEGY:
#	1. Create a pool on a single disk and mostly fill it.
#	2. Expand the pool to create new unallocated metaslabs.
#	3. Run 'zpool trim -p' to only TRIM allocated space maps.
#	4. Verify the disk is least 90% of its original size.
#	5. Run 'zpool trim' to perform a full TRIM.
#	6. Verify the disk is less than 10% of its original size.a

function cleanup
{
	if poolexists $TESTPOOL; then
		destroy_pool $TESTPOOL
	fi

	if [[ -d "$TESTDIR" ]]; then
		rm -rf "$TESTDIR"
	fi

	log_must set_tunable64 zfs_trim_extent_bytes_min $trim_extent_bytes_min
	log_must set_tunable64 zfs_vdev_min_ms_count $vdev_min_ms_count
}
log_onexit cleanup

LARGESIZE=$((MINVDEVSIZE * 4))
LARGEFILE="$TESTDIR/largefile"

# The minimum number of metaslabs is increased in order to simulate the
# behavior of partial trimming on a more typically sized 1TB disk.
typeset vdev_min_ms_count=$(get_tunable zfs_vdev_min_ms_count)
log_must set_tunable64 zfs_vdev_min_ms_count 64

# Minimum trim size is decreased to verify all trim sizes.
typeset trim_extent_bytes_min=$(get_tunable zfs_trim_extent_bytes_min)
log_must set_tunable64 zfs_trim_extent_bytes_min 4096

log_must mkdir "$TESTDIR"
log_must truncate -s $LARGESIZE "$LARGEFILE"
log_must zpool create $TESTPOOL "$LARGEFILE"
log_must mkfile $((LARGESIZE * 0.80)) /$TESTPOOL/file
log_must zpool sync

new_size=$(du -B1 "$LARGEFILE" | cut -f1)
log_must test $new_size -le $LARGESIZE
log_must test $new_size -gt $(( floor(LARGESIZE * 0.70) ))

# Expand the pool to create new unallocated metaslabs.
log_must zpool export $TESTPOOL
log_must dd if=/dev/urandom of=$LARGEFILE conv=notrunc,nocreat \
    seek=$((LARGESIZE / (1024 * 1024))) bs=$((1024 * 1024)) \
    count=$((3 * LARGESIZE / (1024 * 1024)))
log_must zpool import -d $TESTDIR $TESTPOOL
log_must zpool online -e $TESTPOOL "$LARGEFILE"

new_size=$(du -B1 "$LARGEFILE" | cut -f1)
log_must test $new_size -gt $((4 * floor(LARGESIZE * 0.80) ))

# Perform a partial trim, we expect it to skip most of the new metaslabs
# which have never been used and therefore do not need be trimmed.
log_must zpool trim -p $TESTPOOL

while [[ "$(trim_progress $TESTPOOL $LARGEFILE)" -lt "100" ]]; do
	sleep 0.5
done
sleep 1
zpool sync

new_size=$(du -B1 "$LARGEFILE" | cut -f1)
log_must test $new_size -gt $((2 * LARGESIZE))

# Perform a full trim, all metaslabs will be trimmed the pool vdev
# size will be reduced but not down to its original size due to the
# space usage of the new metaslabs.
log_must zpool trim $TESTPOOL

while [[ "$(trim_progress $TESTPOOL $LARGEFILE)" -lt "100" ]]; do
	sleep 0.5
done

new_size=$(du -B1 "$LARGEFILE" | cut -f1)
log_must test $new_size -le $(( 2 * LARGESIZE))
log_must test $new_size -gt $(( floor(LARGESIZE * 0.70) ))

log_pass "Manual 'zpool trim -p' successfully trimmed pool"
