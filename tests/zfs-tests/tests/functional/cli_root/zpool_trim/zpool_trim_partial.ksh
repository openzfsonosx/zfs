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
#	1. Create a pool on a single disk.
#	2. Run 'zpool trim -p' to only TRIM allocated space maps.
#	3. Verify the disk is least 90% of its original size.
#	4. Run 'zpool trim' to perform a full TRIM.
#	5. Verify the disk is less than 10% of its original size.a

function cleanup
{
	if poolexists $TESTPOOL; then
		log_must zpool destroy -f $TESTPOOL
	fi

	if [[ -d "$TESTDIR" ]]; then
		rm -rf "$TESTDIR"
	fi

	log_must set_tunable64 zfs_vdev_min_ms_count $vdev_min_ms_count
}
log_onexit cleanup

LARGESIZE=$((MINVDEVSIZE * 16))
LARGEFILE="$TESTDIR/largefile"

# The minimum number of metaslabs is increased in order to simulate the
# behavior of partial trimming on a more typically sized 1TB disk.
typeset vdev_min_ms_count=$(get_tunable zfs_vdev_min_ms_count)
log_must set_tunable64 zfs_vdev_min_ms_count 64

log_must mkdir "$TESTDIR"
log_must mkfile $LARGESIZE "$LARGEFILE"
log_must zpool create $TESTPOOL "$LARGEFILE"

typeset vdev_min_size=$(( floor(LARGESIZE * 0.20) ))
typeset vdev_max_size=$(( floor(LARGESIZE * 0.80) ))

new_size=$(du -B1 "$LARGEFILE" | cut -f1)
log_must test $new_size -gt $vdev_max_size

# Perform a partial trim.  For a newly create pool most metaslabs will
# never have been allocated from and therefore will not be trimmed
log_must zpool trim -p $TESTPOOL

while [[ "$(trim_progress $TESTPOOL $LARGEFILE)" -lt "100" ]]; do
        sleep 0.5
done

new_size=$(du -B1 "$LARGEFILE" | cut -f1)
log_must test $new_size -gt $vdev_max_size

# Perform a full trim.  In this case all metaslabs will be trimmed.
log_must zpool trim $TESTPOOL

while [[ "$(trim_progress $TESTPOOL $LARGEFILE)" -lt "100" ]]; do
        sleep 0.5
done

new_size=$(du -B1 "$LARGEFILE" | cut -f1)
log_must test $new_size -lt $vdev_min_size

log_pass "Manual 'zpool trim -p' successfully trimmed pool"
