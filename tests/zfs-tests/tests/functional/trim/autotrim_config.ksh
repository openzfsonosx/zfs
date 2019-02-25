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
# Copyright (c) 2017 by Nexenta Systems, Inc. All rights reserved.
# Copyright (c) 2017 Lawrence Livermore National Security, LLC.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/trim/trim.kshlib

#
# DESCRIPTION:
# 	Check various pool geometries (raidz[1-3], mirror, stripe)
#
# STRATEGY:
#	1. Create a pool on file vdevs to trim.
#	2. Set 'autotrim=on' on pool.
#	3. Fill the pool to a known percentage of capacity.
#	4. Verify the vdevs contain 30% or more allocated blocks.
#	5. Remove all files making it possible to trim the entire pool.
#	6. Wait for auto trim to issue trim IOs for the free blocks.
#	4. Verify the disks contain 5% or less allocated blocks.
#	8. Repeat for test for striped, mirrored, and RAIDZ pools.

verify_runnable "global"

log_assert "Set 'autotrim=on' verify pool disks were trimmed"

function cleanup
{
	if poolexists $TESTPOOL; then
		destroy_pool $TESTPOOL
	fi

	log_must rm -f $TRIM_VDEVS

	log_must set_tunable64 zfs_trim_extent_bytes_min $trim_extent_bytes_min
	log_must set_tunable64 zfs_trim_txg_batch $trim_txg_batch
	log_must set_tunable64 zfs_vdev_min_ms_count $vdev_min_ms_count
}
log_onexit cleanup

TRIM_DIR="$TEST_BASE_DIR"
TRIM_VDEVS="$TRIM_DIR/trim-vdev1 $TRIM_DIR/trim-vdev2 \
    $TRIM_DIR/trim-vdev3 $TRIM_DIR/trim-vdev4"

# Minimum trim size is decreased to verify all trim sizes.
typeset trim_extent_bytes_min=$(get_tunable zfs_trim_extent_bytes_min)
log_must set_tunable64 zfs_trim_extent_bytes_min 4096

# Reduced zfs_trim_txg_batch to make trimming more frequent.
typeset trim_txg_batch=$(get_tunable zfs_trim_txg_batch)
log_must set_tunable64 zfs_trim_txg_batch 8

# Increased metaslabs to better simulate larger more realistic devices.
typeset vdev_min_ms_count=$(get_tunable zfs_vdev_min_ms_count)
log_must set_tunable64 zfs_vdev_min_ms_count 32

typeset VDEV_MAX_MB=$(( floor(4 * MINVDEVSIZE * 0.40 / 1024 / 1024) ))
typeset VDEV_MIN_MB=$(( floor(4 * MINVDEVSIZE * 0.30 / 1024 / 1024) ))

for type in "" "mirror" "raidz" "raidz2" "raidz3"; do
	log_must truncate -s $((4 * MINVDEVSIZE)) $TRIM_VDEVS
	log_must zpool create -f $TESTPOOL $type $TRIM_VDEVS
	log_must zpool set autotrim=on $TESTPOOL

	typeset availspace=$(get_prop available $TESTPOOL)
	typeset fill_mb=$(( floor(availspace * 0.95 / 1024 / 1024) ))

	# Fill the pool, verify the vdevs are no longer sparse.
	file_write -o create -f /$TESTPOOL/file -b 1048576 -c $fill_mb -d R
	verify_vdevs "-gt" "$VDEV_MAX_MB" $TRIM_VDEVS

	# Remove the file, wait for trim, verify the vdevs are now sparse.
	log_must rm /$TESTPOOL/file
	wait_trim_io $TESTPOOL "ind" 32
	verify_vdevs "-le" "$VDEV_MIN_MB" $TRIM_VDEVS

	log_must zpool destroy $TESTPOOL
	log_must rm -f $TRIM_VDEVS
done

log_pass "Auto trim successfully shrunk vdevs"
