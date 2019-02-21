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
# Copyright (c) 2019 Lawrence Livermore National Security, LLC.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/trim/trim.kshlib

#
# DESCRIPTION:
#	Verify automatic trim pool data integrity.
#
# STRATEGY:
#	1. Create a pool on sparse file vdevs to trim.
#	2. Set autotrim=on to enable asynchronous pool trimming.
#	3. Generate some interesting pool data which can be trimmed.
#	4. Verify trim IOs of the expected type were issued for the pool.
#	5. Verify data integrity of the pool after trim.
#	6. Repeat test for striped, mirrored, and RAIDZ pools.

verify_runnable "global"

log_assert "Set 'autotrim=on' pool property verify pool data integrity"

function cleanup
{
	if poolexists $TESTPOOL; then
		log_must zpool destroy -f $TESTPOOL
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

# Minimum trim size is decreased to verity all trim sizes.
typeset trim_extent_bytes_min=$(get_tunable zfs_trim_extent_bytes_min)
log_must set_tunable64 zfs_trim_extent_bytes_min 4096

# Reduced zfs_trim_txg_batch to make trimming more frequent.
typeset trim_txg_batch=$(get_tunable zfs_trim_txg_batch)
log_must set_tunable64 zfs_trim_txg_batch 8

# Increased metaslabs to better simulate larger more realistic devices.
typeset vdev_min_ms_count=$(get_tunable zfs_vdev_min_ms_count)
log_must set_tunable64 zfs_vdev_min_ms_count 64

for type in "" "mirror" "raidz" "raidz2" "raidz3"; do
	log_must truncate -s 1G $TRIM_VDEVS

	log_must zpool create -f $TESTPOOL $type $TRIM_VDEVS
	log_must zpool set autotrim=on $TESTPOOL

	# Add and remove data from the pool in a random fashion in order
	# to generate a variety of interesting ranges to be auto trimmed.
	for n in {0..20}; do
		dir="/$TESTPOOL/autotrim-$((RANDOM % 10))"
		filesize=$((4096 + ((RANDOM * 691) % 262144) ))
		log_must rm -rf $dir
		log_must fill_fs $dir 10 10 $filesize 1 R
		zpool sync
	done
	log_must du -hs /$TESTPOOL

	verify_trim_io $TESTPOOL "ind" 1000
	verify_pool $TESTPOOL

	log_must zpool destroy $TESTPOOL
	log_must rm -f $TRIM_VDEVS
done

log_pass "Automatic trim successfully validated"
