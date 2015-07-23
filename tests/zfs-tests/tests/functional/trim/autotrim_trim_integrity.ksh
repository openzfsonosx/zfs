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
#	Verify automatic trim and manual trim coexist correctly.
#
# STRATEGY:
#	1. Create a pool on the provided DISKS to trim.
#	2. Set autotrim=on to enable asynchronous pool trimming.
#	3. Generate some interesting pool data which can be trimmed.
#	4. While generating data issue manual trims.
#	4. Verify trim IOs of the expected type were issued for the pool.
#	5. Verify data integrity of the pool after trim.
#	6. Repeat test for striped, mirrored, and RAIDZ pools.

verify_runnable "global"

log_assert "Set 'autotrim=on', run 'zpool trim' and verify pool data integrity"

function cleanup
{
	if poolexists $TESTPOOL; then
		log_must zpool destroy -f $TESTPOOL
	fi

        log_must set_tunable64 zfs_trim_extent_bytes_min $trim_extent_bytes_min
        log_must set_tunable64 zfs_trim_txg_batch $trim_txg_batch
	log_must set_tunable64 zfs_vdev_min_ms_count $vdev_min_ms_count
}
log_onexit cleanup

DISK1="$(echo $DISKS | cut -d' ' -f1)"
DISK2="$(echo $DISKS | cut -d' ' -f2)"
DISK3="$(echo $DISKS | cut -d' ' -f3)"

# Minimum trim size is decreased to verity all trim sizes.
typeset trim_extent_bytes_min=$(get_tunable zfs_trim_extent_bytes_min)
log_must set_tunable64 zfs_trim_extent_bytes_min 4096

# Reduced zfs_trim_txg_batch to make trimming more frequent.
typeset trim_txg_batch=$(get_tunable zfs_trim_txg_batch)
log_must set_tunable64 zfs_trim_txg_batch 8

# Increased metaslabs to better simulate larger more realistic devices.
typeset vdev_min_ms_count=$(get_tunable zfs_vdev_min_ms_count)
log_must set_tunable64 zfs_vdev_min_ms_count 64

for type in "" "mirror" "raidz" "raidz2"; do
	log_must zpool create -f $TESTPOOL $type $DISK1 $DISK2 $DISK3
	log_must zpool set autotrim=on $TESTPOOL

	# Add and remove data from the pool in a random fashion in order
	# to generate a variety of interesting ranges to be auto trimmed.
	for n in {0..20}; do
		dir="/$TESTPOOL/autotrim-$((RANDOM % 10))"
		filesize=$((4096 + ((RANDOM * 691) % 524288) ))
		log_must rm -rf $dir
		log_must fill_fs $dir 20 10 $filesize 1 R
		zpool sync

		if [[ $((n % 4)) -eq 0 ]]; then
		        log_must zpool trim $TESTPOOL
		        wait_trim $TESTPOOL $DISK1 $DISK2 $DISK3
		fi
	done
	log_must du -hs /$TESTPOOL

	verify_trim_io $TESTPOOL "manual" 100
	verify_trim_io $TESTPOOL "auto" 100
	verify_pool $TESTPOOL

	log_must zpool destroy $TESTPOOL
done

log_pass "Automatic trim and manual trim coexistence successfully validated"
