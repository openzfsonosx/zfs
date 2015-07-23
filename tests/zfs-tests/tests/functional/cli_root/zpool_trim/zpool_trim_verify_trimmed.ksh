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
# Copyright (c) 2016 by Delphix. All rights reserved.
# Copyright (c) 2019 by Lawrence Livermore National Security, LLC.
#
. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zpool_initialize/zpool_initialize.kshlib
. $STF_SUITE/tests/functional/cli_root/zpool_trim/zpool_trim.kshlib

#
# DESCRIPTION:
# After trimming, the disk is actually trimmed.
#
# STRATEGY:
# 1. Create a one-disk pool using a sparse file.
# 2. Initialize the pool and verify the file vdev is no longer sparse.
# 3. Trim the pool and verify the file vdev is again sparse.
#

function cleanup
{
	if poolexists $TESTPOOL; then
		log_must zpool destroy -f $TESTPOOL
	fi

        if [[ -d "$TESTDIR" ]]; then
                rm -rf "$TESTDIR"
        fi
}
log_onexit cleanup

SMALLFILE="$TESTDIR/smallfile"

log_must mkdir "$TESTDIR"
log_must truncate -s $MINVDEVSIZE "$SMALLFILE"
log_must zpool create $TESTPOOL "$SMALLFILE"

original_size=$(du -B1 "$SMALLFILE" | cut -f1)

log_must zpool initialize $TESTPOOL

while [[ "$(initialize_progress $TESTPOOL $SMALLFILE)" -lt "100" ]]; do
        sleep 0.5
done

new_size=$(du -B1 "$SMALLFILE" | cut -f1)
log_must within_tolerance $new_size $MINVDEVSIZE 33554432

log_must zpool trim $TESTPOOL

while [[ "$(trim_progress $TESTPOOL $SMALLFILE)" -lt "100" ]]; do
        sleep 0.5
done

new_size=$(du -B1 "$SMALLFILE" | cut -f1)
log_must within_tolerance $new_size $original_size 4194304

log_pass "Trimmed appropriate amount of disk space"
