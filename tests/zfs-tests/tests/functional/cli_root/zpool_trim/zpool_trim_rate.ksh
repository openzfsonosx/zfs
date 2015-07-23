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
#	Verify 'zpool trim -r <rate>' rate limiting.
#
# STRATEGY:
#	1. Create a pool on a single disk.
#	2. Manually TRIM the pool with rate limiting.
#	3. Verify the TRIM can be suspended.
#	4. Restart the TRIM and verify the rate is preserved.
#
# NOTE: The tolerances and delays used in the test below are intentionally
# set be to fairly large since we are capping the maximum trim rate.  The
# actual trim rate can be lower.  The critical thing is that the trim rate
# is limited, the rate is preserved when resuming, and it can be changed.
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

LARGEFILE="$TESTDIR/largefile"

log_must mkdir "$TESTDIR"
log_must truncate -s 10G "$LARGEFILE"
log_must zpool create -f $TESTPOOL "$LARGEFILE"

# Start trimming at 200M/s for 5 seconds (approximately 10% of the pool)
log_must zpool trim -r 200M $TESTPOOL
log_must sleep 4
progress=$(trim_progress $TESTPOOL $LARGEFILE)
log_must zpool trim -s $TESTPOOL
log_must eval "trim_prog_line $TESTPOOL $LARGEFILE | grep suspended"
log_must within_tolerance 10 $progress 5

# Resuming trimming at 200M/s for 5 seconds (approximately 20% of the pool)
log_must zpool trim $TESTPOOL
log_must sleep 4
progress=$(trim_progress $TESTPOOL $LARGEFILE)
log_must zpool trim -s $TESTPOOL
log_must eval "trim_prog_line $TESTPOOL $LARGEFILE | grep suspended"
log_must within_tolerance 20 $progress 10

# Increase trimming to 600M/s for 5 seconds (approximately 50% of the pool)
log_must zpool trim -r 600M $TESTPOOL
log_must sleep 4
progress=$(trim_progress $TESTPOOL $LARGEFILE)
log_must zpool trim -s $TESTPOOL
log_must eval "trim_prog_line $TESTPOOL $LARGEFILE | grep suspended"
log_must within_tolerance 50 $progress 15

# Set maximum trim rate for 5 seconds (100% of the pool)
log_must zpool trim -r 1T $TESTPOOL
log_must sleep 4
progress=$(trim_progress $TESTPOOL $LARGEFILE)
log_must eval "trim_prog_line $TESTPOOL $LARGEFILE | grep complete"
log_must within_tolerance 100 $progress 0

log_pass "Manual TRIM rate throttles as expected"
