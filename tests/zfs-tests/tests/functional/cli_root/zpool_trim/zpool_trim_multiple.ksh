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
. $STF_SUITE/tests/functional/cli_root/zpool_trim/zpool_trim.kshlib

#
# DESCRIPTION:
# Trimming can be performed multiple times
#
# STRATEGY:
# 1. Create a pool with a single disk.
# 2. Trim the entire pool.
# 3. Verify trimming is reset (status, offset, and action date).
# 4. Repeat steps 2 and 3 with the existing pool.
#

DISK1=${DISKS%% *}

log_must zpool create -f $TESTPOOL $DISK1

typeset action_date="none"
for n in {1..3}; do
	log_must zpool trim -r 2G $TESTPOOL
	log_mustnot eval "trim_prog_line $TESTPOOL $DISK1 | grep complete"

	[[ "$(trim_progress $TESTPOOL $DISK1)" -lt "100" ]] ||
	    log_fail "Trimming progress wasn't reset"

	new_action_date="$(trim_prog_line $TESTPOOL $DISK1 | \
	    sed 's/.*ed at \(.*\)).*/\1/g')"
	[[ "$action_date" != "$new_action_date" ]] ||
		log_fail "Trimming action date wasn't reset"
	action_date=$new_action_date

	while [[ "$(trim_progress $TESTPOOL $DISK1)" -lt "100" ]]; do
		progress="$(trim_progress $TESTPOOL $DISK1)"
		sleep 0.5
		[[ "$progress" -le "$(trim_progress $TESTPOOL $DISK1)" ]] ||
		    log_fail "Trimming progress regressed"
	done

	log_must eval "trim_prog_line $TESTPOOL $DISK1 | grep complete"
	sleep 1
done

log_pass "Trimming multiple times performs as expected"
