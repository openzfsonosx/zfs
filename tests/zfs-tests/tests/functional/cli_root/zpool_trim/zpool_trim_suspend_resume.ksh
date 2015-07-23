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
# Suspending and resuming trimming works.
#
# STRATEGY:
# 1. Create a one-disk pool.
# 2. Start trimming at 10MiB/s and verify that trimming is active.
# 3. Wait 3 seconds, then suspend trimming and verify that the progress
#    reporting says so.
# 4. Wait 5 seconds and ensure trimming progress doesn't advance.
# 5. Restart trimming and verify that the progress doesn't regress.
#

DISK1=${DISKS%% *}

log_must zpool create -f $TESTPOOL $DISK1
log_must zpool trim -r 10M $TESTPOOL

[[ -z "$(trim_progress $TESTPOOL $DISK1)" ]] && \
    log_fail "Trimming did not start"

sleep 5
log_must zpool trim -s $TESTPOOL
log_must eval "trim_prog_line $TESTPOOL $DISK1 | grep suspended"
progress="$(trim_progress $TESTPOOL $DISK1)"

sleep 3
[[ "$progress" -eq "$(trim_progress $TESTPOOL $DISK1)" ]] || \
        log_fail "Trimming progress advanced while suspended"

log_must zpool trim $TESTPOOL $DISK1
[[ "$progress" -le "$(trim_progress $TESTPOOL $DISK1)" ]] ||
        log_fail "Trimming progress regressed after resuming"

log_pass "Suspend + resume trimming works as expected"
