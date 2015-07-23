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
# Cancelling and suspending trim doesn't work if not all specified vdevs
# are being trimmed.
#
# STRATEGY:
# 1. Create a three-disk pool.
# 2. Start trimming and verify that trimming is active.
# 3. Try to cancel and suspend trimming on the non-trimming disks.
# 4. Try to re-trim the currently trimming disk.
#

DISK1=${DISKS%% *}
DISK2="$(echo $DISKS | cut -d' ' -f2)"
DISK3="$(echo $DISKS | cut -d' ' -f3)"

log_must zpool list -v
log_must zpool create -f $TESTPOOL $DISK1 $DISK2 $DISK3
log_must zpool trim -r 128M $TESTPOOL $DISK1

[[ -z "$(trim_progress $TESTPOOL $DISK1)" ]] && \
    log_fail "Trim did not start"

log_mustnot zpool trim -c $TESTPOOL $DISK2
log_mustnot zpool trim -c $TESTPOOL $DISK2 $DISK3

log_mustnot zpool trim -s $TESTPOOL $DISK2
log_mustnot zpool trim -s $TESTPOOL $DISK2 $DISK3

log_mustnot zpool trim $TESTPOOL $DISK1

log_pass "Nonsensical trim operations fail"
