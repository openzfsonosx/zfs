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
# Miscellaneous complex sequences of operations function as expected.
#
# STRATEGY:
# 1. Create a pool with a two-way mirror.
# 2. Start trimming, offline, export, import, online and verify that
#    trimming state is preserved / trimming behaves as expected
#    at each step.
#

DISK1="$(echo $DISKS | cut -d' ' -f1)"
DISK2="$(echo $DISKS | cut -d' ' -f2)"

log_must zpool create -f $TESTPOOL mirror $DISK1 $DISK2

log_must zpool trim -r 128M $TESTPOOL $DISK1
log_must zpool offline $TESTPOOL $DISK1
progress="$(trim_progress $TESTPOOL $DISK1)"
[[ -z "$progress" ]] && log_fail "Trimming did not start"
log_mustnot eval "trim_prog_line $TESTPOOL $DISK1 | grep suspended"

log_must zpool export $TESTPOOL
log_must zpool import $TESTPOOL

new_progress="$(trim_progress $TESTPOOL $DISK1)"
[[ -z "$new_progress" ]] && log_fail "Trimming did not start after import"
[[ "$new_progress" -ge "$progress" ]] || \
    log_fail "Trimming lost progress after import"
log_mustnot eval "trim_prog_line $TESTPOOL $DISK1 | grep suspended"

log_must zpool online $TESTPOOL $DISK1
new_progress="$(trim_progress $TESTPOOL $DISK1)"
[[ "$new_progress" -ge "$progress" ]] || \
    log_fail "Trimming lost progress after online"

log_pass "Trimming behaves as expected at each step of:" \
    "trim + offline + export + import + online"
