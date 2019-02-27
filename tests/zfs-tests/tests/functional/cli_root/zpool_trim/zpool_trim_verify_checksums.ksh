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
# Trimming does not cause file corruption.
#
# STRATEGY:
# 1. Create a one-disk pool.
# 2. Write data to the pool.
# 3. Start trimming and verify that trimming is active.
# 4. Write more data to the pool.
# 5. Run zdb to validate checksums.
#

DISK1=${DISKS%% *}

log_must zpool create -f $TESTPOOL $DISK1
log_must dd if=/dev/urandom of=/$TESTPOOL/file1 bs=1048576 count=30
log_must sync

log_must zpool trim $TESTPOOL

log_must zdb -cc $TESTPOOL

[[ -z "$(trim_progress $TESTPOOL $DISK1)" ]] && \
    log_fail "Trimming did not start"

log_must dd if=/dev/urandom of=/$TESTPOOL/file2 bs=1M count=30
log_must sync

log_must zdb -cc $TESTPOOL

log_pass "Trimming does not corrupt existing or new data"
