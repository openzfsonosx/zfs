#!/bin/ksh -p
#
# CDDL HEADER START
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# CDDL HEADER END
#

#
# Copyright (c) 2019 by Tim Chase. All rights reserved.
# Copyright (c) 2019 Lawrence Livermore National Security, LLC.
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
