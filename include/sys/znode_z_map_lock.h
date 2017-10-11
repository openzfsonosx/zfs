/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2017, Sean Doran <smd@use.net>.  All rights reserved.
 */

/* z_is_mapped rw_lock utility functions */

static inline void
z_map_downgrade_lock(znode_t *zp, boolean_t *need_release, boolean_t *need_upgrade)
{
	if (!rw_write_held(&zp->z_map_lock))
		return;

	rw_downgrade(&zp->z_map_lock);
	*need_upgrade = B_TRUE;
}

static inline uint64_t
z_map_upgrade_lock(znode_t *zp, boolean_t *need_release, boolean_t *need_upgrade, const char *caller)
{
	uint64_t lock_tries = 0;

	if (*need_upgrade != B_TRUE)
		return(lock_tries);

	/* we start at 1 to skip 0 % x => true for all x */
	for (unsigned int i = 1; !rw_tryupgrade(&zp->z_map_lock); i++) {
		lock_tries++;
		if ((i % 512) == 0)
			printf("ZFS: %s: trying to upgrade z_map_lock (%d) for %s (held by %s)\n",
			    __func__, i, caller,
			    (zp->z_map_lock_holder != NULL)
			    ? zp->z_map_lock_holder
			    : "(NULL)");
		if (i > 1000000)
			panic("could not upgrade z_map_lock for %s", caller);
		if ((i % 10)==0)
			delay(2);
		else if ((i % 2)==0)
			kpreempt(KPREEMPT_SYNC);
	}

	zp->z_map_lock_holder = caller;
	*need_upgrade = B_FALSE;
	return(lock_tries);
}

static inline uint64_t
z_map_rw_lock(znode_t *zp, boolean_t *need_release, boolean_t *need_upgrade, const char *caller)
{
	uint64_t lock_tries = 0;

	if (rw_write_held(&zp->z_map_lock)) {
		printf("ZFS: %s: z_map_lock already held (for %s)\n", __func__, caller);
		*need_release = B_FALSE;
		*need_upgrade = B_FALSE;
		return (lock_tries);
	}

	/* we start at 1 to skip 0 % x => true for all x */
	for (unsigned int i=1; !rw_tryenter(&zp->z_map_lock, RW_WRITER) ; i++) {
		lock_tries++;
		if (i > 0 && (i % 512) == 0)
			printf("ZFS: %s: waiting for z_map_lock (%u) for %s (held by %s)\n",
			    __func__, i, caller,
			    (zp->z_map_lock_holder != NULL)
			    ? zp->z_map_lock_holder
			    : "(NULL)");
		if (i > 1000000) { // 2000 seconds for now, enough time to take manual intervention
			panic("could not acquire z_map_lock");
			break;
		}
		if ((i % 10)==0)
			delay(2);
		else if ((i % 2)==0)
			kpreempt(KPREEMPT_SYNC);
	}

	zp->z_map_lock_holder = caller;

	*need_release = B_TRUE;
	return (lock_tries);
}

static inline void
z_map_drop_lock(znode_t *zp, boolean_t *need_release, boolean_t *need_upgrade)
{
	if (*need_release == B_FALSE)
		return;

	VERIFY(rw_lock_held(&zp->z_map_lock));

	zp->z_map_lock_holder = NULL;

	rw_exit(&zp->z_map_lock);

	*need_release = B_FALSE;
}
