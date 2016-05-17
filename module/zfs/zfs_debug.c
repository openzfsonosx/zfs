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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2014 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/kstat.h>

#if !defined(_KERNEL) || !defined(__linux__)
list_t zfs_dbgmsgs;
int zfs_dbgmsg_size = 0;
kmutex_t zfs_dbgmsgs_lock;
int zfs_dbgmsg_maxsize = 4<<20; /* 4MB */
kstat_t *zfs_dbgmsg_kstat;

/*
 * By default only enable the internal ZFS debug messages when running
 * in userspace (ztest).  The kernel log must be manually enabled.
 *
 * # Enable the kernel debug message log.
 * echo 1 > /sys/module/zfs/parameters/zfs_dbgmsg_enable
 *
 * # Clear the kernel debug message log.
 * echo 0 >/proc/spl/kstat/zfs/dbgmsg
 */
#if defined(_KERNEL)
int zfs_dbgmsg_enable = 0;
#else
int zfs_dbgmsg_enable = 1;
#endif

static int
zfs_dbgmsg_headers(char *buf, size_t size)
{
	(void) snprintf(buf, size, "%-12s %-8s\n", "timestamp", "message");

	return (0);
}

static int
zfs_dbgmsg_data(char *buf, size_t size, void *data)
{
	zfs_dbgmsg_t *zdm = (zfs_dbgmsg_t *)data;

	(void) snprintf(buf, size, "%-12llu %-s\n",
	    (u_longlong_t) zdm->zdm_timestamp, zdm->zdm_msg);

	return (0);
}

static void *
zfs_dbgmsg_addr(kstat_t *ksp, loff_t n)
{
	zfs_dbgmsg_t *zdm = (zfs_dbgmsg_t *)ksp->ks_private;

	ASSERT(MUTEX_HELD(&zfs_dbgmsgs_lock));

	if (n == 0)
		ksp->ks_private = list_head(&zfs_dbgmsgs);
	else if (zdm)
		ksp->ks_private = list_next(&zfs_dbgmsgs, zdm);

	return (ksp->ks_private);
}

static void
zfs_dbgmsg_purge(int max_size)
{
	zfs_dbgmsg_t *zdm;
	int size;

	ASSERT(MUTEX_HELD(&zfs_dbgmsgs_lock));

	while (zfs_dbgmsg_size > max_size) {
		zdm = list_remove_head(&zfs_dbgmsgs);
		if (zdm == NULL)
			return;

		size = zdm->zdm_size;
		kmem_free(zdm, size);
		zfs_dbgmsg_size -= size;
	}
}

static int
zfs_dbgmsg_update(kstat_t *ksp, int rw)
{
	if (rw == KSTAT_WRITE)
		zfs_dbgmsg_purge(0);

	return (0);
}

void
zfs_panic_recover(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vcmn_err(zfs_recover ? CE_WARN : CE_PANIC, fmt, adx);
	va_end(adx);
}

/*
 * Debug logging is enabled by default for production kernel builds.
 * The overhead for this is negligible and the logs can be valuable when
 * debugging.  For non-production user space builds all debugging except
 * logging is enabled since performance is no longer a concern.
 */
void
zfs_dbgmsg_init(void)
{
#if !defined(_KERNEL) || !defined(__linux__)
	list_create(&zfs_dbgmsgs, sizeof (zfs_dbgmsg_t),
	    offsetof(zfs_dbgmsg_t, zdm_node));
	mutex_init(&zfs_dbgmsgs_lock, NULL, MUTEX_DEFAULT, NULL);

	zfs_dbgmsg_kstat = kstat_create("zfs", 0, "dbgmsg", "misc",
	    KSTAT_TYPE_RAW, 0, KSTAT_FLAG_VIRTUAL);
	if (zfs_dbgmsg_kstat) {
		zfs_dbgmsg_kstat->ks_lock = &zfs_dbgmsgs_lock;
		zfs_dbgmsg_kstat->ks_ndata = UINT32_MAX;
		zfs_dbgmsg_kstat->ks_private = NULL;
		zfs_dbgmsg_kstat->ks_update = zfs_dbgmsg_update;
		kstat_set_raw_ops(zfs_dbgmsg_kstat, zfs_dbgmsg_headers,
		    zfs_dbgmsg_data, zfs_dbgmsg_addr);
		kstat_install(zfs_dbgmsg_kstat);
	}
}

void
zfs_dbgmsg_fini(void)
{
	if (zfs_dbgmsg_kstat)
		kstat_delete(zfs_dbgmsg_kstat);

	mutex_enter(&zfs_dbgmsgs_lock);
	zfs_dbgmsg_purge(0);
	mutex_exit(&zfs_dbgmsgs_lock);
	mutex_destroy(&zfs_dbgmsgs_lock);
}

void
__zfs_dbgmsg(char *buf)
{
	zfs_dbgmsg_t *zdm;
	int size;

	size = sizeof (zfs_dbgmsg_t) + strlen(buf);
	zdm = kmem_zalloc(size, KM_SLEEP);
	zdm->zdm_size = size;
	zdm->zdm_timestamp = gethrestime_sec();
	strcpy(zdm->zdm_msg, buf);

	mutex_enter(&zfs_dbgmsgs_lock);
	list_insert_tail(&zfs_dbgmsgs, zdm);
	zfs_dbgmsg_size += size;
	zfs_dbgmsg_purge(MAX(zfs_dbgmsg_maxsize, 0));
	mutex_exit(&zfs_dbgmsgs_lock);
}

#ifdef _KERNEL
void
__dprintf(const char *file, const char *func, int line, const char *fmt, ...)
{
	const char *newfile;
	va_list adx;
	size_t size;
	char *buf;
	char *nl;

	(void) printf("ZFS_DBGMSG(%s):\n", tag);
	mutex_enter(&zfs_dbgmsgs_lock);
	for (zdm = list_head(&zfs_dbgmsgs); zdm;
	    zdm = list_next(&zfs_dbgmsgs, zdm))
		(void) printf("%s\n", zdm->zdm_msg);
	mutex_exit(&zfs_dbgmsgs_lock);
}
#endif
