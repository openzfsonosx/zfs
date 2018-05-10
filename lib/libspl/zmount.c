/*-
 * Copyright (c) 2006 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This file implements Solaris compatible zmount() function.
 */


#ifdef __APPLE__

#include <sys/mount.h>
#include <sys/zfs_mount.h>
#include <libzfs_impl.h>

int
zmount(zfs_handle_t *zhp, const char *spec, const char *dir, int mflag,
	char *fstype, char *dataptr, int datalen, char *optptr, int optlen)
{
	int rv;
	struct zfs_mount_args mnt_args;
	char *rpath = NULL;
	assert(spec != NULL);
	assert(dir != NULL);
	assert(fstype != NULL);
	assert(mflag >= 0);
	assert(strcmp(fstype, MNTTYPE_ZFS) == 0);
	assert(dataptr == NULL);
	assert(datalen == 0);
	assert(optptr != NULL);
	assert(optlen > 0);
	zfs_cmd_t zc = { "\0" };
	int devdisk = ZFS_DEVDISK_POOLONLY;
	int ispool = 0;  // the pool dataset, that is


	/*
	 * Figure out if we want this mount as a /dev/diskX mount, if so
	 * ask kernel to create one for us, then use it to mount.
	 */

	// Use dataset name by default
	mnt_args.fspec = spec;

	/* Lookup the dataset property devdisk, and depending on its
	 * setting, we need to create a /dev/diskX for the mount
	 */
	if (zhp) {

		devdisk = zfs_prop_get_int(zhp,	ZFS_PROP_APPLE_DEVDISK);

		if (zhp && zhp->zpool_hdl &&
			!strcmp(zpool_get_name(zhp->zpool_hdl),
				zfs_get_name(zhp)))
			ispool = 1;

		if ((devdisk == ZFS_DEVDISK_ON) ||
			((devdisk == ZFS_DEVDISK_POOLONLY) &&
				ispool)) {

			(void)strlcpy(zc.zc_name, zhp->zfs_name, sizeof(zc.zc_name));
			zc.zc_value[0] = 0;

			rv = zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_PROXY_DATASET, &zc);

#ifdef DEBUG
			if (rv)
				fprintf(stderr, "proxy dataset returns %d '%s'\n",
					rv, zc.zc_value);
#endif

			// Mount using /dev/diskX, use temporary buffer to give it full
			// name
			if (rv == 0) {
				snprintf(zc.zc_name, sizeof(zc.zc_name),
					"/dev/%s", zc.zc_value);
				mnt_args.fspec = zc.zc_name;
			}
		}
	}

	mnt_args.mflag = mflag;
	mnt_args.optptr = optptr;
	mnt_args.optlen = optlen;
	mnt_args.struct_size = sizeof(mnt_args);

	/* There is a bug in XNU where /var/tmp is resolved as
	 * "private/var/tmp" without the leading "/", and both mount(2) and
	 * diskutil mount avoid this by calling realpath() first. So we will
	 * do the same.
	 */
	rpath = realpath(dir, NULL);

	dprintf("%s calling mount with fstype %s, %s %s, fspec %s, mflag %d,"
		" optptr %s, optlen %d, devdisk %d, ispool %d\n",
		__func__, fstype, (rpath ? "rpath" : "dir"),
		(rpath ? rpath : dir), mnt_args.fspec, mflag, optptr, optlen,
		devdisk, ispool);

	rv = mount(fstype, rpath ? rpath : dir, 0, &mnt_args);

	if (rpath) free(rpath);

	return rv;
}

#endif
