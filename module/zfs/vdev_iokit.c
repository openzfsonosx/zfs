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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Portions Copyright 2007 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 * Copyright (C) 2008-2010 Lawrence Livermore National Security, LLC.
 * Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 * Rewritten for Linux by Brian Behlendorf <behlendorf1@llnl.gov>.
 * LLNL-CODE-403049.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/vdev_iokit.h>
#include <sys/vdev_impl.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>
#ifdef __APPLE__
#include <sys/mount.h>
#else
#include <sys/sunldi.h>
#endif /* __APPLE__ */


unsigned int zfs_iokit_vdev_ashift = 0;

extern void vdev_iokit_log(const char *);
extern void vdev_iokit_log_str(const char *, const char *);
extern void vdev_iokit_log_ptr(const char *, const void *);
extern void vdev_iokit_log_num(const char *, const uint64_t);

/*
 * Virtual device vector for disks via Mac OS X IOKit.
 */

int
vdev_iokit_alloc(vdev_iokit_t **dvd)
{
	if (!dvd) {
		return (EINVAL);
	}

	*dvd = (vdev_iokit_t *) kmem_alloc(sizeof (vdev_iokit_t), KM_PUSHPAGE);

	if (!dvd || !(*dvd))
		return (ENOMEM);

	(*dvd)->vd_iokit_hl = 0;
	(*dvd)->vd_zfs_hl = vdev_iokit_get_service();

	/*
	 * (*dvd)->in_command_pool = 0;
	 * (*dvd)->out_command_pool = 0;
	 * (*dvd)->command_set = 0;
	 */

	return (0);
}

void
vdev_iokit_free(vdev_iokit_t **dvd)
{
	if (!dvd)
		return;

	(*dvd)->vd_iokit_hl = 0;
	(*dvd)->vd_zfs_hl = 0;
	/*
	 * (*dvd)->in_command_pool = 0;
	 * (*dvd)->out_command_pool = 0;
	 * (*dvd)->command_set = 0;
	 */

	kmem_free(*dvd, sizeof (vdev_iokit_t));
	*dvd = 0;
}

extern void
vdev_iokit_state_change(vdev_t * vd, int faulted, int degraded)
{
	vdev_iokit_log_ptr("vdev_iokit_state_change: vd", vd);

}

extern int
vdev_iokit_open(vdev_t *vd, uint64_t *size,
				uint64_t *max_size, uint64_t *ashift)
{
	vdev_iokit_t *dvd = 0;
	int error = 0;
	uint64_t checkguid = 0;
	char * physpath = 0;

	if (!vd)
		return (EINVAL);

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}

	if (vd->vdev_tsd) {
		if (vd->vdev_reopening) {
			/*
			 * XXX - TO DO - Disabled the reopen logic to
			 *  resolve zpool scrub failure...
			 *  needs to be resolved
			 *
			 *	TESTING re-enabled
			 */
			dvd = (vdev_iokit_t *)(vd->vdev_tsd);
			goto skip_open;
		/*
		 *	} else {
		 *		error = EBUSY;
		 *		goto out;
		 */
		}
	}

	error = vdev_iokit_alloc((vdev_iokit_t **) &(vd->vdev_tsd));
	dvd = (vdev_iokit_t *)(vd->vdev_tsd);

	if (error != 0 || !dvd) {
		return (error != 0 ? error : ENOMEM);
	}

	/* When creating or splitting pools, don't validate guid */
	if (vd->vdev_spa->spa_load_state != SPA_LOAD_NONE &&
	    vd->vdev_spa->spa_splitting_newspa != B_TRUE) {
		checkguid = vd->vdev_guid;
	}

	/*
	 * When opening a disk device, we want to preserve the user's original
	 * intent. We always want to open the device by the path the user gave
	 * us, even if it is one of multiple paths to the same device. But we
	 * also want to be able to survive disks being removed/recabled.
	 * Therefore the sequence of opening devices is:
	 *
	 * 1. Try opening the device by path. For legacy pools without the
	 *	'whole_disk' property, attempt to fix the path by
	 *	appending 's0'.
	 *
	 * 2. If the devid of the device matches the stored value, return
	 *	success.
	 *
	 * 3. Otherwise, the device may have moved. Try opening the device
	 *	by the devid instead.
	 */

	error = EINVAL;		/* presume failure */

	if (vd->vdev_path != NULL) {

		if (vd->vdev_wholedisk == -1ULL) {
			size_t len = strlen(vd->vdev_path) + 3;
			char *buf = kmem_alloc(len, KM_PUSHPAGE);

			(void) snprintf(buf, len, "%ss0", vd->vdev_path);

			error = vdev_iokit_open_by_path(dvd, buf, checkguid);

			if (error == 0) {
				spa_strfree(vd->vdev_path);
				vd->vdev_path = buf;
				vd->vdev_wholedisk = 1ULL;
			} else {
				kmem_free(buf, len);
			}
		}

		/*
		 * If we have not yet opened the device, try to open it by the
		 * specified path.
		 */
		if (error != 0) {
			error = vdev_iokit_open_by_path(dvd, vd->vdev_path, checkguid);
		}

		/*
		 * If we succeeded in opening the device, but 'vdev_wholedisk'
		 * is not yet set, then this must be a slice.
		 */
		if (error == 0 && vd->vdev_wholedisk == -1ULL)
			vd->vdev_wholedisk = 0;
	}

	/*
	 * If all else fails, then try opening by physical path (if available)
	 * or the logical path (if we failed due to the devid check). While not
	 * as reliable as the devid, this will give us something, and the higher
	 * level vdev validation will prevent us from opening the wrong device.
	 */
	if (error) {

		if (vd->vdev_physpath != NULL) {
			error = vdev_iokit_open_by_path(dvd, vd->vdev_physpath, checkguid);
		}

		/*
		 * Note that we don't support the legacy auto-wholedisk support
		 * as above. This hasn't been used in a very long time and we
		 * don't need to propagate its oddities to this edge condition.
		 */
		if (error && vd->vdev_path != NULL) {
			error = vdev_iokit_open_by_path(dvd, vd->vdev_path, checkguid);
		}

		/*
		 * Since the vdev couldn't be easily located by path,
		 *	now we need to expand the search to all disks and
		 *	attempt to locate the vdev by guid, if known.
		 * This resolves the issue of disks being renumbered
		 *	on Mac OS X, for example when physical disks have
		 *	been re-cabled, moved, removed, or otherwise.
		 */
		if (error && vd->vdev_guid != 0) {
			error = vdev_iokit_open_by_guid(dvd, checkguid);

			if (error == 0) {
			/* Update vdev_path */
				physpath =				vdev_iokit_get_path(dvd);

				if (physpath && strlen(physpath) > 0) {
					/* Save physpath into vdev_path */
					vd->vdev_path =		spa_strdup(physpath);
				}

				if (physpath) {
					kmem_free(physpath, MAXPATHLEN);
					physpath = 0;
				}
			}
		}
	}

	/* If it couldn't be opened, back out now */
	if (error != 0) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (error);
	}

	/* Sync the disk if needed */
	error = vdev_iokit_sync(dvd, 0);

	if (error) {
		/* Ignore the error, but log it */
		vdev_iokit_log_num(
			"vdev_iokit_open: vdev_iokit_sync returned error",
			error);
	}

	/*
	 * Once a device is opened, verify that the physical device path (if
	 * available) is up to date.
	 */

	if (vdev_iokit_physpath(vd) != 0) {
		vdev_iokit_log("vdev_iokit_open: physpath couldn't be updated");
	}

skip_open:

	/*
	 * Determine the actual size of the device.
	 */
	if (vdev_iokit_get_size(dvd, size, max_size, ashift) != 0) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		error = ENXIO;
		goto out;
	}

#if 0 /* Disabled */
	/* Allocate command pools for async IO */
	if (!dvd->in_command_pool ||
		(spa_mode(vd->vdev_spa) > FREAD && !dvd->out_command_pool)) {

		/* Allocate several io_context objects */
		if (vdev_iokit_context_pool_alloc(dvd) != 0) {
			error = ENOMEM;
			goto out;
		}
	}
#endif /* Disabled */

	/*
	 * Done above in vdev_iokit_get_size
	 */
	/*
	 * Take the device's minimum transfer size into account.
	 */
	//	*ashift = highbit(MAX(blksize, SPA_MINBLOCKSIZE)) - 1;

	/*
	 * XXX - not being set here, but working normally with both
	 *  ashift=9 and ashift=12 (plus default ashift=0) pools...
	 */
	//	if (*ashift > 0)
	//		vd->vdev_ashift = *ashift;

	/*
	 * Clear the nowritecache bit, so that on a vdev_reopen() we will
	 * try again.
	 */
	vd->vdev_nowritecache = B_FALSE;

	/*
	 * ### APPLE TODO ###
	 * If we own the whole disk, try to enable disk write caching.
	 * FreeBSD geom can use write caching on individual partitions,
	 *  possibly same on OS X.
	 */

out:
	if (error != 0) {
		if (dvd->vd_iokit_hl) {
			vdev_iokit_handle_close(dvd, spa_mode(vd->vdev_spa));
		}

		/* Clear vdev_tsd, see below */
		vdev_iokit_free(&dvd);

		/*
		 * Since the open has failed, vd->vdev_tsd should
		 * be NULL when we get here, signaling to the
		 * rest of the spa not to try and reopen or close this device
		 */
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
	}

	return (0);
}

extern void
vdev_iokit_close(vdev_t *vd)
{
	vdev_iokit_t *dvd	= 0;
	int error			= 0;

	if (!vd || !vd->vdev_tsd)
		return;

	if (vd->vdev_reopening) {
		return;
	}

	dvd = (vdev_iokit_t *)vd->vdev_tsd;

	if (dvd->vd_iokit_hl != NULL) {
		/* Sync the disk if needed */
		if (!vd->vdev_nowritecache) {
			error = vdev_iokit_sync(dvd, 0);

			if (error) {
				/* Ignore the error, but log it */
				vdev_iokit_log_num(
					"vdev_iokit_close: couldn't sync disk",
					error);
			}
		}

		/* Close the iokit handle */
		error = vdev_iokit_handle_close(dvd, spa_mode(vd->vdev_spa));

		if (error) {
			/* Ignore the error, but log it */
			vdev_iokit_log_num(
				"vdev_iokit_close: handle_close returned error",
				error);
		}

		dvd->vd_iokit_hl = 0;
	}

#if 0 /* Disabled */
	/* Teardown context pool */
	vdev_iokit_context_pool_free(dvd);
#endif /* Disabled */

	vd->vdev_delayed_close = B_FALSE;

	vdev_iokit_free((vdev_iokit_t **) &(vd->vdev_tsd));
	vd->vdev_tsd = 0;
	dvd = 0;
}

extern int
vdev_iokit_io_start(zio_t *zio)
{
	vdev_t *vd = 0;
	vdev_iokit_t *dvd = 0;
	int error = 0;
	/*
	 * If the vdev is closed, it's likely in the REMOVED or FAULTED state.
	 * Nothing to be done here but return failure.
	 */
	if (!zio->io_vd || !zio->io_vd->vdev_tsd) {
		zio->io_error = ENXIO;
		return (ZIO_PIPELINE_CONTINUE);
	}

	vd = zio->io_vd;
	dvd = vd->vdev_tsd;

	if (zio->io_type == ZIO_TYPE_IOCTL) {

		if (!vdev_readable(vd)) {
			zio->io_error = SET_ERROR(ENXIO);
			return (ZIO_PIPELINE_CONTINUE);
		}

		switch (zio->io_cmd) {
		case DKIOCFLUSHWRITECACHE:

			if (zfs_nocacheflush)
				break;

			if (vd->vdev_nowritecache) {
				zio->io_error = SET_ERROR(ENOTSUP);
				break;
			}

			/* Use IOKit to sync the disk */
			error = vdev_iokit_sync(dvd, zio);

			if (error == 0) {
				/* Success */
				zio_interrupt(zio);

				/*
				 * Illumos sync is asynchronous
				 *	calls pipeline_stop once the
				 *	ioctl has been submitted, and
				 *	zio_interrupt when done.
				 *
				 * Mac OS X IOMedia::syncronizeCache
				 *	is synchronous.
				 * For now, the behavior is to call
				 *	zio_interrupt once the operation
				 *	completes, and return pipeline_stop
				 *	after the fact. Shouldn't affect
				 *	the order of zio exection.
				 */
				return (ZIO_PIPELINE_STOP);
			}

			zio->io_error = error;

			if (error == ENOTSUP || error == ENOTTY) {
				/*
				 * If we get ENOTSUP or ENOTTY, we know that
				 * no future attempts will ever succeed.
				 * In this case we set a persistent bit so
				 * that we don't bother with the ioctl in the
				 * future.
				 */
				vd->vdev_nowritecache = B_TRUE;
			}

			break;

		default:
			zio->io_error = SET_ERROR(ENOTSUP);
		}

		return (ZIO_PIPELINE_CONTINUE);
	}

	error = vdev_iokit_strategy(dvd, zio);
	if (error) {
		zio->io_error = error;
		return (ZIO_PIPELINE_CONTINUE);
	}

	return (ZIO_PIPELINE_STOP);
}

/*
 * After IO has completed (whether
 *	successful or failed), The zio
 *	is returned for handling by
 *	zio_interrupt. Once the zio
 *	stack is done, it callsback to
 *	vdev_iokit_io_done for any last
 *	minute teardown/error handling.
 */
extern void
vdev_iokit_io_done(zio_t *zio)
{
	vdev_t * vd = 0;

	if (!zio)
		return;

	vd = zio->io_vd;

	if (!vd)
		return;

	/*
	 * If the zio failed, check
	 *	the device status. If the
	 *	status check fails, queue
	 *	the vdev for removal.
	 */
	if (zio->io_error == EIO) {
		if (vdev_iokit_status(vd->vdev_tsd) != 0) {
			vd->vdev_remove_wanted = B_TRUE;
			spa_async_request(zio->io_spa, SPA_ASYNC_REMOVE);
		}
	}
}

/* Read configuration from disk */
int
vdev_iokit_read_label(vdev_iokit_t * dvd, nvlist_t **config)
{
	vdev_label_t *label = 0;
	size_t labelsize = VDEV_SKIP_SIZE + VDEV_PHYS_SIZE;
	uint64_t s = 0, size = 0;
	uint64_t offset, state, txg = 0;
	int l;
	int error = EINVAL;

	/*
	 * Read the device label and build the nvlist.
	 */

	if (!dvd || !dvd->vd_iokit_hl || !dvd->vd_zfs_hl)
		return (EINVAL);

	/* Open the IOKit handle */
	error = vdev_iokit_handle_open(dvd, FREAD);

	if (error != 0) {
		return (SET_ERROR(EIO));
	}

	if (vdev_iokit_get_size(dvd, &s, 0, 0) != 0) {
		/* Close the disk */
		(void) vdev_iokit_handle_close(dvd, FREAD);
		return (SET_ERROR(EIO));
	}

	size = P2ALIGN_TYPED(s, sizeof (vdev_label_t), uint64_t);
	label = kmem_alloc(sizeof (vdev_label_t), KM_PUSHPAGE);

	if (!label) {
		(void) vdev_iokit_handle_close(dvd, FREAD);
		return (ENOMEM);
	}

	*config = 0;
	for (l = 0; l < VDEV_LABELS; l++) {

		/* read vdev label */
		offset = vdev_label_offset(size, l, 0);

		/* If label is outside disk boundaries, we're done */
		if (offset > s || offset+labelsize > s) {
			break;
		}

		if (vdev_iokit_physio(dvd, (void*)label, labelsize,
							offset, FREAD) != 0) {
			continue;
		}

		error = nvlist_unpack(label->vl_vdev_phys.vp_nvlist,
					sizeof (label->vl_vdev_phys.vp_nvlist),
					config, 0);

		if (error != 0) {
			*config = NULL;
			continue;
		}

		/*
		 * Check that a valid config was loaded
		 *	skip devices that are unavailable,
		 *	uninitialized, or potentially active
		 */
		if (nvlist_lookup_uint64(*config,
				ZPOOL_CONFIG_POOL_STATE, &state) != 0 ||
			state > POOL_STATE_L2CACHE) {

			nvlist_free(*config);
			*config = NULL;
			continue;
		}

		/*
		 * Check and fetch txg number
		 */
		if (state != POOL_STATE_SPARE &&
			state != POOL_STATE_L2CACHE &&
		    (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_POOL_TXG,
				&txg) != 0 || txg == 0)) {

			nvlist_free(*config);
			*config = NULL;
			continue;
		}

		break;
	}

	if (label) {
		kmem_free(label, sizeof (vdev_label_t));
	}

	(void) vdev_iokit_handle_close(dvd, FREAD);

	if (*config == NULL) {
		error = SET_ERROR(EIDRM);
	}

	return (error);
}

/*
 * Given the root disk device handle, read the label from
 * the device, and construct a configuration nvlist.
 */
int
vdev_iokit_read_rootlabel(char *devpath, char *devid, nvlist_t **config)
{
	vdev_iokit_t * dvd = 0;
	int error = EINVAL;

	error = vdev_iokit_alloc(&dvd);

	if (error)
		return (error);

	/* Locate the vdev by pathname, without validating the GUID */
	error = vdev_iokit_find_by_path(dvd, devpath, 0);

	if (error) {
		goto error;
	}

	error = vdev_iokit_read_label(dvd, config);

error:
	vdev_iokit_free(&dvd);

	return (error);
}

vdev_ops_t vdev_iokit_ops = {
	vdev_iokit_open,
	vdev_iokit_close,
	vdev_default_asize,
	vdev_iokit_io_start,
	vdev_iokit_io_done,
	vdev_iokit_state_change,	/* vdev_op_state_change */
	NULL,						/* vdev_op_hold */
	NULL,						/* vdev_op_rele */
	VDEV_TYPE_DISK,				/* name of this vdev type */
	B_TRUE						/* leaf vdev */
};