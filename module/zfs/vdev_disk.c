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
 * Based on Apple MacZFS source code
 * Copyright (c) 2014,2016 by Jorgen Lundman. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/vdev_disk.h>
#include <sys/vdev_impl.h>
#include <sys/abd.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>
#ifdef __APPLE__
/* XXX If renamed to sunldi.h, no ifdef required */
#include <sys/ldi_osx.h>
#else
#include <sys/sunldi.h>
#endif

/*
 * Virtual device vector for disks.
 */

#ifdef illumos
extern ldi_ident_t zfs_li;
#else
/* XXX leave extern if declared elsewhere - originally was in zfs_ioctl.c */
ldi_ident_t zfs_li;
#endif

static void vdev_disk_close(vdev_t *);

typedef struct vdev_disk_ldi_cb {
	list_node_t		lcb_next;
	ldi_callback_id_t	lcb_id;
} vdev_disk_ldi_cb_t;

static void
vdev_disk_alloc(vdev_t *vd)
{
	vdev_disk_t *dvd;

	dvd = vd->vdev_tsd = kmem_zalloc(sizeof (vdev_disk_t), KM_SLEEP);
#ifdef __APPLE__
/* XXX Only alloc that needs zeroed, all others are properly initialized */
	bzero(dvd, sizeof (vdev_disk_t));
#endif

	/*
	 * Create the LDI event callback list.
	 */
	list_create(&dvd->vd_ldi_cbs, sizeof (vdev_disk_ldi_cb_t),
	    offsetof(vdev_disk_ldi_cb_t, lcb_next));
}

static void
vdev_disk_free(vdev_t *vd)
{
	vdev_disk_t *dvd = vd->vdev_tsd;
	vdev_disk_ldi_cb_t *lcb;

	if (dvd == NULL)
		return;

	/*
	 * We have already closed the LDI handle. Clean up the LDI event
	 * callbacks and free vd->vdev_tsd.
	 */
	while ((lcb = list_head(&dvd->vd_ldi_cbs)) != NULL) {
		list_remove(&dvd->vd_ldi_cbs, lcb);
		(void) ldi_ev_remove_callbacks(lcb->lcb_id);
		kmem_free(lcb, sizeof (vdev_disk_ldi_cb_t));
	}
	list_destroy(&dvd->vd_ldi_cbs);
	kmem_free(dvd, sizeof (vdev_disk_t));
	vd->vdev_tsd = NULL;
}

static int
vdev_disk_off_notify(ldi_handle_t lh, ldi_ev_cookie_t ecookie, void *arg,
    void *ev_data)
{
	vdev_t *vd = (vdev_t *)arg;
	vdev_disk_t *dvd = vd->vdev_tsd;

	/*
	 * Ignore events other than offline.
	 */
	if (strcmp(ldi_ev_get_type(ecookie), LDI_EV_OFFLINE) != 0)
		return (LDI_EV_SUCCESS);

	/*
	 * All LDI handles must be closed for the state change to succeed, so
	 * call on vdev_disk_close() to do this.
	 *
	 * We inform vdev_disk_close that it is being called from offline
	 * notify context so it will defer cleanup of LDI event callbacks and
	 * freeing of vd->vdev_tsd to the offline finalize or a reopen.
	 */
	dvd->vd_ldi_offline = B_TRUE;
	vdev_disk_close(vd);

	/*
	 * Now that the device is closed, request that the spa_async_thread
	 * mark the device as REMOVED and notify FMA of the removal.
	 */
	zfs_post_remove(vd->vdev_spa, vd);
	vd->vdev_remove_wanted = B_TRUE;
	spa_async_request(vd->vdev_spa, SPA_ASYNC_REMOVE);

	return (LDI_EV_SUCCESS);
}

/* ARGSUSED */
static void
vdev_disk_off_finalize(ldi_handle_t lh, ldi_ev_cookie_t ecookie,
    int ldi_result, void *arg, void *ev_data)
{
	vdev_t *vd = (vdev_t *)arg;

	/*
	 * Ignore events other than offline.
	 */
	if (strcmp(ldi_ev_get_type(ecookie), LDI_EV_OFFLINE) != 0)
		return;

	/*
	 * We have already closed the LDI handle in notify.
	 * Clean up the LDI event callbacks and free vd->vdev_tsd.
	 */
	vdev_disk_free(vd);
	/*
	 * Request that the vdev be reopened if the offline state change was
	 * unsuccessful.
	 */
	if (ldi_result != LDI_EV_SUCCESS) {
		vd->vdev_probe_wanted = B_TRUE;
		spa_async_request(vd->vdev_spa, SPA_ASYNC_PROBE);
	}
}

static ldi_ev_callback_t vdev_disk_off_callb = {
	.cb_vers = LDI_EV_CB_VERS,
	.cb_notify = vdev_disk_off_notify,
	.cb_finalize = vdev_disk_off_finalize
};

/*
 * We want to be loud in DEBUG kernels when DKIOCGMEDIAINFOEXT fails, or when
 * even a fallback to DKIOCGMEDIAINFO fails.
 */
#ifdef DEBUG
#define        VDEV_DEBUG(...) cmn_err(CE_NOTE, __VA_ARGS__)
#else
#define        VDEV_DEBUG(...) /* Nothing... */
#endif

static int
vdev_disk_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
	spa_t *spa = vd->vdev_spa;
	vdev_disk_t *dvd = vd->vdev_tsd;
	ldi_ev_cookie_t ecookie;
	vdev_disk_ldi_cb_t *lcb;
	union {
		struct dk_minfo_ext ude;
		struct dk_minfo ud;
	} dks;
	struct dk_minfo_ext *dkmext = &dks.ude;
	struct dk_minfo *dkm = &dks.ud;
	int error;
/* XXX Apple - must leave devid unchanged */
#ifdef illumos
	dev_t dev;
	int otyp;
	boolean_t validate_devid = B_FALSE;
	ddi_devid_t devid;
#endif
	uint64_t capacity = 0, blksz = 0, pbsize;
#ifdef __APPLE__
	int isssd;
#endif

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Reopen the device if it's not currently open. Otherwise,
	 * just update the physical size of the device.
	 */
	if (dvd != NULL) {
		if (dvd->vd_ldi_offline && dvd->vd_lh == NULL) {
			/*
			 * If we are opening a device in its offline notify
			 * context, the LDI handle was just closed. Clean
			 * up the LDI event callbacks and free vd->vdev_tsd.
			 */
			vdev_disk_free(vd);
		} else {
			ASSERT(vd->vdev_reopening);
			goto skip_open;
		}
	}

	/*
	 * Create vd->vdev_tsd.
	 */
	vdev_disk_alloc(vd);
	dvd = vd->vdev_tsd;

	/*
	 * When opening a disk device, we want to preserve the user's original
	 * intent.  We always want to open the device by the path the user gave
	 * us, even if it is one of multiple paths to the same device.  But we
	 * also want to be able to survive disks being removed/recabled.
	 * Therefore the sequence of opening devices is:
	 *
	 * 1. Try opening the device by path.  For legacy pools without the
	 *    'whole_disk' property, attempt to fix the path by appending 's0'.
	 *
	 * 2. If the devid of the device matches the stored value, return
	 *    success.
	 *
	 * 3. Otherwise, the device may have moved.  Try opening the device
	 *    by the devid instead.
	 */
/*
 * XXX We must not set or modify the devid as this check would prevent
 * import on Solaris/illumos.
 */
#ifdef illumos
	if (vd->vdev_devid != NULL) {
		if (ddi_devid_str_decode(vd->vdev_devid, &dvd->vd_devid,
		    &dvd->vd_minor) != 0) {
			vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
			return (SET_ERROR(EINVAL));
		}
	}
#endif

	error = EINVAL;		/* presume failure */

	if (vd->vdev_path != NULL) {

/*
 * XXX This assumes that if vdev_path refers to a device path /dev/dsk/cNtNdN,
 * then the whole disk can be found by slice 0 at path /dev/dsk/cNtNdNs0.
 */
#ifdef illumos
		if (vd->vdev_wholedisk == -1ULL) {
			size_t len = strlen(vd->vdev_path) + 3;
			char *buf = kmem_alloc(len, KM_SLEEP);

			(void) snprintf(buf, len, "%ss0", vd->vdev_path);

			error = ldi_open_by_name(buf, spa_mode(spa), kcred,
			    &dvd->vd_lh, zfs_li);
			if (error == 0) {
				spa_strfree(vd->vdev_path);
				vd->vdev_path = buf;
				vd->vdev_wholedisk = 1ULL;
			} else {
				kmem_free(buf, len);
			}
		}
#endif

		/*
		 * If we have not yet opened the device, try to open it by the
		 * specified path.
		 */
		if (error != 0) {
			error = ldi_open_by_name(vd->vdev_path, spa_mode(spa),
			    kcred, &dvd->vd_lh, zfs_li);
		}

/* XXX Apple - must leave devid unchanged */
#ifdef illumos
		/*
		 * Compare the devid to the stored value.
		 */
		if (error == 0 && vd->vdev_devid != NULL &&
		    ldi_get_devid(dvd->vd_lh, &devid) == 0) {
			if (ddi_devid_compare(devid, dvd->vd_devid) != 0) {
				error = SET_ERROR(EINVAL);
				(void) ldi_close(dvd->vd_lh, spa_mode(spa),
				    kcred);
				dvd->vd_lh = NULL;
			}
			ddi_devid_free(devid);
		}
#endif

		/*
		 * If we succeeded in opening the device, but 'vdev_wholedisk'
		 * is not yet set, then this must be a slice.
		 */
		if (error == 0 && vd->vdev_wholedisk == -1ULL)
			vd->vdev_wholedisk = 0;
	}

/* XXX Apple - must leave devid unchanged */
#ifdef illumos
	/*
	 * If we were unable to open by path, or the devid check fails, open by
	 * devid instead.
	 */
	if (error != 0 && vd->vdev_devid != NULL) {
		error = ldi_open_by_devid(dvd->vd_devid, dvd->vd_minor,
		    spa_mode(spa), kcred, &dvd->vd_lh, zfs_li);
	}
#endif

	/*
	 * If all else fails, then try opening by physical path (if available)
	 * or the logical path (if we failed due to the devid check).  While not
	 * as reliable as the devid, this will give us something, and the higher
	 * level vdev validation will prevent us from opening the wrong device.
	 */
	if (error) {
/* XXX Apple - must leave devid unchanged */
#ifdef illumos
		if (vd->vdev_devid != NULL)
			validate_devid = B_TRUE;
#endif

/* XXX Apple to do - make ddi_ interface for this, using IORegistry path */
#ifdef illumos
		if (vd->vdev_physpath != NULL &&
		    (dev = ddi_pathname_to_dev_t(vd->vdev_physpath)) != NODEV)
			error = ldi_open_by_dev(&dev, OTYP_BLK, spa_mode(spa),
			    kcred, &dvd->vd_lh, zfs_li);
#endif

		/*
		 * Note that we don't support the legacy auto-wholedisk support
		 * as above.  This hasn't been used in a very long time and we
		 * don't need to propagate its oddities to this edge condition.
		 */
		if (error && vd->vdev_path != NULL)
			error = ldi_open_by_name(vd->vdev_path, spa_mode(spa),
			    kcred, &dvd->vd_lh, zfs_li);
	}

	if (error) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (error);
	}

/*
 * XXX Apple - We must not set or modify the devid. Import on Solaris/illumos
 * expects a valid devid and fails if it cannot be decoded.
 */
#ifdef illumos
	/*
	 * Now that the device has been successfully opened, update the devid
	 * if necessary.
	 */
	if (validate_devid && spa_writeable(spa) &&
	    ldi_get_devid(dvd->vd_lh, &devid) == 0) {
		if (ddi_devid_compare(devid, dvd->vd_devid) != 0) {
			char *vd_devid;

			vd_devid = ddi_devid_str_encode(devid, dvd->vd_minor);
			zfs_dbgmsg("vdev %s: update devid from %s, "
			    "to %s", vd->vdev_path, vd->vdev_devid, vd_devid);
			spa_strfree(vd->vdev_devid);
			vd->vdev_devid = spa_strdup(vd_devid);
			ddi_devid_str_free(vd_devid);
		}
		ddi_devid_free(devid);
	}
#endif

/* XXX Apple to do, needs IORegistry physpath interface */
#ifdef illumos
	/*
	 * Once a device is opened, verify that the physical device path (if
	 * available) is up to date.
	 */
	if (ldi_get_dev(dvd->vd_lh, &dev) == 0 &&
	    ldi_get_otyp(dvd->vd_lh, &otyp) == 0) {
		char *physpath, *minorname;

		physpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		minorname = NULL;
		if (ddi_dev_pathname(dev, otyp, physpath) == 0 &&
		    ldi_get_minor_name(dvd->vd_lh, &minorname) == 0 &&
		    (vd->vdev_physpath == NULL ||
		    strcmp(vd->vdev_physpath, physpath) != 0)) {
			if (vd->vdev_physpath)
				spa_strfree(vd->vdev_physpath);
			(void) strlcat(physpath, ":", MAXPATHLEN);
			(void) strlcat(physpath, minorname, MAXPATHLEN);
			vd->vdev_physpath = spa_strdup(physpath);
		}
		if (minorname)
			kmem_free(minorname, strlen(minorname) + 1);
		kmem_free(physpath, MAXPATHLEN);
	}
#endif

	/*
	 * Register callbacks for the LDI offline event.
	 */
	if (ldi_ev_get_cookie(dvd->vd_lh, LDI_EV_OFFLINE, &ecookie) ==
	    LDI_EV_SUCCESS) {
		lcb = kmem_zalloc(sizeof (vdev_disk_ldi_cb_t), KM_SLEEP);
		list_insert_tail(&dvd->vd_ldi_cbs, lcb);
		(void) ldi_ev_register_callbacks(dvd->vd_lh, ecookie,
		    &vdev_disk_off_callb, (void *) vd, &lcb->lcb_id);
	}

/* XXX Apple to do - we could support the degrade event, or just no-op */
#ifdef illumos
	/*
	 * Register callbacks for the LDI degrade event.
	 */
	if (ldi_ev_get_cookie(dvd->vd_lh, LDI_EV_DEGRADE, &ecookie) ==
	    LDI_EV_SUCCESS) {
		lcb = kmem_zalloc(sizeof (vdev_disk_ldi_cb_t), KM_SLEEP);
		list_insert_tail(&dvd->vd_ldi_cbs, lcb);
		(void) ldi_ev_register_callbacks(dvd->vd_lh, ecookie,
		    &vdev_disk_dgrd_callb, (void *) vd, &lcb->lcb_id);
	}
#endif

#if 0
	int len = MAXPATHLEN;
	if (vn_getpath(devvp, dvd->vd_readlinkname, &len) == 0) {
		dprintf("ZFS: '%s' resolved name is '%s'\n",
			   vd->vdev_path, dvd->vd_readlinkname);
	} else {
		dvd->vd_readlinkname[0] = 0;
	}
#endif

skip_open:
	/*
	 * Determine the actual size of the device.
	 */
	if (ldi_get_size(dvd->vd_lh, psize) != 0) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(EINVAL));
	}

	*max_psize = *psize;

	/*
	 * Determine the device's minimum transfer size.
	 * If the ioctl isn't supported, assume DEV_BSIZE.
	 */
	if ((error = ldi_ioctl(dvd->vd_lh, DKIOCGMEDIAINFOEXT,
	    (intptr_t)dkmext, FKIOCTL, kcred, NULL)) == 0) {
		capacity = dkmext->dki_capacity - 1;
		blksz = dkmext->dki_lbsize;
		pbsize = dkmext->dki_pbsize;
	} else if ((error = ldi_ioctl(dvd->vd_lh, DKIOCGMEDIAINFO,
	    (intptr_t)dkm, FKIOCTL, kcred, NULL)) == 0) {
		VDEV_DEBUG(
		    "vdev_disk_open(\"%s\"): fallback to DKIOCGMEDIAINFO\n",
		    vd->vdev_path);
		capacity = dkm->dki_capacity - 1;
		blksz = dkm->dki_lbsize;
		pbsize = blksz;
	} else {
		VDEV_DEBUG("vdev_disk_open(\"%s\"): "
		    "both DKIOCGMEDIAINFO{,EXT} calls failed, %d\n",
		    vd->vdev_path, error);
		pbsize = DEV_BSIZE;
	}

	*ashift = highbit64(MAX(pbsize, SPA_MINBLOCKSIZE)) - 1;

/* XXX Now that we opened the device, determine if it is a whole disk. */
#ifdef __APPLE__
	/*
	 * XXX Apple to do - provide an ldi_ mechanism
	 * to report whether this is a whole disk or a
	 * partition.
	 * Return 0 (no), 1 (yes), or -1 (error).
	 */
//	vd->vdev_wholedisk = ldi_is_wholedisk(vd->vd_lh);
#endif

	if (vd->vdev_wholedisk == 1) {
		int wce = 1;

/* Gets information about the disk if it has GPT partitions */
#ifdef illumos
		if (error == 0) {
			/*
			 * If we have the capability to expand, we'd have
			 * found out via success from DKIOCGMEDIAINFO{,EXT}.
			 * Adjust max_psize upward accordingly since we know
			 * we own the whole disk now.
			 */
			*max_psize = capacity * blksz;
		}
#endif

		/*
		 * Since we own the whole disk, try to enable disk write
		 * caching.  We ignore errors because it's OK if we can't do it.
		 */
		(void) ldi_ioctl(dvd->vd_lh, DKIOCSETWCE, (intptr_t)&wce,
		    FKIOCTL, kcred, NULL);
	}

	/*
	 * Clear the nowritecache bit, so that on a vdev_reopen() we will
	 * try again.
	 */
	vd->vdev_nowritecache = B_FALSE;

#ifdef __APPLE__
	/* Inform the ZIO pipeline that we are non-rotational */
	vd->vdev_nonrot = B_FALSE;
	if (ldi_ioctl(dvd->vd_lh, DKIOCISSOLIDSTATE, (intptr_t)&isssd,
	    FKIOCTL, kcred, NULL) == 0) {
		vd->vdev_nonrot = (isssd ? B_TRUE : B_FALSE);
	}
#endif //__APPLE__

	return (0);
}

#if 0
/*
 * It appears on export/reboot, iokit can hold a lock, then call our
 * termination handler, and we end up locking-against-ourselves inside
 * IOKit. We are then forced to make the vnode_close() call be async.
 */
static void vdev_disk_close_thread(void *arg)
{
	struct vnode *vp = arg;

	(void) vnode_close(vp, 0,
					   spl_vfs_context_kernel());
	thread_exit();
}

/* Not static so zfs_osx.cpp can call it on device removal */
void
#endif

static void
vdev_disk_close(vdev_t *vd)
{
	vdev_disk_t *dvd = vd->vdev_tsd;

	if (vd->vdev_reopening || dvd == NULL)
		return;

/* XXX Apple - must leave devid unchanged */
#ifdef illumos
	if (dvd->vd_minor != NULL) {
		ddi_devid_str_free(dvd->vd_minor);
		dvd->vd_minor = NULL;
	}

	if (dvd->vd_devid != NULL) {
		ddi_devid_free(dvd->vd_devid);
		dvd->vd_devid = NULL;
	}
#endif

	if (dvd->vd_lh != NULL) {
		(void) ldi_close(dvd->vd_lh, spa_mode(vd->vdev_spa), kcred);
		dvd->vd_lh = NULL;
	}

	vd->vdev_delayed_close = B_FALSE;
	/*
	 * If we closed the LDI handle due to an offline notify from LDI,
	 * don't free vd->vdev_tsd or unregister the callbacks here;
	 * the offline finalize callback or a reopen will take care of it.
	 */
	if (dvd->vd_ldi_offline)
		return;

	vdev_disk_free(vd);
}

int
vdev_disk_physio(vdev_t *vd, caddr_t data,
    size_t size, uint64_t offset, int flags, boolean_t isdump)
{
	vdev_disk_t *dvd = vd->vdev_tsd;

	/*
	 * If the vdev is closed, it's likely in the REMOVED or FAULTED state.
	 * Nothing to be done here but return failure.
	 */
	if (dvd == NULL || (dvd->vd_ldi_offline && dvd->vd_lh == NULL))
		return (EIO);

	ASSERT(vd->vdev_ops == &vdev_disk_ops);

/* XXX Apple - no equivalent crash dump mechanism on OS X */
#ifdef illumos
	/*
	 * If in the context of an active crash dump, use the ldi_dump(9F)
	 * call instead of ldi_strategy(9F) as usual.
	 */
	if (isdump) {
		ASSERT3P(dvd, !=, NULL);
		return (ldi_dump(dvd->vd_lh, data, lbtodb(offset),
		    lbtodb(size)));
	}
#endif

	return (vdev_disk_ldi_physio(dvd->vd_lh, data, size, offset, flags));
}

int
vdev_disk_ldi_physio(ldi_handle_t vd_lh, caddr_t data,
    size_t size, uint64_t offset, int flags)
{
#ifdef illumos
	buf_t *bp;
#else
	ldi_buf_t *bp;
#endif
	int error = 0;

	if (vd_lh == NULL)
		return (SET_ERROR(EINVAL));

	ASSERT(flags & B_READ || flags & B_WRITE);

	bp = getrbuf(KM_SLEEP);
	bp->b_flags = flags | B_BUSY | B_NOCACHE | B_FAILFAST;
	bp->b_bcount = size;
	bp->b_un.b_addr = (void *)data;
	bp->b_lblkno = lbtodb(offset);
	bp->b_bufsize = size;

	error = ldi_strategy(vd_lh, bp);
	ASSERT(error == 0);

	if ((error = biowait(bp)) == 0 && bp->b_resid != 0)
		error = SET_ERROR(EIO);
	freerbuf(bp);

	return (error);
}

#ifdef illumos
static void
vdev_disk_io_intr(buf_t *bp)
#else
static void
vdev_disk_io_intr(ldi_buf_t *bp)
#endif
{
	vdev_buf_t *vb = (vdev_buf_t *)bp;
	zio_t *zio = vb->vb_io;

	/*
	 * The rest of the zio stack only deals with EIO, ECKSUM, and ENXIO.
	 * Rather than teach the rest of the stack about other error
	 * possibilities (EFAULT, etc), we normalize the error value here.
	 */
	zio->io_error = (geterror(bp) != 0 ? EIO : 0);

	if (zio->io_error == 0 && bp->b_resid != 0)
		zio->io_error = SET_ERROR(EIO);

	if (zio->io_type == ZIO_TYPE_READ) {
		abd_return_buf_copy(zio->io_abd, bp->b_un.b_addr, zio->io_size);
	} else {
		abd_return_buf(zio->io_abd, bp->b_un.b_addr, zio->io_size);
	}

	kmem_free(vb, sizeof (vdev_buf_t));

	zio_delay_interrupt(zio);
}

static void
vdev_disk_ioctl_free(zio_t *zio)
{
	kmem_free(zio->io_vsd, sizeof (struct dk_callback));
}

static const zio_vsd_ops_t vdev_disk_vsd_ops = {
	vdev_disk_ioctl_free,
	zio_vsd_default_cksum_report
};

static void
vdev_disk_ioctl_done(void *zio_arg, int error)
{
	zio_t *zio = zio_arg;

	zio->io_error = error;

	zio_interrupt(zio);
}

static void
vdev_disk_io_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_disk_t *dvd = vd->vdev_tsd;
	vdev_buf_t *vb;
	struct dk_callback *dkc;
#ifdef illumos
	buf_t *bp;
#else
	ldi_buf_t *bp = 0;
#endif
	int flags, error = 0;

	/*
	 * If the vdev is closed, it's likely in the REMOVED or FAULTED state.
	 * Nothing to be done here but return failure.
	 */
	if (dvd == NULL || (dvd->vd_ldi_offline && dvd->vd_lh == NULL)) {
		zio->io_error = ENXIO;
		zio_interrupt(zio);
		return;
	}

	switch (zio->io_type) {
	case ZIO_TYPE_IOCTL:

		if (!vdev_readable(vd)) {
			zio->io_error = SET_ERROR(ENXIO);
			zio_interrupt(zio);
			return;
		}

		switch (zio->io_cmd) {
		case DKIOCFLUSHWRITECACHE:

			if (zfs_nocacheflush)
				break;

			if (vd->vdev_nowritecache) {
				zio->io_error = SET_ERROR(ENOTSUP);
				break;
			}

			zio->io_vsd = dkc = kmem_alloc(sizeof (*dkc), KM_SLEEP);
			zio->io_vsd_ops = &vdev_disk_vsd_ops;

			dkc->dkc_callback = vdev_disk_ioctl_done;
			dkc->dkc_flag = FLUSH_VOLATILE;
			dkc->dkc_cookie = zio;

			error = ldi_ioctl(dvd->vd_lh, zio->io_cmd,
			    (uintptr_t)dkc, FKIOCTL, kcred, NULL);

			if (error == 0) {
				/*
				 * The ioctl will be done asychronously,
				 * and will call vdev_disk_ioctl_done()
				 * upon completion.
				 */
				return;
			}

			zio->io_error = error;

			break;

		default:
			zio->io_error = SET_ERROR(ENOTSUP);
		} /* io_cmd */

		zio_execute(zio);
		return;

	case ZIO_TYPE_WRITE:
		if (zio->io_priority == ZIO_PRIORITY_SYNC_WRITE)
			flags = B_WRITE;
		else
			flags = B_WRITE | B_ASYNC;
		break;

	case ZIO_TYPE_READ:
		if (zio->io_priority == ZIO_PRIORITY_SYNC_READ)
			flags = B_READ;
		else
			flags = B_READ | B_ASYNC;
		break;

	default:
		zio->io_error = SET_ERROR(ENOTSUP);
		zio_execute(zio);
		return;
	} /* io_type */

	ASSERT(zio->io_type == ZIO_TYPE_READ || zio->io_type == ZIO_TYPE_WRITE);

	/* Stop OSX from also caching our data */
	flags |= B_NOCACHE | B_PASSIVE; // smd: also do B_PASSIVE for anti throttling test

	zio->io_target_timestamp = zio_handle_io_delay(zio);

	vb = kmem_alloc(sizeof (vdev_buf_t), KM_SLEEP);

	vb->vb_io = zio;
	bp = &vb->vb_buf;

	ASSERT(bp != NULL);
	ASSERT(zio->io_abd != NULL);
	ASSERT(zio->io_size != 0);

	bioinit(bp);
	bp->b_flags = B_BUSY | flags;
	if (!(zio->io_flags & (ZIO_FLAG_IO_RETRY | ZIO_FLAG_TRYHARD)))
		bp->b_flags |= B_FAILFAST;
	bp->b_bcount = zio->io_size;

	if (zio->io_type == ZIO_TYPE_READ) {
		bp->b_un.b_addr =
		    abd_borrow_buf(zio->io_abd, zio->io_size);
	} else {
		bp->b_un.b_addr =
		    abd_borrow_buf_copy(zio->io_abd, zio->io_size);
	}

	bp->b_lblkno = lbtodb(zio->io_offset);
	bp->b_bufsize = zio->io_size;
	bp->b_iodone = (int (*)())vdev_disk_io_intr;

#if 0
	bp = buf_alloc(dvd->vd_devvp);

	buf_setflags(bp, flags);
	buf_setcount(bp, zio->io_size);
	buf_setdataptr(bp, (uintptr_t)zio->io_data);

	/*
	 * Map offset to blcknumber, based on physical block number.
	 * (512, 4096, ..). If we fail to map, default back to
	 * standard 512. lbtodb() is fixed at 512.
	 */
	buf_setblkno(bp, zio->io_offset >> dvd->vd_ashift);
	buf_setlblkno(bp, zio->io_offset >> dvd->vd_ashift);
#endif

#ifdef illumos
	/* ldi_strategy() will return non-zero only on programming errors */
	VERIFY(ldi_strategy(dvd->vd_lh, bp) == 0);
#else /* !illumos */

	error = ldi_strategy(dvd->vd_lh, bp);
	if (error != 0) {
		dprintf("%s error from ldi_strategy %d\n", __func__, error);
		zio->io_error = EIO;
		kmem_free(vb, sizeof (vdev_buf_t));
		zio_execute(zio);
		// zio_interrupt(zio);
	}
#endif /* !illumos */

}

static void
vdev_disk_io_done(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;

	/*
	 * If the device returned EIO, then attempt a DKIOCSTATE ioctl to see if
	 * the device has been removed.  If this is the case, then we trigger an
	 * asynchronous removal of the device. Otherwise, probe the device and
	 * make sure it's still accessible.
	 */
	if (zio->io_error == EIO && !vd->vdev_remove_wanted) {
		vdev_disk_t *dvd = vd->vdev_tsd;
		int state = DKIO_NONE;

		if (ldi_ioctl(dvd->vd_lh, DKIOCSTATE, (intptr_t)&state,
		    FKIOCTL, kcred, NULL) == 0 && state != DKIO_INSERTED) {
			/*
			 * We post the resource as soon as possible, instead of
			 * when the async removal actually happens, because the
			 * DE is using this information to discard previous I/O
			 * errors.
			 */
			zfs_post_remove(zio->io_spa, vd);
			vd->vdev_remove_wanted = B_TRUE;
			spa_async_request(zio->io_spa, SPA_ASYNC_REMOVE);
		} else if (!vd->vdev_delayed_close) {
			vd->vdev_delayed_close = B_TRUE;
		}
	}
}

vdev_ops_t vdev_disk_ops = {
	vdev_disk_open,
	vdev_disk_close,
	vdev_default_asize,
	vdev_disk_io_start,
	vdev_disk_io_done,
	NULL			/* vdev_op_state_change */,
	NULL			/* vdev_op_hold */,
	NULL			/* vdev_op_rele */,
	VDEV_TYPE_DISK,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};

/*
 * Given the root disk device devid or pathname, read the label from
 * the device, and construct a configuration nvlist.
 */
int
vdev_disk_read_rootlabel(char *devpath, char *devid, nvlist_t **config)
{
	ldi_handle_t vd_lh;
	vdev_label_t *label;
	uint64_t s, size;
	int l;
#ifdef illumos
	ddi_devid_t tmpdevid;
#endif
	int error = -1;
#ifdef illumos
	char *minor_name;
#endif

	/*
	 * Read the device label and build the nvlist.
	 */
/* XXX Apple - no devid */
#ifdef illumos
	if (devid != NULL && ddi_devid_str_decode(devid, &tmpdevid,
	    &minor_name) == 0) {
		error = ldi_open_by_devid(tmpdevid, minor_name,
		    FREAD, kcred, &vd_lh, zfs_li);
		ddi_devid_free(tmpdevid);
		ddi_devid_str_free(minor_name);
	}
#endif

#ifdef __APPLE__
	/* Apple: Error will be -1 at this point, allowing open_by_name */
	error = -1;
	vd_lh = 0;	/* Dismiss compiler warning */
#endif
	if (error && (error = ldi_open_by_name(devpath, FREAD, kcred, &vd_lh,
	    zfs_li)))
		return (error);

	if (ldi_get_size(vd_lh, &s)) {
		(void) ldi_close(vd_lh, FREAD, kcred);
		return (SET_ERROR(EIO));
	}

	size = P2ALIGN_TYPED(s, sizeof (vdev_label_t), uint64_t);
	label = kmem_alloc(sizeof (vdev_label_t), KM_SLEEP);

	*config = NULL;
	for (l = 0; l < VDEV_LABELS; l++) {
		uint64_t offset, state, txg = 0;

		/* read vdev label */
		offset = vdev_label_offset(size, l, 0);
		if (vdev_disk_ldi_physio(vd_lh, (caddr_t)label,
		    VDEV_SKIP_SIZE + VDEV_PHYS_SIZE, offset, B_READ) != 0)
			continue;

		if (nvlist_unpack(label->vl_vdev_phys.vp_nvlist,
		    sizeof (label->vl_vdev_phys.vp_nvlist), config, 0) != 0) {
			*config = NULL;
			continue;
		}

		if (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_POOL_STATE,
		    &state) != 0 || state >= POOL_STATE_DESTROYED) {
			nvlist_free(*config);
			*config = NULL;
			continue;
		}

		if (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_POOL_TXG,
		    &txg) != 0 || txg == 0) {
			nvlist_free(*config);
			*config = NULL;
			continue;
		}

		break;
	}

	kmem_free(label, sizeof (vdev_label_t));
	(void) ldi_close(vd_lh, FREAD, kcred);
	if (*config == NULL)
		error = SET_ERROR(EIDRM);

	return (error);
}
