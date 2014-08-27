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
#include <sys/vdev_disk.h>
#include <sys/vdev_impl.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>
#ifdef __APPLE__
#include <sys/mount.h>
#else
#include <sys/sunldi.h>
#endif /* __APPLE__ */

#ifdef illumos
/*
 * Virtual device vector for disks.
 */

extern ldi_ident_t zfs_li;

static void vdev_disk_close(vdev_t *);

typedef struct vdev_disk_ldi_cb {
	list_node_t		lcb_next;
	ldi_callback_id_t	lcb_id;
} vdev_disk_ldi_cb_t;
#endif

static void
vdev_disk_alloc(vdev_t *vd)
{
	vdev_disk_t *dvd;

	dvd = vd->vdev_tsd = kmem_zalloc(sizeof (vdev_disk_t), KM_SLEEP);
#ifdef illumos
	/*
	 * Create the LDI event callback list.
	 */
	list_create(&dvd->vd_ldi_cbs, sizeof (vdev_disk_ldi_cb_t),
	    offsetof(vdev_disk_ldi_cb_t, lcb_next));
#endif
}

static void
vdev_disk_free(vdev_t *vd)
{
	vdev_disk_t *dvd = vd->vdev_tsd;
#ifdef illumos
	vdev_disk_ldi_cb_t *lcb;
#endif

	if (dvd == NULL)
		return;

#ifdef illumos
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
#endif
	kmem_free(dvd, sizeof (vdev_disk_t));
	vd->vdev_tsd = NULL;
}

static int
vdev_disk_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
	spa_t *spa = vd->vdev_spa;
	vdev_disk_t *dvd = vd->vdev_tsd;
	vnode_t *devvp = NULLVP;
	vfs_context_t context = NULL;
	uint64_t blkcnt;
	uint32_t blksize;
	int fmode = 0;
	int error = 0;

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}

#ifdef illumos
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
#endif

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
	/* ### APPLE TODO ### */
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

		context = vfs_context_create( spl_vfs_context_kernel() );

		/* Obtain an opened/referenced vnode for the device. */
		if ((error = vnode_open(vd->vdev_path, spa_mode(spa), 0, 0,
								&devvp, context))) {
			goto out;
		}
		if (!vnode_isblk(devvp)) {
			error = ENOTBLK;
			goto out;
		}
		/*
		 * ### APPLE TODO ###
		 * vnode_authorize devvp for KAUTH_VNODE_READ_DATA and
		 * KAUTH_VNODE_WRITE_DATA
		 */

		/*
		 * Disallow opening of a device that is currently in use.
		 * Flush out any old buffers remaining from a previous use.
		 */
		if ((error = vfs_mountedon(devvp))) {
			goto out;
		}
		if (VNOP_FSYNC(devvp, MNT_WAIT, context) != 0) {
			error = ENOTBLK;
			goto out;
		}
		if ((error = buf_invalidateblks(devvp, BUF_WRITE_DATA, 0, 0))) {
			goto out;
		}

	} else {
		goto out;
	}
#ifdef illumos
skip_open:
#endif
	/*
	 * Determine the actual size of the device.
	 */
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&blksize, 0,
	    context) != 0 ||
	    VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0,
	    context) != 0) {
		error = EINVAL;
		goto out;
	}

	*psize = blkcnt * (uint64_t)blksize;
	*max_psize = *psize;

	dvd->vd_ashift = highbit(blksize) - 1;
	dprintf("vdev_disk: Device %p ashift set to %d\n", devvp,
	    dvd->vd_ashift);

	*ashift = highbit(MAX(blksize, SPA_MINBLOCKSIZE)) - 1;

	/*
	 *  ### APPLE TODO ###
	 */
#ifdef illumos
	if (vd->vdev_wholedisk == 1) {
		int wce = 1;
		if (error == 0) {
			/*
			 * If we have the capability to expand, we'd have
			 * found out via success from DKIOCGMEDIAINFO{,EXT}.
			 * Adjust max_psize upward accordingly since we know
			 * we own the whole disk now.
			 */
			*max_psize += vdev_disk_get_space(vd, capacity, blksz);
			zfs_dbgmsg("capacity change: vdev %s, psize %llu, "
			    "max_psize %llu", vd->vdev_path, *psize,
			    *max_psize);
		}

		/*
		 * Since we own the whole disk, try to enable disk write
		 * caching.  We ignore errors because it's OK if we can't do it.
		 */
		(void) ldi_ioctl(dvd->vd_lh, DKIOCSETWCE, (intptr_t)&wce,
		    FKIOCTL, kcred, NULL);
#endif

	/*
	 * Clear the nowritecache bit, so that on a vdev_reopen() we will
	 * try again.
	 */
	vd->vdev_nowritecache = B_FALSE;

	dvd->vd_devvp = devvp;
out:
	if (error) {
		if (devvp)
			vnode_close(devvp, fmode, context);
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
	}
	if (context)
		(void) vfs_context_rele(context);

	if (error) printf("ZFS: vdev_disk_open() failed error %d\n", error);

	return (error);
}

static void
vdev_disk_close(vdev_t *vd)
{
	vdev_disk_t *dvd = vd->vdev_tsd;

	if (vd->vdev_reopening || dvd == NULL)
		return;

#ifdef illumos
	if (dvd->vd_minor != NULL) {
		ddi_devid_str_free(dvd->vd_minor);
		dvd->vd_minor = NULL;
	}

	if (dvd->vd_devid != NULL) {
		ddi_devid_free(dvd->vd_devid);
		dvd->vd_devid = NULL;
	}

	if (dvd->vd_lh != NULL) {
		(void) ldi_close(dvd->vd_lh, spa_mode(vd->vdev_spa), kcred);
		dvd->vd_lh = NULL;
	}
#endif

	vd->vdev_delayed_close = B_FALSE;
#ifdef illumos
	/*
	 * If we closed the LDI handle due to an offline notify from LDI,
	 * don't free vd->vdev_tsd or unregister the callbacks here;
	 * the offline finalize callback or a reopen will take care of it.
	 */
	if (dvd->vd_ldi_offline)
		return;
#endif

#ifdef __APPLE__
	if (dvd->vd_devvp != NULL) {
		vfs_context_t context;
		context = vfs_context_create(spl_vfs_context_kernel());
		(void) vnode_close(dvd->vd_devvp, spa_mode(vd->vdev_spa),
		    context);
		(void) vfs_context_rele(context);
	}
#endif

	vdev_disk_free(vd);
}

static void
vdev_disk_io_intr(struct buf *bp, void *arg)
{
	zio_t *zio = (zio_t *)arg;

	zio->io_error = buf_error(bp);

	if (zio->io_error == 0 && buf_resid(bp) != 0) {
		zio->io_error = EIO;
	}
	buf_free(bp);

	zio_interrupt(zio);
}

static void
vdev_disk_ioctl_done(void *zio_arg, int error)
{
	zio_t *zio = zio_arg;

	zio->io_error = error;

	zio_interrupt(zio);
}

static int
vdev_disk_io_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_disk_t *dvd = vd->vdev_tsd;
	struct buf *bp;
	vfs_context_t context;
	int flags, error = 0;

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

			context = vfs_context_create(spl_vfs_context_kernel());
			error = VNOP_IOCTL(dvd->vd_devvp, DKIOCSYNCHRONIZECACHE,
			    NULL, FWRITE, context);
			(void) vfs_context_rele(context);

			if (error == 0)
				vdev_disk_ioctl_done(zio, error);
			else
				error = ENOTSUP;

			if (error == 0) {
				/*
				 * The ioctl will be done asychronously,
				 * and will call vdev_disk_ioctl_done()
				 * upon completion.
				 */
				return (ZIO_PIPELINE_STOP);
			} else if (error == ENOTSUP || error == ENOTTY) {
				/*
				 * If we get ENOTSUP or ENOTTY, we know that
				 * no future attempts will ever succeed.
				 * In this case we set a persistent bit so
				 * that we don't bother with the ioctl in the
				 * future.
				 */
				vd->vdev_nowritecache = B_TRUE;
			}
			zio->io_error = error;

			break;

		default:
			zio->io_error = SET_ERROR(ENOTSUP);
		}

		return (ZIO_PIPELINE_CONTINUE);
	}

	flags = (zio->io_type == ZIO_TYPE_READ ? B_READ : B_WRITE);
	/* flags |= B_NOCACHE; */

	if (zio->io_flags & ZIO_FLAG_FAILFAST)
		flags |= B_FAILFAST;

	bp = buf_alloc(dvd->vd_devvp);

	ASSERT(bp != NULL);
	ASSERT(zio->io_data != NULL);
	ASSERT(zio->io_size != 0);

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

	buf_setsize(bp, zio->io_size);
	if (buf_setcallback(bp, vdev_disk_io_intr, zio) != 0)
		panic("vdev_disk_io_start: buf_setcallback failed\n");

	if (zio->io_type == ZIO_TYPE_WRITE) {
		vnode_startwrite(dvd->vd_devvp);
	}
	error = VNOP_STRATEGY(bp);
	ASSERT(error == 0);

	return (ZIO_PIPELINE_STOP);
}

static void
vdev_disk_io_done(zio_t *zio)
{

#ifndef __APPLE__
	/*
	 * XXX- NOEL TODO
	 * If the device returned EIO, then attempt a DKIOCSTATE ioctl to see if
	 * the device has been removed.  If this is the case, then we trigger an
	 * asynchronous removal of the device.
	 */
	if (zio->io_error == EIO) {
		state = DKIO_NONE;
		if (ldi_ioctl(dvd->vd_lh, DKIOCSTATE, (intptr_t)&state,
		    FKIOCTL, kcred, NULL) == 0 &&
		    state != DKIO_INSERTED) {
			vd->vdev_remove_wanted = B_TRUE;
			spa_async_request(zio->io_spa, SPA_ASYNC_REMOVE);
		}
	}
#endif /* !__APPLE__ */

}

vdev_ops_t vdev_disk_ops = {
	vdev_disk_open,
	vdev_disk_close,
	vdev_default_asize,
	vdev_disk_io_start,
	vdev_disk_io_done,
	NULL	/* vdev_op_state_change */,
	NULL	/* vdev_op_hold */,
	NULL	/* vdev_op_rele */,
	VDEV_TYPE_DISK,	/* name of this vdev type */
	B_TRUE	/* leaf vdev */
};
