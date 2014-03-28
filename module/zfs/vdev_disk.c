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
#endif /*__APPLE__*/


/*
 * Virtual device vector for disks.
 */

#ifndef __APPLE__
extern ldi_ident_t zfs_li;

typedef struct vdev_disk_buf {
	buf_t	vdb_buf;
	zio_t	*vdb_io;
} vdev_disk_buf_t;
#endif /*!__APPLE__*/

static int
vdev_disk_open(vdev_t *vd, uint64_t *size, uint64_t *max_size, uint64_t *ashift)
{
	vdev_disk_t *dvd = NULL;
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
		return (EINVAL);
	}

	dvd = kmem_zalloc(sizeof (vdev_disk_t), KM_SLEEP);
    if (dvd == NULL)
        return ENOMEM;

	/*
	 * When opening a disk device, we want to preserve the user's original
	 * intent.  We always want to open the device by the path the user gave
	 * us, even if it is one of multiple paths to the save device.  But we
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
	 *
	 */

	/* ### APPLE TODO ### */
	/* ddi_devid_str_decode */

	context = vfs_context_create((vfs_context_t)0);

	/* Obtain an opened/referenced vnode for the device. */
	error = vnode_open(vd->vdev_path, spa_mode(vd->vdev_spa), 0, 0, &devvp, context);
	if (error) {
		goto out;
	}

	if (!vnode_isblk(devvp)) {
		error = ENOTBLK;
		goto out;
	}

	/* ### APPLE TODO ### */
	/* vnode_authorize devvp for KAUTH_VNODE_READ_DATA and
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

	/*
	 * Determine the actual size of the device.
	 */
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&blksize, 0, context)
	       	!= 0 || VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt,
		0, context) != 0) {

		error = EINVAL;
		goto out;
	}
	*size = blkcnt * (uint64_t)blksize;

	/*
	 *  ### APPLE TODO ###
	 * If we own the whole disk, try to enable disk write caching.
	 */

	/*
	 * Take the device's minimum transfer size into account.
	 */
	*ashift = highbit(MAX(blksize, SPA_MINBLOCKSIZE)) - 1;

    /*
     * Setting the vdev_ashift did in fact break the pool for import
     * on ZEVO. This puts the logic into question. It appears that vdev_top
     * will also then change. It then panics in space_map from metaslab_alloc
     */
    //vd->vdev_ashift = *ashift;
    dvd->vd_ashift = *ashift;


	/*
	 * Clear the nowritecache bit, so that on a vdev_reopen() we will
	 * try again.
	 */
	vd->vdev_nowritecache = B_FALSE;
	vd->vdev_tsd = dvd;
	dvd->vd_devvp = devvp;
out:
	if (error) {
		if (devvp)
			vnode_close(devvp, fmode, context);
		if (dvd)
			kmem_free(dvd, sizeof (vdev_disk_t));

		/*
		 * Since the open has failed, vd->vdev_tsd should
		 * be NULL when we get here, signaling to the
		 * rest of the spa not to try and reopen or close this device
		 */
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
	}
	if (context) {
		(void) vfs_context_rele(context);
	}
	return (error);
}

static void
vdev_disk_close(vdev_t *vd)
{
	vdev_disk_t *dvd = vd->vdev_tsd;

	if (dvd == NULL)
		return;

	if (dvd->vd_devvp != NULL) {
		vfs_context_t context;

		context = vfs_context_create((vfs_context_t)0);

		(void) vnode_close(dvd->vd_devvp, spa_mode(vd->vdev_spa), context);
		(void) vfs_context_rele(context);
	}

	kmem_free(dvd, sizeof (vdev_disk_t));
	vd->vdev_tsd = NULL;
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
	//zio_next_stage_async(zio);
    zio_interrupt(zio);
}

static void
vdev_disk_ioctl_done(void *zio_arg, int error)
{
	zio_t *zio = zio_arg;

	zio->io_error = error;

	//zio_next_stage_async(zio);
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
		zio_vdev_io_bypass(zio);

		/* XXPOLICY */
		if (vdev_is_dead(vd)) {
			zio->io_error = ENXIO;
			//zio_next_stage_async(zio);
			return (ZIO_PIPELINE_CONTINUE);
            //return;
		}

		switch (zio->io_cmd) {

		case DKIOCFLUSHWRITECACHE:

			if (zfs_nocacheflush)
				break;

			if (vd->vdev_nowritecache) {
				zio->io_error = SET_ERROR(ENOTSUP);
				break;
			}

			context = vfs_context_create((vfs_context_t)0);
			error = VNOP_IOCTL(dvd->vd_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, context);
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
				return ZIO_PIPELINE_STOP;
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

		//zio_next_stage_async(zio);
        return (ZIO_PIPELINE_CONTINUE);
	}

	if (zio->io_type == ZIO_TYPE_READ && vdev_cache_read(zio) == 0)
        return (ZIO_PIPELINE_STOP);
    //		return;

	if ((zio = vdev_queue_io(zio)) == NULL)
        return (ZIO_PIPELINE_CONTINUE);
    //		return;

	flags = (zio->io_type == ZIO_TYPE_READ ? B_READ : B_WRITE);
	//flags |= B_NOCACHE;

	if (zio->io_flags & ZIO_FLAG_FAILFAST)
		flags |= B_FAILFAST;

	/*
	 * Check the state of this device to see if it has been offlined or
	 * is in an error state.  If the device was offlined or closed,
	 * dvd will be NULL and buf_alloc below will fail
	 */
	//error = vdev_is_dead(vd) ? ENXIO : vdev_error_inject(vd, zio);
	if (vdev_is_dead(vd)) {
        error = ENXIO;
    }

	if (error) {
		zio->io_error = error;
		//zio_next_stage_async(zio);
		return (ZIO_PIPELINE_CONTINUE);
	}

	bp = buf_alloc(dvd->vd_devvp);

	ASSERT(bp != NULL);
	ASSERT(zio->io_data != NULL);
	ASSERT(zio->io_size != 0);

	buf_setflags(bp, flags);
	buf_setcount(bp, zio->io_size);
	buf_setdataptr(bp, (uintptr_t)zio->io_data);
    buf_setlblkno(bp, lbtodb(zio->io_offset));
    buf_setblkno(bp, lbtodb(zio->io_offset));

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

	//zio_next_stage(zio);
}

vdev_ops_t vdev_disk_ops = {
	vdev_disk_open,
	vdev_disk_close,
	vdev_default_asize,
	vdev_disk_io_start,
	vdev_disk_io_done,
	NULL /* vdev_op_state_change */,
	NULL /* vdev_op_hold */,
	NULL /* vdev_op_rele */,
	VDEV_TYPE_DISK,	/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};
