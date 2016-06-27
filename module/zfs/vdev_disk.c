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


extern struct vnode *vdev_bootvp;

void
vdev_disk_alloc(vdev_t *vd)
{
	vdev_disk_t *dvd;

	if (vd->vdev_tsd)
		printf("ZFS: WARNING, vdev_tsd already allocated\n");

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
	int isssd;

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
	  if (dvd->vd_offline) {
	    /*
	     * If we are opening a device in its offline notify
	     * context, the LDI handle was just closed. Clean
	     * up the LDI event callbacks and free vd->vdev_tsd.
	     */
	    vdev_disk_free(vd);
	  } else {
	    ASSERT(vd->vdev_reopening);
		devvp = dvd->vd_devvp;
	    goto skip_open;
	  }
	}

	/*
	 * Create vd->vdev_tsd.
	 */
	vdev_disk_alloc(vd);
	dvd = vd->vdev_tsd;

	if (vdev_bootvp) {
		printf("ZFS: global bootvp\n");
		devvp = vdev_bootvp;
		//vdev_bootvp = NULL;
		goto skip_open;
	}

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


	int len = MAXPATHLEN;
	if (vn_getpath(devvp, dvd->vd_readlinkname, &len) == 0) {
		dprintf("ZFS: '%s' resolved name is '%s'\n",
			   vd->vdev_path, dvd->vd_readlinkname);
	} else {
		dvd->vd_readlinkname[0] = 0;
	}



skip_open:
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
	}
#endif

	/*
	 * Clear the nowritecache bit, so that on a vdev_reopen() we will
	 * try again.
	 */
	vd->vdev_nowritecache = B_FALSE;

	/* Inform the ZIO pipeline that we are non-rotational */
	vd->vdev_nonrot = B_FALSE;
	if (VNOP_IOCTL(devvp, DKIOCISSOLIDSTATE, (caddr_t)&isssd, 0,
				   context) == 0) {
		if (isssd)
			vd->vdev_nonrot = B_TRUE;
	}
	dprintf("ZFS: vdev_disk(%s) isSSD %d\n", vd->vdev_path ? vd->vdev_path : "",
			isssd);

	dvd->vd_devvp = devvp;
out:
	if (error) {
	  if (devvp) {
			vnode_close(devvp, fmode, context);
			dvd->vd_devvp = NULL;
	  }
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
	}
	if (context)
		(void) vfs_context_rele(context);

	if (error) printf("ZFS: vdev_disk_open('%s') failed error %d\n",
					  vd->vdev_path ? vd->vdev_path : "", error);
	if (error) panic("hello");
	return (error);
}



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

#ifdef __APPLE__
	/* Do not close it if it is the boot device */
	if (dvd->vd_devvp == vdev_bootvp) return;

	if (dvd->vd_devvp != NULL) {
		/* vnode_close() can stall during removal, so clear vd_devvp now */
		struct vnode *vp = dvd->vd_devvp;
		dvd->vd_devvp = NULL;
		(void) thread_create(NULL, 0, vdev_disk_close_thread,
							 vp, 0, &p0,
							 TS_RUN, minclsyspri);
	}
#endif

	vd->vdev_delayed_close = B_FALSE;

	/*
	 * If we closed the LDI handle due to an offline notify from LDI,
	 * don't free vd->vdev_tsd or unregister the callbacks here;
	 * the offline finalize callback or a reopen will take care of it.
	 */
	if (dvd->vd_offline)
		return;

	vdev_disk_free(vd);
}

static void
vdev_disk_io_intr(struct buf *bp, void *arg)
{
	zio_t *zio = (zio_t *)arg;

	/*
	 * The rest of the zio stack only deals with EIO, ECKSUM, and ENXIO.
	 * Rather than teach the rest of the stack about other error
	 * possibilities (EFAULT, etc), we normalize the error value here.
	 */
	int error;
	error=buf_error(bp);

	zio->io_error = (error != 0 ? EIO : 0);
	if (zio->io_error == 0 && buf_resid(bp) != 0) {
		zio->io_error = EIO;
	}
	buf_free(bp);

	zio_delay_interrupt(zio);
}

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
	struct buf *bp;
	vfs_context_t context;
	int flags, error = 0;

	/*
	 * If the vdev is closed, it's likely in the REMOVED or FAULTED state.
	 * Nothing to be done here but return failure.
	 */
	if (dvd == NULL || (dvd->vd_offline) || dvd->vd_devvp == NULL) {
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
						return;
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
			zio_interrupt(zio);
			return;
	} /* io_type */

	ASSERT(zio->io_type == ZIO_TYPE_READ || zio->io_type == ZIO_TYPE_WRITE);

	/* Stop OSX from also caching our data */
	flags |= B_NOCACHE;

	if (zio->io_flags & ZIO_FLAG_FAILFAST)
		flags |= B_FAILFAST;

	zio->io_target_timestamp = zio_handle_io_delay(zio);

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

	if (error) {
		zio->io_error = error;
		zio_interrupt(zio);
		return;
	}
}

static void
vdev_disk_io_done(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	/*
	 * If the device returned EIO, then attempt a DKIOCSTATE ioctl to see if
	 * the device has been removed. If this is the case, then we trigger an
	 * asynchronous removal of the device.
	 */
	if (zio->io_error == EIO && !vd->vdev_remove_wanted) {

		/* Apple handle device removal in zfs_osx.cpp - read errors etc
		 * should be retried by zio
		 */
#ifdef __APPLE__
		return;
#else
		state = DKIO_NONE;
		if (ldi_ioctl(dvd->vd_lh, DKIOCSTATE, (intptr_t)&state,
					  FKIOCTL, kcred, NULL) == 0 &&
			state != DKIO_INSERTED)
			{
				/*
				 * We post the resource as soon as possible, instead of
				 * when the async removal actually happens, because the
				 * DE is using this information to discard previous I/O
				 * errors.
				 */
				zfs_post_remove(zio->io_spa, vd);
				vd->vdev_remove_wanted = B_TRUE;
				spa_async_request(zio->io_spa, SPA_ASYNC_REMOVE);
				spa_async_dispatch(zio->io_spa);
			} else if (!vd->vdev_delayed_close) {
			vd->vdev_delayed_close = B_TRUE;
		}
#endif
	}
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


/*
 * Given the root disk device devid or pathname, read the label from
 * the device, and construct a configuration nvlist.
 */
int
vdev_disk_read_rootlabel(struct vnode *rdev, nvlist_t **config)
{
	vdev_label_t *label;
	uint64_t s, size;
	int l;
	int retval;
	int error = 0;
	u_int32_t log_blksize;
	u_int32_t phys_blksize;
	daddr64_t log_blkcnt;
	u_int64_t disksize;
	ssize_t resid;
	vfs_context_t context = spl_vfs_context_kernel();

	/*
	 * Read the device label and build the nvlist.
	 */
	if (VNOP_IOCTL(rdev, DKIOCGETBLOCKSIZE, (caddr_t)&log_blksize, 0, context))
		printf("ZFS: DKIOCGETBLOCKSIZE failed\n");

	retval = VNOP_IOCTL(rdev, DKIOCGETPHYSICALBLOCKSIZE, (caddr_t)&phys_blksize, 0, context);
	if (retval) {
		printf("ZFS: DKIOCGETPHYSICALBLOCKSIZE failed\n");
		/* If device does not support this ioctl, assume that physical
		 * block size is same as logical block size
		 */
		phys_blksize = log_blksize;
	}
	/* Switch to 512 byte sectors (temporarily) */
	if (log_blksize > 512) {
		u_int32_t size512 = 512;

		if (VNOP_IOCTL(rdev, DKIOCSETBLOCKSIZE, (caddr_t)&size512, FWRITE, context))
			printf("ZFS: DKIOCSETBLOCKSIZE failed\n");
	}
	/* Get the number of 512 byte physical blocks. */
	if (VNOP_IOCTL(rdev, DKIOCGETBLOCKCOUNT, (caddr_t)&log_blkcnt, 0, context)) {
		/* resetting block size may fail if getting block count did */
		(void)VNOP_IOCTL(rdev, DKIOCSETBLOCKSIZE, (caddr_t)&log_blksize, FWRITE, context);
	}
	/* Compute an accurate disk size (i.e. within 512 bytes) */
	disksize = (u_int64_t)log_blkcnt * (u_int64_t)512;

	if (log_blksize > 512) {
		if (VNOP_IOCTL(rdev, DKIOCSETBLOCKSIZE, (caddr_t)&log_blksize, FWRITE, context))
			printf("ZFS: DKIOCSETBLOCKSIZE2 failed\n");
		/* Get the count of physical blocks. */
		if (VNOP_IOCTL(rdev, DKIOCGETBLOCKCOUNT, (caddr_t)&log_blkcnt, 0,
					   context))
			printf("ZFS: DKIOCGETBLOCKCOUNT2 failed\n");
	}

	s = (uint64_t)log_blkcnt * phys_blksize;

	size = P2ALIGN_TYPED(s, sizeof (vdev_label_t), uint64_t);
	label = kmem_alloc(sizeof (vdev_label_t), KM_SLEEP);

	printf("ZFS: looking for labels: size %llu\n", size);

	*config = NULL;
	for (l = 0; l < VDEV_LABELS; l++) {
		uint64_t offset, state, txg = 0;

		/* read vdev label */
		offset = vdev_label_offset(size, l, 0);

		if ((retval = vn_rdwr(UIO_READ, rdev, (caddr_t)label,
							  VDEV_SKIP_SIZE + VDEV_PHYS_SIZE, offset,
							  UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid))) {
			continue;
		}

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
	if (*config == NULL)
		error = SET_ERROR(EIDRM);

	return (error);
}
