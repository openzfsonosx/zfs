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
#include <sys/vdev_iokit.h>
#include <sys/vdev_impl.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>
#ifdef __APPLE__
#include <sys/mount.h>
#else
#include <sys/sunldi.h>
#endif /*__APPLE__*/


unsigned int zfs_iokit_vdev_ashift = 0;

extern void vdev_iokit_log(const char *);
extern void vdev_iokit_log_str(const char *, const char *);
extern void vdev_iokit_log_ptr(const char *, const void *);
extern void vdev_iokit_log_num(const char *, const uint64_t);

/*
 * Virtual device vector for disks via Mac OS X IOKit.
 */

void vdev_iokit_alloc( vdev_t * vd )
{
    vdev_iokit_t * dvd = 0;
vdev_iokit_log_ptr( "vdev_iokit_alloc: vd", vd );
    if (!vd)
        return;
    
    // KM_SLEEP for vdev context
    dvd =    (vdev_iokit_t *)kmem_alloc(sizeof(vdev_iokit_t), KM_SLEEP);
    
    dvd->vd_iokit_hl =  0;
    dvd->vd_zfs_hl =    0;
    dvd->vd_offline =   0;
    
    vd->vdev_tsd =      (void*)(dvd);
    
vdev_iokit_log_ptr( "vdev_iokit_alloc: vd->vdev_tsd", vd->vdev_tsd );
}

void vdev_iokit_free( vdev_t * vd )
{
    vdev_iokit_t * dvd = 0;
vdev_iokit_log_ptr( "vdev_iokit_free: vd", vd );
    if (!vd)
        return;
    
    dvd = vd->vdev_tsd;
    
    if (!dvd)
        return;
    
    if (dvd->vd_iokit_hl)
vdev_iokit_log_ptr( "vdev_iokit_free: leaking dvd->vd_iokit_hl", dvd->vd_iokit_hl );
    if (dvd->vd_zfs_hl)
vdev_iokit_log_ptr( "vdev_iokit_free: leaking dvd->vd_zfs_hl", dvd->vd_zfs_hl );
    
    dvd->vd_iokit_hl = 0;
    dvd->vd_zfs_hl = 0;
    dvd->vd_offline =   0;
    
    kmem_free(dvd, sizeof (vdev_iokit_t));
    vd->vdev_tsd = 0;
}

extern void
vdev_iokit_state_change(vdev_t * vd, int faulted, int degraded)
{
vdev_iokit_log_ptr( "vdev_iokit_state_change: vd", vd );
    
}

extern void
vdev_iokit_hold(vdev_t * vd)
{
    vdev_iokit_t * dvd = 0;
vdev_iokit_log_ptr( "vdev_iokit_hold: vd", vd );
    
    if (!vd)
        return;
    
vdev_iokit_log_num( "vdev_iokit_hold: spa mode:",   spa_mode(vd->vdev_spa) );
vdev_iokit_log_num( "vdev_iokit_hold: vd state:",   vd->vdev_state );
vdev_iokit_log_num( "vdev_iokit_hold: prevstate:",  vd->vdev_prevstate );
    
	ASSERT(spa_config_held(vd->vdev_spa, SCL_STATE, RW_WRITER));
    
	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/')
		return;
    
	/*
	 * Only prefetch path and devid info if the device has
	 * never been opened.
	 */
	if (vd->vdev_tsd != NULL)
		return;
    
    dvd = (vdev_iokit_t *)(vd->vdev_tsd);
    
vdev_iokit_log_ptr( "vdev_iokit_hold: dvd:",        dvd);
    
    if (!dvd)
        return;

vdev_iokit_log_ptr( "vdev_iokit_hold: iokit_hl:",   dvd->vd_iokit_hl);
vdev_iokit_log_ptr( "vdev_iokit_hold: zfs_hl:",     dvd->vd_zfs_hl);
    
	if (vd->vdev_wholedisk == -1ULL) {
		size_t len = strlen(vd->vdev_path) + 3;
		char *buf = kmem_alloc(len, KM_SLEEP);
        
		(void) snprintf(buf, len, "%ss0", vd->vdev_path);
        
		(void) vdev_iokit_open_by_path(vd, buf);
		kmem_free(buf, len);
	}
    
	if (vd->vdev_name_vp == NULL)
		(void) vdev_iokit_open_by_path(vd, vd->vdev_path);
    
    /* XXX - TO DO
     *  Populate and use devids if possible
     */
    /*
     if (vd->vdev_devid != NULL &&
     ddi_devid_str_decode(vd->vdev_devid, &devid, &minor) == 0) {
     (void) ldi_vp_from_devid(devid, minor, &vd->vdev_devid_vp);
     ddi_devid_str_free(minor);
     ddi_devid_free(devid);
     }
     */
}

extern void
vdev_iokit_rele(vdev_t * vd)
{
    vdev_iokit_t * dvd = 0;
vdev_iokit_log_ptr( "vdev_iokit_rele: vd", vd );
    if (!vd)
        return;

    dvd = (vdev_iokit_t *)(vd->vdev_tsd);
    
vdev_iokit_log_num( "vdev_iokit_rele: spa mode:",   spa_mode(vd->vdev_spa) );
vdev_iokit_log_num( "vdev_iokit_rele: vd state:",   vd->vdev_state );
vdev_iokit_log_num( "vdev_iokit_rele: prevstate:",  vd->vdev_prevstate );

vdev_iokit_log_ptr( "vdev_iokit_rele: dvd:",        dvd);
    
    if (!dvd)
        return;
    
vdev_iokit_log_ptr( "vdev_iokit_rele: iokit_hl:",   dvd->vd_iokit_hl);
vdev_iokit_log_ptr( "vdev_iokit_rele: zfs_hl:",     dvd->vd_zfs_hl);
    
	ASSERT(spa_config_held(vd->vdev_spa, SCL_STATE, RW_WRITER));
    
	if (dvd->vd_iokit_hl) {
        
		//vdev_iokit_release(vd);
        
        //  async( vd, dsl_pool_vnrele_taskq(vd->vdev_spa->spa_dsl_pool));
        
		dvd->vd_iokit_hl =  NULL;
	}
}

/* IOKit doesn't involve the VFS layer to close disks, however we might
 * still need to do this asynchronously to avoid deadlocks
 */
/*
 * Like vn_rele() except if we are going to call VOP_INACTIVE() then do it
 * asynchronously using a taskq. This can avoid deadlocks caused by re-entering
 * the file system as a result of releasing the vnode. Note, file systems
 * already have to handle the race where the vnode is incremented before the
 * inactive routine is called and does its locking.
 *
 * Warning: Excessive use of this routine can lead to performance problems.
 * This is because taskqs throttle back allocation if too many are created.
 */
#if 0           /* NOT CURRENTLY USED */
void
vdev_iokit_hl_rele_async(vdev_t *vd, taskq_t *taskq)
{
	mutex_enter(&vd->v_lock);
	if (vd->v_count == 1) {
		mutex_exit(&vp->v_lock);
		VERIFY(taskq_dispatch(taskq, (task_func_t *)vdev_iokit_release,
                              vd, TQ_SLEEP) != NULL);
		return;
	}
	vp->v_count--;
	mutex_exit(&vp->v_lock);
}
#endif

extern int
vdev_iokit_open(vdev_t *vd, uint64_t *size, uint64_t *max_size, uint64_t *ashift)
{
//	uint64_t blkcnt;
//	uint32_t blksize;
//	int fmode = 0;
    vdev_iokit_t *dvd = 0;
	int error = 0;
    
    if (!vd)
        return EINVAL;
    
vdev_iokit_log_ptr( "vdev_iokit_open: vd:",         vd );
vdev_iokit_log_num( "vdev_iokit_open: spa mode:",   spa_mode(vd->vdev_spa) );
vdev_iokit_log_num( "vdev_iokit_open: vd state:",   vd->vdev_state );
vdev_iokit_log_num( "vdev_iokit_open: prevstate:",  vd->vdev_prevstate );
    
    /*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}
    
    dvd = vd->vdev_tsd;
	
    if (dvd != NULL) {
vdev_iokit_log_ptr( "vdev_iokit_open: dvd:",        dvd);
vdev_iokit_log_ptr( "vdev_iokit_open: iokit_hl:",   dvd->vd_iokit_hl);
vdev_iokit_log_ptr( "vdev_iokit_open: zfs_hl:",     dvd->vd_zfs_hl);
        
        ASSERT(vd->vdev_reopening);
        goto skip_open;
    }
    
    vdev_iokit_alloc(vd);
    dvd = (vdev_iokit_t*)(vd->vdev_tsd);
    
    if(!dvd)
        return ENOMEM;

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
    
    error = EINVAL;		/* presume failure */
    
    if (vd->vdev_path != NULL) {
        
		if (vd->vdev_wholedisk == -1ULL) {
			size_t len = strlen(vd->vdev_path) + 3;
			char *buf = kmem_alloc(len, KM_SLEEP);
            
			(void) snprintf(buf, len, "%ss0", vd->vdev_path);
            
			error = vdev_iokit_open_by_path(vd, buf);
            
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
			error = vdev_iokit_open_by_path(vd, vd->vdev_path);
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
	 * or the logical path (if we failed due to the devid check).  While not
	 * as reliable as the devid, this will give us something, and the higher
	 * level vdev validation will prevent us from opening the wrong device.
	 */
	if (error) {
        
		if (vd->vdev_physpath != NULL) {
			error = vdev_iokit_open_by_path(vd, vd->vdev_physpath);
        }
        
		/*
		 * Note that we don't support the legacy auto-wholedisk support
		 * as above.  This hasn't been used in a very long time and we
		 * don't need to propagate its oddities to this edge condition.
		 */
        /*  This is redundant, but will attempt the open again after
         *   the previous attempts by path and physpath
         */
		if (error && vd->vdev_path != NULL) {
			error = vdev_iokit_open_by_path(vd, vd->vdev_path);
        }
	}
    
    /* If it couldn't be opened, back out now */
    if (error) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (error);
	}
    
    /*
	 * Once a device is opened, verify that the physical device path (if
	 * available) is up to date.
	 */
    char *physpath = 0;
    
    physpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);

    if (vdev_iokit_physpath(vd, physpath) == 0 &&
        (vd->vdev_physpath == NULL ||
         strcmp(vd->vdev_physpath, physpath) != 0)) {
            
            if (vd->vdev_physpath) {
                spa_strfree(vd->vdev_physpath);
            }
        vd->vdev_physpath = spa_strdup(physpath);
    }
    kmem_free(physpath, MAXPATHLEN);
    
    /*
     *  XXX - Replace with IOKit lookup -
     *       currently in vdev_iokit_util.cpp
     *
     *   1 physpath - IOService path, or file path
     *   2 path - file path
     *   3 guid - vdev guid
     */
	/* ### APPLE TODO ### */
	/* ddi_devid_str_decode */
    

    /*
     *  XXX - Obtain an opened/referenced IOKit handle for the device
     */
	/* Obtain an opened/referenced vnode for the device. */
    /*
	error = vnode_open(vd->vdev_path, spa_mode(vd->vdev_spa), 0, 0, &devvp, context);
	if (error) {
		goto out;
	}
     */
    
    if (!dvd->vd_iokit_hl) {
        error = EINVAL;		/* presume failure */

        error = vdev_iokit_handle_open(vd);
        
        if (error != 0) {
            goto out;
        }
    }
    
    /*
     if (!vnode_isblk(devvp)) {
     error = ENOTBLK;
     goto out;
     }
     */

skip_open:
    
	/*
	 * Determine the actual size of the device.
	 */
    vdev_iokit_get_size(vd, size, max_size, ashift);
    
    /*
     *  XXX - Not necessary here - already done
     *   by IOKit when opening the device handle
     */
	/*
	 *  Disallow opening of a device that is currently in use.
	 *  Flush out any old buffers remaining from a previous use.
	 */
    /*
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
     */
    
    
    /*
     * Done above in vdev_iokit_get_size
     */
    /*
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&blksize, 0, context)
	       	!= 0 || VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt,
		0, context) != 0) {

		error = EINVAL;
		goto out;
	}
	*size = blkcnt * (uint64_t)blksize;
     */

    
    
	/*
	 *  ### APPLE TODO ###
	 * If we own the whole disk, try to enable disk write caching.
	 */

    
    
    /*
     * Done above in vdev_iokit_get_size
     */
	/*
	 * Take the device's minimum transfer size into account.
	 */
	//*ashift = highbit(MAX(blksize, SPA_MINBLOCKSIZE)) - 1;

    /*
     *  XXX - not a problem with this IOKit interface...
     */
    /*
     * Setting the vdev_ashift did in fact break the pool for import
     * on ZEVO. This puts the logic into question. It appears that vdev_top
     * will also then change. It then panics in space_map from metaslab_alloc
     */
    //vd->vdev_ashift = *ashift;
    //dvd->vd_ashift = *ashift;

	/*
	 * Clear the nowritecache bit, so that on a vdev_reopen() we will
	 * try again.
	 */
	vd->vdev_nowritecache = B_FALSE;
 
out:
	if (error) {
        if (dvd->vd_iokit_hl) {
vdev_iokit_log_ptr( "vdev_iokit_open: bailing on handle open, trying to close handle [%p]", dvd->vd_iokit_hl );
            vdev_iokit_handle_close(vd);
        }
        
        /* Clear vdev_tsd, see below */
        vdev_iokit_free(vd);

		/*
		 * Since the open has failed, vd->vdev_tsd should
		 * be NULL when we get here, signaling to the
		 * rest of the spa not to try and reopen or close this device
		 */
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
	}
    
    vdev_iokit_log_num( "vdev_iokit_open: size:",       *size );
    vdev_iokit_log_num( "vdev_iokit_open: maxsize:",    *max_size );
    vdev_iokit_log_num( "vdev_iokit_open: ashift:",     *ashift );
    
    vdev_iokit_log_ptr( "vdev_iokit_open: dvd:",        dvd);
    vdev_iokit_log_ptr( "vdev_iokit_open: iokit_hl:",   dvd->vd_iokit_hl);
    vdev_iokit_log_ptr( "vdev_iokit_open: zfs_hl:",     dvd->vd_zfs_hl);

	return (error);
}

extern void
vdev_iokit_close(vdev_t *vd)
{
vdev_iokit_log_ptr( "vdev_iokit_close: vd:",            vd );
    
	vdev_iokit_t *dvd = vd->vdev_tsd;
    
vdev_iokit_log_ptr( "vdev_iokit_close: dvd:",           dvd );
vdev_iokit_log_num( "vdev_iokit_close: reopening:",     vd->vdev_reopening );
vdev_iokit_log_num( "vdev_iokit_close: spa mode:",      spa_mode(vd->vdev_spa) );
vdev_iokit_log_num( "vdev_iokit_close: vd state:",      vd->vdev_state );
vdev_iokit_log_num( "vdev_iokit_close: prevstate:",     vd->vdev_prevstate );
    
    if (vd->vdev_reopening || dvd == NULL)
		return;
    
    if (dvd->vd_iokit_hl != NULL) {
        /* Close the iokit handle */
        vdev_iokit_handle_close(vd);
        
		dvd->vd_iokit_hl = NULL;
	}
    
	vd->vdev_delayed_close = B_FALSE;
    
	vdev_iokit_free(vd);
    
    return;
}

extern void
vdev_iokit_ioctl_done(void *zio_arg, const int error)
{
vdev_iokit_log_ptr( "vdev_iokit_ioctl_done: zio_arg:",  zio_arg );
vdev_iokit_log_num( "vdev_iokit_ioctl_done: error:",    error );
	zio_t *zio = zio_arg;

	zio->io_error = error;

	//zio_next_stage_async(zio);
    zio_interrupt(zio);
}

extern int
vdev_iokit_io_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
//	vdev_iokit_t *dvd = vd->vdev_tsd;
//	struct buf *bp;
//	vfs_context_t context;
	int error = 0;
vdev_iokit_log_ptr( "vdev_iokit_io_start: zio:", zio );
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

            /*
             *  XXX - No context needed
             */
            /*
			context = vfs_context_create((vfs_context_t)0);
             */
                
            /*
             *  XXX - Replace with IOKit ioctl passthrough
             */
            /*
			error = VNOP_IOCTL(dvd->vd_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, context);
             */
            
                
            /* Use IOKit to sync the disk */
            vdev_iokit_sync( vd, zio );
                
//
//
//            vdev_iokit_ioctl( vd, zio );
//
//
            /*
             *  XXX - No context needed
             */
            /*
			(void) vfs_context_rele(context);
             */
                
			if (error == 0)
				vdev_iokit_ioctl_done(zio, error);
			else
				error = ENOTSUP;

			if (error == 0) {
				/*
				 * The ioctl will be done asychronously,
				 * and will call vdev_iokit_ioctl_done()
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

    /*
     *  XXX
     */
//	flags = (zio->io_type == ZIO_TYPE_READ ? B_READ : B_WRITE);
	//flags |= B_NOCACHE;

//	if (zio->io_flags & ZIO_FLAG_FAILFAST)
//		flags |= B_FAILFAST;

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

    /*
     *  XXX - Instead pass the zio/flags to IOKit
     */
    /*
	bp = buf_alloc(dvd->vd_devvp);

	ASSERT(bp != NULL);
     */
	ASSERT(zio->io_data != NULL);
	ASSERT(zio->io_size != 0);

    /*
     *  XXX - Instead pass the zio/flags to IOKit
     */
    /*
	buf_setflags(bp, flags);
	buf_setcount(bp, zio->io_size);
	buf_setdataptr(bp, (uintptr_t)zio->io_data);
     */

    /*
     *  XXX - Instead calculate this in IOKit if needed
     */
    /*
    if (zfs_iokit_vdev_ashift && vd->vdev_ashift) {
        buf_setlblkno(bp, zio->io_offset>>vd->vdev_ashift);
        buf_setblkno(bp,  zio->io_offset>>vd->vdev_ashift);
    } else {
        buf_setlblkno(bp, lbtodb(zio->io_offset));
        buf_setblkno(bp, lbtodb(zio->io_offset));
    }
     */
    
    /*
     *  XXX - Instead pass the zio/flags to IOKit
     */
    /*
	buf_setsize(bp, zio->io_size);
     */
    
    /*
     *  XXX - Instead pass the callback to IOKit
     */
    /*
	if (buf_setcallback(bp, vdev_iokit_io_intr, zio) != 0)
		panic("vdev_iokit_io_start: buf_setcallback failed\n");
     */
    
    /*
     *  XXX - Instead do the read/write strategy in IOKit
     */
    /*
	if (zio->io_type == ZIO_TYPE_WRITE) {
		vnode_startwrite(dvd->vd_devvp);
	}
	error = VNOP_STRATEGY(bp);
     */
    
    error =     vdev_iokit_strategy( vd, zio );
    
	ASSERT(error == 0);

    return (ZIO_PIPELINE_STOP);
}

extern void
vdev_iokit_io_done(zio_t *zio)
{
    /*
     *  XXX - TO DO
     *
     *  By attaching to the IOMedia device, we can both check
     *   the status via IOKit functions, and be informed of
     *   device changes.
     *
     *  Call an IOKit helper function to check the IOMedia
     *   device - status, properties, and/or ioctl.
     */
    vdev_t * vd = 0;
 
vdev_iokit_log_ptr( "vdev_iokit_io_done: zio:", zio );
    
    if (!zio)
        return;

	vd = zio->io_vd;
    
    if (!vd)
        return;
    
    /*     Not needed, currently
     *
//    vdev_iokit_t * dvd = 0;
//
//    dvd = vd->vdev_tsd;
//    
//    if (!dvd)
//        return;
     *
     */
    
	if (zio->io_error == EIO) {
        if ( !vdev_iokit_status(vd) ) {
			vd->vdev_remove_wanted = B_TRUE;
			spa_async_request(zio->io_spa, SPA_ASYNC_REMOVE);
        }
    }
}

#if 0
extern void
vdev_iokit_io_intr(struct buf *bp, void *arg)
{
vdev_iokit_log_ptr( "vdev_iokit_io_intr: bp:",  bp );
vdev_iokit_log_ptr( "vdev_iokit_io_intr: arg:", arg );
	zio_t *zio = (zio_t *)arg;
    
    zio->io_error = buf_error(bp);
    
	if (zio->io_error == 0 && buf_resid(bp) != 0) {
		zio->io_error = EIO;
	}
	buf_free(bp);
	//zio_next_stage_async(zio);
    zio_interrupt(zio);
}
#endif

vdev_ops_t vdev_iokit_ops = {
	vdev_iokit_open,
	vdev_iokit_close,
	vdev_default_asize,
	vdev_iokit_io_start,
	vdev_iokit_io_done,
	vdev_iokit_state_change,  /* vdev_op_state_change */
	vdev_iokit_hold,
	vdev_iokit_rele,
	VDEV_TYPE_DISK,         /* name of this vdev type */
	B_TRUE                  /* leaf vdev */
};
