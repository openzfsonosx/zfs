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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Portions Copyright 2010 Robert Milkowski
 *
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 *
 * Portions Copyright 2013 Jorgen Lundman
 *
 */

/*
 * ZFS volume emulation driver.
 *
 * Makes a DMU object look like a volume of arbitrary size, up to 2^64 bytes.
 * Volumes are accessed through the symbolic links named:
 *
 * /dev/zvol/dsk/<pool_name>/<dataset_name>
 * /dev/zvol/rdsk/<pool_name>/<dataset_name>
 *
 * These links are created by the /dev filesystem (sdev_zvolops.c).
 * Volumes are persistent through reboot.  No user command needs to be
 * run before opening and using a device.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/dmu_traverse.h>
#include <sys/dnode.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/dkio.h>
// #include <sys/efi_partition.h>
#include <sys/byteorder.h>
#include <sys/pathname.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/crc32.h>
#include <sys/dirent.h>
#include <sys/policy.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/mkdev.h>
#include <sys/zil.h>
#include <sys/refcount.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_rlock.h>
#include <sys/vdev_disk.h>
#include <sys/vdev_impl.h>
#include <sys/zvol.h>
#include <sys/dumphdr.h>
#include <sys/zil_impl.h>
#include <sys/dbuf.h>
#include <sys/callb.h>

#include "zfs_namecheck.h"

dev_info_t zfs_dip_real = { 0 };
dev_info_t *zfs_dip = &zfs_dip_real;
extern int zfs_major;
extern int zfs_bmajor;

/*
 * ZFS minor numbers can refer to either a control device instance or
 * a zvol. Depending on the value of zss_type, zss_data points to either
 * a zvol_state_t or a zfs_onexit_t.
 */

void *zfsdev_state;
static char *zvol_tag = "zvol_tag";

#define	ZVOL_DUMPSIZE		"dumpsize"

void *
zfsdev_get_soft_state(minor_t minor, enum zfs_soft_state_type which)
{
	zfs_soft_state_t *zp;

	zp = ddi_get_soft_state(zfsdev_state, minor);
	if (zp == NULL || zp->zss_type != which)
		return (NULL);

	return (zp->zss_data);
}

/*
 * This lock protects the zfsdev_state structure from being modified
 * while it's being used, e.g. an open that comes in before a create
 * finishes.  It also protects temporary opens of the dataset so that,
 * e.g., an open doesn't get a spurious EBUSY.
 */
static uint32_t zvol_minors;

typedef struct zvol_extent {
	list_node_t	ze_node;
	dva_t		ze_dva;		/* dva associated with this extent */
	uint64_t	ze_nblks;	/* number of blocks in extent */
} zvol_extent_t;



/*
 * zvol maximum transfer in one DMU tx.
 */
int zvol_maxphys = DMU_MAX_ACCESS/2;

extern int zfs_set_prop_nvlist(const char *, zprop_source_t,
    nvlist_t *, nvlist_t *);
static void zvol_log_truncate(zvol_state_t *zv, dmu_tx_t *tx, uint64_t off,
    uint64_t len, boolean_t sync);
static int zvol_remove_zv(zvol_state_t *);
static int zvol_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio);
// static int zvol_dumpify(zvol_state_t *zv);
// static int zvol_dump_fini(zvol_state_t *zv);
// static int zvol_dump_init(zvol_state_t *zv, boolean_t resize);

static void
zvol_size_changed(zvol_state_t *zv, uint64_t volsize)
{
	(void) makedevice(zfs_major, zv->zv_minor);

	zv->zv_volsize = volsize;
	VERIFY(ddi_prop_update_int64(dev, zfs_dip,
	    "Size", volsize) == DDI_SUCCESS);
	VERIFY(ddi_prop_update_int64(dev, zfs_dip,
	    "Nblocks",
	    volsize / zv_zv_volblocksize) == DDI_SUCCESS);

	// zvolSetVolsize(zv);

	/* Notify specfs to invalidate the cached size */
	// spec_size_invalidate(dev, VBLK);
	// spec_size_invalidate(dev, VCHR);
}

int
zvol_check_volsize(uint64_t volsize, uint64_t blocksize)
{
	if (volsize == 0)
		return (EINVAL);

	if (volsize % blocksize != 0)
		return (EINVAL);

#ifdef _ILP32XXX
	if (volsize - 1 > SPEC_MAXOFFSET_T)
		return (EOVERFLOW);
#endif
	return (0);
}

int
zvol_check_volblocksize(uint64_t volblocksize)
{
	if (volblocksize < SPA_MINBLOCKSIZE ||
	    volblocksize > SPA_MAXBLOCKSIZE ||
	    !ISP2(volblocksize))
		return (EDOM);

	return (0);
}

int
zvol_get_stats(objset_t *os, nvlist_t *nv)
{
	int error;
	dmu_object_info_t doi;
	uint64_t val;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &val);
	if (error)
		return (error);

	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLSIZE, val);

	error = dmu_object_info(os, ZVOL_OBJ, &doi);

	if (error == 0) {
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLBLOCKSIZE,
		    doi.doi_data_block_size);
	}

	return (error);
}

static zvol_state_t *
zvol_minor_lookup(const char *name)
{
	minor_t minor;
	zvol_state_t *zv;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	for (minor = 1; minor <= ZFSDEV_MAX_MINOR; minor++) {
		zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
		if (zv == NULL)
			continue;
		if (strcmp(zv->zv_name, name) == 0)
			return (zv);
	}

	return (NULL);
}

/* extent mapping arg */
struct maparg {
	zvol_state_t	*ma_zv;
	uint64_t	ma_blks;
};

#if 0 // unused function
/*ARGSUSED*/
static int
zvol_map_block(spa_t *spa, zilog_t *zilog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const dnode_phys_t *dnp, void *arg)
{
	struct maparg *ma = arg;
	zvol_extent_t *ze;
	int bs = ma->ma_zv->zv_volblocksize;

	if (bp == NULL || zb->zb_object != ZVOL_OBJ || zb->zb_level != 0)
		return (0);

	VERIFY3U(ma->ma_blks, ==, zb->zb_blkid);
	ma->ma_blks++;

	/* Abort immediately if we have encountered gang blocks */
	if (BP_IS_GANG(bp))
		return (EFRAGS);

	/*
	 * See if the block is at the end of the previous extent.
	 */
	ze = list_tail(&ma->ma_zv->zv_extents);
	if (ze &&
	    DVA_GET_VDEV(BP_IDENTITY(bp)) == DVA_GET_VDEV(&ze->ze_dva) &&
	    DVA_GET_OFFSET(BP_IDENTITY(bp)) ==
	    DVA_GET_OFFSET(&ze->ze_dva) + ze->ze_nblks * bs) {
		ze->ze_nblks++;
		return (0);
	}

	dprintf_bp(bp, "%s", "next blkptr:");

	/* start a new extent */
	ze = kmem_zalloc(sizeof (zvol_extent_t), KM_SLEEP);
	ze->ze_dva = bp->blk_dva[0];	/* structure assignment */
	ze->ze_nblks = 1;
	list_insert_tail(&ma->ma_zv->zv_extents, ze);
	return (0);
}
#endif

static void
zvol_free_extents(zvol_state_t *zv)
{
	zvol_extent_t *ze;

	while ((ze = list_head(&zv->zv_extents))) {
		list_remove(&zv->zv_extents, ze);
		kmem_free(ze, sizeof (zvol_extent_t));
	}
}

#if 0 // unused function
static int
zvol_get_lbas(zvol_state_t *zv)
{
	objset_t *os = zv->zv_objset;
	struct maparg	ma;
	int		err;

	ma.ma_zv = zv;
	ma.ma_blks = 0;
	zvol_free_extents(zv);

	/* commit any in-flight changes before traversing the dataset */
	txg_wait_synced(dmu_objset_pool(os), 0);
	err = traverse_dataset(dmu_objset_ds(os), 0,
	    TRAVERSE_PRE | TRAVERSE_PREFETCH_METADATA,
	    zvol_map_block, &ma);
	if (err || ma.ma_blks != (zv->zv_volsize / zv->zv_volblocksize)) {
		zvol_free_extents(zv);
		return (err ? err : EIO);
	}

	return (0);
}
#endif

/* ARGSUSED */
void
zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	zfs_creat_t *zct = arg;
	nvlist_t *nvprops = zct->zct_props;
	int error;
	uint64_t volblocksize, volsize;

	VERIFY(nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE),
	    &volsize) == 0);
	if (nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE),
	    &volblocksize) != 0)
		volblocksize = zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);

	/*
	 * These properties must be removed from the list so the generic
	 * property setting step won't apply to them.
	 */
	VERIFY(nvlist_remove_all(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE)) == 0);
	(void) nvlist_remove_all(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE));

	error = dmu_object_claim(os, ZVOL_OBJ, DMU_OT_ZVOL, volblocksize,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_create_claim(os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize, tx);
	ASSERT(error == 0);
}

/*
 * Replay a TX_TRUNCATE ZIL transaction if asked.  TX_TRUNCATE is how we
 * implement DKIOCFREE/free-long-range.
 */
static int
zvol_replay_truncate(void *zv, char *lr, boolean_t byteswap)
{
	zvol_state_t *the_zv = (zvol_state_t *)zv;
	lr_truncate_t *the_lr = (lr_truncate_t *)lr;

	uint64_t offset, length;

	if (byteswap)
		byteswap_uint64_array(the_lr, sizeof (*the_lr));

	offset = the_lr->lr_offset;
	length = the_lr->lr_length;

	return (dmu_free_long_range(the_zv->zv_objset,
	    ZVOL_OBJ, offset, length));
}

/*
 * Replay a TX_WRITE ZIL transaction that didn't get committed
 * after a system failure
 */
static int
zvol_replay_write(void *zv, char *lr, boolean_t byteswap)
{
	zvol_state_t *the_zv = (zvol_state_t *)zv;
	lr_write_t *the_lr = (lr_write_t *)lr;

	objset_t *os = the_zv->zv_objset;
	char *data = (char *)(lr + 1);	/* data follows lr_write_t */
	uint64_t offset, length;
	dmu_tx_t *tx;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	offset = the_lr->lr_offset;
	length = the_lr->lr_length;

	/* If it's a dmu_sync() block, write the whole block */
	if (the_lr->lr_common.lrc_reclen == sizeof (lr_write_t)) {
		uint64_t blocksize = BP_GET_LSIZE(&the_lr->lr_blkptr);
		if (length < blocksize) {
			offset -= offset % blocksize;
			length = blocksize;
		}
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_write(tx, ZVOL_OBJ, offset, length);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
	} else {
		dmu_write(os, ZVOL_OBJ, offset, length, data, tx);
		dmu_tx_commit(tx);
	}

	return (error);
}

/* ARGSUSED */
static int
zvol_replay_err(void *zv, char *lr, boolean_t byteswap)
{
	return (ENOTSUP);
}

/*
 * Callback vectors for replaying records.
 * Only TX_WRITE and TX_TRUNCATE are needed for zvol.
 */
zil_replay_func_t zvol_replay_vector[TX_MAX_TYPE] = {
	zvol_replay_err,	/* 0 no such transaction type */
	zvol_replay_err,	/* TX_CREATE */
	zvol_replay_err,	/* TX_MKDIR */
	zvol_replay_err,	/* TX_MKXATTR */
	zvol_replay_err,	/* TX_SYMLINK */
	zvol_replay_err,	/* TX_REMOVE */
	zvol_replay_err,	/* TX_RMDIR */
	zvol_replay_err,	/* TX_LINK */
	zvol_replay_err,	/* TX_RENAME */
	zvol_replay_write,	/* TX_WRITE */
	zvol_replay_truncate,	/* TX_TRUNCATE */
	zvol_replay_err,	/* TX_SETATTR */
	zvol_replay_err,	/* TX_ACL */
	zvol_replay_err,	/* TX_CREATE_ACL */
	zvol_replay_err,	/* TX_CREATE_ATTR */
	zvol_replay_err,	/* TX_CREATE_ACL_ATTR */
	zvol_replay_err,	/* TX_MKDIR_ACL */
	zvol_replay_err,	/* TX_MKDIR_ATTR */
	zvol_replay_err,	/* TX_MKDIR_ACL_ATTR */
	zvol_replay_err,	/* TX_WRITE2 */
};

int
zvol_name2minor(const char *name, minor_t *minor)
{
	zvol_state_t *zv;

	mutex_enter(&spa_namespace_lock);
	zv = zvol_minor_lookup(name);
	if (minor && zv)
		*minor = zv->zv_minor;
	mutex_exit(&spa_namespace_lock);
	return (zv ? 0 : -1);
}

/*
 * ZVOL UNMAP THREAD. Handle unmap/discard requests as they come in.
 * Each request is already locked (to stop writes) we just need to tx and
 * commit
 */
uint64_t zvol_num_unmap = 0;

void
zvol_unmap_thread(void *arg)
{
	zvol_unmap_t *um;
	callb_cpr_t cpr;
	zvol_state_t *zv = (zvol_state_t *)arg;
	dmu_tx_t *tx		= 0;
	int error			= 0;

#define VERBOSE_UNMAP
/*
 * #define VERBOSE_UNMAP
 */
#ifdef VERBOSE_UNMAP
	int count = 0;
	printf("ZFS: unmap %p thread is alive!\n", zv);
#endif
	CALLB_CPR_INIT(&cpr, &zv->zv_unmap_thr_lock, callb_generic_cpr,
	    FTAG);
	mutex_enter(&zv->zv_unmap_thr_lock);
	while (1) {
		while (1) {
			mutex_enter(&zv->zv_unmap_lock);
			um = list_head(&zv->zv_unmap_list);
			if (um) {
				list_remove(&zv->zv_unmap_list, um);
			}
			mutex_exit(&zv->zv_unmap_lock);
			/* Only exit thread once list is empty */
			if (!um)
				break;
#ifdef VERBOSE_UNMAP
			count++;
#endif
			atomic_dec_64(&zvol_num_unmap);

			/* CODE */

			if (um && zv && zv->zv_objset) {

				tx = dmu_tx_create(um->zv->zv_objset);

				error = dmu_tx_assign(tx, TXG_WAIT);

				if (error) {
					dmu_tx_abort(tx);
				} else {

					zvol_log_truncate(um->zv, tx, um->offset, um->bytes, B_TRUE);

					dmu_tx_commit(tx);

					error = dmu_free_long_range(um->zv->zv_objset,
												ZVOL_OBJ, um->offset, um->bytes);
				}

				zfs_range_unlock(um->rl);

				if (error == 0) {
					/*
					 * If the write-cache is disabled or 'sync' property
					 * is set to 'always' then treat this as a synchronous
					 * operation (i.e. commit to zil).
					 */
					if (!(um->zv->zv_flags & ZVOL_WCE) ||
						(um->zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS)) {

						zil_commit(um->zv->zv_zilog, ZVOL_OBJ);

					}
				}
			}
			/* CODE */

		} /* until empty */
#ifdef VERBOSE_UNMAP
		if (count)
			printf("unmap_thr: %p nodes cleared: %d "
				   "(in list %llu)\n", zv, count,
				   zvol_num_unmap);
		count = 0;
#endif
		/* Allow us to quit, since list is empty */
		if (zv->zv_unmap_thread_exit == TRUE)
			break;
		/* block until needed, or one second, whichever is shorter */
		CALLB_CPR_SAFE_BEGIN(&cpr);
		(void) cv_timedwait_interruptible(&zv->zv_unmap_thr_cv,
										  &zv->zv_unmap_thr_lock, (ddi_get_lbolt() + (hz>>1)));
		CALLB_CPR_SAFE_END(&cpr, &zv->zv_unmap_thr_lock);

	} /* forever */

#ifdef VERBOSE_UNMAP
	printf("ZFS: unmap thread %p is quitting!\n", zv);
#endif
	zv->zv_unmap_thread_exit = FALSE;
	cv_broadcast(&zv->zv_unmap_thr_cv);
	CALLB_CPR_EXIT(&cpr);
	thread_exit();
}






/*
 * Create a minor node (plus a whole lot more) for the specified volume.
 */
int
zvol_create_minor(const char *name)
{
	zfs_soft_state_t *zs;
	zvol_state_t *zv;
	objset_t *os;
	dmu_object_info_t doi;
	minor_t minor = 0;
	int error;

	dprintf("zvol_create_minor: '%s'\n", name);

	mutex_enter(&spa_namespace_lock);

	if (zvol_minor_lookup(name) != NULL) {
		mutex_exit(&spa_namespace_lock);
		return (EEXIST);
	}

	/* lie and say we're read-only */
	error = dmu_objset_own(name, DMU_OST_ZVOL, B_TRUE, FTAG, &os);

	if (error) {
		mutex_exit(&spa_namespace_lock);
		return (error);
	}

	// we should hold mutex_enter(&zfsdev_state_lock);
	if ((minor = zfsdev_minor_alloc()) == 0) {
		//mutex_exit(&zfsdev_state_lock);
		dmu_objset_disown(os, FTAG);
		mutex_exit(&spa_namespace_lock);
		return (ENXIO);
	}
	//mutex_exit(&zfsdev_state_lock);

	if (ddi_soft_state_zalloc(zfsdev_state, minor) != DDI_SUCCESS) {
		dmu_objset_disown(os, FTAG);
		mutex_exit(&spa_namespace_lock);
		return (EAGAIN);
	}
	(void) ddi_prop_update_string(minor, zfs_dip, ZVOL_PROP_NAME,
	    (char *)name);

	/*
	 * This is the old BSD kernel interface to create the /dev/nodes, now
	 * we also use IOKit to create an IOBlockStorageDevice.
	 */
#if 0
	char chrbuf[30], blkbuf[30];

	if (ddi_create_minor_node(zfs_dip, name, S_IFCHR,
	    minor, DDI_PSEUDO, zfs_major) == DDI_FAILURE) {
		ddi_soft_state_free(zfsdev_state, minor);
		dmu_objset_disown(os, FTAG);
		mutex_exit(&spa_namespace_lock);
		return (EAGAIN);
	}

	if (ddi_create_minor_node(zfs_dip, name, S_IFBLK,
	    minor, DDI_PSEUDO, zfs_bmajor) == DDI_FAILURE) {
		ddi_remove_minor_node(zfs_dip, chrbuf);
		ddi_soft_state_free(zfsdev_state, minor);
		dmu_objset_disown(os, FTAG);
		mutex_exit(&spa_namespace_lock);
		return (EAGAIN);
	}
#endif
	zs = ddi_get_soft_state(zfsdev_state, minor);
	zs->zss_type = ZSST_ZVOL;
	zv = zs->zss_data = kmem_zalloc(sizeof (zvol_state_t), KM_SLEEP);
	(void) strlcpy(zv->zv_name, name, MAXPATHLEN);
	zv->zv_min_bs = DEV_BSHIFT;
	zv->zv_minor = minor;
	zv->zv_objset = os;
	if (dmu_objset_is_snapshot(os) || !spa_writeable(dmu_objset_spa(os)))
		zv->zv_flags |= ZVOL_RDONLY;
	mutex_init(&zv->zv_znode.z_range_lock, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&zv->zv_znode.z_range_avl, zfs_range_compare,
	    sizeof (rl_t), offsetof(rl_t, r_node));
	list_create(&zv->zv_extents, sizeof (zvol_extent_t),
	    offsetof(zvol_extent_t, ze_node));

	printf("ZFS: zvol starting unmap thread\n");
	mutex_init(&zv->zv_unmap_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zv->zv_unmap_list, sizeof (zvol_unmap_t),
	    offsetof(zvol_unmap_t, unmap_next));
	mutex_init(&zv->zv_unmap_thr_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&zv->zv_unmap_thr_cv, NULL, CV_DEFAULT, NULL);
	zv->zv_unmap_thread_exit = FALSE;
	(void) thread_create(NULL, 0, zvol_unmap_thread, zv, 0, &p0,
						 TS_RUN, minclsyspri);

	zv->zv_znode.z_is_zvol = 1;

	/* get and cache the blocksize */
	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	ASSERT(error == 0);
	zv->zv_volblocksize = doi.doi_data_block_size;

	if (spa_writeable(dmu_objset_spa(os))) {
		if (zil_replay_disable)
			zil_destroy(dmu_objset_zil(os), B_FALSE);
		else
			zil_replay(os, zv, zvol_replay_vector);
	}

	// Call IOKit to create a new ZVOL device, we like the size being
	// set here.
	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &zv->zv_volsize);

	dmu_objset_disown(os, FTAG);
	zv->zv_objset = NULL;

	zvol_minors++;

	mutex_exit(&spa_namespace_lock);

	// The iokit framework may call Open, so we can not be locked.
	zvolCreateNewDevice(zv);



	return (0);
}


/*
 * Given a path, return TRUE if path is a ZVOL.
 */
boolean_t
zvol_is_zvol(const char *device)
{
	/* stat path, check for minor */
	return (B_FALSE);
}


/*
 * Remove minor node for the specified volume.
 */
static int
zvol_remove_zv(zvol_state_t *zv)
{
	minor_t minor = zv->zv_minor;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));
	if (zv->zv_total_opens != 0)
		return (EBUSY);

	// Call IOKit to remove the ZVOL device
	zvolRemoveDevice(zv);

#if 0
	ddi_remove_minor_node(zfs_dip, NULL);
	ddi_remove_minor_node(zfs_dip, NULL);
#endif

	printf("ZFS: zvol stopping unmap thread\n");

	mutex_enter(&zv->zv_unmap_thr_lock);
	zv->zv_unmap_thread_exit = TRUE;
	cv_signal(&zv->zv_unmap_thr_cv);
	while(zv->zv_unmap_thread_exit == TRUE) {
		cv_wait(&zv->zv_unmap_thr_cv, &zv->zv_unmap_thr_lock);
	}
	mutex_exit(&zv->zv_unmap_thr_lock);
	mutex_destroy(&zv->zv_unmap_thr_lock);
	cv_destroy(&zv->zv_unmap_thr_cv);

	avl_destroy(&zv->zv_znode.z_range_avl);
	mutex_destroy(&zv->zv_znode.z_range_lock);
	list_destroy(&zv->zv_unmap_list);
	mutex_destroy(&zv->zv_unmap_lock);

	kmem_free(zv, sizeof (zvol_state_t));

	ddi_soft_state_free(zfsdev_state, minor);

	zvol_minors--;
	return (0);
}

int
zvol_remove_minor(const char *name)
{
	zvol_state_t *zv;
	int rc;

	mutex_enter(&spa_namespace_lock);
	if ((zv = zvol_minor_lookup(name)) == NULL) {
		mutex_exit(&spa_namespace_lock);
		return (ENXIO);
	}
	zvol_remove_minor_symlink(name);
	rc = zvol_remove_zv(zv);
	if (rc != 0)
		zvol_add_symlink(zv, &zv->zv_bsdname[1], zv->zv_bsdname);
	mutex_exit(&spa_namespace_lock);
	return (rc);
}

int
zvol_remove_minor_symlink(const char *name)
{
	zvol_state_t *zv;
	int rc = 0;

	if ((zv = zvol_minor_lookup(name)) == NULL)
		return (ENXIO);

	zvol_remove_symlink(zv);
	return (rc);
}

/*
 * Rename a block device minor mode for the specified volume.
 */
#if 0 // unused function
static void
__zvol_rename_minor(zvol_state_t *zv, const char *newname)
{
#ifdef LINUX
	int readonly = get_disk_ro(zv->zv_disk);
#endif

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	strlcpy(zv->zv_name, newname, sizeof (zv->zv_name));

#ifdef LINUX
	/*
	 * The block device's read-only state is briefly changed causing
	 * a KOBJ_CHANGE uevent to be issued.  This ensures udev detects
	 * the name change and fixes the symlinks.  This does not change
	 * ZVOL_RDONLY in zv->zv_flags so the actual read-only state never
	 * changes.  This would normally be done using kobject_uevent() but
	 * that is a GPL-only symbol which is why we need this workaround.
	 */
	set_disk_ro(zv->zv_disk, !readonly);
	set_disk_ro(zv->zv_disk, readonly);
#endif
}
#endif

extern boolean_t spa_exporting_vdevs;

int
zvol_first_open(zvol_state_t *zv)
{
	objset_t *os;
	uint64_t volsize;
	int error;
	uint64_t readonly;

	dprintf("zvol_first_open: '%s'\n", zv->zv_name);

	/* lie and say we're read-only */
	error = dmu_objset_own(zv->zv_name, DMU_OST_ZVOL, B_TRUE,
	    zvol_tag, &os);
	if (error)
		return (error);

	zv->zv_objset = os;
	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize);
	if (error) {
		ASSERT(error == 0);
		dmu_objset_disown(os, zvol_tag);
		return (error);
	}

	error = dmu_bonus_hold(os, ZVOL_OBJ, zvol_tag, &zv->zv_dbuf);
	if (error) {
		dmu_objset_disown(os, zvol_tag);
		return (error);
	}

	zvol_size_changed(zv, volsize);
	zv->zv_zilog = zil_open(os, zvol_get_data);

	VERIFY(dsl_prop_get_integer(zv->zv_name, "readonly", &readonly,
	    NULL) == 0);
	if (readonly || dmu_objset_is_snapshot(os) ||
	    !spa_writeable(dmu_objset_spa(os)))
		zv->zv_flags |= ZVOL_RDONLY;
	else
		zv->zv_flags &= ~ZVOL_RDONLY;

	return (error);
}

void
zvol_last_close(zvol_state_t *zv)
{

	dprintf("zvol_last_close\n");

	zil_close(zv->zv_zilog);
	zv->zv_zilog = NULL;

	dmu_buf_rele(zv->zv_dbuf, zvol_tag);
	zv->zv_dbuf = NULL;

	/*
	 * Evict cached data
	 */
	if (dsl_dataset_is_dirty(dmu_objset_ds(zv->zv_objset)) &&
	    !(zv->zv_flags & ZVOL_RDONLY))
		txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);
	dmu_objset_evict_dbufs(zv->zv_objset);

	dmu_objset_disown(zv->zv_objset, zvol_tag);
	zv->zv_objset = NULL;
}

int
zvol_prealloc(zvol_state_t *zv)
{
	objset_t *os = zv->zv_objset;
	dmu_tx_t *tx;
	uint64_t refd, avail, usedobjs, availobjs;
	uint64_t resid = zv->zv_volsize;
	uint64_t off = 0;

	/* Check the space usage before attempting to allocate the space */
	dmu_objset_space(os, &refd, &avail, &usedobjs, &availobjs);
	if (avail < zv->zv_volsize)
		return (ENOSPC);

	/* Free old extents if they exist */
	zvol_free_extents(zv);

	while (resid != 0) {
		int error;
		uint64_t bytes = MIN(resid, SPA_MAXBLOCKSIZE);

		tx = dmu_tx_create(os);
		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			(void) dmu_free_long_range(os, ZVOL_OBJ, 0, off);
			return (error);
		}
		dmu_prealloc(os, ZVOL_OBJ, off, bytes, tx);
		dmu_tx_commit(tx);
		off += bytes;
		resid -= bytes;
	}
	txg_wait_synced(dmu_objset_pool(os), 0);

	return (0);
}

static int
zvol_update_volsize(objset_t *os, uint64_t volsize)
{
	dmu_tx_t *tx;
	int error;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1,
	    &volsize, tx);
	dmu_tx_commit(tx);

	if (error == 0)
		error = dmu_free_long_range(os,
		    ZVOL_OBJ, volsize, DMU_OBJECT_END);
	return (error);
}

void
zvol_remove_minors(const char *name)
{
	zvol_state_t *zv;
	char *namebuf;
	minor_t minor;

	size_t name_buf_len = strlen(name) + 2;

	namebuf = kmem_zalloc(name_buf_len, KM_SLEEP);
	(void) strncpy(namebuf, name, strlen(name));
	(void) strlcat(namebuf, "/", name_buf_len);
	mutex_enter(&spa_namespace_lock);
	for (minor = 1; minor <= ZFSDEV_MAX_MINOR; minor++) {

		zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
		if (zv == NULL)
			continue;
		if (strncmp(namebuf, zv->zv_name, strlen(namebuf)) == 0)
			(void) zvol_remove_zv(zv);
	}
	kmem_free(namebuf, strlen(name) + 2);

	mutex_exit(&spa_namespace_lock);
}

void
zvol_remove_minors_symlink(const char *name)
{
	zvol_state_t *zv;
	char *namebuf;
	minor_t minor;

	size_t name_buf_len = strlen(name) + 2;

	namebuf = kmem_zalloc(name_buf_len, KM_SLEEP);
	(void) strncpy(namebuf, name, strlen(name));
	(void) strlcat(namebuf, "/", name_buf_len);
	for (minor = 1; minor <= ZFSDEV_MAX_MINOR; minor++) {

		zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
		if (zv == NULL)
			continue;
		if (strncmp(namebuf, zv->zv_name, strlen(namebuf)) == 0)
			zvol_remove_symlink(zv);
	}
	kmem_free(namebuf, strlen(name) + 2);
}

/*
 * Rename minors for specified dataset including children and snapshots.
 */
void
zvol_rename_minors(const char *oldname, const char *newname)
{
	int oldnamelen, newnamelen;
	char *name;

#ifdef LINUX
	if (zvol_inhibit_dev)
		return;
#endif

	oldnamelen = strlen(oldname);
	newnamelen = strlen(newname);
	name = kmem_alloc(MAXNAMELEN, KM_PUSHPAGE);

	mutex_enter(&spa_namespace_lock);

#ifdef LINUX
	zvol_state_t *zv, *zv_next;

	for (zv = list_head(&zvol_state_list); zv != NULL; zv = zv_next) {
		zv_next = list_next(&zvol_state_list, zv);

		if (strcmp(zv->zv_name, oldname) == 0) {
			__zvol_rename_minor(zv, newname);
		} else if (strncmp(zv->zv_name, oldname, oldnamelen) == 0 &&
		    (zv->zv_name[oldnamelen] == '/' ||
		    zv->zv_name[oldnamelen] == '@')) {
			snprintf(name, MAXNAMELEN, "%s%c%s", newname,
			    zv->zv_name[oldnamelen],
			    zv->zv_name + oldnamelen + 1);

			__zvol_rename_minor(zv, name);

		}
	}
#endif

	mutex_exit(&spa_namespace_lock);

	kmem_free(name, MAXNAMELEN);
}



static int
zvol_update_live_volsize(zvol_state_t *zv, uint64_t volsize)
{
	uint64_t old_volsize = 0ULL;
	int error = 0;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	/*
	 * Reinitialize the dump area to the new size. If we
	 * failed to resize the dump area then restore it back to
	 * its original size.  We must set the new volsize prior
	 * to calling dumpvp_resize() to ensure that the devices'
	 * size(9P) is not visible by the dump subsystem.
	 */
	old_volsize = zv->zv_volsize;
	zvol_size_changed(zv, volsize);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		if ((error = zvol_dumpify(zv)) != 0 ||
		    (error = dumpvp_resize()) != 0) {

			int dumpify_error;

			(void) zvol_update_volsize(zv->zv_objset, old_volsize);
			zvol_size_changed(zv, old_volsize);
			dumpify_error = zvol_dumpify(zv);
			error = dumpify_error ? dumpify_error : error;
		}
	}
#endif

	/*
	 * Generate a LUN expansion event.
	 */
	if (error == 0) {
#if sun
		sysevent_id_t eid;
		nvlist_t *attr;
		char *physpath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

		(void) snprintf(physpath, MAXPATHLEN, "%s%u", ZVOL_PSEUDO_DEV,
		    zv->zv_minor);

		VERIFY(nvlist_alloc(&attr, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_string(attr, DEV_PHYS_PATH, physpath) == 0);

		(void) ddi_log_sysevent(zfs_dip, SUNW_VENDOR, EC_DEV_STATUS,
		    ESC_DEV_DLE, attr, &eid, DDI_SLEEP);

		nvlist_free(attr);
		kmem_free(physpath, MAXPATHLEN);
#endif
	}
	return (error);
}

static int
snapdev_snapshot_changed_cb(const char *dsname, void *arg) {
	uint64_t snapdev = *(uint64_t *)arg;

	if (strchr(dsname, '@') == NULL)
		return (0);

	switch (snapdev) {
		case ZFS_SNAPDEV_VISIBLE:
			(void) zvol_create_minor(dsname);
			break;
		case ZFS_SNAPDEV_HIDDEN:
			(void) zvol_remove_minor(dsname);
			break;
	}
	return (0);
}



int
zvol_set_snapdev(const char *dsname, uint64_t snapdev) {
	(void) dmu_objset_find((char *)dsname, snapdev_snapshot_changed_cb,
				&snapdev, DS_FIND_SNAPSHOTS | DS_FIND_CHILDREN);
	/* caller should continue to modify snapdev property */
	return (-1);
}


int
zvol_set_volsize(const char *name, uint64_t volsize)
{
	zvol_state_t *zv = NULL;
	objset_t *os;
	int error;
	dmu_object_info_t doi;
	uint64_t readonly;
	boolean_t owned = B_FALSE;

	dprintf("zvol_set_volsize %llu\n", volsize);

	error = dsl_prop_get_integer(name,
	    zfs_prop_to_name(ZFS_PROP_READONLY),
	    &readonly, NULL);
	if (error != 0)
		return (error);
	if (readonly)
		return (EROFS);

	mutex_enter(&spa_namespace_lock);
	zv = zvol_minor_lookup(name);

	if (zv == NULL || zv->zv_objset == NULL) {
		if ((error = dmu_objset_own(name, DMU_OST_ZVOL, B_FALSE,
		    FTAG, &os)) != 0) {
			mutex_exit(&spa_namespace_lock);
			return (error);
		}
		owned = B_TRUE;
		if (zv != NULL)
			zv->zv_objset = os;
	} else {
		os = zv->zv_objset;
	}

	if ((error = dmu_object_info(os, ZVOL_OBJ, &doi)) != 0 ||
	    (error = zvol_check_volsize(volsize,
	    doi.doi_data_block_size)) != 0)
		goto out;

	error = zvol_update_volsize(os, volsize);

	if (error == 0 && zv != NULL)
		error = zvol_update_live_volsize(zv, volsize);
out:
	if (owned) {
		dmu_objset_disown(os, FTAG);
		if (zv != NULL)
			zv->zv_objset = NULL;
	}
	mutex_exit(&spa_namespace_lock);
	return (error);
}


int
zvol_open_impl(zvol_state_t *zv, int flag, int otyp, struct proc *p)
{
	int err = 0;
	// int locked = 1;

	// if (mutex_owner(&spa_namespace_lock))
	//   locked = 0;
	// else
	//   mutex_enter(&spa_namespace_lock);

	if (zv->zv_total_opens == 0)
		err = zvol_first_open(zv);

	if (err) {
		//	if (locked) mutex_exit(&spa_namespace_lock);
		return (err);
	}
	if ((flag & FWRITE) && (zv->zv_flags & ZVOL_RDONLY)) {
		err = EROFS;
		goto out;
	}
	if (zv->zv_flags & ZVOL_EXCL) {
		dprintf("already open as exclusive\n");
		err = EBUSY;
		goto out;
	}
	if (flag & FEXCL) {
		if (zv->zv_total_opens != 0) {
			err = EBUSY;
			goto out;
		}
		dprintf("setting exclusive\n");
		zv->zv_flags |= ZVOL_EXCL;
	}

#if sun
	if (zv->zv_open_count[otyp] == 0 || otyp == OTYP_LYR) {
		zv->zv_open_count[otyp]++;
	}
#endif
	zv->zv_total_opens++;

	//	if (locked) mutex_exit(&spa_namespace_lock);

	dprintf("zol_open()->%d\n", err);
	return (err);
out:
	if (zv->zv_total_opens == 0)
		zvol_last_close(zv);
	// if (locked) mutex_exit(&spa_namespace_lock);
	dprintf("zol_open(x)->%d\n", err);
	return (err);
}



/*ARGSUSED*/
int
zvol_open(dev_t devp, int flag, int otyp, struct proc *p)
{
	zvol_state_t *zv;

	// Minor 0 is the /dev/zfs control, not zvol.
	if (!getminor(devp))
		return (0);

	dprintf("zvol_open: minor %d\n", getminor(devp));

	mutex_enter(&spa_namespace_lock);

	zv = zfsdev_get_soft_state(getminor(devp), ZSST_ZVOL);
	if (zv == NULL) {
		dprintf("zv is NULL\n");
		mutex_exit(&spa_namespace_lock);
		return (ENXIO);
	}

	mutex_exit(&spa_namespace_lock); // Is there a race here?

	return (zvol_open_impl(zv, flag, otyp, p));
}




int
zvol_close_impl(zvol_state_t *zv, int flag, int otyp, struct proc *p)
{
	int error = 0;
	// int locked = 1;

	// if (mutex_owner(&spa_namespace_lock))
	//	locked = 0;
	// else
	//	mutex_enter(&spa_namespace_lock);

	dprintf("zvol_close_impl\n");

	if (zv->zv_flags & ZVOL_EXCL) {
		ASSERT(zv->zv_total_opens == 1);
		zv->zv_flags &= ~ZVOL_EXCL;
		dprintf("clearing exclusive\n");
	}

	/*
	 * If the open count is zero, this is a spurious close.
	 * That indicates a bug in the kernel / DDI framework.
	 */
	// ASSERT(zv->zv_open_count[otyp] != 0);
	ASSERT(zv->zv_total_opens != 0);

	/*
	 * You may get multiple opens, but only one close.
	 */
	// zv->zv_open_count[otyp]--;
	zv->zv_total_opens--;

	if (zv->zv_total_opens == 0)
		zvol_last_close(zv);

	// if (locked) mutex_exit(&spa_namespace_lock);
	return (error);
}

/*ARGSUSED*/
int
zvol_close(dev_t dev, int flag, int otyp, struct proc *p)
{
	minor_t minor = getminor(dev);
	zvol_state_t *zv;

	// Minor 0 is the /dev/zfs control, not zvol.
	if (!getminor(dev))
		return (0);

	dprintf("zvol_close(%d)\n", getminor(dev));

	mutex_enter(&spa_namespace_lock);

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
	if (zv == NULL) {
		mutex_exit(&spa_namespace_lock);
		return (ENXIO);
	}

	mutex_exit(&spa_namespace_lock); // Is there a race here..
	return (zvol_close_impl(zv, flag, otyp, p));
}

static void
zvol_get_done(zgd_t *zgd, int error)
{
	if (zgd->zgd_db)
		dmu_buf_rele(zgd->zgd_db, zgd);

	zfs_range_unlock(zgd->zgd_rl);

	if (error == 0 && zgd->zgd_bp)
		zil_add_block(zgd->zgd_zilog, zgd->zgd_bp);

	kmem_free(zgd, sizeof (zgd_t));
}

/*
 * Get data to generate a TX_WRITE intent log record.
 */
static int
zvol_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio)
{
	zvol_state_t *zv = arg;
	objset_t *os = zv->zv_objset;
	uint64_t object = ZVOL_OBJ;
	uint64_t offset = lr->lr_offset;
	uint64_t size = lr->lr_length;	/* length of user data */
	blkptr_t *bp = &lr->lr_blkptr;
	dmu_buf_t *db;
	zgd_t *zgd;
	int error;

	ASSERT(zio != NULL);
	ASSERT(size != 0);

	zgd = kmem_zalloc(sizeof (zgd_t), KM_SLEEP);
	zgd->zgd_zilog = zv->zv_zilog;
	zgd->zgd_rl = zfs_range_lock(&zv->zv_znode, offset, size, RL_READER);

	/*
	 * Write records come in two flavors: immediate and indirect.
	 * For small writes it's cheaper to store the data with the
	 * log record (immediate); for large writes it's cheaper to
	 * sync the data and get a pointer to it (indirect) so that
	 * we don't have to write the data twice.
	 */
	if (buf != NULL) {	/* immediate write */
		error = dmu_read(os, object, offset, size, buf,
		    DMU_READ_NO_PREFETCH);
	} else {
		size = zv->zv_volblocksize;
		offset = P2ALIGN(offset, size);
		error = dmu_buf_hold(os, object, offset, zgd, &db,
		    DMU_READ_NO_PREFETCH);
		if (error == 0) {
			blkptr_t *obp = dmu_buf_get_blkptr(db);
			if (obp) {
				ASSERT(BP_IS_HOLE(bp));
				*bp = *obp;
			}

			zgd->zgd_db = db;
			zgd->zgd_bp = bp;

			ASSERT(db->db_offset == offset);
			ASSERT(db->db_size == size);

			error = dmu_sync(zio, lr->lr_common.lrc_txg,
			    zvol_get_done, zgd);

			if (error == 0)
				return (0);
		}
	}

	zvol_get_done(zgd, error);

	return (error);
}

/*
 * zvol_log_write() handles synchronous writes using TX_WRITE ZIL transactions.
 *
 * We store data in the log buffers if it's small enough.
 * Otherwise we will later flush the data out via dmu_sync().
 */
ssize_t zvol_immediate_write_sz = 32768;

static void
zvol_log_write(zvol_state_t *zv, dmu_tx_t *tx, offset_t off, ssize_t resid,
    boolean_t sync)
{
	uint32_t blocksize = zv->zv_volblocksize;
	zilog_t *zilog = zv->zv_zilog;
	boolean_t slogging;
	ssize_t immediate_write_sz;

	if (zil_replaying(zilog, tx))
		return;

	immediate_write_sz = (zilog->zl_logbias == ZFS_LOGBIAS_THROUGHPUT)
	    ? 0 : zvol_immediate_write_sz;

	slogging = spa_has_slogs(zilog->zl_spa) &&
	    (zilog->zl_logbias == ZFS_LOGBIAS_LATENCY);

	while (resid) {
		itx_t *itx;
		lr_write_t *lr;
		ssize_t len;
		itx_wr_state_t write_state;

		/*
		 * Unlike zfs_log_write() we can be called with
		 * upto DMU_MAX_ACCESS/2 (5MB) writes.
		 */
		if (blocksize > immediate_write_sz && !slogging &&
		    resid >= blocksize && off % blocksize == 0) {
			write_state = WR_INDIRECT; /* uses dmu_sync */
			len = blocksize;
		} else if (sync) {
			write_state = WR_COPIED;
			len = MIN(ZIL_MAX_LOG_DATA, resid);
		} else {
			write_state = WR_NEED_COPY;
			len = MIN(ZIL_MAX_LOG_DATA, resid);
		}

		itx = zil_itx_create(TX_WRITE, sizeof (*lr) +
		    (write_state == WR_COPIED ? len : 0));
		lr = (lr_write_t *)&itx->itx_lr;
		if (write_state == WR_COPIED && dmu_read(zv->zv_objset,
		    ZVOL_OBJ, off, len, lr + 1,
		    DMU_READ_NO_PREFETCH) != 0) {

			zil_itx_destroy(itx);
			itx = zil_itx_create(TX_WRITE, sizeof (*lr));
			lr = (lr_write_t *)&itx->itx_lr;
			write_state = WR_NEED_COPY;
		}

		itx->itx_wr_state = write_state;
		if (write_state == WR_NEED_COPY)
			itx->itx_sod += len;
		lr->lr_foid = ZVOL_OBJ;
		lr->lr_offset = off;
		lr->lr_length = len;
		lr->lr_blkoff = 0;
		BP_ZERO(&lr->lr_blkptr);

		itx->itx_private = zv;
		itx->itx_sync = sync;

		zil_itx_assign(zilog, itx, tx);

		off += len;
		resid -= len;
	}
}

#if 0 // unused function

static int
zvol_dumpio_vdev(vdev_t *vd, void *addr, uint64_t offset, uint64_t size,
    boolean_t doread, boolean_t isdump)
{
#if sun
	vdev_disk_t *dvd;
	int numerrors = 0;
	int c;

	for (c = 0; c < vd->vdev_children; c++) {
		ASSERT(vd->vdev_ops == &vdev_mirror_ops ||
		    vd->vdev_ops == &vdev_replacing_ops ||
		    vd->vdev_ops == &vdev_spare_ops);
		int err = zvol_dumpio_vdev(vd->vdev_child[c],
		    addr, offset, size, doread, isdump);
		if (err != 0) {
			numerrors++;
		} else if (doread) {
			break;
		}
	}

	if (!vd->vdev_ops->vdev_op_leaf)
		return (numerrors < vd->vdev_children ? 0 : EIO);

	if (doread && !vdev_readable(vd))
		return (EIO);
	else if (!doread && !vdev_writeable(vd))
		return (EIO);

	dvd = vd->vdev_tsd;
	ASSERT3P(dvd, !=, NULL);
	offset += VDEV_LABEL_START_SIZE;

	if (ddi_in_panic() || isdump) {
		ASSERT(!doread);
		if (doread)
			return (EIO);
		return (ldi_dump(dvd->vd_lh, addr, lbtodb(offset),
		    lbtodb(size)));
	} else {
		return (vdev_disk_physio(dvd->vd_lh, addr, size, offset,
		    doread ? B_READ : B_WRITE));
	}
#endif
	return (ENOTSUP);
}

#endif

static int
zvol_dumpio(zvol_state_t *zv, void *addr, uint64_t offset, uint64_t size,
    boolean_t doread, boolean_t isdump)
{
	int error = 0;
#if sun
	vdev_t *vd;
	zvol_extent_t *ze;
	spa_t *spa = dmu_objset_spa(zv->zv_objset);
	/* Must be sector aligned, and not stradle a block boundary. */
	if (P2PHASE(offset, DEV_BSIZE) || P2PHASE(size, DEV_BSIZE) ||
	    P2BOUNDARY(offset, size, zv->zv_volblocksize)) {
		return (EINVAL);
	}
	ASSERT(size <= zv->zv_volblocksize);

	/* Locate the extent this belongs to */
	ze = list_head(&zv->zv_extents);
	while (offset >= ze->ze_nblks * zv->zv_volblocksize) {
		offset -= ze->ze_nblks * zv->zv_volblocksize;
		ze = list_next(&zv->zv_extents, ze);
	}

	if (ze == NULL)
		return (EINVAL);

	if (!ddi_in_panic())
		spa_config_enter(spa, SCL_STATE, FTAG, RW_READER);

	vd = vdev_lookup_top(spa, DVA_GET_VDEV(&ze->ze_dva));
	offset += DVA_GET_OFFSET(&ze->ze_dva);
	error = zvol_dumpio_vdev(vd, addr, offset, size, doread, isdump);

	if (!ddi_in_panic())
		spa_config_exit(spa, SCL_STATE, FTAG);
#endif
	return (error);
}

void
zvol_strategy(struct buf *bp)
{
	zfs_soft_state_t *zs = NULL;
	zvol_state_t *zv;
	uint64_t off, volsize;
	size_t resid;
	char *addr;
	objset_t *os;
	rl_t *rl;
	int error = 0;
	boolean_t doread = buf_flags(bp) & B_READ;
	boolean_t is_dump;
	boolean_t sync;

	dprintf("zvol_strategy\n");

	if (getminor(buf_device(bp)) == 0) {
		error = EINVAL;
	} else {
		zs = ddi_get_soft_state(zfsdev_state, getminor(buf_device(bp)));
		if (zs == NULL)
			error = ENXIO;
		else if (zs->zss_type != ZSST_ZVOL)
			error = EINVAL;
	}

	if (error) {
		bioerror(bp, error);
		biodone(bp);
		return;
	}

	zv = zs->zss_data;

	if (!(buf_flags(bp) & B_READ) && (zv->zv_flags & ZVOL_RDONLY)) {
		bioerror(bp, EROFS);
		biodone(bp);
		return;
	}

	off = ldbtob(buf_lblkno(bp));
	volsize = zv->zv_volsize;

	os = zv->zv_objset;
	ASSERT(os != NULL);

	/*
	 * bp_mapin() is used to map virtual address space to a page list
	 * maintained by the buffer header during a paged-I/O request.
	 * bp_mapin() allocates system virtual address space, maps that space to
	 * the page list, and returns the starting address of the space in the
	 * bp->b_un.b_addr field of the buf(9S) structure. Virtual address space
	 * is then deallocated using the bp_mapout(9F) function.
	 */
	// bp_mapin(bp);
	// addr = buf_dataptr(bp);
	buf_map(bp, &addr);
	resid = buf_count(bp);

	if (resid > 0 && (off >= volsize)) {
		bioerror(bp, EIO);
		biodone(bp);
		return;
	}

	is_dump = zv->zv_flags & ZVOL_DUMPIFIED;
	sync = ((!(buf_flags(bp) & B_ASYNC) &&
	    !(zv->zv_flags & ZVOL_WCE)) ||
	    (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS)) &&
	    !doread && !is_dump;

	/*
	 * There must be no buffer changes when doing a dmu_sync() because
	 * we can't change the data whilst calculating the checksum.
	 */
	rl = zfs_range_lock(&zv->zv_znode, off, resid,
	    doread ? RL_READER : RL_WRITER);

	while (resid != 0 && off < volsize) {
		size_t size = MIN(resid, zvol_maxphys);
		if (is_dump) {
			size = MIN(size, P2END(off, zv->zv_volblocksize) - off);
			error = zvol_dumpio(zv, addr, off, size,
			    doread, B_FALSE);
		} else if (doread) {
			error = dmu_read(os, ZVOL_OBJ, off, size, addr,
			    DMU_READ_PREFETCH);
		} else {
			dmu_tx_t *tx = dmu_tx_create(os);
			dmu_tx_hold_write(tx, ZVOL_OBJ, off, size);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error) {
				dmu_tx_abort(tx);
			} else {
				dmu_write(os, ZVOL_OBJ, off, size, addr, tx);
				zvol_log_write(zv, tx, off, size, sync);
				dmu_tx_commit(tx);
			}
		}
		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = EIO;
			break;
		}
		off += size;
		addr += size;
		resid -= size;
	}
	zfs_range_unlock(rl);

	buf_setresid(bp, resid);
	if (buf_resid(bp) == buf_count(bp))
		bioerror(bp, off > volsize ? EINVAL : error);

	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
	biodone(bp);
}

/*
 * Set the buffer count to the zvol maximum transfer.
 * Using our own routine instead of the default minphys()
 * means that for larger writes we write bigger buffers on X86
 * (128K instead of 56K) and flush the disk write cache less often
 * (every zvol_maxphys - currently 1MB) instead of minphys (currently
 * 56K on X86 and 128K on sparc).
 */
void
zvol_minphys(struct buf *bp)
{
	if (buf_count(bp) > zvol_maxphys)
		buf_setcount(bp, zvol_maxphys);
}

int
zvol_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblocks)
{
	minor_t minor = getminor(dev);
	zvol_state_t *zv;
	int error = 0;
	uint64_t size;
	uint64_t boff;
	uint64_t resid;

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
	if (zv == NULL)
		return (ENXIO);

	if ((zv->zv_flags & ZVOL_DUMPIFIED) == 0)
		return (EINVAL);

	boff = ldbtob(blkno);
	resid = ldbtob(nblocks);

	VERIFY3U(boff + resid, <=, zv->zv_volsize);

	while (resid) {
		size = MIN(resid, P2END(boff, zv->zv_volblocksize) - boff);
		error = zvol_dumpio(zv, addr, boff, size, B_FALSE, B_TRUE);
		if (error)
			break;
		boff += size;
		addr += size;
		resid -= size;
	}

	return (error);
}



/*ARGSUSED*/
int
zvol_read(dev_t dev, struct uio *uio, int p)
{
	minor_t minor = getminor(dev);
	zvol_state_t *zv;
	uint64_t volsize;
	rl_t *rl;
	int error = 0;

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);

	if (zv == NULL)
		return (ENXIO);

	volsize = zv->zv_volsize;
	if (uio_resid(uio) > 0 &&
	    (uio_offset(uio) < 0 || uio_offset(uio) >= volsize))
		return (EIO);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		error = physio(zvol_strategy, NULL, dev, B_READ,
		    zvol_minphys, uio, zv->zv_volblocksize);
		return (error);
	}
#endif

	rl = zfs_range_lock(&zv->zv_znode, uio_offset(uio), uio_resid(uio),
	    RL_READER);
	while (uio_resid(uio) > 0 && uio_offset(uio) < volsize) {
		uint64_t bytes = MIN(uio_resid(uio), DMU_MAX_ACCESS >> 1);

		/* don't read past the end */
		if (bytes > volsize - uio_offset(uio))
			bytes = volsize - uio_offset(uio);

		error =  dmu_read_uio(zv->zv_objset, ZVOL_OBJ, uio, bytes);
		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = EIO;
			break;
		}
	}
	zfs_range_unlock(rl);
	return (error);
}

/*ARGSUSED*/
int
zvol_write(dev_t dev, struct uio *uio, int p)
{
	minor_t minor = getminor(dev);
	zvol_state_t *zv;
	uint64_t volsize;
	rl_t *rl;
	int error = 0;
	boolean_t sync;

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);

	if (zv == NULL)
		return (ENXIO);

	volsize = zv->zv_volsize;
	if (uio_resid(uio) > 0 &&
	    (uio_offset(uio) < 0 || uio_offset(uio) >= volsize))
		return (EIO);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		error = physio(zvol_strategy, NULL, dev, B_WRITE,
		    zvol_minphys, uio, zv->zv_volblocksize);
		return (error);
	}
#endif

	sync = !(zv->zv_flags & ZVOL_WCE) ||
	    (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS);

	rl = zfs_range_lock(&zv->zv_znode, uio_offset(uio), uio_resid(uio),
	    RL_WRITER);
	while (uio_resid(uio) > 0 && uio_offset(uio) < volsize) {
		uint64_t bytes = MIN(uio_resid(uio), DMU_MAX_ACCESS >> 1);
		uint64_t off = uio_offset(uio);
		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);

		if (bytes > volsize - off)	/* don't write past the end */
			bytes = volsize - off;

		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			break;
		}
		error = dmu_write_uio_dbuf(zv->zv_dbuf, uio, bytes, tx);
		if (error == 0)
			zvol_log_write(zv, tx, off, bytes, sync);
		dmu_tx_commit(tx);

		if (error)
			break;
	}
	zfs_range_unlock(rl);
	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
	return (error);
}

/*
 * IOKit read operations will pass IOMemoryDescriptor along here, so
 * that we can call io->writeBytes to read into IOKit zvolumes.
 */
int
zvol_read_iokit(zvol_state_t *zv, uint64_t position,
    uint64_t count, void *iomem)
{
	uint64_t volsize;
	rl_t *rl;
	int error = 0;
	uint64_t offset = 0;

	if (zv == NULL)
		return (ENXIO);

	volsize = zv->zv_volsize;
	if (count > 0 &&
	    (position >= volsize))
		return (EIO);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		error = physio(zvol_strategy, NULL, dev, B_READ,
		    zvol_minphys, uio, zv->zv_volblocksize);
		return (error);
	}
#endif

	rl = zfs_range_lock(&zv->zv_znode, position, count,
	    RL_READER);
	while (count > 0 && (position+offset) < volsize) {
		uint64_t bytes = MIN(count, DMU_MAX_ACCESS >> 1);

		/* don't read past the end */
		if (bytes > volsize - (position + offset))
			bytes = volsize - (position + offset);

		dprintf("%s %llu offset %llu len %llu bytes %llu\n",
		    "zvol_read_iokit: position",
		    position, offset, count, bytes);

		error =  dmu_read_iokit(zv->zv_objset, ZVOL_OBJ, &offset,
		    position, &bytes, iomem);

		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = EIO;
			break;
		}
		count -= MIN(count, DMU_MAX_ACCESS >> 1) - bytes;
	}
	zfs_range_unlock(rl);

	return (error);
}


/*
 * IOKit write operations will pass IOMemoryDescriptor along here, so
 * that we can call io->readBytes to write into IOKit zvolumes.
 */

int
zvol_write_iokit(zvol_state_t *zv, uint64_t position,
    uint64_t count, void *iomem)
{
	uint64_t volsize;
	rl_t *rl;
	int error = 0;
	boolean_t sync;
	uint64_t offset = 0;

	if (zv == NULL)
		return (ENXIO);

	volsize = zv->zv_volsize;
	if (count > 0 &&
	    (position >= volsize))
		return (EIO);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		error = physio(zvol_strategy, NULL, dev, B_WRITE,
		    zvol_minphys, uio, zv->zv_volblocksize);
		return (error);
	}
#endif

	dprintf("zvol_write_iokit(position %llu offset 0x%llx bytes 0x%llx)\n",
	    position, offset, count);

	sync = !(zv->zv_flags & ZVOL_WCE) ||
	    (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS);

	rl = zfs_range_lock(&zv->zv_znode, position, count,
	    RL_WRITER);
	while (count > 0 && (position + offset) < volsize) {
		uint64_t bytes = MIN(count, DMU_MAX_ACCESS >> 1);
		uint64_t off = offset;
		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);

		/* don't write past the end */
		if (bytes > volsize - (position + off))
			bytes = volsize - (position + off);

		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			break;
		}

		error = dmu_write_iokit_dbuf(zv->zv_dbuf, &offset, position,
		    &bytes, iomem, tx);

		if (error == 0) {
			count -= MIN(count, DMU_MAX_ACCESS >> 1) + bytes;
			zvol_log_write(zv, tx, off, bytes, sync);
		}
		dmu_tx_commit(tx);

		if (error)
			break;
	}
	zfs_range_unlock(rl);
	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

	return (error);
}

int
zvol_unmap(zvol_state_t *zv, uint64_t off, uint64_t bytes)
{
	zvol_unmap_t *um;
	uint64_t volsize;

	if (zv == NULL)
		return (ENXIO);

	dprintf("ZFS: unmap %llx length %llx\n", off, bytes);

	volsize = zv->zv_volsize;

	if (bytes > volsize - off)	/* don't write past the end */
		bytes = volsize - off;

	um = kmem_alloc(sizeof(zvol_unmap_t), KM_SLEEP);
	um->offset = off;
	um->bytes = bytes;
	um->zv = zv;
	list_link_init(&um->unmap_next);

	um->rl = zfs_range_lock(&zv->zv_znode, off, bytes, RL_WRITER);

	mutex_enter(&zv->zv_unmap_lock);
	list_insert_tail(&zv->zv_unmap_list, um);
	mutex_exit(&zv->zv_unmap_lock);
	atomic_inc_64(&zvol_num_unmap);

	return (0);
}

int
zvol_getefi(void *arg, int flag, uint64_t vs, uint8_t bs)
{
#if sun
	struct uuid uuid = EFI_RESERVED;
	efi_gpe_t gpe = { 0 };
	uint32_t crc;
	dk_efi_t efi;
	int length;
	char *ptr;

	if (ddi_copyin(arg, &efi, sizeof (dk_efi_t), flag))
		return (EFAULT);
	ptr = (char *)(uintptr_t)efi.dki_data_64;
	length = efi.dki_length;
	/*
	 * Some clients may attempt to request a PMBR for the
	 * zvol.  Currently this interface will return EINVAL to
	 * such requests.  These requests could be supported by
	 * adding a check for lba == 0 and consing up an appropriate
	 * PMBR.
	 */
	if (efi.dki_lba < 1 || efi.dki_lba > 2 || length <= 0)
		return (EINVAL);

	gpe.efi_gpe_StartingLBA = LE_64(34ULL);
	gpe.efi_gpe_EndingLBA = LE_64((vs >> bs) - 1);
	UUID_LE_CONVERT(gpe.efi_gpe_PartitionTypeGUID, uuid);

	if (efi.dki_lba == 1) {
		efi_gpt_t gpt = { 0 };

		gpt.efi_gpt_Signature = LE_64(EFI_SIGNATURE);
		gpt.efi_gpt_Revision = LE_32(EFI_VERSION_CURRENT);
		gpt.efi_gpt_HeaderSize = LE_32(sizeof (gpt));
		gpt.efi_gpt_MyLBA = LE_64(1ULL);
		gpt.efi_gpt_FirstUsableLBA = LE_64(34ULL);
		gpt.efi_gpt_LastUsableLBA = LE_64((vs >> bs) - 1);
		gpt.efi_gpt_PartitionEntryLBA = LE_64(2ULL);
		gpt.efi_gpt_NumberOfPartitionEntries = LE_32(1);
		gpt.efi_gpt_SizeOfPartitionEntry =
		    LE_32(sizeof (efi_gpe_t));
		CRC32(crc, &gpe, sizeof (gpe), -1U, crc32_table);
		gpt.efi_gpt_PartitionEntryArrayCRC32 = LE_32(~crc);
		CRC32(crc, &gpt, sizeof (gpt), -1U, crc32_table);
		gpt.efi_gpt_HeaderCRC32 = LE_32(~crc);
		if (ddi_copyout(&gpt, ptr, MIN(sizeof (gpt), length),
		    flag))
			return (EFAULT);
		ptr += sizeof (gpt);
		length -= sizeof (gpt);
	}
	if (length > 0 && ddi_copyout(&gpe, ptr,
	    MIN(sizeof (gpe), length), flag))
		return (EFAULT);
#endif
	return (0);
}

/*
 * BEGIN entry points to allow external callers access to the volume.
 */
/*
 * Return the volume parameters needed for access from an external caller.
 * These values are invariant as long as the volume is held open.
 */
int
zvol_get_volume_params(minor_t minor, uint64_t *blksize,
    uint64_t *max_xfer_len, void **minor_hdl,
    void **objset_hdl, void **zil_hdl,
    void **rl_hdl, void **bonus_hdl)
{
	zvol_state_t *zv;

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
	if (zv == NULL)
		return (ENXIO);
	if (zv->zv_flags & ZVOL_DUMPIFIED)
		return (ENXIO);

	ASSERT(blksize && max_xfer_len && minor_hdl &&
	    objset_hdl && zil_hdl && rl_hdl && bonus_hdl);

	*blksize = zv->zv_volblocksize;
	*max_xfer_len = (uint64_t)zvol_maxphys;
	*minor_hdl = zv;
	*objset_hdl = zv->zv_objset;
	*zil_hdl = zv->zv_zilog;
	*rl_hdl = &zv->zv_znode;
	*bonus_hdl = zv->zv_dbuf;
	return (0);
}

/*
 * Return the current volume size to an external caller.
 * The size can change while the volume is open.
 */
int
zvol_get_volume_size(dev_t dev)
{
	zvol_state_t *zv;
	dprintf("zvol_get_volume_size\n");

	// Minor 0 is the /dev/zfs control, not zvol.
	if (!getminor(dev))
		return (ENXIO);

	mutex_enter(&spa_namespace_lock);

	zv = zfsdev_get_soft_state(getminor(dev), ZSST_ZVOL);
	if (zv == NULL) {
		dprintf("zv is NULL\n");
		mutex_exit(&spa_namespace_lock);
		return (ENXIO);
	}

	mutex_exit(&spa_namespace_lock);
	return (zv->zv_volsize / zv->zv_volblocksize);
}


int
zvol_get_volume_blocksize(dev_t dev)
{
	zvol_state_t *zv;
	dprintf("zvol_get_volume_blocksize\n");

	// Minor 0 is the /dev/zfs control, not zvol.
	if (!getminor(dev))
		return (ENXIO);

	mutex_enter(&spa_namespace_lock);

	zv = zfsdev_get_soft_state(getminor(dev), ZSST_ZVOL);
	if (zv == NULL) {
		dprintf("zv is NULL\n");
		mutex_exit(&spa_namespace_lock);
		return (ENXIO);
	}

	dprintf("zvol_get_volume_blocksize: %d\n", zv->zv_volblocksize);

	mutex_exit(&spa_namespace_lock);
	// return (zv->zv_volblocksize);
	return (DEV_BSIZE);
}

/*
 * Return the current WCE setting to an external caller.
 * The WCE setting can change while the volume is open.
 */
int
zvol_get_volume_wce(void *minor_hdl)
{
	zvol_state_t *zv = minor_hdl;

	return ((zv->zv_flags & ZVOL_WCE) ? 1 : 0);
}

/*
 * Entry point for external callers to zvol_log_write
 */
void
zvol_log_write_minor(void *minor_hdl, dmu_tx_t *tx, offset_t off, ssize_t resid,
    boolean_t sync)
{
	zvol_state_t *zv = minor_hdl;

	zvol_log_write(zv, tx, off, resid, sync);
}
/*
 * END entry points to allow external callers access to the volume.
 */

/*
 * Log a DKIOCFREE/free-long-range to the ZIL with TX_TRUNCATE.
 */
static void
zvol_log_truncate(zvol_state_t *zv, dmu_tx_t *tx, uint64_t off, uint64_t len,
    boolean_t sync)
{
	itx_t *itx;
	lr_truncate_t *lr;
	zilog_t *zilog = zv->zv_zilog;

	if (zil_replaying(zilog, tx))
		return;

	itx = zil_itx_create(TX_TRUNCATE, sizeof (*lr));
	lr = (lr_truncate_t *)&itx->itx_lr;
	lr->lr_foid = ZVOL_OBJ;
	lr->lr_offset = off;
	lr->lr_length = len;

	itx->itx_sync = sync;
	zil_itx_assign(zilog, itx, tx);
}

/*
 * Dirtbag ioctls to support mkfs(1M) for UFS filesystems.  See dkio(7I).
 * Also a dirtbag dkio ioctl for unmap/free-block functionality.
 */
/*ARGSUSED*/
int
zvol_ioctl(dev_t dev, unsigned long cmd, caddr_t data, int isblk,
    cred_t *cr, int *rvalp)
{
	int error = 0;
	u_int32_t *f;
	u_int64_t *o;
	zvol_state_t *zv;

	if (!getminor(dev))
		return (ENXIO);

	mutex_enter(&spa_namespace_lock);

	zv = zfsdev_get_soft_state(getminor(dev), ZSST_ZVOL);
	if (zv == NULL) {
		dprintf("zv is NULL\n");
		mutex_exit(&spa_namespace_lock);
		return (ENXIO);
	}

	f = (u_int32_t *)data;
	o = (u_int64_t *)data;

	switch (cmd) {

		case DKIOCGETMAXBLOCKCOUNTREAD:
			dprintf("DKIOCGETMAXBLOCKCOUNTREAD\n");
			*o = 32;
			break;

		case DKIOCGETMAXBLOCKCOUNTWRITE:
			dprintf("DKIOCGETMAXBLOCKCOUNTWRITE\n");
			*o = 32;
			break;

		case DKIOCGETMAXSEGMENTCOUNTREAD:
			dprintf("DKIOCGETMAXSEGMENTCOUNTREAD\n");
			*o = 32;
			break;

		case DKIOCGETMAXSEGMENTCOUNTWRITE:
			dprintf("DKIOCGETMAXSEGMENTCOUNTWRITE\n");
			*o = 32;
			break;

		case DKIOCGETBLOCKSIZE:
			dprintf("DKIOCGETBLOCKSIZE: %llu\n",
			    zv->zv_volblocksize);
			*f = zv->zv_volblocksize;
			break;

		case DKIOCSETBLOCKSIZE:
			dprintf("DKIOCSETBLOCKSIZE %lu\n", *f);

			if (!isblk) {
				/* We can only do this for a block device */
				error = ENODEV;
				break;
			}

			if (zvol_check_volblocksize((uint64_t)*f)) {
				error = EINVAL;
				break;
			}

			/* set the new block size */
			zv->zv_volblocksize = (uint64_t)*f;
			dprintf("setblocksize changed: %llu\n",
			    zv->zv_volblocksize);
			break;

		case DKIOCISWRITABLE:
			dprintf("DKIOCISWRITABLE\n");
			if (zv && (zv->zv_flags & ZVOL_RDONLY))
				*f = 0;
			else
				*f = 1;
			break;

		case DKIOCGETBLOCKCOUNT32:
			dprintf("DKIOCGETBLOCKCOUNT32: %lu\n",
			    (uint32_t)zv->zv_volsize / zv->zv_volblocksize);
			*f = (uint32_t)zv->zv_volsize / zv->zv_volblocksize;
			break;

		case DKIOCGETBLOCKCOUNT:
			dprintf("DKIOCGETBLOCKCOUNT: %llu\n",
			    zv->zv_volsize / zv->zv_volblocksize);
			*o = (uint64_t)zv->zv_volsize / zv->zv_volblocksize;
			break;

		case DKIOCGETBASE:
			dprintf("DKIOCGETBASE\n");
			/*
			 * What offset should we say?
			 * 0 is ok for FAT but to HFS
			 */
			*o = zv->zv_volblocksize * 0;
			break;

		case DKIOCGETPHYSICALBLOCKSIZE:
			dprintf("DKIOCGETPHYSICALBLOCKSIZE\n");
			*f = zv->zv_volblocksize;
			break;

#ifdef DKIOCGETTHROTTLEMASK
		case DKIOCGETTHROTTLEMASK:
			dprintf("DKIOCGETTHROTTLEMASK\n");
			*o = 0;
			break;
#endif

		case DKIOCGETMAXBYTECOUNTREAD:
			*o = SPA_MAXBLOCKSIZE;
			break;

		case DKIOCGETMAXBYTECOUNTWRITE:
			*o = SPA_MAXBLOCKSIZE;
			break;

#ifdef DKIOCUNMAP
		case DKIOCUNMAP:
			dprintf("DKIOCUNMAP\n");
			*f = 1;
			break;
#endif

		case DKIOCGETFEATURES:
			*f = 0;
			break;

#ifdef DKIOCISSOLIDSTATE
		case DKIOCISSOLIDSTATE:
			dprintf("DKIOCISSOLIDSTATE\n");
			*f = 0;
			break;
#endif

		case DKIOCISVIRTUAL:
			*f = 1;
			break;

		case DKIOCGETMAXSEGMENTBYTECOUNTREAD:
			*o = 32 * zv->zv_volblocksize;
			break;

		case DKIOCGETMAXSEGMENTBYTECOUNTWRITE:
			*o = 32 * zv->zv_volblocksize;
			break;

		case DKIOCSYNCHRONIZECACHE:
			dprintf("DKIOCSYNCHRONIZECACHE\n");
			break;

		default:
			dprintf("unknown ioctl: ENOTTY\n");
			error = ENOTTY;
			break;
	}


	mutex_exit(&spa_namespace_lock);
	dprintf("zvol_ioctl returning %d\n", error);
	return (error);


#if 0
	zvol_state_t *zv;
	struct dk_cinfo dki;
	struct dk_minfo dkm;
	struct dk_callback *dkc;
	int error = 0;
	rl_t *rl;

	mutex_enter(&spa_namespace_lock);

	zv = zfsdev_get_soft_state(getminor(dev), ZSST_ZVOL);

	if (zv == NULL) {
		mutex_exit(&spa_namespace_lock);
		return (ENXIO);
	}
	ASSERT(zv->zv_total_opens > 0);

	switch (cmd) {

		case DKIOCINFO:
			bzero(&dki, sizeof (dki));
			(void) strcpy(dki.dki_cname, "zvol");
			(void) strcpy(dki.dki_dname, "zvol");
			dki.dki_ctype = DKC_UNKNOWN;
			dki.dki_unit = getminor(dev);
			dki.dki_maxtransfer = (1 << (SPA_MAXBLOCKSHIFT -
			    zv->zv_min_bs));
			mutex_exit(&spa_namespace_lock);
			if (ddi_copyout(&dki, (void *)arg, sizeof (dki), flag))
				error = EFAULT;
			return (error);

		case DKIOCGMEDIAINFO:
			bzero(&dkm, sizeof (dkm));
			dkm.dki_lbsize = 1U << zv->zv_min_bs;
			dkm.dki_capacity = zv->zv_volsize >> zv->zv_min_bs;
			dkm.dki_media_type = DK_UNKNOWN;
			mutex_exit(&spa_namespace_lock);
			if (ddi_copyout(&dkm, (void *)arg, sizeof (dkm), flag))
				error = EFAULT;
			return (error);

		case DKIOCGETEFI:
		{
			uint64_t vs = zv->zv_volsize;
			uint8_t bs = zv->zv_min_bs;

			mutex_exit(&spa_namespace_lock);
			error = zvol_getefi((void *)arg, flag, vs, bs);
			return (error);
		}

		case DKIOCFLUSHWRITECACHE:
			dkc = (struct dk_callback *)arg;
			mutex_exit(&spa_namespace_lock);
			zil_commit(zv->zv_zilog, ZVOL_OBJ);
			if ((flag & FKIOCTL) && dkc != NULL &&
			    dkc->dkc_callback) {

				(*dkc->dkc_callback)(dkc->dkc_cookie, error);
				error = 0;
			}
			return (error);

		case DKIOCGETWCE:
		{
			int wce = (zv->zv_flags & ZVOL_WCE) ? 1 : 0;
			if (ddi_copyout(&wce, (void *)arg,
			    sizeof (int), flag))
				error = EFAULT;
			break;
		}
		case DKIOCSETWCE:
		{
			int wce;
			if (ddi_copyin((void *)arg, &wce,
			    sizeof (int), flag)) {

				error = EFAULT;
				break;
			}
			if (wce) {
				zv->zv_flags |= ZVOL_WCE;
				mutex_exit(&spa_namespace_lock);
			} else {
				zv->zv_flags &= ~ZVOL_WCE;
				mutex_exit(&spa_namespace_lock);
				zil_commit(zv->zv_zilog, ZVOL_OBJ);
			}
			return (0);
		}

		case DKIOCGGEOM:
		case DKIOCGVTOC:
			/*
			 * commands using these (like prtvtoc) expect ENOTSUP
			 * since we're emulating an EFI label
			 */
			error = ENOTSUP;
			break;

		case DKIOCDUMPINIT:
			rl = zfs_range_lock(&zv->zv_znode, 0, zv->zv_volsize,
			    RL_WRITER);
			error = zvol_dumpify(zv);
			zfs_range_unlock(rl);
			break;

		case DKIOCDUMPFINI:
			if (!(zv->zv_flags & ZVOL_DUMPIFIED))
				break;
			rl = zfs_range_lock(&zv->zv_znode, 0, zv->zv_volsize,
			    RL_WRITER);
			error = zvol_dump_fini(zv);
			zfs_range_unlock(rl);
			break;

		case DKIOCFREE:
		{
			dkioc_free_t df;
			dmu_tx_t *tx;

			if (ddi_copyin((void *)arg, &df, sizeof (df), flag)) {
				error = EFAULT;
				break;
			}

			/*
			 * Apply Postel's Law to length-checking. If they
			 * overshoot, just blank out until the end, if there's a
			 * need to blank out anything.
			 */
			if (df.df_start >= zv->zv_volsize)
				break;	/* No need to do anything... */
			if (df.df_start + df.df_length > zv->zv_volsize)
				df.df_length = DMU_OBJECT_END;

			rl = zfs_range_lock(&zv->zv_znode, df.df_start,
			    df.df_length, RL_WRITER);
			tx = dmu_tx_create(zv->zv_objset);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error != 0) {
				dmu_tx_abort(tx);
			} else {
				zvol_log_truncate(zv, tx, df.df_start,
				    df.df_length, B_TRUE);
				dmu_tx_commit(tx);
				error = dmu_free_long_range(zv->zv_objset,
				    ZVOL_OBJ, df.df_start, df.df_length);
			}

			zfs_range_unlock(rl);

			if (error == 0) {
				/*
				 * If the write-cache is disabled or 'sync'
				 * property is set to 'always' then treat
				 * this as a synchronous operation (i.e.
				 * commit to zil).
				 */
				if (!(zv->zv_flags & ZVOL_WCE) ||
				    (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS))
					zil_commit(zv->zv_zilog, ZVOL_OBJ);

				/*
				 * If the caller really wants synchronous
				 * writes, and can't wait for them, don't
				 * return until the write is done.
				 */
				if (df.df_flags & DF_WAIT_SYNC) {
					txg_wait_synced(dmu_objset_pool(
					    zv->zv_objset), 0);
				}
			}
			break;
		}

		default:
			error = ENOTTY;
			break;

	}
	mutex_exit(&spa_namespace_lock);
	return (error);
#endif
	return (ENOTSUP);
}

int
zvol_busy(void)
{
	return (zvol_minors != 0);
}

int
zvol_init(void)
{
	dprintf("zvol_init\n");
	VERIFY(ddi_soft_state_init(&zfsdev_state, sizeof (zfs_soft_state_t),
	    1) == 0);
#ifdef illumos
	mutex_init(&zfsdev_state_lock, NULL, MUTEX_DEFAULT, NULL);
#endif
	dprintf("zfsdev_state: %p\n", zfsdev_state);
	return (0);
}

void
zvol_fini(void)
{
#ifdef illumos
	mutex_destroy(&zfsdev_state_lock);
#endif
	ddi_soft_state_fini(&zfsdev_state);
}

#if 0 // unused function
static int
zvol_dump_init(zvol_state_t *zv, boolean_t resize)
{
	dmu_tx_t *tx;
	int error = 0;
	objset_t *os = zv->zv_objset;
	nvlist_t *nv = NULL;
	uint64_t version = spa_version(dmu_objset_spa(zv->zv_objset));

	ASSERT(MUTEX_HELD(&spa_namespace_lock));
	error = dmu_free_long_range(zv->zv_objset, ZVOL_OBJ, 0,
	    DMU_OBJECT_END);
	/* wait for dmu_free_long_range to actually free the blocks */
	txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	dmu_tx_hold_bonus(tx, ZVOL_OBJ);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}

	/*
	 * If we are resizing the dump device then we only need to
	 * update the refreservation to match the newly updated
	 * zvolsize. Otherwise, we save off the original state of the
	 * zvol so that we can restore them if the zvol is ever undumpified.
	 */
	if (resize) {
		error = zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 8, 1,
		    &zv->zv_volsize, tx);
	} else {
		uint64_t checksum, compress, refresrv, vbs, dedup;

		error = dsl_prop_get_integer(zv->zv_name,
		    zfs_prop_to_name(ZFS_PROP_COMPRESSION), &compress, NULL);
		error = error ? error : dsl_prop_get_integer(zv->zv_name,
		    zfs_prop_to_name(ZFS_PROP_CHECKSUM), &checksum, NULL);
		error = error ? error : dsl_prop_get_integer(zv->zv_name,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), &refresrv, NULL);
		error = error ? error : dsl_prop_get_integer(zv->zv_name,
		    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), &vbs, NULL);
		if (version >= SPA_VERSION_DEDUP) {
			error = error ? error :
			    dsl_prop_get_integer(zv->zv_name,
			    zfs_prop_to_name(ZFS_PROP_DEDUP), &dedup, NULL);
		}

		error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_COMPRESSION), 8, 1,
		    &compress, tx);
		error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_CHECKSUM), 8, 1, &checksum, tx);
		error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 8, 1,
		    &refresrv, tx);
		error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), 8, 1,
		    &vbs, tx);
		error = error ? error : dmu_object_set_blocksize(
		    os, ZVOL_OBJ, SPA_MAXBLOCKSIZE, 0, tx);
		if (version >= SPA_VERSION_DEDUP) {
			error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
			    zfs_prop_to_name(ZFS_PROP_DEDUP), 8, 1,
			    &dedup, tx);
		}
		if (error == 0)
			zv->zv_volblocksize = SPA_MAXBLOCKSIZE;
	}
	dmu_tx_commit(tx);

	/*
	 * We only need update the zvol's property if we are initializing
	 * the dump area for the first time.
	 */
	if (!resize) {
		VERIFY(nvlist_alloc(&nv, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 0) == 0);
		VERIFY(nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_COMPRESSION),
		    ZIO_COMPRESS_OFF) == 0);
		VERIFY(nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_CHECKSUM),
		    ZIO_CHECKSUM_OFF) == 0);
		if (version >= SPA_VERSION_DEDUP) {
			VERIFY(nvlist_add_uint64(nv,
			    zfs_prop_to_name(ZFS_PROP_DEDUP),
			    ZIO_CHECKSUM_OFF) == 0);
		}

		error = zfs_set_prop_nvlist(zv->zv_name, ZPROP_SRC_LOCAL,
		    nv, NULL);
		nvlist_free(nv);

		if (error)
			return (error);
	}

	/* Allocate the space for the dump */
	error = zvol_prealloc(zv);
	return (error);
}

static int
zvol_dumpify(zvol_state_t *zv)
{
	int error = 0;
	uint64_t dumpsize = 0;
	dmu_tx_t *tx;
	objset_t *os = zv->zv_objset;

	if (zv->zv_flags & ZVOL_RDONLY)
		return (EROFS);

	if (zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ, ZVOL_DUMPSIZE,
	    8, 1, &dumpsize) != 0 ||
	    dumpsize != zv->zv_volsize) {

		boolean_t resize = (dumpsize > 0);

		if ((error = zvol_dump_init(zv, resize)) != 0) {
			(void) zvol_dump_fini(zv);
			return (error);
		}
	}

	/*
	 * Build up our lba mapping.
	 */
	error = zvol_get_lbas(zv);
	if (error) {
		(void) zvol_dump_fini(zv);
		return (error);
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		(void) zvol_dump_fini(zv);
		return (error);
	}

	zv->zv_flags |= ZVOL_DUMPIFIED;
	error = zap_update(os, ZVOL_ZAP_OBJ, ZVOL_DUMPSIZE, 8, 1,
	    &zv->zv_volsize, tx);
	dmu_tx_commit(tx);

	if (error) {
		(void) zvol_dump_fini(zv);
		return (error);
	}

	txg_wait_synced(dmu_objset_pool(os), 0);
	return (0);
}

static int
zvol_dump_fini(zvol_state_t *zv)
{
	dmu_tx_t *tx;
	objset_t *os = zv->zv_objset;
	nvlist_t *nv;
	int error = 0;
	uint64_t checksum, compress, refresrv, vbs, dedup;
	uint64_t version = spa_version(dmu_objset_spa(zv->zv_objset));

	/*
	 * Attempt to restore the zvol back to its pre-dumpified state.
	 * This is a best-effort attempt as it's possible that not all
	 * of these properties were initialized during the dumpify process
	 * (i.e. error during zvol_dump_init).
	 */

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}
	(void) zap_remove(os, ZVOL_ZAP_OBJ, ZVOL_DUMPSIZE, tx);
	dmu_tx_commit(tx);

	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_CHECKSUM),
	    8, 1, &checksum);
	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_COMPRESSION),
	    8, 1, &compress);
	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_REFRESERVATION),
	    8, 1, &refresrv);
	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE),
	    8, 1, &vbs);

	VERIFY(nvlist_alloc(&nv, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	(void) nvlist_add_uint64(nv,
	    zfs_prop_to_name(ZFS_PROP_CHECKSUM),
	    checksum);
	(void) nvlist_add_uint64(nv,
	    zfs_prop_to_name(ZFS_PROP_COMPRESSION),
	    compress);
	(void) nvlist_add_uint64(nv,
	    zfs_prop_to_name(ZFS_PROP_REFRESERVATION),
	    refresrv);
	if (version >= SPA_VERSION_DEDUP &&
	    zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_DEDUP),
	    8, 1, &dedup) == 0) {

		(void) nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_DEDUP), dedup);
	}
	(void) zfs_set_prop_nvlist(zv->zv_name, ZPROP_SRC_LOCAL,
	    nv, NULL);
	nvlist_free(nv);

	zvol_free_extents(zv);
	zv->zv_flags &= ~ZVOL_DUMPIFIED;
	(void) dmu_free_long_range(os, ZVOL_OBJ, 0, DMU_OBJECT_END);
	/* wait for dmu_free_long_range to actually free the blocks */
	txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);
	tx = dmu_tx_create(os);
	dmu_tx_hold_bonus(tx, ZVOL_OBJ);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}
	if (dmu_object_set_blocksize(os, ZVOL_OBJ, vbs, 0, tx) == 0)
		zv->zv_volblocksize = vbs;
	dmu_tx_commit(tx);

	return (0);
}

#endif


int
zvol_create_minors(const char *name)
{
	uint64_t cookie;
	objset_t *os;
	char *osname, *p;
	int error, len;

	if (dataset_name_hidden(name))
		return (0);

	if ((error = dmu_objset_hold(name, FTAG, &os)) != 0) {
		dprintf("ZFS WARNING 1: Unable to put hold on %s (error=%d).\n",
		    name, error);
		return (error);
	}

	if (dmu_objset_type(os) == DMU_OST_ZVOL) {
		/*
		 * In OSX, create_minor() will call IOKit, which may end up
		 * calling zvol_first_open(), so we can not hold a lock here.
		 */
		dmu_objset_rele(os, FTAG);

		if ((error = zvol_create_minor(name)) == 0)
		/* error = zvol_create_snapshots(os, name) */;
		else {
			dprintf("ZFS WARNING: %s %s (error=%d).\n",
			    "Unable to create ZVOL",
			    name, error);
		}
		return (error);
	}
	if (dmu_objset_type(os) != DMU_OST_ZFS) {
		dmu_objset_rele(os, FTAG);
		return (0);
	}

	osname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (snprintf(osname, MAXPATHLEN, "%s/", name) >= MAXPATHLEN) {
		dmu_objset_rele(os, FTAG);
		kmem_free(osname, MAXPATHLEN);
		return (ENOENT);
	}
	p = osname + strlen(osname);
	len = MAXPATHLEN - (p - osname);

#if 0
	/* Prefetch the datasets. */
	cookie = 0;
	while (dmu_dir_list_next(os, len, p, NULL, &cookie) == 0) {
		if (!dataset_name_hidden(osname))
			(void) dmu_objset_prefetch(osname, NULL);
	}
#endif

	cookie = 0;
	while (dmu_dir_list_next(os, MAXPATHLEN - (p - osname), p, NULL,
	    &cookie) == 0) {
		dmu_objset_rele(os, FTAG);
		(void) zvol_create_minors(osname);
		if ((error = dmu_objset_hold(name, FTAG, &os)) != 0) {
			dprintf("ZFS WARNING 2: %s %s (error=%d).\n",
			    "Unable to put hold on",
			    name, error);
			kmem_free(osname, MAXPATHLEN);
			return (error);
		}
	}

	dmu_objset_rele(os, FTAG);
	kmem_free(osname, MAXPATHLEN);
	return (0);
}




/*
 * Due to OS X limitations in /dev, we create a symlink for "/dev/zvol" to
 * "/var/run/zfs" (if we can) and for each pool, create the traditional
 * ZFS Volume symlinks.
 *
 * Ie, for ZVOL $POOL/$VOLUME
 * BSDName /dev/disk2 /dev/rdisk2
 * /dev/zvol -> /var/run/zfs
 * /var/run/zfs/zvol/dsk/$POOL/$VOLUME -> /dev/disk2
 * /var/run/zfs/zvol/rdsk/$POOL/$VOLUME -> /dev/rdisk2
 *
 * Note, we do not create symlinks for the partitioned slices.
 *
 */

void
zvol_add_symlink(zvol_state_t *zv, const char *bsd_disk, const char *bsd_rdisk)
{
	zfs_ereport_zvol_post(FM_EREPORT_ZVOL_CREATE_SYMLINK,
	    zv->zv_name, bsd_disk, bsd_rdisk);
}


void
zvol_remove_symlink(zvol_state_t *zv)
{
	if (!zv || !zv->zv_name)
		return;

	zfs_ereport_zvol_post(FM_EREPORT_ZVOL_REMOVE_SYMLINK,
	    zv->zv_name, &zv->zv_bsdname[1],
	    zv->zv_bsdname);
}
