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
 *
 * Portions Copyright 2007-2008 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

/* Portions Copyright 2007 Jeremy Teo */

/* Portions Copyright 2013 Jorgen Lundman */

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/mntent.h>
#ifndef __APPLE__
#include <sys/mkdev.h>
#include <sys/vfs_opreg.h>
#endif /*!__APPLE__*/
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/unistd.h>
#ifndef __APPLE__
#include <sys/mode.h>
#endif /*!__APPLE__*/
#include <sys/atomic.h>
#ifndef __APPLE__
#include <vm/pvn.h>
#include "fs/fs_subr.h"
#endif /*!__APPLE__*/
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_rlock.h>
#include <sys/fs/zfs.h>
#ifdef __APPLE__
//#include <maczfs/kernel/maczfs_kernel.h>
#endif
#endif /* _KERNEL */

#include <sys/dmu.h>
#include <sys/refcount.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/zfs_znode.h>

#include <sys/zfs_sa.h>

#include <sys/vnode.h>

/*
 * Functions needed for userland (ie: libzpool) are not put under
 * #ifdef_KERNEL; the rest of the functions have dependencies
 * (such as VFS logic) that will not compile easily in userland.
 */
#ifdef _KERNEL
/*
 * Needed to close a small window in zfs_znode_move() that allows the zfsvfs to
 * be freed before it can be safely accessed.
 */
krwlock_t zfsvfs_lock;

struct kmem_cache *znode_cache = NULL;

static int
zfs_grab_sa_handle(objset_t *osp, uint64_t obj, sa_handle_t **hdlp,
                   dmu_buf_t **db, void *tag);
static int
zfs_sa_setup(objset_t *osp, sa_attr_type_t **sa_table);


/*ARGSUSED*/
static void
znode_pageout_func(dmu_buf_t *dbuf, void *user_ptr)
{
	znode_t *zp = user_ptr;

    printf("pageout\n");
#ifdef __APPLE__
#ifdef ZFS_DEBUG
	znode_stalker(zp, N_znode_pageout);
#endif
	mutex_enter(&zp->z_lock);
	/* indicate that this znode can be freed */
	//zp->z_dbuf = NULL;

	if (zp->z_zfsvfs && vfs_isforce(zp->z_zfsvfs->z_vfs)) {
		mutex_exit(&zp->z_lock);
		zfs_znode_free(zp);
        return ;
	} else {
        	mutex_exit(&zp->z_lock);
        }
#else
	vnode_t *vp = ZTOV(zp);

	mutex_enter(&zp->z_lock);
	if (vp->v_count == 0) {
		mutex_exit(&zp->z_lock);
		vn_invalid(vp);
		zfs_znode_free(zp);
        return;
	} else {
		/* signal force unmount that this znode can be freed */
		//zp->z_dbuf = NULL;
		mutex_exit(&zp->z_lock);
	}
#endif /* __APPLE__ */
}

/*ARGSUSED*/
static int
zfs_znode_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	znode_t *zp = buf;

#ifdef __APPLE__
	zp->z_vnode = NULLVP;
	cv_init(&zp->z_cv, NULL, CV_DEFAULT, NULL);
	zp->z_link_node.list_next = NULL;
	zp->z_link_node.list_prev = NULL;
#else
	zp->z_vnode = vn_alloc(KM_SLEEP);
	zp->z_vnode->v_data = (caddr_t)zp;
#endif
	mutex_init(&zp->z_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&zp->z_map_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zp->z_parent_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zp->z_name_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zp->z_xattr_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&zp->z_acl_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&zp->z_range_lock, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&zp->z_range_avl, zfs_range_compare,
	    sizeof (rl_t), offsetof(rl_t, r_node));

	//zp->z_dbuf_held = 0;
	zp->z_dirlocks = 0;
	return (0);
}

/*ARGSUSED*/
static void
zfs_znode_cache_destructor(void *buf, void *cdarg)
{
	znode_t *zp = buf;

	ASSERT(zp->z_dirlocks == 0);
	mutex_destroy(&zp->z_lock);
	rw_destroy(&zp->z_map_lock);
	rw_destroy(&zp->z_parent_lock);
	rw_destroy(&zp->z_name_lock);
	rw_destroy(&zp->z_xattr_lock);
	mutex_destroy(&zp->z_acl_lock);
	avl_destroy(&zp->z_range_avl);
	mutex_destroy(&zp->z_range_lock);

#ifdef __APPLE__
	cv_destroy(&zp->z_cv);
#else
	ASSERT(ZTOV(zp)->v_count == 0);
	vn_free(ZTOV(zp));
#endif
}

void
zfs_znode_init(void)
{
	/*
	 * Initialize zcache
	 */
    rw_init(&zfsvfs_lock, NULL, RW_DEFAULT, NULL);
	ASSERT(znode_cache == NULL);
	znode_cache = kmem_cache_create("zfs_znode_cache",
	    sizeof (znode_t), 0, zfs_znode_cache_constructor,
	    zfs_znode_cache_destructor, NULL, NULL, NULL, 0);
}

void
zfs_znode_fini(void)
{
	/*
	 * Cleanup vfs & vnode ops
	 */
#ifndef __APPLE__
	zfs_remove_op_tables();
#endif /*!__APPLE__*/
	/*
	 * Cleanup zcache
	 */
	if (znode_cache)
		kmem_cache_destroy(znode_cache);
	znode_cache = NULL;
    rw_destroy(&zfsvfs_lock);
}

#ifdef __APPLE__
extern int (**zfs_dvnodeops) (void *);
extern int (**zfs_evnodeops) (void *);
extern int (**zfs_fvnodeops) (void *);
extern int (**zfs_symvnodeops) (void *);
extern int (**zfs_xdvnodeops) (void *);

struct kmem_cache * znode_cache_get(void);

struct kmem_cache *
znode_cache_get(void)
{
	return znode_cache;
}

#else
struct vnodeops *zfs_dvnodeops;
struct vnodeops *zfs_fvnodeops;
struct vnodeops *zfs_symvnodeops;
struct vnodeops *zfs_xdvnodeops;
struct vnodeops *zfs_evnodeops;

void
zfs_remove_op_tables()
{
	/*
	 * Remove vfs ops
	 */
	ASSERT(zfsfstype);
	(void) vfs_freevfsops_by_type(zfsfstype);
	zfsfstype = 0;

	/*
	 * Remove vnode ops
	 */
	if (zfs_dvnodeops)
		vn_freevnodeops(zfs_dvnodeops);
	if (zfs_fvnodeops)
		vn_freevnodeops(zfs_fvnodeops);
	if (zfs_symvnodeops)
		vn_freevnodeops(zfs_symvnodeops);
	if (zfs_xdvnodeops)
		vn_freevnodeops(zfs_xdvnodeops);
	if (zfs_evnodeops)
		vn_freevnodeops(zfs_evnodeops);

	zfs_dvnodeops = NULL;
	zfs_fvnodeops = NULL;
	zfs_symvnodeops = NULL;
	zfs_xdvnodeops = NULL;
	zfs_evnodeops = NULL;
}

extern const fs_operation_def_t zfs_dvnodeops_template[];
extern const fs_operation_def_t zfs_fvnodeops_template[];
extern const fs_operation_def_t zfs_xdvnodeops_template[];
extern const fs_operation_def_t zfs_symvnodeops_template[];
extern const fs_operation_def_t zfs_evnodeops_template[];

int
zfs_create_op_tables()
{
	int error;

	/*
	 * zfs_dvnodeops can be set if mod_remove() calls mod_installfs()
	 * due to a failure to remove the the 2nd modlinkage (zfs_modldrv).
	 * In this case we just return as the ops vectors are already set up.
	 */
	if (zfs_dvnodeops)
		return (0);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_dvnodeops_template,
	    &zfs_dvnodeops);
	if (error)
		return (error);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_fvnodeops_template,
	    &zfs_fvnodeops);
	if (error)
		return (error);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_symvnodeops_template,
	    &zfs_symvnodeops);
	if (error)
		return (error);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_xdvnodeops_template,
	    &zfs_xdvnodeops);
	if (error)
		return (error);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_evnodeops_template,
	    &zfs_evnodeops);

	return (error);
}
#endif /*__APPLE__*/


/*
 * define a couple of values we need available
 * for both 64 and 32 bit environments.
 */
#ifndef NBITSMINOR64
#define	NBITSMINOR64	32
#endif
#ifndef MAXMAJ64
#define	MAXMAJ64	0xffffffffUL
#endif
#ifndef	MAXMIN64
#define	MAXMIN64	0xffffffffUL
#endif

/*
 * Create special expldev for ZFS private use.
 * Can't use standard expldev since it doesn't do
 * what we want.  The standard expldev() takes a
 * dev32_t in LP64 and expands it to a long dev_t.
 * We need an interface that takes a dev32_t in ILP32
 * and expands it to a long dev_t.
 */
static uint64_t
zfs_expldev(dev_t dev)
{
#ifndef _LP64
	major_t major = (major_t)dev >> NBITSMINOR32 & MAXMAJ32;
	return (((uint64_t)major << NBITSMINOR64) |
	    ((minor_t)dev & MAXMIN32));
#else
	return (dev);
#endif
}

/*
 * Special cmpldev for ZFS private use.
 * Can't use standard cmpldev since it takes
 * a long dev_t and compresses it to dev32_t in
 * LP64.  We need to do a compaction of a long dev_t
 * to a dev32_t in ILP32.
 */
dev_t
zfs_cmpldev(uint64_t dev)
{
#ifndef _LP64
	minor_t minor = (minor_t)dev & MAXMIN64;
	major_t major = (major_t)(dev >> NBITSMINOR64) & MAXMAJ64;

	if (major > MAXMAJ32 || minor > MAXMIN32)
		return (NODEV32);

	return (((dev32_t)major << NBITSMINOR32) | minor);
#else
	return (dev);
#endif
}

static void
zfs_znode_sa_init(zfsvfs_t *zfsvfs, znode_t *zp,
    dmu_buf_t *db, dmu_object_type_t obj_type, sa_handle_t *sa_hdl)
{
	ASSERT(!POINTER_IS_VALID(zp->z_zfsvfs) || (zfsvfs == zp->z_zfsvfs));
	ASSERT(MUTEX_HELD(ZFS_OBJ_MUTEX(zp)));

	mutex_enter(&zp->z_lock);

	ASSERT(zp->z_sa_hdl == NULL);
	ASSERT(zp->z_acl_cached == NULL);
	if (sa_hdl == NULL) {
		VERIFY(0 == sa_handle_get_from_db(zfsvfs->z_os, db, zp,
		    SA_HDL_SHARED, &zp->z_sa_hdl));
	} else {
		zp->z_sa_hdl = sa_hdl;
		sa_set_userp(sa_hdl, zp);
	}

	zp->z_is_sa = (obj_type == DMU_OT_SA) ? B_TRUE : B_FALSE;

	/*
	 * Slap on VROOT if we are the root znode
	 */
	//if (zp->z_id == zfsvfs->z_root)
    //   ZTOV(zp)->v_flag |= VROOT;

	mutex_exit(&zp->z_lock);
	vn_exists(ZTOV(zp));
}

void
zfs_znode_dmu_fini(znode_t *zp)
{
	ASSERT(MUTEX_HELD(ZFS_OBJ_MUTEX(zp)) ||
	    zp->z_unlinked ||
	    RW_WRITE_HELD(&zp->z_zfsvfs->z_teardown_inactive_lock));

	sa_handle_destroy(zp->z_sa_hdl);
	zp->z_sa_hdl = NULL;
}




/*
 * Construct a new znode/vnode and intialize.
 *
 * This does not do a call to dmu_set_user() that is
 * up to the caller to do, in case you don't want to
 * return the znode
 */
static znode_t *
zfs_znode_alloc(zfsvfs_t *zfsvfs, dmu_buf_t *db, int blksz,
                dmu_object_type_t obj_type, sa_handle_t *hdl)
{
	znode_t	*zp;
	vnode_t *vp;
        uint64_t mode;
        uint64_t parent;
        sa_bulk_attr_t bulk[9];
        int count = 0;

        if (!blksz) {
            blksz = 512;
            printf("zfs_znode_alloc blksize is ZERO; fixed %d\n", blksz);
        }

	zp = kmem_cache_alloc(znode_cache, KM_SLEEP);

	ASSERT(zp->z_dirlocks == NULL);

    zp->z_sa_hdl = NULL;
	//zp->z_phys = db->db_data;
	zp->z_unlinked = 0;
	zp->z_atime_dirty = 0;

#ifdef __APPLE__
	zp->z_mmapped = 0;
#else
	zp->z_mapcnt = 0;
#endif
	zp->z_mapcnt = 0;
	zp->z_last_itx = 0;
    zp->z_id = db->db_object;
	zp->z_blksz = blksz;
	zp->z_seq = 0x7A4653;
	zp->z_sync_cnt = 0;
    zp->z_acl_cached = NULL;

    zp->z_is_zvol = 0;
    zp->z_is_mapped = 0;
    zp->z_is_ctldir = 0;
    zp->z_vfs = NULL;
    zp->z_xattr = 0;
    zp->z_xattr_cached = NULL;
    zp->z_xattr_parent = NULL;

	zp->z_vnode = NULL;
	zp->z_vid = 0;



#ifdef ZFS_DEBUG
	list_create(&zp->z_stalker, sizeof (findme_t),
		       	offsetof(findme_t, n_elem));
	znode_stalker(zp, N_znode_alloc);
#endif /* ZFS_DEBUG */

            vp = ZTOV(zp);
            //vn_reinit(vp);

        zfs_znode_sa_init(zfsvfs, zp, db, obj_type, hdl);

        SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MODE(zfsvfs), NULL, &mode, 8);
        SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GEN(zfsvfs), NULL, &zp->z_gen, 8);
        SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zfsvfs), NULL,
            &zp->z_size, 8);
        SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_LINKS(zfsvfs), NULL,
            &zp->z_links, 8);
        SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
            &zp->z_pflags, 8);
        SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_PARENT(zfsvfs), NULL, &parent, 8);
        SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_ATIME(zfsvfs), NULL,
            &zp->z_atime, 16);
        SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_UID(zfsvfs), NULL,
            &zp->z_uid, 8);
        SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GID(zfsvfs), NULL,
            &zp->z_gid, 8);


        if (sa_bulk_lookup(zp->z_sa_hdl, bulk, count) != 0 || zp->z_gen == 0) {
                if (hdl == NULL)
                        sa_handle_destroy(zp->z_sa_hdl);
                kmem_cache_free(znode_cache, zp);
                return (NULL);
        }
        zp->z_mode = mode;

        zp->z_parent = parent;

#if 0
        if (variant != ZA_TRANSIENT) {
            /* Now that znode is ready, obtain a vnode from VFS */


            if (zfsx_vnode_alloc(zp, &vp,
                        variant == ZA_RETAIN_PREDECESSOR, hasname) != 0) {
                if (hdl == NULL)
                    sa_handle_destroy(zp->z_sa_hdl);
                kmem_cache_free(znode_cache, zp);
                return (NULL);
            }
        }

#endif
        mutex_enter(&zfsvfs->z_znodes_lock);
        list_insert_tail(&zfsvfs->z_all_znodes, zp);
        membar_producer();
        /*
         * Everything else must be valid before assigning z_zfsvfs makes the
         * znode eligible for zfs_znode_move().
         */
        zp->z_zfsvfs = zfsvfs;

        mutex_exit(&zfsvfs->z_znodes_lock);

        VFS_HOLD(zfsvfs->z_vfs);

	return (zp);
}


/*
 * Create a new DMU object to hold a zfs znode.
 *
 *	IN:	dzp	- parent directory for new znode
 *		vap	- file attributes for new znode
 *		tx	- dmu transaction id for zap operations
 *		cr	- credentials of caller
 *		flag	- flags:
 *			  IS_ROOT_NODE	- new object will be root
 *			  IS_XATTR	- new object is an attribute
 *			  IS_REPLAY	- intent log replay
 *
 *	OUT:	oid	- ID of created object
 *
 * OSX implementation:
 *
 * The caller of zfs_mknode() is expected to call zfs_attach_vnode()
 * AFTER the dmu_tx_commit() is performed.  This prevents deadlocks
 * since vnode_create can indirectly attempt to clean a dirty vnode.
 *
 * The current list of callers includes:
 *	zfs_vnop_create
 *	zfs_vnop_mkdir
 *	zfs_vnop_symlink
 *	zfs_obtain_xattr
 *	zfs_make_xattrdir
 */
static uint64_t empty_xattr;
static uint64_t pad[4];
static zfs_acl_phys_t acl_phys;
void
zfs_mknode(znode_t *dzp, vattr_t *vap, dmu_tx_t *tx, cred_t *cr,
    uint_t flag, znode_t **zpp, zfs_acl_ids_t *acl_ids)
{
        uint64_t        crtime[2], atime[2], mtime[2], ctime[2];
        uint64_t        mode, size, links, parent, pflags;
        uint64_t        dzp_pflags = 0;
        uint64_t        rdev = 0;
        zfsvfs_t        *zfsvfs = dzp->z_zfsvfs;
        dmu_buf_t       *db;
        timestruc_t     now;
        uint64_t        gen, obj;
        int             err;
        int             bonuslen;
        sa_handle_t     *sa_hdl;
        dmu_object_type_t obj_type;
        sa_bulk_attr_t  sa_attrs[ZPL_END];
        int             cnt = 0;

        ASSERT(vap && (vap->va_mask & (AT_TYPE|AT_MODE)) == (AT_TYPE|AT_MODE));

        if (zfsvfs->z_replay) {
                obj = vap->va_nodeid;
                now = vap->va_ctime;            /* see zfs_replay_create() */
                gen = vap->va_nblocks;          /* ditto */
        } else {
                obj = 0;
                gethrestime(&now);
                gen = dmu_tx_get_txg(tx);
        }

        obj_type = zfsvfs->z_use_sa ? DMU_OT_SA : DMU_OT_ZNODE;
        bonuslen = (obj_type == DMU_OT_SA) ?
            DN_MAX_BONUSLEN : ZFS_OLD_ZNODE_PHYS_SIZE;

        /*
         * Create a new DMU object.
         */
        /*
         * There's currently no mechanism for pre-reading the blocks that will
         * be needed to allocate a new object, so we accept the small chance
         * that there will be an i/o error and we will fail one of the
         * assertions below.
         */
        printf("mknode vtype %d use_sa %d: obj_type %d\n", vap->va_type,
               zfsvfs->z_use_sa, obj_type);

        if (vap->va_type == VDIR) {
                if (zfsvfs->z_replay) {
                        err = zap_create_claim_norm(zfsvfs->z_os, obj,
                            zfsvfs->z_norm, DMU_OT_DIRECTORY_CONTENTS,
                            obj_type, bonuslen, tx);
                        ASSERT3U(err, ==, 0);
                } else {
                        obj = zap_create_norm(zfsvfs->z_os,
                            zfsvfs->z_norm, DMU_OT_DIRECTORY_CONTENTS,
                            obj_type, bonuslen, tx);
                }
        } else {
                if (zfsvfs->z_replay) {
                        err = dmu_object_claim(zfsvfs->z_os, obj,
                            DMU_OT_PLAIN_FILE_CONTENTS, 0,
                            obj_type, bonuslen, tx);
                        ASSERT3U(err, ==, 0);
                } else {
                        obj = dmu_object_alloc(zfsvfs->z_os,
                            DMU_OT_PLAIN_FILE_CONTENTS, 0,
                            obj_type, bonuslen, tx);
                }
        }

        ZFS_OBJ_HOLD_ENTER(zfsvfs, obj);
        VERIFY(0 == sa_buf_hold(zfsvfs->z_os, obj, NULL, &db));

        /*
         * If this is the root, fix up the half-initialized parent pointer
         * to reference the just-allocated physical data area.
         */
        if (flag & IS_ROOT_NODE) {
                dzp->z_id = obj;
        } else {
                dzp_pflags = dzp->z_pflags;
        }

        /*
         * If parent is an xattr, so am I.
         */
        if (dzp_pflags & ZFS_XATTR) {
                flag |= IS_XATTR;
        }

#if 1
        if (zfsvfs->z_use_fuids)
                pflags = ZFS_ARCHIVE | ZFS_AV_MODIFIED;
        else
                pflags = 0;
#endif

        if (vap->va_type == VDIR) {
                size = 2;               /* contents ("." and "..") */
                links = (flag & (IS_ROOT_NODE | IS_XATTR)) ? 2 : 1;
        } else {
                size = links = 0;
        }

        if (vap->va_type == VBLK || vap->va_type == VCHR) {
                rdev = zfs_expldev(vap->va_rdev);
        }

        parent = dzp->z_id;
        mode = acl_ids->z_mode;
        if (flag & IS_XATTR)
                pflags |= ZFS_XATTR;

        /*
         * No execs denied will be deterimed when zfs_mode_compute() is called.
         */
        pflags |= acl_ids->z_aclp->z_hints &
            (ZFS_ACL_TRIVIAL|ZFS_INHERIT_ACE|ZFS_ACL_AUTO_INHERIT|
            ZFS_ACL_DEFAULTED|ZFS_ACL_PROTECTED);

        ZFS_TIME_ENCODE(&now, crtime);
        ZFS_TIME_ENCODE(&now, ctime);

        if (vap->va_mask & AT_ATIME) {
                ZFS_TIME_ENCODE(&vap->va_atime, atime);
        } else {
                ZFS_TIME_ENCODE(&now, atime);
        }

        if (vap->va_mask & AT_MTIME) {
                ZFS_TIME_ENCODE(&vap->va_mtime, mtime);
        } else {
                ZFS_TIME_ENCODE(&now, mtime);
        }

        /* Now add in all of the "SA" attributes */
        VERIFY(0 == sa_handle_get_from_db(zfsvfs->z_os, db, NULL, SA_HDL_SHARED,
            &sa_hdl));

        /*
         * Setup the array of attributes to be replaced/set on the new file
         *
         * order for  DMU_OT_ZNODE is critical since it needs to be constructed
         * in the old znode_phys_t format.  Don't change this ordering
         */

        if (obj_type == DMU_OT_ZNODE) {
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_ATIME(zfsvfs),
                    NULL, &atime, 16);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_MTIME(zfsvfs),
                    NULL, &mtime, 16);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_CTIME(zfsvfs),
                    NULL, &ctime, 16);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_CRTIME(zfsvfs),
                    NULL, &crtime, 16);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_GEN(zfsvfs),
                    NULL, &gen, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_MODE(zfsvfs),
                    NULL, &mode, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_SIZE(zfsvfs),
                    NULL, &size, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_PARENT(zfsvfs),
                    NULL, &parent, 8);
        } else {
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_MODE(zfsvfs),
                    NULL, &mode, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_SIZE(zfsvfs),
                    NULL, &size, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_GEN(zfsvfs),
                    NULL, &gen, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_UID(zfsvfs), NULL,
                    &acl_ids->z_fuid, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_GID(zfsvfs), NULL,
                    &acl_ids->z_fgid, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_PARENT(zfsvfs),
                    NULL, &parent, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_FLAGS(zfsvfs),
                    NULL, &pflags, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_ATIME(zfsvfs),
                    NULL, &atime, 16);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_MTIME(zfsvfs),
                    NULL, &mtime, 16);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_CTIME(zfsvfs),
                    NULL, &ctime, 16);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_CRTIME(zfsvfs),
                    NULL, &crtime, 16);
        }

        SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_LINKS(zfsvfs), NULL, &links, 8);

        if (obj_type == DMU_OT_ZNODE) {
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_XATTR(zfsvfs), NULL,
                    &empty_xattr, 8);
        }
        if (obj_type == DMU_OT_ZNODE ||
            (vap->va_type == VBLK || vap->va_type == VCHR)) {
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_RDEV(zfsvfs),
                    NULL, &rdev, 8);
        }
        if (obj_type == DMU_OT_ZNODE) {
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_FLAGS(zfsvfs),
                    NULL, &pflags, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_UID(zfsvfs), NULL,
                    &acl_ids->z_fuid, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_GID(zfsvfs), NULL,
                    &acl_ids->z_fgid, 8);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_PAD(zfsvfs), NULL, pad,
                    sizeof (uint64_t) * 4);
                SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_ZNODE_ACL(zfsvfs), NULL,
                    &acl_phys, sizeof (zfs_acl_phys_t));
        }


        VERIFY(sa_replace_all_by_template(sa_hdl, sa_attrs, cnt, tx) == 0);
        if (!(flag & IS_ROOT_NODE)) {
            while ((*zpp = zfs_znode_alloc(zfsvfs, db, 0, obj_type, sa_hdl)) == NULL);
        } else {
                /*
                 * If we are creating the root node, the "parent" we
                 * passed in is the znode for the root.
                 */
                *zpp = dzp;

                (*zpp)->z_sa_hdl = sa_hdl;
        }

        (*zpp)->z_pflags = pflags;
        (*zpp)->z_mode = mode;

        if (vap->va_mask & AT_XVATTR)
            zfs_xvattr_set(*zpp, (xvattr_t *)vap, tx);

        if (obj_type == DMU_OT_ZNODE ||
            acl_ids->z_aclp->z_version < ZFS_ACL_VERSION_FUID) {
                err = zfs_aclset_common(*zpp, acl_ids->z_aclp, cr, tx);
                ASSERT3P(err, ==, 0);
        }
        ZFS_OBJ_HOLD_EXIT(zfsvfs, obj);
}


/*
 * zfs_xvattr_set only updates the in-core attributes
 * it is assumed the caller will be doing an sa_bulk_update
 * to push the changes out
 */
void
zfs_xvattr_set(znode_t *zp, xvattr_t *xvap, dmu_tx_t *tx)
{
	xoptattr_t *xoap;

	xoap = xva_getxoptattr(xvap);
	ASSERT(xoap);

	if (XVA_ISSET_REQ(xvap, XAT_CREATETIME)) {
		uint64_t times[2];
		ZFS_TIME_ENCODE(&xoap->xoa_createtime, times);
		(void) sa_update(zp->z_sa_hdl, SA_ZPL_CRTIME(zp->z_zfsvfs),
		    &times, sizeof (times), tx);
		XVA_SET_RTN(xvap, XAT_CREATETIME);
	}
	if (XVA_ISSET_REQ(xvap, XAT_READONLY)) {
		ZFS_ATTR_SET(zp, ZFS_READONLY, xoap->xoa_readonly,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_READONLY);
	}
	if (XVA_ISSET_REQ(xvap, XAT_HIDDEN)) {
		ZFS_ATTR_SET(zp, ZFS_HIDDEN, xoap->xoa_hidden,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_HIDDEN);
	}
	if (XVA_ISSET_REQ(xvap, XAT_SYSTEM)) {
		ZFS_ATTR_SET(zp, ZFS_SYSTEM, xoap->xoa_system,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_SYSTEM);
	}
	if (XVA_ISSET_REQ(xvap, XAT_ARCHIVE)) {
		ZFS_ATTR_SET(zp, ZFS_ARCHIVE, xoap->xoa_archive,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_ARCHIVE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_IMMUTABLE)) {
		ZFS_ATTR_SET(zp, ZFS_IMMUTABLE, xoap->xoa_immutable,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_IMMUTABLE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_NOUNLINK)) {
		ZFS_ATTR_SET(zp, ZFS_NOUNLINK, xoap->xoa_nounlink,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_NOUNLINK);
	}
	if (XVA_ISSET_REQ(xvap, XAT_APPENDONLY)) {
		ZFS_ATTR_SET(zp, ZFS_APPENDONLY, xoap->xoa_appendonly,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_APPENDONLY);
	}
	if (XVA_ISSET_REQ(xvap, XAT_NODUMP)) {
		ZFS_ATTR_SET(zp, ZFS_NODUMP, xoap->xoa_nodump,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_NODUMP);
	}
	if (XVA_ISSET_REQ(xvap, XAT_OPAQUE)) {
		ZFS_ATTR_SET(zp, ZFS_OPAQUE, xoap->xoa_opaque,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_OPAQUE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_AV_QUARANTINED)) {
		ZFS_ATTR_SET(zp, ZFS_AV_QUARANTINED,
		    xoap->xoa_av_quarantined, zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_AV_QUARANTINED);
	}
	if (XVA_ISSET_REQ(xvap, XAT_AV_MODIFIED)) {
		ZFS_ATTR_SET(zp, ZFS_AV_MODIFIED, xoap->xoa_av_modified,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_AV_MODIFIED);
	}
	if (XVA_ISSET_REQ(xvap, XAT_AV_SCANSTAMP)) {
		zfs_sa_set_scanstamp(zp, xvap, tx);
		XVA_SET_RTN(xvap, XAT_AV_SCANSTAMP);
	}
	if (XVA_ISSET_REQ(xvap, XAT_REPARSE)) {
		ZFS_ATTR_SET(zp, ZFS_REPARSE, xoap->xoa_reparse,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_REPARSE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_OFFLINE)) {
		ZFS_ATTR_SET(zp, ZFS_OFFLINE, xoap->xoa_offline,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_OFFLINE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_SPARSE)) {
		ZFS_ATTR_SET(zp, ZFS_SPARSE, xoap->xoa_sparse,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_SPARSE);
	}
}




/*
 * Attach a vnode to a znode.
 */
int
zfs_attach_vnode(znode_t *zp)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	struct vnode_fsparam vfsp;

	bzero(&vfsp, sizeof (vfsp));
	vfsp.vnfs_str = "zfs";

    // parent is a uint?
    if (!zfsvfs->z_vfs) printf("z_vfs should not be NULL here\n");
	vfsp.vnfs_mp = zfsvfs->z_vfs;
	//vfsp.vnfs_vtype = IFTOVT((mode_t)zp->z_mode);
	vfsp.vnfs_vtype = IFTOVT((mode_t)zp->z_mode);
	vfsp.vnfs_fsnode = zp;
	vfsp.vnfs_flags = VNFS_ADDFSREF;

	/*
	 * XXX HACK - workaround missing vnode_setnoflush() KPI...
	 */
	/* Tag system files */
	if ((zp->z_pflags & ZFS_XATTR) &&
	    (zfsvfs->z_last_unmount_time == 0xBADC0DE) &&
	    (zfsvfs->z_last_mtime_synced == zp->z_parent)) {
		vfsp.vnfs_marksystem = 1;
	}

	/* Tag root directory */
	if (zp->z_id == zfsvfs->z_root) {
		vfsp.vnfs_markroot = 1;
	}
#if 0
	if (dvp == NULLVP || cnp == NULL || !(cnp->cn_flags & MAKEENTRY)) {
		vfsp.vnfs_flags |= VNFS_NOCACHE;
	}
	vfsp.vnfs_dvp = dvp;
	vfsp.vnfs_cnp = cnp;
#endif

    // This is a hack
    if (vfsp.vnfs_vtype == 0) vfsp.vnfs_vtype = VDIR;


	switch (vfsp.vnfs_vtype) {
	case VDIR:
		if (zp->z_pflags & ZFS_XATTR) {
			vfsp.vnfs_vops = zfs_xdvnodeops;
		} else {
			vfsp.vnfs_vops = zfs_dvnodeops;
		}
		zp->z_zn_prefetch = B_TRUE; /* z_prefetch default is enabled */
		break;
	case VBLK:
	case VCHR:
		//vfsp.vnfs_rdev = zfs_cmpldev(zp->z_rdev);
		/*FALLTHROUGH*/
	case VFIFO:
	case VSOCK:
		vfsp.vnfs_vops = zfs_fvnodeops;
		break;
	case VREG:
		vfsp.vnfs_vops = zfs_fvnodeops;
		vfsp.vnfs_filesize = zp->z_size;
		break;
	case VLNK:
		vfsp.vnfs_vops = zfs_symvnodeops;
#if 0
		vfsp.vnfs_filesize = ???;
#endif
		break;
	default:
		vfsp.vnfs_vops = zfs_evnodeops;
		break;
	}

	/*
	 * ### TBD ###
	 * The rest of the code assumes we can always obtain a vnode.
	 * So for now, just spin until we get one.
	 */
    if (zp->z_vnode) printf("why is vp already set? %p\n", zp->z_vnode);
    if (zp->z_vid) printf("why is vid already set? %d\n", zp->z_vid);


	while (vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &zp->z_vnode) != 0);

    printf("Attaching zp %p to vp %p type %d: zmode 0x%04x\n", zp, zp->z_vnode,
           vfsp.vnfs_vtype, zp->z_mode);

	mutex_enter(&zp->z_lock);
	vnode_settag(zp->z_vnode, VT_ZFS);
    //vfs_getnewfsid(zp->z_vnode); // ZEVO
    //vnode_setmountedon(); // if block device
    //vnode_makeimode();
	zp->z_vid = vnode_vid(zp->z_vnode);
	/* Wake up any waiters. */
	cv_broadcast(&zp->z_cv);
	mutex_exit(&zp->z_lock);

	/* Insert it on our list of active znodes */
	mutex_enter(&zfsvfs->z_znodes_lock);
	list_insert_tail(&zfsvfs->z_all_znodes, zp);
	mutex_exit(&zfsvfs->z_znodes_lock);
    printf("attach done\n");
	return (0);
}




enum znode_alloc {
    ZA_UNKNOWN=0,
    ZA_GETDATA
};

#ifdef __APPLE__
static int
zfs_zget_internal(zfsvfs_t *zfsvfs, uint64_t obj_num, znode_t **zpp, int skip_vnode)
#else
int
zfs_zget(zfsvfs_t *zfsvfs, uint64_t obj_num, znode_t **zpp)
#endif /* __APPLE__ */
{
	dmu_object_info_t doi;
	dmu_buf_t	*db = NULL;
	znode_t		*zp = NULL;
	int err;
    sa_handle_t     *hdl = NULL;

	*zpp = NULL;

    //    printf("+zget %d\n", obj_num);

#ifdef __APPLE__
again:
#endif

	ZFS_OBJ_HOLD_ENTER(zfsvfs, obj_num);

    err = sa_buf_hold(zfsvfs->z_os, obj_num, NULL, &db);
    if (err) {
        ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
        printf("-zget nohold\n");
        return (err);
    }

	dmu_object_info_from_db(db, &doi);

    if (doi.doi_bonus_type != DMU_OT_SA &&
        (doi.doi_bonus_type != DMU_OT_ZNODE ||
         (doi.doi_bonus_type == DMU_OT_ZNODE &&
          doi.doi_bonus_size < sizeof (znode_phys_t)))) {
        sa_buf_rele(db, NULL);
		ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
        printf("-zget no znode\n");
		return (EINVAL);
    }

    hdl = dmu_buf_get_user(db);
    if (hdl != NULL) {
        zp  = sa_get_userdata(hdl);

		/*
		 * Since "SA" does immediate eviction we
		 * should never find a sa handle that doesn't
		 * know about the znode.
		 */
		ASSERT3P(zp, !=, NULL);

        mutex_enter(&zp->z_lock);

        if (zp->z_unlinked) {
			err = ENOENT;
        } else {

            /*
             * Make sure the vnode exists, if it doesn't we're
             * racing with zfs_attach_vnode and need to wait.
             *
             * Make sure the existing vnode hasn't changed identity.
             */

            /*
             * Since zp may disappear after we unlock, we save a copy of
             * vp and vid before we unlock
             */
            uint32_t vid = zp->z_vid;
            vnode_t *vp = ZTOV(zp);
            int holderr;

            sa_buf_rele(db, NULL);
            mutex_exit(&zp->z_lock);
            ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);

            if ((vp == NULL) || ((holderr = vnode_getwithvid(vp, vid)) != 0)) {
                printf("zfs_zget holderr %d\n", holderr);
                if (holderr==EALREADY) return EALREADY;
                goto again;
            }

            ZFS_OBJ_HOLD_ENTER(zfsvfs, obj_num);
            err = sa_buf_hold(zfsvfs->z_os, obj_num, NULL, &db);
            if (err) {
                ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
                printf("-zget nohold2\n");
                return (err);
            }
            mutex_enter(&zp->z_lock);
            /*
             * Since we had to drop all of our locks above, make sure
             * after we've reaquired all locks that we have the vnode
             * and znode we had before.
             */
            if ((vid != zp->z_vid) || (vp != ZTOV(zp))) {
                vnode_put(ZTOV(zp));
                mutex_exit(&zp->z_lock);
                ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
                printf("different vnode, loop\n");
                goto again;
            }

            *zpp = zp;
			err = 0;
		}

		sa_buf_rele(db, NULL);
		mutex_exit(&zp->z_lock);
		ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);

        //        printf("-zget %d exit 1\n", obj_num);
		return (err);
	} // hdl



    // BUG, for some reason our block size is not set, hanging IO
    if (doi.doi_data_block_size == 0) {
        printf("zfs_znode: would call znode_alloc with 0 blksz, fixing\n");
        //doi.doi_data_block_size = 131072;
        doi.doi_data_block_size = 512;
    }

    /*
     * Not found, create new znode/vnode
     */
    zp = zfs_znode_alloc(zfsvfs, db, doi.doi_data_block_size,
                         doi.doi_bonus_type, NULL);
    ASSERT3U(zp->z_id, ==, obj_num);
    //zfs_znode_dmu_init(zp);
    ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);

    if (skip_vnode) {
        printf("Not attaching znode for vp %p\n", zp);
        mutex_enter(&zfsvfs->z_znodes_lock);
        list_insert_tail(&zfsvfs->z_all_znodes, zp);
        mutex_exit(&zfsvfs->z_znodes_lock);
    } else {
        printf("zfs_znode attach 1\n");
        zfs_attach_vnode(zp);
    }

    if (zp == NULL) {
        err = ENOENT;
    } else {
        *zpp = zp;
    }
    //    printf("-zget %d\n", obj_num);
    return (err);
}

#ifdef __APPLE__
    /*
 * Get a znode from cache or create one if necessary.
 */
int
zfs_zget(zfsvfs_t *zfsvfs, uint64_t obj_num, znode_t **zpp)
{
	return zfs_zget_internal(zfsvfs, obj_num, zpp, 0);
}

/*
 * Some callers don't require a vnode, so allow them to
 * get a znode without attaching a vnode to it.
 */
int
zfs_zget_sans_vnode(zfsvfs_t *zfsvfs, uint64_t obj_num, znode_t **zpp)
{
	return zfs_zget_internal(zfsvfs, obj_num, zpp, 1);
}
#endif /* __APPLE__ */

int
zfs_rezget(znode_t *zp)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	dmu_object_info_t doi;
	dmu_buf_t *db;
	uint64_t obj_num = zp->z_id;
	uint64_t mode;
	sa_bulk_attr_t bulk[8];
	int err;
	int count = 0;
	uint64_t gen;

    printf("zfs_rezget\n");

	ZFS_OBJ_HOLD_ENTER(zfsvfs, obj_num);

	mutex_enter(&zp->z_acl_lock);
	if (zp->z_acl_cached) {
		zfs_acl_free(zp->z_acl_cached);
		zp->z_acl_cached = NULL;
	}

	mutex_exit(&zp->z_acl_lock);
	ASSERT(zp->z_sa_hdl == NULL);
	err = sa_buf_hold(zfsvfs->z_os, obj_num, NULL, &db);
	if (err) {
		ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
		return (err);
	}

	dmu_object_info_from_db(db, &doi);
	if (doi.doi_bonus_type != DMU_OT_SA &&
	    (doi.doi_bonus_type != DMU_OT_ZNODE ||
	    (doi.doi_bonus_type == DMU_OT_ZNODE &&
	    doi.doi_bonus_size < sizeof (znode_phys_t)))) {
		sa_buf_rele(db, NULL);
		ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
		return (EINVAL);
	}

	zfs_znode_sa_init(zfsvfs, zp, db, doi.doi_bonus_type, NULL);

	/* reload cached values */
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GEN(zfsvfs), NULL,
	    &gen, sizeof (gen));
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zfsvfs), NULL,
	    &zp->z_size, sizeof (zp->z_size));
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_LINKS(zfsvfs), NULL,
	    &zp->z_links, sizeof (zp->z_links));
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
	    &zp->z_pflags, sizeof (zp->z_pflags));
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_ATIME(zfsvfs), NULL,
	    &zp->z_atime, sizeof (zp->z_atime));
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_UID(zfsvfs), NULL,
	    &zp->z_uid, sizeof (zp->z_uid));
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GID(zfsvfs), NULL,
	    &zp->z_gid, sizeof (zp->z_gid));
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MODE(zfsvfs), NULL,
	    &mode, sizeof (mode));

	if (sa_bulk_lookup(zp->z_sa_hdl, bulk, count)) {
		zfs_znode_dmu_fini(zp);
		ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
		return (EIO);
	}

	zp->z_mode = mode;

	if (gen != zp->z_gen) {
		zfs_znode_dmu_fini(zp);
		ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
		return (EIO);
	}

	zp->z_unlinked = (zp->z_links == 0);
	zp->z_blksz = doi.doi_data_block_size;

	ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);

	return (0);
}


void zfs_znode_delete(znode_t *zp, dmu_tx_t *tx)
{
    zfsvfs_t *zfsvfs = zp->z_zfsvfs;
    objset_t *os = zfsvfs->z_os;
    uint64_t obj = zp->z_id;
    uint64_t acl_obj = zfs_external_acl(zp);

    printf("znode_delete\n");

    ZFS_OBJ_HOLD_ENTER(zfsvfs, obj);
    if (acl_obj) {
        VERIFY(!zp->z_is_sa);
        VERIFY(0 == dmu_object_free(os, acl_obj, tx));
    }
    VERIFY(0 == dmu_object_free(os, obj, tx));
    zfs_znode_dmu_fini(zp);
    ZFS_OBJ_HOLD_EXIT(zfsvfs, obj);
    zfs_znode_free(zp); // ZOL does not call free
}


void
zfs_zinactive(znode_t *zp)
{
#ifndef __APPLE__
	vnode_t	*vp = ZTOV(zp);
#endif
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	uint64_t z_id = zp->z_id;

    printf("zfs_zinactive\n");

#ifdef __APPLE__
    //	ASSERT(/*zp->z_dbuf && */ zp->z_phys);
#else
	ASSERT(zp->z_dbuf_held && zp->z_phys);
#endif
	/*
	 * Don't allow a zfs_zget() while were trying to release this znode
	 */
	ZFS_OBJ_HOLD_ENTER(zfsvfs, z_id);

	mutex_enter(&zp->z_lock);

	/*
	 * If this was the last reference to a file with no links,
	 * remove the file from the file system.
	 */
	if (zp->z_unlinked) {
		mutex_exit(&zp->z_lock);
		ZFS_OBJ_HOLD_EXIT(zfsvfs, z_id);
		zfs_rmnode(zp);
		// zfs_znode_free(zp); !ZEVO
		return;
	}

	mutex_exit(&zp->z_lock);
	zfs_znode_dmu_fini(zp);
	ZFS_OBJ_HOLD_EXIT(zfsvfs, z_id);
    zfs_znode_free(zp); // ZEVO
}

void
zfs_znode_free(znode_t *zp)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
    struct vnode *vp;

    vp = ZTOV(zp);

    printf("znode_free zp %p vp %p\n", zp, ZTOV(zp));
    vnode_removefsref(vp);
    vnode_clearfsnode(vp);
    vnode_recycle(vp);

#ifdef __APPLE__
	/*
	 * Note: the znode isn't inserted into the zfsvfs->z_all_znodes
	 * list until after the vnode is attached so make sure its in
	 * the list before attempting to remove it.
	 */
	if (zp->z_link_node.list_next || zp->z_link_node.list_prev) {
#endif
		mutex_enter(&zfsvfs->z_znodes_lock);
		list_remove(&zfsvfs->z_all_znodes, zp);
		mutex_exit(&zfsvfs->z_znodes_lock);
#ifdef __APPLE__
	}

    //	ASSERT(zp->z_dbuf_held == 0);
	ASSERT(zp->z_zfsvfs != (struct zfsvfs *)0xDEADBEEF);

	zp->z_id = 0;
	zp->z_vid = 0;
	zp->z_vnode = (vnode_t *)0xDEADBEEF;
	zp->z_zfsvfs = (struct zfsvfs *)0xDEADBEEF;

#ifdef ZFS_DEBUG
	znode_stalker_fini(zp);
#endif /* ZFS_DEBUG */

#endif __APPLE__
    printf("znode_free %p\n", zp);

	kmem_cache_free(znode_cache, zp);

    // fix me later
#ifdef __APPLEX__
	/*
	 * If we're beyond our target footprint, start up a reclaim thread
	 */
	if (zfs_footprint.current > zfs_footprint.target) {
		static struct timeval lastreap = {0, 0};

		struct timeval tv;

		microuptime(&tv);
		if (tv.tv_sec > lastreap.tv_sec + 15) {
			lastreap = tv;
			kmem_reap();
		}
	}
#endif /* __APPLE__ */
}

void
zfs_tstamp_update_setup(znode_t *zp, uint_t flag, uint64_t mtime[2],
    uint64_t ctime[2], boolean_t have_tx)
{
        timestruc_t     now;

        gethrestime(&now);

        if (have_tx) {  /* will sa_bulk_update happen really soon? */
                zp->z_atime_dirty = 0;
                zp->z_seq++;
        } else {
                zp->z_atime_dirty = 1;
        }

        if (flag & AT_ATIME) {
                ZFS_TIME_ENCODE(&now, zp->z_atime);
        }

        if (flag & AT_MTIME) {
                ZFS_TIME_ENCODE(&now, mtime);
                if (zp->z_zfsvfs->z_use_fuids) {
                        zp->z_pflags |= (ZFS_ARCHIVE |
                            ZFS_AV_MODIFIED);
                }
        }

        if ((flag & AT_MTIME) &&
            (zp->z_zfsvfs->z_mtime_vp != NULL) &&
            (VTOZ(zp->z_zfsvfs->z_mtime_vp) != zp)) {
            znode_t *mzp = VTOZ(zp->z_zfsvfs->z_mtime_vp);

            mutex_enter(&mzp->z_lock);
            ZFS_TIME_ENCODE(&now, mzp->z_mtime);
            mutex_exit(&mzp->z_lock);

            if (zp->z_zfsvfs->z_use_fuids)
                zp->z_pflags |= ZFS_ARCHIVE;

        }
}




/*
 * Grow the block size for a file.
 *
 *	IN:	zp	- znode of file to free data in.
 *		size	- requested block size
 *		tx	- open transaction.
 *
 * NOTE: this function assumes that the znode is write locked.
 */
void
zfs_grow_blocksize(znode_t *zp, uint64_t size, dmu_tx_t *tx)
{
	int		error;
	u_longlong_t	dummy;

	if (size <= zp->z_blksz)
		return;
	/*
	 * If the file size is already greater than the current blocksize,
	 * we will not grow.  If there is more than one block in a file,
	 * the blocksize cannot change.
	 */
	if (zp->z_blksz && zp->z_size > zp->z_blksz)
		return;

	error = dmu_object_set_blocksize(zp->z_zfsvfs->z_os, zp->z_id,
	    size, 0, tx);
	if (error == ENOTSUP)
		return;
	ASSERT3U(error, ==, 0);

	/* What blocksize did we actually get? */
	dmu_object_size_from_db(sa_get_db(zp->z_sa_hdl), &zp->z_blksz, &dummy);

}

#ifndef __APPLE__
/*
 * This is a dummy interface used when pvn_vplist_dirty() should *not*
 * be calling back into the fs for a putpage().  E.g.: when truncating
 * a file, the pages being "thrown away" don't need to be written out.
 */
/* ARGSUSED */
static int
zfs_no_putpage(vnode_t *vp, page_t *pp, u_offset_t *offp, size_t *lenp,
    int flags, cred_t *cr)
{
	ASSERT(0);
	return (0);
}
#endif /* !__APPLE__ */

/*
 * Free space in a file.
 *
 *	IN:	zp	- znode of file to free data in.
 *		off	- start of section to free.
 *		len	- length of section to free (0 => to EOF).
 *		flag	- current file open mode flags.
 *
 * 	RETURN:	0 if success
 *		error code if failure
 */
int
zfs_freesp(znode_t *zp, uint64_t off, uint64_t len, int flag, boolean_t log)
{
	vnode_t *vp = ZTOV(zp);
	dmu_tx_t *tx;
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	zilog_t *zilog = zfsvfs->z_log;
	rl_t *rl;
	uint64_t end = off + len;
	uint64_t size, new_blksz;
	uint64_t mtime[2], ctime[2];
	sa_bulk_attr_t bulk[3];
	int count = 0;
	int error;

#ifdef __APPLE__
	if (vnode_isfifo(ZTOV(zp)))
#else
	if (ZTOV(zp)->v_type == VFIFO)
#endif
		return (0);

	/*
	 * If we will change zp_size then lock the whole file,
	 * otherwise just lock the range being freed.
	 */
	if (len == 0 || off + len > zp->z_size) {
		rl = zfs_range_lock(zp, 0, UINT64_MAX, RL_WRITER);
	} else {
		rl = zfs_range_lock(zp, off, len, RL_WRITER);
		/* recheck, in case zp_size changed */
		if (off + len > zp->z_size) {
			/* lost race: file size changed, lock whole file */
			zfs_range_unlock(rl);
			rl = zfs_range_lock(zp, 0, UINT64_MAX, RL_WRITER);
		}
	}

	/*
	 * Nothing to do if file already at desired length.
	 */
	size = zp->z_size;
	if (len == 0 && size == off && off != 0) {
		zfs_range_unlock(rl);
		return (0);
	}

	/*
	 * Check for any locks in the region to be freed.
	 */
	if (MANDLOCK(vp, (mode_t)zp->z_mode)) {
		uint64_t start = off;
		uint64_t extent = len;

		if (off > size) {
			start = size;
			extent += off - size;
		} else if (len == 0) {
			extent = size - off;
		}
		if ((error = chklock(vp, FWRITE, start, extent, flag, NULL))) {
			zfs_range_unlock(rl);
			return (error);
		}
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	zfs_sa_upgrade_txholds(tx, zp);

	new_blksz = 0;
	if (end > size &&
	    (!ISP2(zp->z_blksz) || zp->z_blksz < zfsvfs->z_max_blksz)) {
		/*
		 * We are growing the file past the current block size.
		 */
		if (zp->z_blksz > zp->z_zfsvfs->z_max_blksz) {
			ASSERT(!ISP2(zp->z_blksz));
			new_blksz = MIN(end, SPA_MAXBLOCKSIZE);
		} else {
			new_blksz = MIN(end, zp->z_zfsvfs->z_max_blksz);
		}
		dmu_tx_hold_write(tx, zp->z_id, 0, MIN(end, new_blksz));
	} else if (off < size) {
		/*
		 * If len == 0, we are truncating the file.
		 */
		dmu_tx_hold_free(tx, zp->z_id, off, len ? len : DMU_OBJECT_END);
	}

	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT)
			dmu_tx_wait(tx);
		dmu_tx_abort(tx);
		zfs_range_unlock(rl);
		return (error);
	}

    SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL, mtime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL, ctime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs),
                     NULL, &zp->z_pflags, 8);
	zfs_tstamp_update_setup(zp, CONTENT_MODIFIED, mtime, ctime, B_TRUE);
	error = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);


	if (new_blksz)
		zfs_grow_blocksize(zp, new_blksz, tx);

	if (end > size || len == 0)
		zp->z_size = end;

	if (off < size) {
		objset_t *os = zfsvfs->z_os;
		uint64_t rlen = len;

		if (len == 0)
			rlen = -1;
		else if (end > size)
			rlen = size - off;
		VERIFY(0 == dmu_free_range(os, zp->z_id, off, rlen, tx));
	}

	zfs_range_unlock(rl);

	zfs_log_truncate(zilog, tx, TX_TRUNCATE, zp, off, len);

	dmu_tx_commit(tx);

	/*
	 * Clear any mapped pages in the truncated region.  This has to
	 * happen outside of the transaction to avoid the possibility of
	 * a deadlock with someone trying to push a page that we are
	 * about to invalidate.
	 */
/* ### APPLE ZFS TODO ### */
#ifndef __APPLE__
	rw_enter(&zp->z_map_lock, RW_WRITER);
	if (off < size && vn_has_cached_data(vp)) {
		page_t *pp;
		uint64_t start = off & PAGEMASK;
		int poff = off & PAGEOFFSET;

		if (poff != 0 && (pp = page_lookup(vp, start, SE_SHARED))) {
			/*
			 * We need to zero a partial page.
			 */
			pagezero(pp, poff, PAGESIZE - poff);
			start += PAGESIZE;
			page_unlock(pp);
		}
		error = pvn_vplist_dirty(vp, start, zfs_no_putpage,
		    B_INVAL | B_TRUNC, NULL);
		ASSERT(error == 0);
	}
	rw_exit(&zp->z_map_lock);
#endif

	return (0);
}

void
zfs_create_fs(objset_t *os, cred_t *cr, nvlist_t *zplprops, dmu_tx_t *tx)
{
	zfsvfs_t	zfsvfs;
	uint64_t	moid, doid, roid = 0, sa_obj, version;
    uint64_t        norm = 0;

	int		error;
	znode_t		*rootzp = NULL;
	vnode_t		*vp;
	vattr_t		vattr;
        nvpair_t        *elem;
        uint64_t        sense = ZFS_CASE_SENSITIVE;
        znode_t         *zp;
        zfs_acl_ids_t   acl_ids;

	/*
	 * First attempt to create master node.
	 */
	/*
	 * In an empty objset, there are no blocks to read and thus
	 * there can be no i/o errors (which we assert below).
	 */
	moid = MASTER_NODE_OBJ;
	error = zap_create_claim(os, moid, DMU_OT_MASTER_NODE,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	/*
	 * Set starting attributes.
	 */

        /*
         * Set starting attributes.
         */
        version = zfs_zpl_version_map(spa_version(dmu_objset_spa(os)));
        elem = NULL;
        while ((elem = nvlist_next_nvpair(zplprops, elem)) != NULL) {
                /* For the moment we expect all zpl props to be uint64_ts */
                uint64_t val;
                char *name;

                ASSERT(nvpair_type(elem) == DATA_TYPE_UINT64);
                VERIFY(nvpair_value_uint64(elem, &val) == 0);
                name = nvpair_name(elem);
                if (strcmp(name, zfs_prop_to_name(ZFS_PROP_VERSION)) == 0) {
                        if (val < version)
                                version = val;
                } else {
                        error = zap_update(os, moid, name, 8, 1, &val, tx);
                }
                ASSERT(error == 0);
                if (strcmp(name, zfs_prop_to_name(ZFS_PROP_NORMALIZE)) == 0)
                        norm = val;
                else if (strcmp(name, zfs_prop_to_name(ZFS_PROP_CASE)) == 0)
                        sense = val;
        }
        ASSERT(version != 0);

        error = zap_update(os, moid, ZPL_VERSION_STR, 8, 1, &version, tx);

	ASSERT(error == 0);

        /*
         * Create zap object used for SA attribute registration
         */

        if (version >= ZPL_VERSION_SA) {
                sa_obj = zap_create(os, DMU_OT_SA_MASTER_NODE,
                    DMU_OT_NONE, 0, tx);
                error = zap_add(os, moid, ZFS_SA_ATTRS, 8, 1, &sa_obj, tx);
                ASSERT(error == 0);
        } else {
                sa_obj = 0;
        }
	/*
	 * Create a delete queue.
	 */
	doid = zap_create(os, DMU_OT_UNLINKED_SET, DMU_OT_NONE, 0, tx);

	error = zap_add(os, moid, ZFS_UNLINKED_SET, 8, 1, &doid, tx);
	ASSERT(error == 0);

	/*
	 * Create root znode.  Create minimal znode/vnode/zfsvfs
	 * to allow zfs_mknode to work.
	 */
	vattr.va_mask = AT_MODE|AT_UID|AT_GID|AT_TYPE;
	vattr.va_type = VDIR;
	vattr.va_mode = S_IFDIR|0755;
	vattr.va_uid = crgetuid(cr);
	vattr.va_gid = crgetgid(cr);

	rootzp = kmem_cache_alloc(znode_cache, KM_SLEEP);
	rootzp->z_zfsvfs = &zfsvfs;
	rootzp->z_unlinked = 0;
	rootzp->z_atime_dirty = 0;
    //	rootzp->z_dbuf_held = 0;
    rootzp->z_is_sa = USE_SA(version, os);

	vp = ZTOV(rootzp);
#ifndef __APPLE__
	vn_reinit(vp);
	vp->v_type = VDIR;
#endif

	bzero(&zfsvfs, sizeof (zfsvfs_t));

	zfsvfs.z_os = os;
	zfsvfs.z_assign = TXG_NOWAIT;
	zfsvfs.z_parent = &zfsvfs;
    zfsvfs.z_version = version;
    zfsvfs.z_use_fuids = USE_FUIDS(version, os);
    zfsvfs.z_use_sa = USE_SA(version, os);
    zfsvfs.z_norm = norm;

    error = sa_setup(os, sa_obj, zfs_attr_table, ZPL_END,
                     &zfsvfs.z_attr_table);

	mutex_init(&zfsvfs.z_znodes_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zfsvfs.z_all_znodes, sizeof (znode_t),
	    offsetof(znode_t, z_link_node));

    rootzp->z_zfsvfs = &zfsvfs;
    VERIFY(0 == zfs_acl_ids_create(rootzp, IS_ROOT_NODE, &vattr,
                                   cr, NULL, &acl_ids));

	//zfs_mknode(rootzp, &vattr, &roid, tx, cr, IS_ROOT_NODE, NULL, 0);
    zfs_mknode(rootzp, &vattr, tx, cr, IS_ROOT_NODE, &zp, &acl_ids);

	ASSERT3U(rootzp->z_id, ==, roid);
	error = zap_add(os, moid, ZFS_ROOT_OBJ, 8, 1, &rootzp->z_id, tx);
	ASSERT(error == 0);
    zfs_acl_ids_free(&acl_ids);
    sa_handle_destroy(rootzp->z_sa_hdl);

#ifndef __APPLE__
	ZTOV(rootzp)->v_count = 0;
#endif
	kmem_cache_free(znode_cache, rootzp);

}


static int
zfs_sa_setup(objset_t *osp, sa_attr_type_t **sa_table)
{
	uint64_t sa_obj = 0;
	int error;

	error = zap_lookup(osp, MASTER_NODE_OBJ, ZFS_SA_ATTRS, 8, 1, &sa_obj);
	if (error != 0 && error != ENOENT)
		return (error);

	error = sa_setup(osp, sa_obj, zfs_attr_table, ZPL_END, sa_table);
	return (error);
}

static int
zfs_grab_sa_handle(objset_t *osp, uint64_t obj, sa_handle_t **hdlp,
    dmu_buf_t **db, void *tag)
{
	dmu_object_info_t doi;
	int error;

	if ((error = sa_buf_hold(osp, obj, tag, db)) != 0)
		return (error);

	dmu_object_info_from_db(*db, &doi);
	if ((doi.doi_bonus_type != DMU_OT_SA &&
	    doi.doi_bonus_type != DMU_OT_ZNODE) ||
        ( doi.doi_bonus_type == DMU_OT_ZNODE &&
          doi.doi_bonus_size < sizeof (znode_phys_t))) {
		sa_buf_rele(*db, tag);
		return (ENOTSUP);
	}

	error = sa_handle_get(osp, obj, NULL, SA_HDL_PRIVATE, hdlp);
	if (error != 0) {
		sa_buf_rele(*db, tag);
		return (error);
	}

	return (0);
}

void
zfs_release_sa_handle(sa_handle_t *hdl, dmu_buf_t *db, void *tag)
{
	sa_handle_destroy(hdl);
	sa_buf_rele(db, tag);
}




#endif /* _KERNEL */

/*
 * Given an object number, return its parent object number and whether
 * or not the object is an extended attribute directory.
 */
static int
zfs_obj_to_pobj(objset_t *osp, uint64_t obj, uint64_t *pobjp, int *is_xattrdir)
{
	dmu_buf_t *db;
	dmu_object_info_t doi;
	znode_phys_t *zp;
	int error;

	if ((error = dmu_bonus_hold(osp, obj, FTAG, &db)) != 0)
		return (error);

	dmu_object_info_from_db(db, &doi);
	if (doi.doi_bonus_type != DMU_OT_ZNODE ||
	    doi.doi_bonus_size < sizeof (znode_phys_t)) {
		dmu_buf_rele(db, FTAG);
		return (EINVAL);
	}

	zp = db->db_data;
	*pobjp = zp->zp_parent;
	*is_xattrdir = ((zp->zp_flags & ZFS_XATTR) != 0) &&
	    S_ISDIR(zp->zp_mode);
	dmu_buf_rele(db, FTAG);

	return (0);
}

#if 0
int
zfs_obj_to_path_impl(objset_t *osp, uint64_t obj, char *buf, int len)
{
	char *path = buf + len - 1;
	int error;

	*path = '\0';

	for (;;) {
		uint64_t pobj;
		char component[MAXNAMELEN + 2];
		size_t complen;
		int is_xattrdir;

		if ((error = zfs_obj_to_pobj(osp, obj, &pobj,
		    &is_xattrdir)) != 0)
			break;

		if (pobj == obj) {
			if (path[0] != '/')
				*--path = '/';
			break;
		}

		component[0] = '/';
		if (is_xattrdir) {
			(void) snprintf(component + 1, sizeof(component), "<xattrdir>");
		} else {
			error = zap_value_search(osp, pobj, obj,
			    ZFS_DIRENT_OBJ(-1ULL), component + 1);
			if (error != 0)
				break;
		}

		complen = strlen(component);
		path -= complen;
		ASSERT(path >= buf);
		bcopy(component, path, complen);
		obj = pobj;
	}

	if (error == 0)
		(void) memmove(buf, path, buf + len - path);
	return (error);
}
#else

static int
zfs_obj_to_path_impl(objset_t *osp, uint64_t obj, sa_handle_t *hdl,
    sa_attr_type_t *sa_table, char *buf, int len)
{
	sa_handle_t *sa_hdl;
	sa_handle_t *prevhdl = NULL;
	dmu_buf_t *prevdb = NULL;
	dmu_buf_t *sa_db = NULL;
	char *path = buf + len - 1;
	int error;

	*path = '\0';
	sa_hdl = hdl;

	for (;;) {
		uint64_t pobj;
		char component[MAXNAMELEN + 2];
		size_t complen;
		int is_xattrdir;

		if (prevdb)
			zfs_release_sa_handle(prevhdl, prevdb, FTAG);

		if ((error = zfs_obj_to_pobj(sa_hdl, sa_table, &pobj,
		    &is_xattrdir)) != 0)
			break;

		if (pobj == obj) {
			if (path[0] != '/')
				*--path = '/';
			break;
		}

		component[0] = '/';
		if (is_xattrdir) {
			(void) sprintf(component + 1, "<xattrdir>");
		} else {
			error = zap_value_search(osp, pobj, obj,
			    ZFS_DIRENT_OBJ(-1ULL), component + 1);
			if (error != 0)
				break;
		}

		complen = strlen(component);
		path -= complen;
		ASSERT(path >= buf);
		bcopy(component, path, complen);
		obj = pobj;

		if (sa_hdl != hdl) {
			prevhdl = sa_hdl;
			prevdb = sa_db;
		}
		error = zfs_grab_sa_handle(osp, obj, &sa_hdl, &sa_db, FTAG);
		if (error != 0) {
			sa_hdl = prevhdl;
			sa_db = prevdb;
			break;
		}
	}

	if (sa_hdl != NULL && sa_hdl != hdl) {
		ASSERT(sa_db != NULL);
		zfs_release_sa_handle(sa_hdl, sa_db, FTAG);
	}

	if (error == 0)
		(void) memmove(buf, path, buf + len - path);

	return (error);
}

#endif


int
zfs_obj_to_path(objset_t *osp, uint64_t obj, char *buf, int len)
{
	sa_attr_type_t *sa_table;
	sa_handle_t *hdl;
	dmu_buf_t *db;
	int error;

	error = zfs_sa_setup(osp, &sa_table);
	if (error != 0)
		return (error);

	error = zfs_grab_sa_handle(osp, obj, &hdl, &db, FTAG);
	if (error != 0)
		return (error);

	error = zfs_obj_to_path_impl(osp, obj, hdl, sa_table, buf, len);

	zfs_release_sa_handle(hdl, db, FTAG);
	return (error);
}


#ifdef __APPLE__
#ifdef _KERNEL
uint32_t
zfs_getbsdflags(znode_t *zp)
{
	uint64_t  zflags = zp->z_pflags;
	uint32_t  bsdflags = 0;

	if (zflags & ZFS_NODUMP)
		bsdflags |= UF_NODUMP;
	if (zflags & ZFS_IMMUTABLE)
		bsdflags |= UF_IMMUTABLE;
	if (zflags & ZFS_APPENDONLY)
		bsdflags |= UF_APPEND;
	if (zflags & ZFS_OPAQUE)
		bsdflags |= UF_OPAQUE;
	if (zflags & ZFS_HIDDEN)
		bsdflags |= UF_HIDDEN;
	if (zflags & ZFS_ARCHIVE)
		bsdflags |= SF_ARCHIVED;

	return (bsdflags);
}

void
zfs_setbsdflags(znode_t *zp, uint32_t bsdflags)
{
	uint64_t  zflags = zp->z_pflags;

	if (bsdflags & UF_NODUMP)
		zflags |= ZFS_NODUMP;
	else
		zflags &= ~ZFS_NODUMP;

	if (bsdflags & UF_IMMUTABLE)
		zflags |= ZFS_IMMUTABLE;
	else
		zflags &= ~ZFS_IMMUTABLE;

	if (bsdflags & UF_APPEND)
		zflags |= ZFS_APPENDONLY;
	else
		zflags &= ~ZFS_APPENDONLY;

	if (bsdflags & UF_OPAQUE)
		zflags |= ZFS_OPAQUE;
	else
		zflags &= ~ZFS_OPAQUE;

	if (bsdflags & UF_HIDDEN)
		zflags |= ZFS_HIDDEN;
	else
		zflags &= ~ZFS_HIDDEN;

	if (bsdflags & SF_ARCHIVED)
		zflags |= ZFS_ARCHIVE;
	else
		zflags &= ~ZFS_ARCHIVE;

	zp->z_pflags = zflags;
}
#endif

#ifdef _KERNEL
#ifdef ZFS_DEBUG
char *
n_event_to_str(whereami_t event); // the prototype that removes gcc warning
char *
n_event_to_str(whereami_t event)
{
        switch (event) {
        case N_znode_alloc:
                return("N_znode_alloc");
        case N_vnop_inactive:
                return("N_vnop_inactive");
        case N_zinactive:
                return("N_zinactive");
        case N_vnop_reclaim:
                return("N_vnop_reclaim");
        case N_znode_delete:
                return("N_znode_delete");
        case N_znode_pageout:
                return("N_znode_pageout");
        case N_zfs_nolink_add:
                return("N_zfs_nolink_add");
        case N_mknode_err:
                return("N_mknode_err");
        case N_zinact_retearly:
                return("N_zinact_retearly");
        case N_zfs_rmnode:
                return("N_zfs_rmnode");
        case N_vnop_fsync_zil:
                return("N_vnop_fsync_zil");
        default:
                return("don't know");
        }
}

void
znode_stalker(znode_t *zp, whereami_t event)
{
	findme_t *n;
	if( k_maczfs_debug_stalk ) {
		n = kmem_alloc(sizeof (findme_t), KM_SLEEP);
		n->event = event;
		mutex_enter(&zp->z_lock);
		list_insert_tail(&zp->z_stalker, n);
		mutex_exit(&zp->z_lock);
		printf("stalk: zp %p %s\n", zp, n_event_to_str(event));
	}
}

void
znode_stalker_fini(znode_t *zp)
{
	findme_t *n;

	while (n = list_head(&zp->z_stalker)) {
                list_remove(&zp->z_stalker, n);
                kmem_free(n, sizeof(findme_t));
        }
	list_destroy(&zp->z_stalker);
}
#endif /* ZFS_DEBUG */

/*
 * Given an object number, return some zpl level statistics
 */
static int
zfs_obj_to_stats_impl(sa_handle_t *hdl, sa_attr_type_t *sa_table,
    zfs_stat_t *sb)
{
	sa_bulk_attr_t bulk[4];
	int count = 0;

	SA_ADD_BULK_ATTR(bulk, count, sa_table[ZPL_MODE], NULL,
	    &sb->zs_mode, sizeof (sb->zs_mode));
	SA_ADD_BULK_ATTR(bulk, count, sa_table[ZPL_GEN], NULL,
	    &sb->zs_gen, sizeof (sb->zs_gen));
	SA_ADD_BULK_ATTR(bulk, count, sa_table[ZPL_LINKS], NULL,
	    &sb->zs_links, sizeof (sb->zs_links));
	SA_ADD_BULK_ATTR(bulk, count, sa_table[ZPL_CTIME], NULL,
	    &sb->zs_ctime, sizeof (sb->zs_ctime));

	return (sa_bulk_lookup(hdl, bulk, count));
}


int
zfs_obj_to_stats(objset_t *osp, uint64_t obj, zfs_stat_t *sb,
    char *buf, int len)
{
	char *path = buf + len - 1;
	sa_attr_type_t *sa_table;
	sa_handle_t *hdl;
	dmu_buf_t *db;
	int error=99;

	*path = '\0';

	//error = zfs_sa_setup(osp, &sa_table);
	if (error != 0)
        return (error);

	error = zfs_grab_sa_handle(osp, obj, &hdl, &db, FTAG);
	if (error != 0)
		return (error);

	error = zfs_obj_to_stats_impl(hdl, sa_table, sb);
	if (error != 0) {
		zfs_release_sa_handle(hdl, db, FTAG);
		return (error);
	}

	//error = zfs_obj_to_path_impl(osp, obj, hdl, sa_table, buf, len);
	error = zfs_obj_to_path(osp, obj, buf, len);

	zfs_release_sa_handle(hdl, db, FTAG);
	return (error);
}


#endif /* _KERNEL */
#endif /* __APPLE__ */
