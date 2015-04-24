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
 * Copyright (c) 2011 Pawel Jakub Dawidek <pawel@dawidek.net>.
 * All rights reserved.
 * Copyright (C) 2011 Lawrence Livermore National Security, LLC.
 * Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 * LLNL-CODE-403049.
 * Rewritten for Linux by:
 *   Rohan Puri <rohan.puri15@gmail.com>
 *   Brian Behlendorf <behlendorf1@llnl.gov>
 * Copyright (c) 2012, 2015 by Delphix. All rights reserved.
 *
 * Rewritten for OSX by (based on FreeBSD)
 *   Jorgen Lundman <lundman@lundman.net>
 */

/*
 * ZFS control directory (a.k.a. ".zfs")
 *
 * This directory provides a common location for all ZFS meta-objects.
 * Currently, this is only the 'snapshot' directory, but this may expand in the
 * future.  The elements are built using the GFS primitives, as the hierarchy
 * does not actually exist on disk.
 *
 * For 'snapshot', we don't want to have all snapshots always mounted, because
 * this would take up a huge amount of space in /etc/mnttab.  We have three
 * types of objects:
 *
 * 	ctldir ------> snapshotdir -------> snapshot
 *                                             |
 *                                             |
 *                                             V
 *                                         mounted fs
 *
 * The 'snapshot' node contains just enough information to lookup '..' and act
 * as a mountpoint for the snapshot.  Whenever we lookup a specific snapshot, we
 * perform an automount of the underlying filesystem and return the
 * corresponding vnode.
 *
 * All mounts are handled automatically by the kernel, but unmounts are
 * (currently) handled from user land.  The main reason is that there is no
 * reliable way to auto-unmount the filesystem when it's "no longer in use".
 * When the user unmounts a filesystem, we call zfsctl_unmount(), which
 * unmounts any snapshots within the snapshot directory.
 *
 * The '.zfs', '.zfs/snapshot', and all directories created under
 * '.zfs/snapshot' (ie: '.zfs/snapshot/<snapname>') are all GFS nodes and
 * share the same vfs_t as the head filesystem (what '.zfs' lives under).
 *
 * File systems mounted ontop of the GFS nodes '.zfs/snapshot/<snapname>'
 * (ie: snapshots) are ZFS nodes and have their own unique vfs_t.
 * However, vnodes within these mounted on file systems have their v_vfsp
 * fields set to the head filesystem to make NFS happy (see
 * zfsctl_snapdir_lookup()). We VFS_HOLD the head filesystem's vfs_t
 * so that it cannot be freed until all snapshots have been unmounted.
 */

#include <sys/mount.h>
#include <sys/types.h>
#include <sys/pathname.h>
#include <sys/zfs_context.h>
#include <sys/zfs_ctldir.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_vfsops.h>
#include <sys/namei.h>
#include <sys/gfs.h>
#include <sys/stat.h>
#include <sys/dmu.h>
#include <sys/dsl_destroy.h>

#include <sys/dsl_deleg.h>
#include <sys/mount.h>
#include <sys/sunddi.h>

#include "zfs_namecheck.h"

/*
 * Two AVL trees are maintained which contain all currently automounted
 * snapshots.  Every automounted snapshots maps to a single zfs_snapentry_t
 * entry which MUST:
 *
 *   - be attached to both trees, and
 *   - be unique, no duplicate entries are allowed.
 *
 * The zfs_snapshots_by_name tree is indexed by the full dataset name
 * while the zfs_snapshots_by_objsetid tree is indexed by the unique
 * objsetid.  This allows for fast lookups either by name or objsetid.
 */
static avl_tree_t zfs_snapshots_by_name;
static avl_tree_t zfs_snapshots_by_objsetid;
static kmutex_t zfs_snapshot_lock;

/*
 * Control Directory Tunables (.zfs)
 */
int zfs_expire_snapshot = ZFSCTL_EXPIRE_SNAPSHOT;

/*
 *            OSX     FreeBSD
 *           -------  ---------
 * Short:    iocount  usecount
 * Long:    usecount  holdcount
 * incr:   vnode_get  vget
 * decr:   vnode_put  vrele / vput (vput unlocks and vrele)
 *
 */

typedef struct {
	char		*se_name;	/* full snapshot name */
	char		*se_path;	/* full mount path */
	uint64_t	se_objsetid;	/* snapshot objset id */
	struct dentry   *se_root_dentry; /* snapshot root dentry */
	taskqid_t	se_taskqid;	/* scheduled unmount taskqid */
	avl_node_t	se_node_name;	/* zfs_snapshots_by_name link */
	avl_node_t	se_node_objsetid; /* zfs_snapshots_by_objsetid link */
	refcount_t	se_refcount;	/* reference count */
} zfs_snapentry_t;

static void zfsctl_snapshot_unmount_delay_impl(zfs_snapentry_t *se, int delay);

/*
 * Allocate a new zfs_snapentry_t being careful to make a copy of the
 * the snapshot name and provided mount point.  No reference is taken.
 */
static zfs_snapentry_t *
zfsctl_snapshot_alloc(char *full_name, char *full_path, uint64_t objsetid,
    struct dentry *root_dentry)
{
	zfs_snapentry_t *se;

	se = kmem_zalloc(sizeof (zfs_snapentry_t), KM_SLEEP);

	se->se_name = strdup(full_name);
	se->se_path = strdup(full_path);
	se->se_objsetid = objsetid;
	se->se_root_dentry = root_dentry;
	se->se_taskqid = -1;

	refcount_create(&se->se_refcount);

	return (se);
}

/*
 * Free a zfs_snapentry_t the called must ensure there are no active
 * references.
 */
static void
zfsctl_snapshot_free(zfs_snapentry_t *se)
{
	refcount_destroy(&se->se_refcount);
	strfree(se->se_name);
	strfree(se->se_path);

	kmem_free(se, sizeof (zfs_snapentry_t));
}

/*
 * Hold a reference on the zfs_snapentry_t.
 */
static void
zfsctl_snapshot_hold(zfs_snapentry_t *se)
{
	refcount_add(&se->se_refcount, NULL);
}

/*
 * Release a reference on the zfs_snapentry_t.  When the number of
 * references drops to zero the structure will be freed.
 */
static void
zfsctl_snapshot_rele(zfs_snapentry_t *se)
{
	if (refcount_remove(&se->se_refcount, NULL) == 0)
		zfsctl_snapshot_free(se);
}

/*
 * Add a zfs_snapentry_t to both the zfs_snapshots_by_name and
 * zfs_snapshots_by_objsetid trees.  While the zfs_snapentry_t is part
 * of the trees a reference is held.
 */
static void
zfsctl_snapshot_add(zfs_snapentry_t *se)
{
	ASSERT(MUTEX_HELD(&zfs_snapshot_lock));
	refcount_add(&se->se_refcount, NULL);
	avl_add(&zfs_snapshots_by_name, se);
	avl_add(&zfs_snapshots_by_objsetid, se);
}

/*
 * Remove a zfs_snapentry_t from both the zfs_snapshots_by_name and
 * zfs_snapshots_by_objsetid trees.  Upon removal a reference is dropped,
 * this can result in the structure being freed if that was the last
 * remaining reference.
 */
static void
zfsctl_snapshot_remove(zfs_snapentry_t *se)
{
	ASSERT(MUTEX_HELD(&zfs_snapshot_lock));
	avl_remove(&zfs_snapshots_by_name, se);
	avl_remove(&zfs_snapshots_by_objsetid, se);
	zfsctl_snapshot_rele(se);
}

/*
 * Snapshot name comparison function for the zfs_snapshots_by_name.
 */
static int
snapentry_compare_by_name(const void *a, const void *b)
{
	const zfs_snapentry_t *se_a = a;
	const zfs_snapentry_t *se_b = b;
	int ret;

	ret = strcmp(se_a->se_name, se_b->se_name);

	if (ret < 0)
		return (-1);
	else if (ret > 0)
		return (1);
	else
		return (0);
}

/*
 * Snapshot name comparison function for the zfs_snapshots_by_objsetid.
 */
static int
snapentry_compare_by_objsetid(const void *a, const void *b)
{
	const zfs_snapentry_t *se_a = a;
	const zfs_snapentry_t *se_b = b;

	if (se_a->se_objsetid < se_b->se_objsetid)
		return (-1);
	else if (se_a->se_objsetid > se_b->se_objsetid)
		return (1);
	else
		return (0);
}

/*
 * Find a zfs_snapentry_t in zfs_snapshots_by_name.  If the snapname
 * is found a pointer to the zfs_snapentry_t is returned and a reference
 * taken on the structure.  The caller is responsible for dropping the
 * reference with zfsctl_snapshot_rele().  If the snapname is not found
 * NULL will be returned.
 */
static zfs_snapentry_t *
zfsctl_snapshot_find_by_name(char *snapname)
{
	zfs_snapentry_t *se, search;

	ASSERT(MUTEX_HELD(&zfs_snapshot_lock));

	search.se_name = snapname;
	se = avl_find(&zfs_snapshots_by_name, &search, NULL);
	if (se)
		refcount_add(&se->se_refcount, NULL);

	return (se);
}

/*
 * Find a zfs_snapentry_t in zfs_snapshots_by_objsetid given the objset id
 * rather than the snapname.  In all other respects it behaves the same
 * as zfsctl_snapshot_find_by_name().
 */
static zfs_snapentry_t *
zfsctl_snapshot_find_by_objsetid(uint64_t objsetid)
{
	zfs_snapentry_t *se, search;

	ASSERT(MUTEX_HELD(&zfs_snapshot_lock));

	search.se_objsetid = objsetid;
	se = avl_find(&zfs_snapshots_by_objsetid, &search, NULL);
	if (se)
		refcount_add(&se->se_refcount, NULL);

	return (se);
}

/*
 * Rename a zfs_snapentry_t in the zfs_snapshots_by_name.  The structure is
 * removed, renamed, and added back to the new correct location in the tree.
 */
static int
zfsctl_snapshot_rename(char *old_snapname, char *new_snapname)
{
	zfs_snapentry_t *se;

	ASSERT(MUTEX_HELD(&zfs_snapshot_lock));

	se = zfsctl_snapshot_find_by_name(old_snapname);
	if (se == NULL)
		return (ENOENT);

	zfsctl_snapshot_remove(se);
	strfree(se->se_name);
	se->se_name = strdup(new_snapname);
	zfsctl_snapshot_add(se);
	zfsctl_snapshot_rele(se);

	return (0);
}

/*
 * Delayed task responsible for unmounting an expired automounted snapshot.
 */
static void
snapentry_expire(void *data)
{
	zfs_snapentry_t *se = (zfs_snapentry_t *)data;
	uint64_t objsetid = se->se_objsetid;

	se->se_taskqid = -1;
	(void) zfsctl_snapshot_unmount(se->se_name, MNT_EXPIRE);
	zfsctl_snapshot_rele(se);

	/*
	 * Reschedule the unmount if the zfs_snapentry_t wasn't removed.
	 * This can occur when the snapshot is busy.
	 */
	mutex_enter(&zfs_snapshot_lock);
	if ((se = zfsctl_snapshot_find_by_objsetid(objsetid)) != NULL) {
		zfsctl_snapshot_unmount_delay_impl(se, zfs_expire_snapshot);
		zfsctl_snapshot_rele(se);
	}
	mutex_exit(&zfs_snapshot_lock);
}

/*
 * Cancel an automatic unmount of a snapname.  This callback is responsible
 * for dropping the reference on the zfs_snapentry_t which was taken when
 * during dispatch.
 */
static void
zfsctl_snapshot_unmount_cancel(zfs_snapentry_t *se)
{
	ASSERT(MUTEX_HELD(&zfs_snapshot_lock));

	if (taskq_cancel_id(zfs_expire_taskq, se->se_taskqid) == 0) {
		se->se_taskqid = -1;
		zfsctl_snapshot_rele(se);
	}
}

/*
 * Dispatch the unmount task for delayed handling with a hold protecting it.
 */
static void
zfsctl_snapshot_unmount_delay_impl(zfs_snapentry_t *se, int delay)
{
	ASSERT3S(se->se_taskqid, ==, -1);

	se->se_taskqid = taskq_dispatch_delay(zfs_expire_taskq,
	    snapentry_expire, se, TQ_SLEEP, ddi_get_lbolt() + delay * HZ);
	zfsctl_snapshot_hold(se);
}

/*
 * Schedule an automatic unmount of objset id to occur in delay seconds from
 * now.  Any previous delayed unmount will be cancelled in favor of the
 * updated deadline.  A reference is taken by zfsctl_snapshot_find_by_name()
 * and held until the outstanding task is handled or cancelled.
 */
int
zfsctl_snapshot_unmount_delay(uint64_t objsetid, int delay)
{
	zfs_snapentry_t *se;
	int error = ENOENT;

	mutex_enter(&zfs_snapshot_lock);
	if ((se = zfsctl_snapshot_find_by_objsetid(objsetid)) != NULL) {
		zfsctl_snapshot_unmount_cancel(se);
		zfsctl_snapshot_unmount_delay_impl(se, delay);
		zfsctl_snapshot_rele(se);
		error = 0;
	}
	mutex_exit(&zfs_snapshot_lock);

	return (error);
}

/*
 * Check if snapname is currently mounted.  Returned non-zero when mounted
 * and zero when unmounted.
 */
static boolean_t
zfsctl_snapshot_ismounted(char *snapname)
{
	zfs_snapentry_t *se;
	boolean_t ismounted = B_FALSE;

	mutex_enter(&zfs_snapshot_lock);
	if ((se = zfsctl_snapshot_find_by_name(snapname)) != NULL) {
		zfsctl_snapshot_rele(se);
		ismounted = B_TRUE;
	}
	mutex_exit(&zfs_snapshot_lock);

	return (ismounted);
}

/*
 * Check if the given inode is a part of the virtual .zfs directory.
 */
boolean_t
zfsctl_is_node(struct inode *ip)
{
#ifdef sun
	/*
	 * Remove vfsctl vnode ops
	 */
	if (zfsctl_ops_root)
		vn_freevnodeops(zfsctl_ops_root);
	if (zfsctl_ops_snapdir)
		vn_freevnodeops(zfsctl_ops_snapdir);
	if (zfsctl_ops_snapshot)
		vn_freevnodeops(zfsctl_ops_snapshot);
	if (zfsctl_ops_shares)
		vn_freevnodeops(zfsctl_ops_shares);
	if (zfsctl_ops_shares_dir)
		vn_freevnodeops(zfsctl_ops_shares_dir);

	zfsctl_ops_root = NULL;
	zfsctl_ops_snapdir = NULL;
	zfsctl_ops_snapshot = NULL;
	zfsctl_ops_shares = NULL;
	zfsctl_ops_shares_dir = NULL;
#endif	/* sun */
}

/*
 * Check if the given inode is a .zfs/snapshots/snapname directory.
 */
boolean_t
zfsctl_is_node(struct vnode *vp)
{
    if (vnode_tag(vp) == VT_OTHER)
        return B_TRUE;
    return B_FALSE;
}

/*
 * Return the inode number associated with the 'snapshot' or
 * 'shares' directory.
 */
/* ARGSUSED */
static ino64_t
zfsctl_root_inode_cb(struct vnode *vp, int index)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(vnode_mount(vp));

	ASSERT(index <= 2);

	if (index == 0)
		return (ZFSCTL_INO_SNAPDIR);

	return (zfsvfs->z_shares_dir);
}

/*
 * Create the '.zfs' directory.  This directory is cached as part of the VFS
 * structure.  This results in a hold on the vfs_t.  The code in zfs_umount()
 * therefore checks against a vfs_count of 2 instead of 1.  This reference
 * is removed when the ctldir is destroyed in the unmount.
 */
void
zfsctl_create(zfsvfs_t *zfsvfs)
{
	struct vnode *vp = NULL, *rvp = NULL;
	zfsctl_node_t *zcp;
	uint64_t crtime[2];


	ASSERT(zfsvfs->z_ctldir == NULL);

    dprintf("zfsctl_create\n");

    /*
     * This creates a vnode with VROOT set, this is so that unmount's
     * vflush() (called before our vfs_unmount) will pass (and not block
     * waiting for the usercount ref to be released). We then release the
     * VROOT vnode in zfsctl_destroy, and release the usercount ref.
     */

	vp = gfs_root_create(sizeof (zfsctl_node_t), zfsvfs->z_vfs,
                         zfsctl_ops_root_dvnodeops,
                         ZFSCTL_INO_ROOT, zfsctl_root_entries,
	    zfsctl_root_inode_cb, MAXNAMELEN, NULL, NULL);

    zcp = vnode_fsnode(vp);
    zcp->zc_id = ZFSCTL_INO_ROOT;

    VERIFY(VFS_ROOT(zfsvfs->z_vfs, 0, &rvp) == 0);
    VERIFY(0 == sa_lookup(VTOZ(rvp)->z_sa_hdl, SA_ZPL_CRTIME(zfsvfs),
                          &crtime, sizeof (crtime)));
    ZFS_TIME_DECODE(&zcp->zc_cmtime, crtime);
    VN_RELE(rvp);


#ifdef __LINUX__
    /*
     * We're only faking the fact that we have a root of a filesystem for
     * the sake of the GFS interfaces.  Undo the flag manipulation it did
     * for us.
     */
    vp->v_vflag &= ~VV_ROOT;
#endif
    /* In OSX we mark the node VSYSTEM instead */

    zfsvfs->z_ctldir = vp;

    /*
     * Explicitely hold a usecount (not iocount) reference here, so that
     * .zfs is hold until unmount is called
     */
    vnode_ref(zfsvfs->z_ctldir); // Hold an usecount ref

    VN_RELE(zfsvfs->z_ctldir); // release iocount ref(vnode_get/vnode_create)
}


/*
 * Create the '.zfs' directory.  This directory is cached as part of the VFS
 * structure.  This results in a hold on the zfs_sb_t.  The code in zfs_umount()
 * therefore checks against a vfs_count of 2 instead of 1.  This reference
 * is removed when the ctldir is destroyed in the unmount.  All other entities
 * under the '.zfs' directory are created dynamically as needed.
 *
 * Because the dynamically created '.zfs' directory entries assume the use
 * of 64-bit inode numbers this support must be disabled on 32-bit systems.
 */
/* ARGSUSED */
static int
zfsctl_common_open(struct vnop_open_args *ap)
{
	int flags = ap->a_mode;

    dprintf("zfsctl_open: %p on %p\n",
           ap->a_vp, vnode_mountedhere(ap->a_vp));

	if (flags & FWRITE)
        return (EACCES);

	return (0);
}

/*
 * Destroy the '.zfs' directory or remove a snapshot from zfs_snapshots_by_name.
 * Only called when the filesystem is unmounted.
 */
/* ARGSUSED */
static int
zfsctl_common_close(struct vnop_close_args *ap)
{
	if (zsb->z_issnap) {
		zfs_snapentry_t *se;
		uint64_t objsetid = dmu_objset_id(zsb->z_os);

		mutex_enter(&zfs_snapshot_lock);
		if ((se = zfsctl_snapshot_find_by_objsetid(objsetid)) != NULL) {
			zfsctl_snapshot_unmount_cancel(se);
			zfsctl_snapshot_remove(se);
			zfsctl_snapshot_rele(se);
		}
		mutex_exit(&zfs_snapshot_lock);
	} else if (zsb->z_ctldir) {
		iput(zsb->z_ctldir);
		zsb->z_ctldir = NULL;
	}
}



/*
 * Common access routine.  Disallow writes.
 */
/* ARGSUSED */
static int
zfsctl_common_access(ap)
	struct vnop_access_args /* {
		struct vnode *a_vp;
		accmode_t a_accmode;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	int accmode = ap->a_action;
    dprintf("zfsctl_access\n");

#ifdef TODO
	if (flags & V_ACE_MASK) {
		if (accmode & ACE_ALL_WRITE_PERMS)
			return (EACCES);
	} else {
#endif
		if (accmode & VWRITE)
			return (EACCES);
#ifdef TODO
	}
#endif

	return (0);
}

/*
 * Common getattr function.  Fill in basic information.
 */
static void
zfsctl_common_getattr(struct vnode *vp, vattr_t *vap)
{
	timestruc_t	now;

    dprintf("zfsctl: +getattr: %p iocount %d usecount %d\n",
            vp,
            ((uint32_t *)vp)[23],
            ((uint32_t *)vp)[22]);

#ifdef __APPLE__
    VATTR_SET_SUPPORTED(vap, va_mode);
    VATTR_SET_SUPPORTED(vap, va_type);
    VATTR_SET_SUPPORTED(vap, va_uid);
    VATTR_SET_SUPPORTED(vap, va_gid);
    VATTR_SET_SUPPORTED(vap, va_data_size);
    VATTR_SET_SUPPORTED(vap, va_total_size);
    VATTR_SET_SUPPORTED(vap, va_data_alloc);
    VATTR_SET_SUPPORTED(vap, va_total_alloc);
    VATTR_SET_SUPPORTED(vap, va_access_time);
    VATTR_SET_SUPPORTED(vap, va_dirlinkcount);
    VATTR_SET_SUPPORTED(vap, va_flags);
#endif

    vap->va_dirlinkcount = 1; //directory hard links.
    vap->va_nlink = 3;
	vap->va_uid = 0;
	vap->va_gid = 0;
	vap->va_rdev = 0;
	/*
	 * We are a purely virtual object, so we have no
	 * blocksize or allocated blocks.
	 */
    //	vap->va_blksize = 0;
    vap->va_data_alloc = 512;
    vap->va_total_alloc = 512;
    vap->va_data_size = 0;
    vap->va_total_size = 0;
	vap->va_nblocks = 0;
	//vap->va_seq = 0;
	vap->va_gen = 0;

	vap->va_mode = S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP |
	    S_IROTH | S_IXOTH;
	vap->va_type = VDIR;

	if (VATTR_IS_ACTIVE(vap, va_nchildren) && vnode_isdir(vp)) {
		VATTR_RETURN(vap, va_nchildren, vap->va_nlink - 2);
    }
    vap->va_iosize = 512;

	/*
	 * We live in the now (for atime).
	 */
	gethrestime(&now);
	vap->va_atime = now;
	/* FreeBSD: Reset chflags(2) flags. */
	vap->va_flags = 0;

    dprintf("zfsctl: -getattr\n");
}

int
zfsctl_fid(struct inode *ip, fid_t *fidp)
{
	struct vnode		*vp = ap->a_vp;
	fid_t		*fidp = (void *)ap->a_fid;
	zfsvfs_t	*zfsvfs = vfs_fsprivate(vnode_mount(vp));
	zfsctl_node_t	*zcp = vnode_fsnode(vp);
	uint64_t	object = zcp->zc_id;
	zfid_short_t	*zfid;
	int		i;

	ZFS_ENTER(zfsvfs);

	fidp->fid_len = SHORT_FID_LEN;

	zfid = (zfid_short_t *)fidp;

	zfid->zf_len = SHORT_FID_LEN;

	for (i = 0; i < sizeof (zfid->zf_object); i++)
		zfid->zf_object[i] = (uint8_t)(object >> (8 * i));

	/* .zfs znodes always have a generation number of 0 */
	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		zfid->zf_gen[i] = 0;

	ZFS_EXIT(zfsvfs);
	return (0);
}
#endif

/*
 * Construct a full dataset name in full_name: "pool/dataset@snap_name"
 */
static int
zfsctl_snapshot_name(zfs_sb_t *zsb, const char *snap_name, int len,
    char *full_name)
{
	objset_t *os = zsb->z_os;

	if (zfs_component_namecheck(snap_name, NULL, NULL) != 0)
		return (SET_ERROR(EILSEQ));

	dmu_objset_name(os, full_name);
	if ((strlen(full_name) + 1 + strlen(snap_name)) >= len)
		return (SET_ERROR(ENAMETOOLONG));

	(void) strcat(full_name, "@");
	(void) strcat(full_name, snap_name);

	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif

/*
 * Returns full path in full_path: "/pool/dataset/.zfs/snapshot/snap_name/"
 */
static int
zfsctl_snapshot_path(struct path *path, int len, char *full_path)
{
	struct vnode *vp = ap->a_vp;
	gfs_file_t *fp = vnode_fsnode(vp);

    dprintf("zfsctl: +reclaim vp %p mountedon %d\n", vp,
            vnode_mountedhere(vp));

	/*
	 * Destroy the vm object and flush associated pages.
	 */
#ifdef __APPLE__
    /*
     * It would appear that Darwin does not guarantee that vnop_inactive is
     * always called, but reclaim is used instead. All release happens in here
     * and inactive callbacks are mostly empty.
     */
    if (fp) {

        if (fp->gfs_type == GFS_DIR)
            gfs_dir_inactive(vp);
        else
            gfs_file_inactive(vp);

	memcpy(full_path, path_ptr, path_len);
	full_path[path_len] = '\0';
out:
	kmem_free(path_buffer, len);

    }

    vnode_removefsref(vp); /* ADDREF from vnode_create */
    vnode_clearfsnode(vp); /* vp->v_data = NULL */

#else
	vnode_destroy_vobject(vp);
	VI_LOCK(vp);
	vp->v_data = NULL;
	VI_UNLOCK(vp);
#endif

    dprintf("zfsctl: -reclaim vp %p\n", vp);
	return (0);
}

#define	ZFSCTL_INO_SNAP(id)	(id)

/*
 * Get root directory attributes.
 */
/* ARGSUSED */
static int
zfsctl_root_getattr(ap)
	struct vnop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	vattr_t *vap = ap->a_vap;
	zfsvfs_t *zfsvfs = vfs_fsprivate(vnode_mount(vp));
	zfsctl_node_t *zcp = vnode_fsnode(vp);

	ZFS_ENTER(zfsvfs);
#ifdef __APPLE__
    VATTR_SET_SUPPORTED(vap, va_modify_time);
    VATTR_SET_SUPPORTED(vap, va_create_time);
    VATTR_SET_SUPPORTED(vap, va_fsid);
    VATTR_SET_SUPPORTED(vap, va_fileid); // SPL: va_nodeid
    VATTR_CLEAR_SUPPORTED(vap, va_acl);
#endif
    // CALL statvfs to get FSID here
	vap->va_fsid = vfs_statfs(vnode_mount(vp))->f_fsid.val[0];
	vap->va_nodeid = ZFSCTL_INO_ROOT;
	vap->va_nlink = vap->va_size = NROOT_ENTRIES;
	vap->va_mtime = vap->va_ctime = zcp->zc_cmtime;
	vap->va_ctime = vap->va_ctime;

	if (VATTR_IS_ACTIVE(vap, va_name) && vap->va_name) {
        (void)strlcpy(vap->va_name, ".zfs", MAXPATHLEN);
        VATTR_SET_SUPPORTED(vap, va_name);
    }

	zfsctl_common_getattr(vp, vap);

	ZFS_EXIT(zfsvfs);

	return (0);
}

/*
 * Special case the handling of "..".
 */
int
zfsctl_root_lookup(struct vnode *dvp, char *nm, struct vnode **vpp, pathname_t *pnp,
    int flags, struct vnode *rdir, cred_t *cr, caller_context_t *ct,
    int *direntflags, pathname_t *realpnp)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(vnode_mount(dvp));
	int err;

    dprintf("zfsctl_root_lookup dvp %p\n", dvp);

    if (!zfsvfs) return EINVAL;

	/*
	 * No extended attributes allowed under .zfs
	 */
#ifndef __APPLE__
	if (flags & LOOKUP_XATTR)
		return (EINVAL);
#endif

	ZFS_ENTER(zfsvfs);

	if (strcmp(nm, "..") == 0) {
        err = VFS_ROOT(vnode_mount(dvp), LK_EXCLUSIVE, vpp);
#ifdef __FreeBSD__
		if (err == 0) {
			VOP_UNLOCK(*vpp, 0);
        }
#endif
	} else {
		err = gfs_vop_lookup(dvp, nm, vpp, pnp, flags, rdir,
		    cr, ct, direntflags, realpnp);
    }

	ZFS_EXIT(zfsvfs);

	return (err);
}



#ifdef sun
static int
zfsctl_pathconf(struct vnode *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	/*
	 * We only care about ACL_ENABLED so that libsec can
	 * display ACL correctly and not default to POSIX draft.
	 */
	if (cmd == _PC_ACL_ENABLED) {
		*valp = _ACL_ACE_ENABLED;
		return (0);
	}

	return (fs_pathconf(vp, cmd, valp, cr, ct));
}
#endif	/* sun */

#ifdef sun
static const fs_operation_def_t zfsctl_tops_root[] = {
	{ VOPNAME_OPEN,		{ .vop_open = zfsctl_common_open }	},
	{ VOPNAME_CLOSE,	{ .vop_close = zfsctl_common_close }	},
	{ VOPNAME_IOCTL,	{ .error = fs_inval }			},
	{ VOPNAME_GETATTR,	{ .vop_getattr = zfsctl_root_getattr }	},
	{ VOPNAME_ACCESS,	{ .vop_access = zfsctl_common_access }	},
	{ VOPNAME_READDIR,	{ .vop_readdir = gfs_vop_readdir } 	},
	{ VOPNAME_LOOKUP,	{ .vop_lookup = zfsctl_root_lookup }	},
	{ VOPNAME_SEEK,		{ .vop_seek = fs_seek }			},
	{ VOPNAME_INACTIVE,	{ .vop_inactive = gfs_vop_inactive }	},
	{ VOPNAME_PATHCONF,	{ .vop_pathconf = zfsctl_pathconf }	},
	{ VOPNAME_FID,		{ .vop_fid = zfsctl_common_fid	}	},
	{ NULL }
};
#endif	/* sun */

/*
 * Special case the handling of "..".
 */
int
zfsctl_freebsd_root_lookup(ap)
	struct vnop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	cred_t *cr = (cred_t *)vfs_context_ucred((ap)->a_context);
	int flags = ap->a_cnp->cn_flags;
	int nameiop = ap->a_cnp->cn_nameiop;
	char nm[NAME_MAX + 1];
	int err;

    dprintf("zfsctl: +freebsd_root_lookup: nameiop %d\n", nameiop);


	if ((flags & ISLASTCN) && (nameiop == RENAME || nameiop == CREATE)) {
        dprintf("failed\n");
		return (EOPNOTSUPP);
    }

	ASSERT(ap->a_cnp->cn_namelen < sizeof(nm));
	strlcpy(nm, ap->a_cnp->cn_nameptr, ap->a_cnp->cn_namelen + 1);

	err = zfsctl_root_lookup(dvp, nm, vpp, NULL, 0, NULL, cr, NULL, NULL, NULL);

#ifdef __FreeBSD__
	if (err == 0 && (nm[0] != '.' || nm[1] != '\0'))
        vn_lock(*vpp, LK_EXCLUSIVE | LK_RETRY);
#endif

	return (err);
}

#ifdef __FreeBSD__
static struct vop_vector zfsctl_ops_root = {
	.vop_default =	&default_vnodeops,
	.vop_open =	zfsctl_common_open,
	.vop_close =	zfsctl_common_close,
	.vop_ioctl =	VOP_EINVAL,
	.vop_getattr =	zfsctl_root_getattr,
	.vop_access =	zfsctl_common_access,
	.vop_readdir =	gfs_vop_readdir,
	.vop_lookup =	zfsctl_freebsd_root_lookup,
	.vop_inactive =	gfs_vop_inactive,
	.vop_reclaim =	zfsctl_common_reclaim,
#ifdef TODO
	.vop_pathconf =	zfsctl_pathconf,
#endif
	.vop_fid =	zfsctl_common_fid,
};
#endif

#ifdef __APPLE__
#define VOPFUNC int (*)(void *)
#include <vfs/vfs_support.h>
/* Directory vnode operations template */
//int (**zfsctl_ops_root_dvnodeops) (void *);
static struct vnodeopv_entry_desc zfsctl_ops_root_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_open_desc,	(VOPFUNC)zfsctl_common_open},
	{&vnop_close_desc,	(VOPFUNC)zfsctl_common_close},
	//{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_getattr_desc,	(VOPFUNC)zfsctl_root_getattr},
	{&vnop_access_desc,	(VOPFUNC)zfsctl_common_access},
	{&vnop_readdir_desc,	(VOPFUNC)gfs_vop_readdir},
	//{&vnop_readdirattr_desc, (VOPFUNC)zfs_vnop_readdirattr},
	//{&vnop_lookup_desc,	(VOPFUNC)zfsctl_root_lookup},
	{&vnop_lookup_desc,	(VOPFUNC)zfsctl_freebsd_root_lookup},
	{&vnop_inactive_desc,	(VOPFUNC)gfs_vop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfsctl_common_reclaim},

    { &vnop_revoke_desc, (VOPFUNC)err_revoke },             /* revoke */
    { &vnop_fsync_desc, (VOPFUNC)nop_fsync },               /* fsync */

	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfsctl_ops_root =
{ &zfsctl_ops_root_dvnodeops, zfsctl_ops_root_template };

#endif



static int
zfsctl_snapshot_zname(struct vnode *vp, const char *name, int len, char *zname)
{
	objset_t *os = ((zfsvfs_t *)(vfs_fsprivate(vnode_mount(vp))))->z_os;

	if (zfs_component_namecheck(name, NULL, NULL) != 0)
		return (EILSEQ);
	dmu_objset_name(os, zname);
	if (strlen(zname) + 1 + strlen(name) >= len)
		return (ENAMETOOLONG);
	(void) strlcat(zname, "@", len);
	(void) strlcat(zname, name, len);
	return (0);
}

static int
zfsctl_unmount_snap(zfs_snapentry_t *sep, int fflags, cred_t *cr)
{
	struct vnode *svp = sep->se_root;
	int error;
	struct vnop_inactive_args iap;

	ASSERT(vn_ismntpt(svp));

	/* this will be dropped by dounmount() */
	if ((error = vn_vfswlock(svp)) != 0)
		return (error);

#ifdef sun
	VN_HOLD(svp);
	error = dounmount(vn_mountedvfs(svp), fflags, cr);
	if (error) {
		VN_RELE(svp);
		return (error);
	}
#endif

	*ipp = zfsctl_inode_lookup(zsb, ZFSCTL_INO_SNAPDIRS - id,
	    &simple_dir_operations, &simple_dir_inode_operations);
	if (*ipp == NULL)
		error = SET_ERROR(ENOENT);

    dprintf("zfsctldir: Releasing '%s'\n", sep->se_name);
	kmem_free(sep->se_name, strlen(sep->se_name) + 1);
    sep->se_name = NULL;
	kmem_free(sep, sizeof (zfs_snapentry_t));
    sep = NULL;

	return (0);
}

/*
 * Renaming a directory under '.zfs/snapshot' will automatically trigger
 * a rename of the snapshot to the new given name.  The rename is confined
 * to the '.zfs/snapshot' directory snapshots cannot be moved elsewhere.
 */
int
zfsctl_snapdir_rename(struct inode *sdip, char *snm,
    struct inode *tdip, char *tnm, cred_t *cr, int flags)
{
	zfs_sb_t *zsb = ITOZSB(sdip);
	char *to, *from, *real, *fsname;
	int error;

	char from[ZFS_MAX_DATASET_NAME_LEN], to[ZFS_MAX_DATASET_NAME_LEN];
	char real[ZFS_MAX_DATASET_NAME_LEN];
	int err;

	zfsvfs = vfs_fsprivate(vnode_mount(sdvp));
	ZFS_ENTER(zfsvfs);

	if ((flags & FIGNORECASE) || zfsvfs->z_case == ZFS_CASE_INSENSITIVE) {
		err = dmu_snapshot_realname(zfsvfs->z_os, snm, real,
		    sizeof (real), NULL);
		if (err == 0) {
			snm = real;
		} else if (err != ENOTSUP) {
			ZFS_EXIT(zfsvfs);
			return (err);
		}
	}

	ZFS_EXIT(zfsvfs);

	error = zfsctl_snapshot_name(ITOZSB(sdip), snm, MAXNAMELEN, from);
	if (error == 0)
		error = zfsctl_snapshot_name(ITOZSB(tdip), tnm, MAXNAMELEN, to);
	if (error == 0)
		error = zfs_secpolicy_rename_perms(from, to, cr);
	if (error != 0)
		goto out;

	/*
	 * Cannot move snapshots out of the snapdir.
	 */
	if (sdvp != tdvp)
		error = SET_ERROR(EINVAL);
		goto out;
	}

	/*
	 * No-op when names are identical.
	 */
	if (strcmp(snm, tnm) == 0) {
		error = 0;
		goto out;
	}

	mutex_enter(&zfs_snapshot_lock);

	error = dsl_dataset_rename_snapshot(fsname, snm, tnm, B_FALSE);
	if (error == 0)
		(void) zfsctl_snapshot_rename(snm, tnm);

	mutex_exit(&zfs_snapshot_lock);
out:
	kmem_free(from, MAXNAMELEN);
	kmem_free(to, MAXNAMELEN);
	kmem_free(real, MAXNAMELEN);
	kmem_free(fsname, MAXNAMELEN);

	mutex_exit(&sdp->sd_lock);

	return (err);
}
#endif	/* sun */

/*
 * Removing a directory under '.zfs/snapshot' will automatically trigger
 * the removal of the snapshot with the given name.
 */
int
zfsctl_snapdir_remove(struct inode *dip, char *name, cred_t *cr, int flags)
{
	zfsctl_snapdir_t *sdp = vnode_fsnode(dvp);
	zfs_snapentry_t *sep = NULL;
	zfs_snapentry_t search;
	zfsvfs_t *zfsvfs;
	char snapname[ZFS_MAX_DATASET_NAME_LEN];
	char real[ZFS_MAX_DATASET_NAME_LEN];
	int err;

	zfsvfs = vfs_fsprivate(vnode_mount(dvp));
	ZFS_ENTER(zfsvfs);

	if ((flags & FIGNORECASE) || zfsvfs->z_case == ZFS_CASE_INSENSITIVE) {

		err = dmu_snapshot_realname(zfsvfs->z_os, name, real,
		    sizeof (real), NULL);
		if (err == 0) {
			name = real;
		} else if (err != ENOTSUP) {
			ZFS_EXIT(zfsvfs);
			return (err);
		}
	}

	error = zfsctl_snapshot_name(ITOZSB(dip), name, MAXNAMELEN, snapname);
	if (error == 0)
		error = zfs_secpolicy_destroy_perms(snapname, cr);
	if (error != 0)
		goto out;

	error = zfsctl_snapshot_unmount(snapname, MNT_FORCE);
	if ((error == 0) || (error == ENOENT))
		error = dsl_destroy_snapshot(snapname, B_FALSE);
out:
	kmem_free(snapname, MAXNAMELEN);
	kmem_free(real, MAXNAMELEN);

	mutex_enter(&sdp->sd_lock);

	search.se_name = name;
	sep = avl_find(&sdp->sd_snaps, &search, NULL);
	if (sep) {
		avl_remove(&sdp->sd_snaps, sep);
		err = zfsctl_unmount_snap(sep, MS_FORCE, cr);
		if (err) {
			avl_index_t where;

			if (avl_find(&sdp->sd_snaps, sep, &where) == NULL)
				avl_insert(&sdp->sd_snaps, sep, where);
		} else
			err = dmu_objset_destroy(snapname, B_FALSE);
	} else {
		err = ENOENT;
	}

	mutex_exit(&sdp->sd_lock);

	return (err);
}
#endif	/* sun */

/*
 * This creates a snapshot under '.zfs/snapshot'.
 */
int
zfsctl_snapdir_mkdir(struct inode *dip, char *dirname, vattr_t *vap,
	struct inode **ipp, cred_t *cr, int flags)
{
    return ENOTSUP;
#if 0
	zfsvfs_t *zfsvfs = vfs_fsprivate(vnode_mount(dvp));
	char name[MAXNAMELEN];
	int err, error;
	//static enum symfollow follow = NO_FOLLOW;
	static enum uio_seg seg = UIO_SYSSPACE;

	if (snapshot_namecheck(dirname, NULL, NULL) != 0)

	zfs_sb_t *zsb = ITOZSB(dip);
	char *dsname;
	int error;

	dsname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	if (zfs_component_namecheck(dirname, NULL, NULL) != 0) {
		error = SET_ERROR(EILSEQ);
		goto out;
	}

	dmu_objset_name(zfsvfs->z_os, name);

	*vpp = NULL;

	err = zfs_secpolicy_snapshot_perms(name, cr);
	if (err)
		return (err);

	if (err == 0) {
        //		err = dmu_objset_snapshot(name, dirname, NULL, NULL,
        //  B_FALSE, B_FALSE, -1);
		if (err)
			return (err);
        err = zfsctl_snapdir_lookup(dvp, dirname, vpp,
                                    0, cr, NULL, NULL);
	}
out:
	return (err);
#endif
}

static int
zfsctl_freebsd_snapdir_mkdir(ap)
        struct vnop_mkdir_args /* {
                struct vnode *a_dvp;
                struct vnode **a_vpp;
                struct componentname *a_cnp;
                struct vattr *a_vap;
        } */ *ap;
{

//	ASSERT(ap->a_cnp->cn_flags & SAVENAME);
	cred_t *cr = (cred_t *)vfs_context_ucred((ap)->a_context);

	return (zfsctl_snapdir_mkdir(ap->a_dvp, ap->a_cnp->cn_nameptr, NULL,
	    ap->a_vpp, cr, NULL, 0, NULL));
}

static int
zfsctl_snapdir_readdir_cb(struct vnode *vp, void *dp, int *eofp,
     offset_t *offp, offset_t *nextp, void *data, int flags);

/*
 * Attempt to unmount a snapshot by making a call to user space.
 * There is no assurance that this can or will succeed, is just a
 * best effort.  In the case where it does fail, perhaps because
 * it's in use, the unmount will fail harmlessly.
 */
#define	SET_UNMOUNT_CMD \
	"exec 0</dev/null " \
	"     1>/dev/null " \
	"     2>/dev/null; " \
	"umount -t zfs -n %s'%s'"

int
zfsctl_snapshot_unmount(char *snapname, int flags)
{
	char *argv[] = { "/bin/sh", "-c", NULL, NULL };
	char *envp[] = { NULL };
	zfs_snapentry_t *se;
	int error;

	mutex_enter(&zfs_snapshot_lock);
	if ((se = zfsctl_snapshot_find_by_name(snapname)) == NULL) {
		mutex_exit(&zfs_snapshot_lock);
		return (ENOENT);
	}
	mutex_exit(&zfs_snapshot_lock);

	argv[2] = kmem_asprintf(SET_UNMOUNT_CMD,
	    flags & MNT_FORCE ? "-f " : "", se->se_path);
	zfsctl_snapshot_rele(se);
	dprintf("unmount; path=%s\n", se->se_path);
	error = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	strfree(argv[2]);


	/*
	 * If we get a recursive call, that means we got called
	 * from the domount() code while it was trying to look up the
	 * spec (which looks like a local path for zfs).  We need to
	 * add some flag to domount() to tell it not to do this lookup.
	 */
	if (MUTEX_HELD(&sdp->sd_lock))
		return (ENOENT);

	ZFS_ENTER(zfsvfs);

    // Returns if LOCK is held, otherwise we do not hold vpp
	if (gfs_lookup_dot(vpp, dvp, zfsvfs->z_ctldir, nm) == 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	if (flags & FIGNORECASE) {
		boolean_t conflict = B_FALSE;

		err = dmu_snapshot_realname(zfsvfs->z_os, nm, real,
		    MAXNAMELEN, &conflict);
		if (err == 0) {
			strlcpy(nm, real, sizeof(nm));
		} else if (err != ENOTSUP) {
			ZFS_EXIT(zfsvfs);
			return (err);
		}
#if 0
		if (realpnp)
			(void) strlcpy(realpnp->pn_buf, nm,
			    realpnp->pn_bufsize);
		if (conflict && direntflags)
			*direntflags = ED_CASE_CONFLICT;
#endif
	}

	mutex_enter(&sdp->sd_lock);
	search.se_name = (char *)nm;
	if ((sep = avl_find(&sdp->sd_snaps, &search, &where)) != NULL) {
		*vpp = sep->se_root;
		VN_HOLD(*vpp);
		err = traverse(vpp, LK_EXCLUSIVE | LK_RETRY);

		if (err) {
			VN_RELE(*vpp);
			*vpp = NULL;
            dprintf("vnrele\n");
		} else if (*vpp == sep->se_root) {
			/*
			 * The snapshot was unmounted behind our backs,
			 * try to remount it.
			 */
			VERIFY(zfsctl_snapshot_zname(dvp, nm, ZFS_MAX_DATASET_NAME_LEN, snapname) == 0);
            dprintf("goto domount\n");
			goto domount;
		} else {
			/*
			 * VROOT was set during the traverse call.  We need
			 * to clear it since we're pretending to be part
			 * of our parent's vfs.
			 */
			//(*vpp)->v_flag &= ~VROOT;
		}
		mutex_exit(&sdp->sd_lock);
		ZFS_EXIT(zfsvfs);
		return (err);
	}

	return (error);
}
#endif

#define	MOUNT_BUSY 0x80		/* Mount failed due to EBUSY (from mntent.h) */
#define	SET_MOUNT_CMD \
	"exec 0</dev/null " \
	"     1>/dev/null " \
	"     2>/dev/null; " \
	"mount -t zfs -n '%s' '%s'"

int
zfsctl_snapshot_mount(struct path *path, int flags)
{
	struct dentry *dentry = path->dentry;
	struct inode *ip = dentry->d_inode;
	zfs_sb_t *zsb;
	zfs_sb_t *snap_zsb;
	zfs_snapentry_t *se;
	char *full_name, *full_path;
	char *argv[] = { "/bin/sh", "-c", NULL, NULL };
	char *envp[] = { NULL };
	int error;

	if (ip == NULL)
		return (EISDIR);

	zsb = ITOZSB(ip);
	ZFS_ENTER(zsb);

	full_name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
	full_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	error = zfsctl_snapshot_name(zsb, dname(dentry),
	    MAXNAMELEN, full_name);
	if (error)
		goto error;

	error = zfsctl_snapshot_path(path, MAXPATHLEN, full_path);
	if (error)
		goto error;

	/*
	 * Multiple concurrent automounts of a snapshot are never allowed.
	 * The snapshot may be manually mounted as many times as desired.
	 */
	if (zfsctl_snapshot_ismounted(full_name)) {
		error = SET_ERROR(EISDIR);
		goto error;
	}

	/*
	 * Attempt to mount the snapshot from user space.  Normally this
	 * would be done using the vfs_kern_mount() function, however that
	 * function is marked GPL-only and cannot be used.  On error we
	 * careful to log the real error to the console and return EISDIR
	 * to safely abort the automount.  This should be very rare.
	 *
	 * If the user mode helper happens to return EBUSY, a concurrent
	 * mount is already in progress in which case the error is ignored.
	 * Take note that if the program was executed successfully the return
	 * value from call_usermodehelper() will be (exitcode << 8 + signal).
	 */
	dprintf("mount; name=%s path=%s\n", full_name, full_path);
	argv[2] = kmem_asprintf(SET_MOUNT_CMD, full_name, full_path);
	error = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	strfree(argv[2]);
	if (error && !(error & MOUNT_BUSY << 8)) {
		cmn_err(CE_WARN, "Unable to automount %s/%s: %d",
		    full_path, full_name, error);
		error = SET_ERROR(EISDIR);
		goto error;
	}

	/*
	 * Follow down in to the mounted snapshot and set MNT_SHRINKABLE
	 * to identify this as an automounted filesystem.
	 */
	zpl_follow_down_one(path);
	snap_zsb = ITOZSB(path->dentry->d_inode);
	dentry = path->dentry;
	path->mnt->mnt_flags |= MNT_SHRINKABLE;
	zpl_follow_up(path);
	error = 0;

	mutex_enter(&zfs_snapshot_lock);
	se = zfsctl_snapshot_alloc(full_name, full_path,
	    dmu_objset_id(snap_zsb->z_os), dentry);
	zfsctl_snapshot_add(se);
	zfsctl_snapshot_unmount_delay_impl(se, zfs_expire_snapshot);
	mutex_exit(&zfs_snapshot_lock);
error:
	kmem_free(full_name, MAXNAMELEN);
	kmem_free(full_path, MAXPATHLEN);

	if (!locked)
		mutex_exit(&sdp->sd_lock);
	VN_RELE(dvp);

end:
	/*
	 * Dispose of the vnode for the snapshot mount point.
	 * This is safe to do because once this entry has been removed
	 * from the AVL tree, it can't be found again, so cannot become
	 * "active".  If we lookup the same name again we will end up
	 * creating a new vnode.
	 */
	iap.a_vp = vp;
	return (gfs_vop_inactive(&iap));
}

/*
 * Given the objset id of the snapshot return its zfs_sb_t as zsbp.
 */
int
zfsctl_lookup_objset(struct super_block *sb, uint64_t objsetid, zfs_sb_t **zsbp)
{
	zfs_snapentry_t *se;
	int error;

	/*
	 * Verify that the snapshot is mounted then lookup the mounted root
	 * rather than the covered mount point.  This may fail if the
	 * snapshot has just been unmounted by an unrelated user space
	 * process.  This race cannot occur to an expired mount point
	 * because we hold the zfs_snapshot_lock to prevent the race.
	 */
	mutex_enter(&zfs_snapshot_lock);
	if ((se = zfsctl_snapshot_find_by_objsetid(objsetid)) != NULL) {
		*zsbp = ITOZSB(se->se_root_dentry->d_inode);
		ASSERT3U(dmu_objset_id((*zsbp)->z_os), ==, objsetid);
		zfsctl_snapshot_rele(se);
		error = SET_ERROR(0);
	} else {
		error = SET_ERROR(ENOENT);
	}
	mutex_exit(&zfs_snapshot_lock);

	return (error);
}

int
zfsctl_umount_snapshots(vfs_t *vfsp, int fflags, cred_t *cr)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(vfsp);
	struct vnode *dvp;
	zfsctl_snapdir_t *sdp;
	zfs_snapentry_t *sep, *next;
	int error;

    dprintf("unmount_snapshots\n");

	ASSERT(zfsvfs->z_ctldir != NULL);
	error = zfsctl_root_lookup(zfsvfs->z_ctldir, "snapshot", &dvp,
	    NULL, 0, NULL, cr, NULL, NULL, NULL);
	if (error != 0)
		return (error);

	sdp = vnode_fsnode(dvp);
    if (!sdp) return 0;

	mutex_enter(&sdp->sd_lock);

	sep = avl_first(&sdp->sd_snaps);
	while (sep != NULL) {
		next = AVL_NEXT(&sdp->sd_snaps, sep);

		/*
		 * If this snapshot is not mounted, then it must
		 * have just been unmounted by somebody else, and
		 * will be cleaned up by zfsctl_snapdir_inactive().
		 */
		if (vn_ismntpt(sep->se_root)) {
			error = zfsctl_unmount_snap(sep, fflags, cr);
			if (error) {
				avl_index_t where;

				/*
				 * Before reinserting snapshot to the tree,
				 * check if it was actually removed. For example
				 * when snapshot mount point is busy, we will
				 * have an error here, but there will be no need
				 * to reinsert snapshot.
				 */
				if (avl_find(&sdp->sd_snaps, sep, &where) == NULL)
					avl_insert(&sdp->sd_snaps, sep, where);
				break;
			}
		}
		sep = next;
	}

	mutex_exit(&sdp->sd_lock);

/*
 * Initialize the various pieces we'll need to create and manipulate .zfs
 * directories.  Currently this is unused but available.
 */
void
zfsctl_init(void)
{
	avl_create(&zfs_snapshots_by_name, snapentry_compare_by_name,
	    sizeof (zfs_snapentry_t), offsetof(zfs_snapentry_t,
	    se_node_name));
	avl_create(&zfs_snapshots_by_objsetid, snapentry_compare_by_objsetid,
	    sizeof (zfs_snapentry_t), offsetof(zfs_snapentry_t,
	    se_node_objsetid));
	mutex_init(&zfs_snapshot_lock, NULL, MUTEX_DEFAULT, NULL);

	zfs_expire_taskq = taskq_create("z_unmount", 1, defclsyspri,
	    1, 8, TASKQ_PREPOPULATE);
}

/*
 * Cleanup the various pieces we needed for .zfs directories.  In particular
 * ensure the expiry timer is canceled safely.
 */
void
zfsctl_fini(void)
{
	taskq_destroy(zfs_expire_taskq);

	avl_destroy(&zfs_snapshots_by_name);
	avl_destroy(&zfs_snapshots_by_objsetid);
	mutex_destroy(&zfs_snapshot_lock);
}
