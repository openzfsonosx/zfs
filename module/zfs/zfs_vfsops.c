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

#include <sys/types.h>
#include <sys/syslimits.h>
#include <sys/param.h>

#include <sys/systm.h>

#ifndef __APPLE__
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/mntent.h>
#endif /* !__APPLE__ */

#include <sys/mount.h>
#include <sys/vnode.h>

#ifdef __APPLE__
#include <sys/zfs_context.h>
#include <sys/zfs_vfsops.h>
#include <sys/sysctl.h>
//#include <maczfs/kernel/maczfs_kernel.h>
#endif /* __APPLE__ */

#ifndef __APPLE__
#include <sys/cmn_err.h>
#include "fs/fs_subr.h"
#endif /* !__APPLE__ */

#include <sys/zfs_znode.h>
#include <sys/zfs_dir.h>

#ifdef __APPLE__
#include <sys/zfs_ctldir.h>
#include <sys/refcount.h>
#else
#include <sys/zil.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/dsl_prop.h>
#endif /* __APPLE__ */

#include <sys/dsl_dataset.h>
#include <sys/dsl_deleg.h>
#include <sys/spa.h>
#include <sys/zap.h>

#ifndef __APPLE__
#include <sys/varargs.h>
#include <sys/policy.h>
#include <sys/atomic.h>
#include <sys/mkdev.h>
#include <sys/modctl.h>
#include <sys/refstr.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_ctldir.h>
#include <sys/bootconf.h>
#include <sys/sunddi.h>
#include <sys/dnlc.h>
#endif /* !__APPLE__ */

#ifdef __APPLE__

static int  zfs_vfs_init (struct vfsconf *vfsp);
static int  zfs_vfs_start (struct mount *mp, int flags, vfs_context_t context);
static int  zfs_vfs_mount (struct mount *mp, vnode_t *devvp, user_addr_t data, vfs_context_t context);
static int  zfs_vfs_unmount (struct mount *mp, int mntflags, vfs_context_t context);
static int  zfs_vfs_root (struct mount *mp, vnode_t **vpp, vfs_context_t context);
static int  zfs_vfs_vget (struct mount *mp, ino64_t ino, vnode_t **vpp, vfs_context_t context);
static int  zfs_vfs_getattr (struct mount *mp, struct vfs_attr *fsap, vfs_context_t context);
static int  zfs_vfs_setattr (struct mount *mp, struct vfs_attr *fsap, vfs_context_t context);
static int  zfs_vfs_sync (struct mount *mp, int waitfor, vfs_context_t context);
static int  zfs_vfs_fhtovp (struct mount *mp, int fhlen, unsigned char *fhp, vnode_t **vpp, vfs_context_t context);
static int  zfs_vfs_vptofh (vnode_t *vp, int *fhlenp, unsigned char *fhp, vfs_context_t context);
extern int  zfs_vfs_sysctl (int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp,  user_addr_t newp, size_t newlen, vfs_context_t context);
static int  zfs_vfs_quotactl ( struct mount *mp, int cmds, uid_t uid, caddr_t datap, vfs_context_t context);
static void zfs_objset_close(zfsvfs_t *zfsvfs);

int  zfs_module_start(kmod_info_t *ki, void *data);
int  zfs_module_stop(kmod_info_t *ki, void *data);


/*
 * Mac OS X needs a file system modify time
 *
 * We use the mtime of the "com.apple.system.mtime"
 * extended attribute, which is associated with the
 * file system root directory.  This attribute has
 * no associated data.
 */
#define ZFS_MTIME_XATTR		"com.apple.system.mtime"

extern int zfs_obtain_xattr(znode_t *, const char *, mode_t, cred_t *, vnode_t **, int);

/*
 * zfs vfs operations.
 */
static struct vfsops zfs_vfsops_template = {
	zfs_vfs_mount,
	zfs_vfs_start,
	zfs_vfs_unmount,
	zfs_vfs_root,
	zfs_vfs_quotactl,
	zfs_vfs_getattr,
	zfs_vfs_sync,
	zfs_vfs_vget,
	zfs_vfs_fhtovp,
	zfs_vfs_vptofh,
	zfs_vfs_init,
	zfs_vfs_sysctl,
	zfs_vfs_setattr,
	{NULL}
};


extern struct vnodeopv_desc zfs_dvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_fvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_symvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_xdvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_evnodeop_opv_desc;

#define ZFS_VNOP_TBL_CNT	5

static struct vnodeopv_desc *zfs_vnodeop_opv_desc_list[ZFS_VNOP_TBL_CNT] =
{
	&zfs_dvnodeop_opv_desc,
	&zfs_fvnodeop_opv_desc,
	&zfs_symvnodeop_opv_desc,
	&zfs_xdvnodeop_opv_desc,
	&zfs_evnodeop_opv_desc,
};

static vfstable_t zfs_vfsconf;

/*
 * We need to keep a count of active fs's.
 * This is necessary to prevent our kext
 * from being unloaded after a umount -f
 */
SInt32	zfs_active_fs_count = 0;

extern void zfs_ioctl_init(void);
extern void zfs_ioctl_fini(void);


static int
zfs_vfs_sync(struct mount *mp, __unused int waitfor, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X needs a file system modify time
	 *
	 * We use the mtime of the "com.apple.system.mtime"
	 * extended attribute, which is associated with the
	 * file system root directory.
	 *
	 * Here we sync any mtime changes to this attribute.
	 */
	if (zfsvfs->z_mtime_vp != NULL) {
		timestruc_t  mtime;
		znode_t  *zp;
top:
		zp = VTOZ(zfsvfs->z_mtime_vp);
		ZFS_TIME_DECODE(&mtime, zp->z_phys->zp_mtime);
		if (zfsvfs->z_last_mtime_synced < mtime.tv_sec) {
			dmu_tx_t  *tx;
			int  error;

			tx = dmu_tx_create(zfsvfs->z_os);
			dmu_tx_hold_bonus(tx, zp->z_id);
			error = dmu_tx_assign(tx, zfsvfs->z_assign);
			if (error) {
				if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
					dmu_tx_wait(tx);
					dmu_tx_abort(tx);
					goto top;
				}
				dmu_tx_abort(tx);
			} else {
				dmu_buf_will_dirty(zp->z_dbuf, tx);
				dmu_tx_commit(tx);
				zfsvfs->z_last_mtime_synced = mtime.tv_sec;
			}
		}
	}

	if (zfsvfs->z_log != NULL)
		zil_commit(zfsvfs->z_log, 0);
	else
		txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
	ZFS_EXIT(zfsvfs);

	return (0);
}

#else

int zfsfstype;
vfsops_t *zfs_vfsops = NULL;
static major_t zfs_major;
static minor_t zfs_minor;
static kmutex_t	zfs_dev_mtx;

static int zfs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr);
static int zfs_umount(vfs_t *vfsp, int fflag, cred_t *cr);
static int zfs_mountroot(vfs_t *vfsp, enum whymountroot);
static int zfs_root(vfs_t *vfsp, vnode_t **vpp);
static int zfs_statvfs(vfs_t *vfsp, struct statvfs64 *statp);
static int zfs_vget(vfs_t *vfsp, vnode_t **vpp, fid_t *fidp);
static void zfs_freevfs(vfs_t *vfsp);

static const fs_operation_def_t zfs_vfsops_template[] = {
	VFSNAME_MOUNT,		{ .vfs_mount = zfs_mount },
	VFSNAME_MOUNTROOT,	{ .vfs_mountroot = zfs_mountroot },
	VFSNAME_UNMOUNT,	{ .vfs_unmount = zfs_umount },
	VFSNAME_ROOT,		{ .vfs_root = zfs_root },
	VFSNAME_STATVFS,	{ .vfs_statvfs = zfs_statvfs },
	VFSNAME_SYNC,		{ .vfs_sync = zfs_sync },
	VFSNAME_VGET,		{ .vfs_vget = zfs_vget },
	VFSNAME_FREEVFS,	{ .vfs_freevfs = zfs_freevfs },
	NULL,			NULL
};

static const fs_operation_def_t zfs_vfsops_eio_template[] = {
	VFSNAME_FREEVFS,	{ .vfs_freevfs =  zfs_freevfs },
	NULL,			NULL
};

/*
 * We need to keep a count of active fs's.
 * This is necessary to prevent our module
 * from being unloaded after a umount -f
 */
static uint32_t	zfs_active_fs_count = 0;

static char *noatime_cancel[] = { MNTOPT_ATIME, NULL };
static char *atime_cancel[] = { MNTOPT_NOATIME, NULL };
static char *noxattr_cancel[] = { MNTOPT_XATTR, NULL };
static char *xattr_cancel[] = { MNTOPT_NOXATTR, NULL };

/*
 * MO_DEFAULT is not used since the default value is determined
 * by the equivalent property.
 */
static mntopt_t mntopts[] = {
	{ MNTOPT_NOXATTR, noxattr_cancel, NULL, 0, NULL },
	{ MNTOPT_XATTR, xattr_cancel, NULL, 0, NULL },
	{ MNTOPT_NOATIME, noatime_cancel, NULL, 0, NULL },
	{ MNTOPT_ATIME, atime_cancel, NULL, 0, NULL }
};

static mntopts_t zfs_mntopts = {
	sizeof (mntopts) / sizeof (mntopt_t),
	mntopts
};

/*ARGSUSED*/
int
zfs_sync(vfs_t *vfsp, short flag, cred_t *cr)
{
	/*
	 * Data integrity is job one.  We don't want a compromised kernel
	 * writing to the storage pool, so we never sync during panic.
	 */
	if (panicstr)
		return (0);

	/*
	 * SYNC_ATTR is used by fsflush() to force old filesystems like UFS
	 * to sync metadata, which they would otherwise cache indefinitely.
	 * Semantically, the only requirement is that the sync be initiated.
	 * The DMU syncs out txgs frequently, so there's nothing to do.
	 */
	if (flag & SYNC_ATTR)
		return (0);

	if (vfsp != NULL) {
		/*
		 * Sync a specific filesystem.
		 */
		zfsvfs_t *zfsvfs = vfsp->vfs_data;

		ZFS_ENTER(zfsvfs);
		if (zfsvfs->z_log != NULL)
			zil_commit(zfsvfs->z_log, 0);
		else
			txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
		ZFS_EXIT(zfsvfs);
	} else {
		/*
		 * Sync all ZFS filesystems.  This is what happens when you
		 * run sync(1M).  Unlike other filesystems, ZFS honors the
		 * request by waiting for all pools to commit all dirty data.
		 */
		spa_sync_allpools();
	}

	return (0);
}

static int
zfs_create_unique_device(dev_t *dev)
{
	major_t new_major;

	do {
		ASSERT3U(zfs_minor, <=, MAXMIN32);
		minor_t start = zfs_minor;
		do {
			mutex_enter(&zfs_dev_mtx);
			if (zfs_minor >= MAXMIN32) {
				/*
				 * If we're still using the real major
				 * keep out of /dev/zfs and /dev/zvol minor
				 * number space.  If we're using a getudev()'ed
				 * major number, we can use all of its minors.
				 */
				if (zfs_major == ddi_name_to_major(ZFS_DRIVER))
					zfs_minor = ZFS_MIN_MINOR;
				else
					zfs_minor = 0;
			} else {
				zfs_minor++;
			}
			*dev = makedevice(zfs_major, zfs_minor);
			mutex_exit(&zfs_dev_mtx);
		} while (vfs_devismounted(*dev) && zfs_minor != start);
		if (zfs_minor == start) {
			/*
			 * We are using all ~262,000 minor numbers for the
			 * current major number.  Create a new major number.
			 */
			if ((new_major = getudev()) == (major_t)-1) {
				cmn_err(CE_WARN,
				    "zfs_mount: Can't get unique major "
				    "device number.");
				return (-1);
			}
			mutex_enter(&zfs_dev_mtx);
			zfs_major = new_major;
			zfs_minor = 0;

			mutex_exit(&zfs_dev_mtx);
		} else {
			break;
		}
		/* CONSTANTCONDITION */
	} while (1);

	return (0);
}

static void
atime_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	if (newval == TRUE) {
		zfsvfs->z_atime = TRUE;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_NOATIME);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_ATIME, NULL, 0);
	} else {
		zfsvfs->z_atime = FALSE;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_ATIME);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_NOATIME, NULL, 0);
	}
}

static void
xattr_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	if (newval == TRUE) {
		/* XXX locking on vfs_flag? */
		zfsvfs->z_vfs->vfs_flag |= VFS_XATTR;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_NOXATTR);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_XATTR, NULL, 0);
	} else {
		/* XXX locking on vfs_flag? */
		zfsvfs->z_vfs->vfs_flag &= ~VFS_XATTR;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_XATTR);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_NOXATTR, NULL, 0);
	}
}

static void
blksz_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	if (newval < SPA_MINBLOCKSIZE ||
	    newval > SPA_MAXBLOCKSIZE || !ISP2(newval))
		newval = SPA_MAXBLOCKSIZE;

	zfsvfs->z_max_blksz = newval;
	zfsvfs->z_vfs->vfs_bsize = newval;
}

static void
readonly_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	if (newval) {
		/* XXX locking on vfs_flag? */
		zfsvfs->z_vfs->vfs_flag |= VFS_RDONLY;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_RW);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_RO, NULL, 0);
	} else {
		/* XXX locking on vfs_flag? */
		zfsvfs->z_vfs->vfs_flag &= ~VFS_RDONLY;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_RO);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_RW, NULL, 0);
	}
}

static void
devices_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	if (newval == FALSE) {
		zfsvfs->z_vfs->vfs_flag |= VFS_NODEVICES;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_DEVICES);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_NODEVICES, NULL, 0);
	} else {
		zfsvfs->z_vfs->vfs_flag &= ~VFS_NODEVICES;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_NODEVICES);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_DEVICES, NULL, 0);
	}
}

static void
setuid_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	if (newval == FALSE) {
		zfsvfs->z_vfs->vfs_flag |= VFS_NOSETUID;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_SETUID);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_NOSETUID, NULL, 0);
	} else {
		zfsvfs->z_vfs->vfs_flag &= ~VFS_NOSETUID;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_NOSETUID);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_SETUID, NULL, 0);
	}
}

static void
exec_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	if (newval == FALSE) {
		zfsvfs->z_vfs->vfs_flag |= VFS_NOEXEC;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_EXEC);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_NOEXEC, NULL, 0);
	} else {
		zfsvfs->z_vfs->vfs_flag &= ~VFS_NOEXEC;
		vfs_clearmntopt(zfsvfs->z_vfs, MNTOPT_NOEXEC);
		vfs_setmntopt(zfsvfs->z_vfs, MNTOPT_EXEC, NULL, 0);
	}
}

static void
snapdir_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	zfsvfs->z_show_ctldir = newval;
}

static void
acl_mode_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	zfsvfs->z_acl_mode = newval;
}

static void
acl_inherit_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	zfsvfs->z_acl_inherit = newval;
}

static int
zfs_register_callbacks(vfs_t *vfsp)
{
	struct dsl_dataset *ds = NULL;
	objset_t *os = NULL;
	zfsvfs_t *zfsvfs = NULL;
	int readonly, do_readonly = FALSE;
	int setuid, do_setuid = FALSE;
	int exec, do_exec = FALSE;
	int devices, do_devices = FALSE;
	int xattr, do_xattr = FALSE;
	int atime, do_atime = FALSE;
	int error = 0;

	ASSERT(vfsp);
	zfsvfs = vfsp->vfs_data;
	ASSERT(zfsvfs);
	os = zfsvfs->z_os;

	/*
	 * The act of registering our callbacks will destroy any mount
	 * options we may have.  In order to enable temporary overrides
	 * of mount options, we stash away the current values and
	 * restore them after we register the callbacks.
	 */
	if (vfs_optionisset(vfsp, MNTOPT_RO, NULL)) {
		readonly = B_TRUE;
		do_readonly = B_TRUE;
	} else if (vfs_optionisset(vfsp, MNTOPT_RW, NULL)) {
		readonly = B_FALSE;
		do_readonly = B_TRUE;
	}
	if (vfs_optionisset(vfsp, MNTOPT_NOSUID, NULL)) {
		devices = B_FALSE;
		setuid = B_FALSE;
		do_devices = B_TRUE;
		do_setuid = B_TRUE;
	} else {
		if (vfs_optionisset(vfsp, MNTOPT_NODEVICES, NULL)) {
			devices = B_FALSE;
			do_devices = B_TRUE;
		} else if (vfs_optionisset(vfsp, MNTOPT_DEVICES, NULL)) {
			devices = B_TRUE;
			do_devices = B_TRUE;
		}

		if (vfs_optionisset(vfsp, MNTOPT_NOSETUID, NULL)) {
			setuid = B_FALSE;
			do_setuid = B_TRUE;
		} else if (vfs_optionisset(vfsp, MNTOPT_SETUID, NULL)) {
			setuid = B_TRUE;
			do_setuid = B_TRUE;
		}
	}
	if (vfs_optionisset(vfsp, MNTOPT_NOEXEC, NULL)) {
		exec = B_FALSE;
		do_exec = B_TRUE;
	} else if (vfs_optionisset(vfsp, MNTOPT_EXEC, NULL)) {
		exec = B_TRUE;
		do_exec = B_TRUE;
	}
	if (vfs_optionisset(vfsp, MNTOPT_NOXATTR, NULL)) {
		xattr = B_FALSE;
		do_xattr = B_TRUE;
	} else if (vfs_optionisset(vfsp, MNTOPT_XATTR, NULL)) {
		xattr = B_TRUE;
		do_xattr = B_TRUE;
	}
	if (vfs_optionisset(vfsp, MNTOPT_NOATIME, NULL)) {
		atime = B_FALSE;
		do_atime = B_TRUE;
	} else if (vfs_optionisset(vfsp, MNTOPT_ATIME, NULL)) {
		atime = B_TRUE;
		do_atime = B_TRUE;
	}

	/*
	 * Register property callbacks.
	 *
	 * It would probably be fine to just check for i/o error from
	 * the first prop_register(), but I guess I like to go
	 * overboard...
	 */
	ds = dmu_objset_ds(os);
	error = dsl_prop_register(ds, "atime", atime_changed_cb, zfsvfs);
	error = error ? error : dsl_prop_register(ds,
	    "xattr", xattr_changed_cb, zfsvfs);
	error = error ? error : dsl_prop_register(ds,
	    "recordsize", blksz_changed_cb, zfsvfs);
	error = error ? error : dsl_prop_register(ds,
	    "readonly", readonly_changed_cb, zfsvfs);
	error = error ? error : dsl_prop_register(ds,
	    "devices", devices_changed_cb, zfsvfs);
	error = error ? error : dsl_prop_register(ds,
	    "setuid", setuid_changed_cb, zfsvfs);
	error = error ? error : dsl_prop_register(ds,
	    "exec", exec_changed_cb, zfsvfs);
	error = error ? error : dsl_prop_register(ds,
	    "snapdir", snapdir_changed_cb, zfsvfs);
	error = error ? error : dsl_prop_register(ds,
	    "aclmode", acl_mode_changed_cb, zfsvfs);
	error = error ? error : dsl_prop_register(ds,
	    "aclinherit", acl_inherit_changed_cb, zfsvfs);
	if (error)
		goto unregister;

	/*
	 * Invoke our callbacks to restore temporary mount options.
	 */
	if (do_readonly)
		readonly_changed_cb(zfsvfs, readonly);
	if (do_setuid)
		setuid_changed_cb(zfsvfs, setuid);
	if (do_exec)
		exec_changed_cb(zfsvfs, exec);
	if (do_devices)
		devices_changed_cb(zfsvfs, devices);
	if (do_xattr)
		xattr_changed_cb(zfsvfs, xattr);
	if (do_atime)
		atime_changed_cb(zfsvfs, atime);

	return (0);

unregister:
	/*
	 * We may attempt to unregister some callbacks that are not
	 * registered, but this is OK; it will simply return ENOMSG,
	 * which we will ignore.
	 */
	(void) dsl_prop_unregister(ds, "atime", atime_changed_cb, zfsvfs);
	(void) dsl_prop_unregister(ds, "xattr", xattr_changed_cb, zfsvfs);
	(void) dsl_prop_unregister(ds, "recordsize", blksz_changed_cb, zfsvfs);
	(void) dsl_prop_unregister(ds, "readonly", readonly_changed_cb, zfsvfs);
	(void) dsl_prop_unregister(ds, "devices", devices_changed_cb, zfsvfs);
	(void) dsl_prop_unregister(ds, "setuid", setuid_changed_cb, zfsvfs);
	(void) dsl_prop_unregister(ds, "exec", exec_changed_cb, zfsvfs);
	(void) dsl_prop_unregister(ds, "snapdir", snapdir_changed_cb, zfsvfs);
	(void) dsl_prop_unregister(ds, "aclmode", acl_mode_changed_cb, zfsvfs);
	(void) dsl_prop_unregister(ds, "aclinherit", acl_inherit_changed_cb,
	    zfsvfs);
	return (error);

}

#endif /* __APPLE__ */

static int
#ifdef __APPLE__
zfs_domount(struct mount *vfsp, dev_t mount_dev, char *osname, vfs_context_t ctx)
#else
zfs_domount(vfs_t *vfsp, char *osname, cred_t *cr)
#endif
{
#ifndef __APPLE__
	dev_t mount_dev;
	uint64_t recordsize;
#endif
	uint64_t readonly;
	int error = 0;
	int mode;
	zfsvfs_t *zfsvfs;
	znode_t *zp = NULL;
#ifdef __APPLE__
	struct timeval tv;
#endif
	ASSERT(vfsp);
	ASSERT(osname);

    printf("vfsops: domount\n");

	/*
	 * Initialize the zfs-specific filesystem structure.
	 * Should probably make this a kmem cache, shuffle fields,
	 * and just bzero up to z_hold_mtx[].
	 */
	zfsvfs = kmem_zalloc(sizeof (zfsvfs_t), KM_SLEEP);
	zfsvfs->z_vfs = vfsp;
	zfsvfs->z_parent = zfsvfs;
	zfsvfs->z_assign = TXG_NOWAIT;
	zfsvfs->z_max_blksz = SPA_MAXBLOCKSIZE;
	zfsvfs->z_show_ctldir = ZFS_SNAPDIR_VISIBLE;

	mutex_init(&zfsvfs->z_znodes_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zfsvfs->z_all_znodes, sizeof (znode_t),
	    offsetof(znode_t, z_link_node));
	rw_init(&zfsvfs->z_unmount_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zfsvfs->z_unmount_inactive_lock, NULL, RW_DEFAULT, NULL);
#ifdef __APPLE__
	vfs_setfsprivate(vfsp, zfsvfs);
#else
	/* Initialize the generic filesystem structure. */
	vfsp->vfs_bcount = 0;
	vfsp->vfs_data = NULL;

	if (zfs_create_unique_device(&mount_dev) == -1) {
		error = ENODEV;
		goto out;
	}
	ASSERT(vfs_devismounted(mount_dev) == 0);

	if (error = dsl_prop_get_integer(osname, "recordsize", &recordsize,
	    NULL))
		goto out;

	vfsp->vfs_dev = mount_dev;
	vfsp->vfs_fstype = zfsfstype;
	vfsp->vfs_bsize = recordsize;
	vfsp->vfs_flag |= VFS_NOTRUNC;
	vfsp->vfs_data = zfsvfs;
#endif /* __APPLE__ */

	if (error = dsl_prop_get_integer(osname, "readonly", &readonly, NULL))
		goto out;

	if (readonly)
	{
		mode = DS_MODE_PRIMARY | DS_MODE_READONLY;
#ifdef __APPLE__
		vfs_setflags(vfsp, (u_int64_t)((unsigned int)MNT_RDONLY));
#endif
	}
	else
		mode = DS_MODE_PRIMARY;

	//error = dmu_objset_open(osname, DMU_OST_ZFS, mode, &zfsvfs->z_os);
	error = dmu_objset_own(osname, DMU_OST_ZFS,
                           readonly ? B_TRUE : B_FALSE, &zfsvfs, &zfsvfs->z_os);
    printf("dmu_objset_own: %d\n", error);
	if (error == EROFS) {
		mode = DS_MODE_PRIMARY | DS_MODE_READONLY;
        error = dmu_objset_own(osname, DMU_OST_ZFS,
                               B_TRUE, &zfsvfs, &zfsvfs->z_os);
		//error = dmu_objset_open(osname, DMU_OST_ZFS, mode,
        //   &zfsvfs->z_os);
	}

	if (error)
		goto out;

    printf("domount z_os %p\n", zfsvfs->z_os);

#ifdef __APPLE__
	if (error = zfs_init_fs(zfsvfs, &zp, vfs_context_ucred(ctx)))
		goto out;

    printf("domount 1\n");
	/* The call to zfs_init_fs leaves the vnode held, release it here. */
	vnode_put(ZTOV(zp));
#else
	if (error = zfs_init_fs(zfsvfs, &zp, cr))
		goto out;

	/* The call to zfs_init_fs leaves the vnode held, release it here. */
	VN_RELE(ZTOV(zp));
#endif /* __APPLE__ */

    printf("domount 2\n");

	if (dmu_objset_is_snapshot(zfsvfs->z_os)) {
		uint64_t xattr;

		ASSERT(mode & DS_MODE_READONLY);
#if 0
		atime_changed_cb(zfsvfs, B_FALSE);
		readonly_changed_cb(zfsvfs, B_TRUE);
		if (error = dsl_prop_get_integer(osname, "xattr", &xattr, NULL))
			goto out;
		xattr_changed_cb(zfsvfs, xattr);
#endif
		zfsvfs->z_issnap = B_TRUE;
	} else {
#ifdef __APPLE__
		if (!vfs_isrdonly(vfsp))
			zfs_unlinked_drain(zfsvfs);
        printf("domount 3\n");
        zfsvfs->z_log = zil_open(zfsvfs->z_os, zfs_get_data);
#else
		uint_t readonly;
		error = zfs_register_callbacks(vfsp);
		if (error)
			goto out;

		/*
		 * During replay we remove the read only flag to
		 * allow replays to succeed.
		 */
		readonly = zfsvfs->z_vfs->vfs_flag & VFS_RDONLY;
		if (readonly != 0)
			zfsvfs->z_vfs->vfs_flag &= ~VFS_RDONLY;
		else
			zfs_unlinked_drain(zfsvfs);

		/*
		 * Parse and replay the intent log.
		 *
		 * Because of ziltest, this must be done after
		 * zfs_unlinked_drain().  (Further note: ziltest doesn't
		 * use readonly mounts, where zfs_unlinked_drain() isn't
		 * called.)  This is because ziltest causes spa_sync()
		 * to think it's committed, but actually it is not, so
		 * the intent log contains many txg's worth of changes.
		 *
		 * In particular, if object N is in the unlinked set in
		 * the last txg to actually sync, then it could be
		 * actually freed in a later txg and then reallocated in
		 * a yet later txg.  This would write a "create object
		 * N" record to the intent log.  Normally, this would be
		 * fine because the spa_sync() would have written out
		 * the fact that object N is free, before we could write
		 * the "create object N" intent log record.
		 *
		 * But when we are in ziltest mode, we advance the "open
		 * txg" without actually spa_sync()-ing the changes to
		 * disk.  So we would see that object N is still
		 * allocated and in the unlinked set, and there is an
		 * intent log record saying to allocate it.
		 */
		zil_replay(zfsvfs->z_os, zfsvfs, &zfsvfs->z_assign,
		    zfs_replay_vector);

		zfsvfs->z_vfs->vfs_flag |= readonly; /* restore readonly bit */

		if (!zil_disable)
			zfsvfs->z_log = zil_open(zfsvfs->z_os, zfs_get_data);
#endif /* __APPLE__ */
	}

#if 0
	if (!zfsvfs->z_issnap)
		zfsctl_create(zfsvfs);
#endif

	/*
	 * Record the mount time (for Spotlight)
	 */
	microtime(&tv);
	zfsvfs->z_mount_time = tv.tv_sec;

out:
    printf("domount out %d\n", error);
	if (error) {
		if (zfsvfs->z_os)
            //		dmu_objset_close(zfsvfs->z_os);
            dmu_objset_disown(zfsvfs->z_os, NULL);

		mutex_destroy(&zfsvfs->z_znodes_lock);
		list_destroy(&zfsvfs->z_all_znodes);
		rw_destroy(&zfsvfs->z_unmount_lock);
		rw_destroy(&zfsvfs->z_unmount_inactive_lock);
		kmem_free(zfsvfs, sizeof (zfsvfs_t));
	} else {
#ifdef __APPLE__
		atomic_inc_32(&zfs_active_fs_count);
		(void) copystr(osname, vfs_statfs(vfsp)->f_mntfromname, MNAMELEN - 1, 0);
		vfs_getnewfsid(vfsp);
#else
                atomic_add_32(&zfs_active_fs_count, 1);
#endif /* __APPLE__ */
	}

	return (error);

}

#ifndef __APPLE__
void
zfs_unregister_callbacks(zfsvfs_t *zfsvfs)
{
	objset_t *os = zfsvfs->z_os;
	struct dsl_dataset *ds;

	/*
	 * Unregister properties.
	 */
	if (!dmu_objset_is_snapshot(os)) {
		ds = dmu_objset_ds(os);
		VERIFY(dsl_prop_unregister(ds, "atime", atime_changed_cb,
		    zfsvfs) == 0);

		VERIFY(dsl_prop_unregister(ds, "xattr", xattr_changed_cb,
		    zfsvfs) == 0);

		VERIFY(dsl_prop_unregister(ds, "recordsize", blksz_changed_cb,
		    zfsvfs) == 0);

		VERIFY(dsl_prop_unregister(ds, "readonly", readonly_changed_cb,
		    zfsvfs) == 0);

		VERIFY(dsl_prop_unregister(ds, "devices", devices_changed_cb,
		    zfsvfs) == 0);

		VERIFY(dsl_prop_unregister(ds, "setuid", setuid_changed_cb,
		    zfsvfs) == 0);

		VERIFY(dsl_prop_unregister(ds, "exec", exec_changed_cb,
		    zfsvfs) == 0);

		VERIFY(dsl_prop_unregister(ds, "snapdir", snapdir_changed_cb,
		    zfsvfs) == 0);

		VERIFY(dsl_prop_unregister(ds, "aclmode", acl_mode_changed_cb,
		    zfsvfs) == 0);

		VERIFY(dsl_prop_unregister(ds, "aclinherit",
		    acl_inherit_changed_cb, zfsvfs) == 0);
	}
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/*
 * Convert a decimal digit string to a uint64_t integer.
 */
static int
str_to_uint64(char *str, uint64_t *objnum)
{
	uint64_t num = 0;

	while (*str) {
		if (*str < '0' || *str > '9')
			return (EINVAL);

		num = num*10 + *str++ - '0';
	}

	*objnum = num;
	return (0);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/*
 * The boot path passed from the boot loader is in the form of
 * "rootpool-name/root-filesystem-object-number'. Convert this
 * string to a dataset name: "rootpool-name/root-filesystem-name".
 */
static int
parse_bootpath(char *bpath, char *outpath)
{
	char *slashp;
	uint64_t objnum;
	int error;

	if (*bpath == 0 || *bpath == '/')
		return (EINVAL);

	slashp = strchr(bpath, '/');

	/* if no '/', just return the pool name */
	if (slashp == NULL) {
		(void) strcpy(outpath, bpath);
		return (0);
	}

	if (error = str_to_uint64(slashp+1, &objnum))
		return (error);

	*slashp = '\0';
	error = dsl_dsobj_to_dsname(bpath, objnum, outpath);
	*slashp = '/';

	return (error);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
static int
zfs_mountroot(vfs_t *vfsp, enum whymountroot why)
{
	int error = 0;
	int ret = 0;
	static int zfsrootdone = 0;
	zfsvfs_t *zfsvfs = NULL;
	znode_t *zp = NULL;
	vnode_t *vp = NULL;
	char *zfs_bootpath;

	ASSERT(vfsp);

	/*
	 * The filesystem that we mount as root is defined in the
	 * "zfs-bootfs" property.
	 */
	if (why == ROOT_INIT) {
		if (zfsrootdone++)
			return (EBUSY);

		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
		    DDI_PROP_DONTPASS, "zfs-bootfs", &zfs_bootpath) !=
		    DDI_SUCCESS)
			return (EIO);

		error = parse_bootpath(zfs_bootpath, rootfs.bo_name);
		ddi_prop_free(zfs_bootpath);

		if (error)
			return (error);

		if (error = vfs_lock(vfsp))
			return (error);

		if (error = zfs_domount(vfsp, rootfs.bo_name, CRED()))
			goto out;

		zfsvfs = (zfsvfs_t *)vfsp->vfs_data;
		ASSERT(zfsvfs);
		if (error = zfs_zget(zfsvfs, zfsvfs->z_root, &zp))
			goto out;

		vp = ZTOV(zp);
		mutex_enter(&vp->v_lock);
		vp->v_flag |= VROOT;
		mutex_exit(&vp->v_lock);
		rootvp = vp;

		/*
		 * The zfs_zget call above returns with a hold on vp, we release
		 * it here.
		 */
		VN_RELE(vp);

		/*
		 * Mount root as readonly initially, it will be remouted
		 * read/write by /lib/svc/method/fs-usr.
		 */
		readonly_changed_cb(vfsp->vfs_data, B_TRUE);
		vfs_add((struct vnode *)0, vfsp,
		    (vfsp->vfs_flag & VFS_RDONLY) ? MS_RDONLY : 0);
out:
		vfs_unlock(vfsp);
		ret = (error) ? error : 0;
		return (ret);
	} else if (why == ROOT_REMOUNT) {
		readonly_changed_cb(vfsp->vfs_data, B_FALSE);
		vfsp->vfs_flag |= VFS_REMOUNT;

		/* refresh mount options */
		zfs_unregister_callbacks(vfsp->vfs_data);
		return (zfs_register_callbacks(vfsp));

	} else if (why == ROOT_UNMOUNT) {
		zfs_unregister_callbacks((zfsvfs_t *)vfsp->vfs_data);
		(void) zfs_sync(vfsp, 0, 0);
		return (0);
	}

	/*
	 * if "why" is equal to anything else other than ROOT_INIT,
	 * ROOT_REMOUNT, or ROOT_UNMOUNT, we do not support it.
	 */
	return (ENOTSUP);
}
#endif /* !__APPLE__ */

/*ARGSUSED*/
static int
#ifdef __APPLE__
zfs_vfs_mount(struct mount *mp, vnode_t *devvp, user_addr_t data, vfs_context_t context)
#else
zfs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
#endif
{
	char		*osname = { '\0' };
	int		error = 0;
	int		canwrite;
#ifdef __APPLE__
	size_t		osnamelen = 0;
#else
	pathname_t	spn;
	uio_seg_t	fromspace = (uap->flags & MS_SYSSPACE) ?
	    UIO_SYSSPACE : UIO_USERSPACE;
#endif /* __APPLE__ */

    printf("vfsops: vfs_mount\n");

#ifdef __APPLE__
        /*
         * Get the objset name (the "special" mount argument).
         */
        if (data) {
		// 10a286 renames fspec to datasetpath
                user_addr_t fspec = USER_ADDR_NULL;
                osname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

                if (vfs_context_is64bit(context)) {
                        if ( (error = copyin(data, (caddr_t)&fspec, sizeof(fspec))) )
                                goto out;
                } else {
                        user32_addr_t tmp;
                        if ( (error = copyin(data, (caddr_t)&tmp, sizeof(tmp))) )
                                goto out;
                        /* munge into LP64 addr */
                        fspec = CAST_USER_ADDR_T(tmp);
                }
                if ( (error = copyinstr(fspec, osname, MAXPATHLEN, &osnamelen)) )
                        goto out;
        }
#else /* OpenSolaris */
	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_REMOUNT) == 0 &&
	    (uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * ZFS does not support passing unparsed data in via MS_DATA.
	 * Users should use the MS_OPTIONSTR interface; this means
	 * that all option parsing is already done and the options struct
	 * can be interrogated.
	 */
	if ((uap->flags & MS_DATA) && uap->datalen > 0)
		return (EINVAL);

	/*
	 * Get the objset name (the "special" mount argument).
	 */
	if (error = pn_get(uap->spec, fromspace, &spn))
		return (error);

	osname = spn.pn_path;

	/*
	 * Check for mount privilege?
	 *
	 * If we don't have privilege then see if
	 * we have local permission to allow it
	 */
	error = secpolicy_fs_mount(cr, mvp, vfsp);
	if (error) {
		error = dsl_deleg_access(osname, ZFS_DELEG_PERM_MOUNT, cr);
		if (error == 0) {
			vattr_t		vattr;

			/*
			 * Make sure user is the owner of the mount point
			 * or has sufficient privileges.
			 */

			vattr.va_mask = AT_UID;

			if (error = VOP_GETATTR(mvp, &vattr, 0, cr)) {
				goto out;
			}

			if (error = secpolicy_vnode_owner(cr, vattr.va_uid)) {
				goto out;
			}

			if (error = VOP_ACCESS(mvp, VWRITE, 0, cr)) {
				goto out;
			}

			secpolicy_fs_mount_clearopts(cr, vfsp);
		} else {
			goto out;
		}
	}

	/*
	 * Refuse to mount a filesystem if we are in a local zone and the
	 * dataset is not visible.
	 */
	if (!INGLOBALZONE(curproc) &&
	    (!zone_dataset_visible(osname, &canwrite) || !canwrite)) {
		error = EPERM;
		goto out;
	}

	/*
	 * When doing a remount, we simply refresh our temporary properties
	 * according to those options set in the current VFS options.
	 */
	if (uap->flags & MS_REMOUNT) {
		/* refresh mount options */
		zfs_unregister_callbacks(vfsp->vfs_data);
		error = zfs_register_callbacks(vfsp);
		goto out;
	}
#endif /* __APPLE__ */

#ifdef __APPLE__
	error = zfs_domount(mp, 0, osname, context);
#else
	error = zfs_domount(vfsp, osname, cr);
#endif /* __APPLE__ */

#ifdef __APPLE__
	if (error)
		printf("zfs_vfs_mount: error %d\n", error);
	if (error == 0) {
		zfsvfs_t *zfsvfs = NULL;

		/* Make the Finder treat sub file systems just like a folder */
		if (strpbrk(osname, "/"))
			vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_DONTBROWSE));

		/* Indicate to VFS that we support ACLs. */
		vfs_setextendedsecurity(mp);

		/* Advisory locking should be handled at the VFS layer */
		vfs_setlocklocal(mp);

		/*
		 * Mac OS X needs a file system modify time
		 *
		 * We use the mtime of the "com.apple.system.mtime"
		 * extended attribute, which is associated with the
		 * file system root directory.
		 *
		 * Here we need to take a ref on z_mtime_vp to keep it around.
		 * If the attribute isn't there, attempt to create it.
		 */
		zfsvfs = vfs_fsprivate(mp);
		if (zfsvfs->z_mtime_vp == NULL) {
			vnode_t *rvp;
			vnode_t *xdvp = NULLVP;
			vnode_t *xvp = NULLVP;
			znode_t *rootzp;
			timestruc_t modify_time;
			cred_t  *cr;
			timestruc_t  now;
			int flag;
			int result;

			if (zfs_zget(zfsvfs, zfsvfs->z_root, &rootzp) != 0) {
				goto out;
			}
			rvp = ZTOV(rootzp);
			cr = (cred_t *)vfs_context_ucred(context);

			/* Grab the hidden attribute directory vnode. */
			result = zfs_get_xattrdir(rootzp, &xdvp, cr, CREATE_XATTR_DIR);
			vnode_put(rvp);	/* all done with root vnode */
			rvp = NULL;
			if (result) {
				goto out;
			}

			/*
			 * HACK - workaround missing vnode_setnoflush() KPI...
			 *
			 * We tag zfsvfs so that zfs_attach_vnode() can then set
			 * vnfs_marksystem when the vnode gets created.
			 */
			zfsvfs->z_last_unmount_time = 0xBADC0DE;
			zfsvfs->z_last_mtime_synced = VTOZ(xdvp)->z_id;
			flag = vfs_isrdonly(mp) ? 0 : ZEXISTS;
			/* Lookup or create the named attribute. */
			if ( zfs_obtain_xattr(VTOZ(xdvp), ZFS_MTIME_XATTR,
			                          S_IRUSR | S_IWUSR, cr, &xvp,
			                          flag) ) {
					zfsvfs->z_last_unmount_time = 0;
					zfsvfs->z_last_mtime_synced = 0;
					vnode_put(xdvp);
					goto out;
				}
				gethrestime(&now);
			ZFS_TIME_ENCODE(&now, VTOZ(xvp)->z_phys->zp_mtime);
			vnode_put(xdvp);
			vnode_ref(xvp);

			zfsvfs->z_mtime_vp = xvp;
			ZFS_TIME_DECODE(&modify_time, VTOZ(xvp)->z_phys->zp_mtime);
			zfsvfs->z_last_unmount_time = modify_time.tv_sec;
			zfsvfs->z_last_mtime_synced = modify_time.tv_sec;

			/*
			 * Keep this referenced vnode from impeding an unmount.
			 *
			 * XXX vnode_setnoflush() is MIA from KPI (see workaround above).
			 */
#if 0
			vnode_setnoflush(xvp);
#endif
			vnode_put(xvp);
		}
	}
#endif /* __APPLE__ */
out:
#ifdef __APPLE__
	if (osname) {
		kmem_free(osname, MAXPATHLEN);
	}
#else
	pn_free(&spn);
#endif /* __APPLE__ */
	return (error);
}

#ifdef __APPLE__
/*
 * ZFS file system features.
 */
const vol_capabilities_attr_t zfs_capabilities = {
	{
		/* Format capabilities we support: */
		VOL_CAP_FMT_PERSISTENTOBJECTIDS |
		VOL_CAP_FMT_SYMBOLICLINKS |
		VOL_CAP_FMT_HARDLINKS |
		VOL_CAP_FMT_SPARSE_FILES |
		VOL_CAP_FMT_CASE_SENSITIVE |
		VOL_CAP_FMT_CASE_PRESERVING |
		VOL_CAP_FMT_FAST_STATFS |
		VOL_CAP_FMT_2TB_FILESIZE |
		VOL_CAP_FMT_HIDDEN_FILES |
		VOL_CAP_FMT_PATH_FROM_ID,

		/* Interface capabilities we support: */
		VOL_CAP_INT_ATTRLIST |
		VOL_CAP_INT_NFSEXPORT |
		VOL_CAP_INT_READDIRATTR |
		VOL_CAP_INT_VOL_RENAME |
		VOL_CAP_INT_ADVLOCK |
		VOL_CAP_INT_FLOCK |
		VOL_CAP_INT_EXTENDED_SECURITY |
		VOL_CAP_INT_NAMEDSTREAMS |
		VOL_CAP_INT_EXTENDED_ATTR ,

		0 , 0
	},
	{
		/* Format capabilities we know about: */
		VOL_CAP_FMT_PERSISTENTOBJECTIDS |
		VOL_CAP_FMT_SYMBOLICLINKS |
		VOL_CAP_FMT_HARDLINKS |
		VOL_CAP_FMT_JOURNAL |
		VOL_CAP_FMT_JOURNAL_ACTIVE |
		VOL_CAP_FMT_NO_ROOT_TIMES |
		VOL_CAP_FMT_SPARSE_FILES |
		VOL_CAP_FMT_ZERO_RUNS |
		VOL_CAP_FMT_CASE_SENSITIVE |
		VOL_CAP_FMT_CASE_PRESERVING |
		VOL_CAP_FMT_FAST_STATFS |
		VOL_CAP_FMT_2TB_FILESIZE |
		VOL_CAP_FMT_OPENDENYMODES |
		VOL_CAP_FMT_HIDDEN_FILES |
		VOL_CAP_FMT_PATH_FROM_ID ,

		/* Interface capabilities we know about: */
		VOL_CAP_INT_SEARCHFS |
		VOL_CAP_INT_ATTRLIST |
		VOL_CAP_INT_NFSEXPORT |
		VOL_CAP_INT_READDIRATTR |
		VOL_CAP_INT_EXCHANGEDATA |
		VOL_CAP_INT_COPYFILE |
		VOL_CAP_INT_ALLOCATE |
		VOL_CAP_INT_VOL_RENAME |
		VOL_CAP_INT_ADVLOCK |
		VOL_CAP_INT_FLOCK |
		VOL_CAP_INT_EXTENDED_SECURITY |
		VOL_CAP_INT_USERACCESS |
		VOL_CAP_INT_MANLOCK |
		VOL_CAP_INT_NAMEDSTREAMS |
		VOL_CAP_INT_EXTENDED_ATTR ,

		0, 0
	}
};
#endif /* __APPLE__ */

#ifdef __APPLE__
/*
 * ZFS file system attributes (for getattrlist).
 */
const attribute_set_t zfs_attributes = {
		ATTR_CMN_NAME	|
		ATTR_CMN_DEVID	|
		ATTR_CMN_FSID	|
		ATTR_CMN_OBJTYPE |
		ATTR_CMN_OBJTAG	|
		ATTR_CMN_OBJID	|
		ATTR_CMN_OBJPERMANENTID |
		ATTR_CMN_PAROBJID |
		ATTR_CMN_CRTIME |
		ATTR_CMN_MODTIME |
		ATTR_CMN_CHGTIME |
		ATTR_CMN_ACCTIME |
		ATTR_CMN_BKUPTIME |
		ATTR_CMN_FNDRINFO |
		ATTR_CMN_OWNERID |
		ATTR_CMN_GRPID	|
		ATTR_CMN_ACCESSMASK |
		ATTR_CMN_FLAGS	|
		ATTR_CMN_USERACCESS |
		ATTR_CMN_EXTENDED_SECURITY |
		ATTR_CMN_UUID |
		ATTR_CMN_GRPUUID ,

		ATTR_VOL_FSTYPE	|
		ATTR_VOL_SIGNATURE |
		ATTR_VOL_SIZE	|
		ATTR_VOL_SPACEFREE |
		ATTR_VOL_SPACEAVAIL |
		ATTR_VOL_MINALLOCATION |
		ATTR_VOL_ALLOCATIONCLUMP |
		ATTR_VOL_IOBLOCKSIZE |
		ATTR_VOL_OBJCOUNT |
		ATTR_VOL_FILECOUNT |
		ATTR_VOL_DIRCOUNT |
		ATTR_VOL_MAXOBJCOUNT |
		ATTR_VOL_MOUNTPOINT |
		ATTR_VOL_NAME	|
		ATTR_VOL_MOUNTFLAGS |
		ATTR_VOL_MOUNTEDDEVICE |
		ATTR_VOL_CAPABILITIES |
		ATTR_VOL_ATTRIBUTES ,

		ATTR_DIR_LINKCOUNT |
		ATTR_DIR_ENTRYCOUNT |
		ATTR_DIR_MOUNTSTATUS ,

		ATTR_FILE_LINKCOUNT |
		ATTR_FILE_TOTALSIZE |
		ATTR_FILE_ALLOCSIZE |
		/* ATTR_FILE_IOBLOCKSIZE */
		ATTR_FILE_DEVTYPE |
		ATTR_FILE_DATALENGTH |
		ATTR_FILE_DATAALLOCSIZE |
		ATTR_FILE_RSRCLENGTH |
		ATTR_FILE_RSRCALLOCSIZE ,

		0
};
#endif /* __APPLE__ */

static int
#ifdef __APPLE__
zfs_vfs_getattr(struct mount *mp, struct vfs_attr *fsap, __unused vfs_context_t context)
#else
zfs_statvfs(vfs_t *vfsp, struct statvfs64 *statp)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
        zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
#else
	zfsvfs_t *zfsvfs = vfsp->vfs_data;
#endif /* __APPLE__ */

	dev32_t d32;
	uint64_t refdbytes, availbytes, usedobjs, availobjs;

	ZFS_ENTER(zfsvfs);

	dmu_objset_space(zfsvfs->z_os,
	    &refdbytes, &availbytes, &usedobjs, &availobjs);

#ifdef __APPLE__
	VFSATTR_RETURN(fsap, f_objcount, usedobjs);
	VFSATTR_RETURN(fsap, f_maxobjcount, 0x7fffffffffffffff);
	/*
	 * Carbon depends on f_filecount and f_dircount so
	 * make up some values based on total objects.
	 */
	VFSATTR_RETURN(fsap, f_filecount, usedobjs - (usedobjs / 4));
	VFSATTR_RETURN(fsap, f_dircount, usedobjs / 4);
#endif /* __APPLE__ */

	/*
	 * The underlying storage pool actually uses multiple block sizes.
	 * We report the fragsize as the smallest block size we support,
	 * and we report our blocksize as the filesystem's maximum blocksize.
	 */
#ifdef __APPLE__
	VFSATTR_RETURN(fsap, f_bsize, 1UL << SPA_MINBLOCKSHIFT);
	VFSATTR_RETURN(fsap, f_iosize, zfsvfs->z_max_blksz);
#else
	statp->f_frsize = 1UL << SPA_MINBLOCKSHIFT;
	statp->f_bsize = zfsvfs->z_max_blksz;
#endif /* __APPLE__ */

	/*
	 * The following report "total" blocks of various kinds in the
	 * file system, but reported in terms of f_frsize - the
	 * "fragment" size.
	 */
#ifdef __APPLE__
	VFSATTR_RETURN(fsap, f_blocks,
	               (u_int64_t)((refdbytes + availbytes) >> SPA_MINBLOCKSHIFT));
	VFSATTR_RETURN(fsap, f_bfree, (u_int64_t)(availbytes >> SPA_MINBLOCKSHIFT));
	VFSATTR_RETURN(fsap, f_bavail, fsap->f_bfree);  /* no root reservation */
	VFSATTR_RETURN(fsap, f_bused, fsap->f_blocks - fsap->f_bfree);
#else
	statp->f_blocks = (refdbytes + availbytes) >> SPA_MINBLOCKSHIFT;
	statp->f_bfree = availbytes >> SPA_MINBLOCKSHIFT;
	statp->f_bavail = statp->f_bfree; /* no root reservation */
#endif /* __APPLE__ */

	/*
	 * statvfs() should really be called statufs(), because it assumes
	 * static metadata.  ZFS doesn't preallocate files, so the best
	 * we can do is report the max that could possibly fit in f_files,
	 * and that minus the number actually used in f_ffree.
	 * For f_ffree, report the smaller of the number of object available
	 * and the number of blocks (each object will take at least a block).
	 */
#ifdef __APPLE__
	VFSATTR_RETURN(fsap, f_ffree, (u_int64_t)MIN(availobjs, fsap->f_bfree));
	VFSATTR_RETURN(fsap, f_files,  fsap->f_ffree + usedobjs);

#if 0
	statp->f_flag = vf_to_stf(vfsp->vfs_flag);
#endif

	if (VFSATTR_IS_ACTIVE(fsap, f_fsid)) {
		VFSATTR_RETURN(fsap, f_fsid, vfs_statfs(mp)->f_fsid);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		bcopy(&zfs_capabilities, &fsap->f_capabilities, sizeof (zfs_capabilities));
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		bcopy(&zfs_attributes, &fsap->f_attributes.validattr, sizeof (zfs_attributes));
		bcopy(&zfs_attributes, &fsap->f_attributes.nativeattr, sizeof (zfs_attributes));
		VFSATTR_SET_SUPPORTED(fsap, f_attributes);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_create_time)) {
		dmu_objset_stats_t dmu_stat;

		dmu_objset_fast_stat(zfsvfs->z_os, &dmu_stat);
		//fsap->f_create_time.tv_sec = dmu_stat.dds_creation_time;
		fsap->f_create_time.tv_nsec = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_create_time);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_modify_time)) {
		if (zfsvfs->z_mtime_vp != NULL) {
			znode_t *mzp;

			mzp = VTOZ(zfsvfs->z_mtime_vp);
			ZFS_TIME_DECODE(&fsap->f_modify_time, mzp->z_phys->zp_mtime);
		} else {
			fsap->f_modify_time.tv_sec = 0;
			fsap->f_modify_time.tv_nsec = 0;
		}
		VFSATTR_SET_SUPPORTED(fsap, f_modify_time);
	}
	/*
	 * For Carbon compatibility, pretend to support this legacy/unused
	 * attribute
	 */
	if (VFSATTR_IS_ACTIVE(fsap, f_backup_time)) {
		fsap->f_backup_time.tv_sec = 0;
		fsap->f_backup_time.tv_nsec = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_backup_time);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_vol_name)) {
		spa_t *spa = dmu_objset_spa(zfsvfs->z_os);
		spa_config_enter(spa, SCL_ALL, FTAG, RW_READER);
		strlcpy(fsap->f_vol_name, spa_name(spa), MAXPATHLEN);
		spa_config_exit(spa, SCL_ALL, FTAG);
		VFSATTR_SET_SUPPORTED(fsap, f_vol_name);
	}
	VFSATTR_RETURN(fsap, f_fssubtype, 0);
	VFSATTR_RETURN(fsap, f_signature, 0x5a21);  /* 'Z!' */
	VFSATTR_RETURN(fsap, f_carbon_fsid, 0);
#else /* OpenSolaris */
	statp->f_ffree = MIN(availobjs, statp->f_bfree);
	statp->f_favail = statp->f_ffree;	/* no "root reservation" */
	statp->f_files = statp->f_ffree + usedobjs;

	(void) cmpldev(&d32, vfsp->vfs_dev);
	statp->f_fsid = d32;

	/*
	 * We're a zfs filesystem.
	 */
	(void) strcpy(statp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name);

	statp->f_flag = vf_to_stf(vfsp->vfs_flag);

	statp->f_namemax = ZFS_MAXNAMELEN;

	/*
	 * We have all of 32 characters to stuff a string here.
	 * Is there anything useful we could/should provide?
	 */
	bzero(statp->f_fstr, sizeof (statp->f_fstr));
#endif /* __APPLE__ */

	ZFS_EXIT(zfsvfs);
	return (0);
}

static int
#ifdef __APPLE__
zfs_vfs_root(struct mount *mp, vnode_t **vpp, __unused vfs_context_t context)
#else
zfs_root(vfs_t *vfsp, vnode_t **vpp)
#endif
{
#ifdef __APPLE__
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
#else
	zfsvfs_t *zfsvfs = vfsp->vfs_data;
#endif /* __APPLE__ */
	znode_t *rootzp;
	int error;

	ZFS_ENTER(zfsvfs);

	error = zfs_zget(zfsvfs, zfsvfs->z_root, &rootzp);
	if (error == 0)
		*vpp = ZTOV(rootzp);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*ARGSUSED*/
static int
#ifdef __APPLE__
zfs_vfs_unmount(struct mount *mp, int mntflags, vfs_context_t context)
#else
zfs_umount(vfs_t *vfsp, int fflag, cred_t *cr)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
#else
	zfsvfs_t *zfsvfs = vfsp->vfs_data;
#endif /* __APPLE__ */
	objset_t *os = zfsvfs->z_os;
	znode_t	*zp, *nextzp;
	int ret;
#ifdef __APPLE__
	int i;
	int flags;
#endif

#ifndef __APPLE__
	/*XXX NOEL: delegation admin stuffs, add back if we use delg. admin */
	ret = secpolicy_fs_unmount(cr, vfsp);
	if (ret) {
		ret = dsl_deleg_access((char *)refstr_value(vfsp->vfs_resource),
		    ZFS_DELEG_PERM_MOUNT, cr);
		if (ret)
			return (ret);
	}

	/*
	 * We purge the parent filesystem's vfsp as the parent filesystem
	 * and all of its snapshots have their vnode's v_vfsp set to the
	 * parent's filesystem's vfsp.  Note, 'z_parent' is self
	 * referential for non-snapshots.
	 */
	(void) dnlc_purge_vfsp(zfsvfs->z_parent->z_vfs, 0);
#endif /* !__APPLE__ */

	/*
	 * Unmount any snapshots mounted under .zfs before unmounting the
	 * dataset itself.
	 */
#ifndef __APPLE__
	// .zfs isn't supported yet
	if (zfsvfs->z_ctldir != NULL &&
	    (ret = zfsctl_umount_snapshots(vfsp, fflag, cr)) != 0) {
		return (ret);
	}
#endif /* __APPLE__ */

#ifdef __APPLE__
	flags = SKIPSYSTEM;
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	ret = vflush(mp, NULLVP, flags);

	/*
	 * Mac OS X needs a file system modify time
	 *
	 * We use the mtime of the "com.apple.system.mtime"
	 * extended attribute, which is associated with the
	 * file system root directory.
	 *
	 * Here we need to release the ref we took on z_mtime_vp during mount.
	 */
	if ((ret == 0) || (mntflags & MNT_FORCE)) {
		if (zfsvfs->z_mtime_vp != NULL) {
			vnode_t *mvp;

			mvp = zfsvfs->z_mtime_vp;
			zfsvfs->z_mtime_vp = NULL;

			if (vnode_get(mvp) == 0) {
				vnode_rele(mvp);
				vnode_recycle(mvp);
				vnode_put(mvp);
			}
		}
	}

	if (!(mntflags & MNT_FORCE))
#else
	if (!(fflag & MS_FORCE))
#endif /* __APPLE__ */
	{
		/*
		 * Check the number of active vnodes in the file system.
		 * Our count is maintained in the vfs structure, but the
		 * number is off by 1 to indicate a hold on the vfs
		 * structure itself.
		 *
		 * The '.zfs' directory maintains a reference of its
		 * own, and any active references underneath are
		 * reflected in the vnode count.
		 */
#ifdef __APPLE__
		if (ret)
			return (EBUSY);
#else
		if (zfsvfs->z_ctldir == NULL) {
			if (vfsp->vfs_count > 1)
				return (EBUSY);
		} else {
			if (vfsp->vfs_count > 2 ||
			    zfsvfs->z_ctldir->v_count > 1) {
				return (EBUSY);
			}
		}
#endif /* __APPLE__ */
	}

#ifndef __APPLE__
	vfsp->vfs_flag |= VFS_UNMOUNTED;
#endif

	rw_enter(&zfsvfs->z_unmount_lock, RW_WRITER);
	rw_enter(&zfsvfs->z_unmount_inactive_lock, RW_WRITER);

	/*
	 * At this point there are no vops active, and any new vops will
	 * fail with EIO since we have z_unmount_lock for writer (only
	 * relavent for forced unmount).
	 *
	 * Release all holds on dbufs.
	 * Note, the dmu can still callback via znode_pageout_func()
	 * which can zfs_znode_free() the znode.  So we lock
	 * z_all_znodes; search the list for a held dbuf; drop the lock
	 * (we know zp can't disappear if we hold a dbuf lock) then
	 * regrab the lock and restart.
	 */
	mutex_enter(&zfsvfs->z_znodes_lock);
	for (zp = list_head(&zfsvfs->z_all_znodes); zp; zp = nextzp) {
		nextzp = list_next(&zfsvfs->z_all_znodes, zp);
		if (zp->z_dbuf_held) {
			/* dbufs should only be held when force unmounting */
			zp->z_dbuf_held = 0;
			mutex_exit(&zfsvfs->z_znodes_lock);
			dmu_buf_rele(zp->z_dbuf, NULL);
			/* Start again */
			mutex_enter(&zfsvfs->z_znodes_lock);
			nextzp = list_head(&zfsvfs->z_all_znodes);
		}
	}
	mutex_exit(&zfsvfs->z_znodes_lock);

	/*
	 * Set the unmounted flag and let new vops unblock.
	 * zfs_inactive will have the unmounted behavior, and all other
	 * vops will fail with EIO.
	 */
	zfsvfs->z_unmounted = B_TRUE;
	rw_exit(&zfsvfs->z_unmount_lock);
	rw_exit(&zfsvfs->z_unmount_inactive_lock);

#ifndef __APPLE__
	/*
	 * Unregister properties.
	 */
	if (!dmu_objset_is_snapshot(os))
		zfs_unregister_callbacks(zfsvfs);
#endif

	/*
	 * Close the zil. NB: Can't close the zil while zfs_inactive
	 * threads are blocked as zil_close can call zfs_inactive.
	 */
	if (zfsvfs->z_log) {
		zil_close(zfsvfs->z_log);
		zfsvfs->z_log = NULL;
	}

	/*
	 * Evict cached data
	 */
	(void) dmu_objset_evict_dbufs(os);

	/*
	 * Finally close the objset
	 */
	//dmu_objset_close(os);
    dmu_objset_disown(os, zfsvfs);

	/*
	 * We can now safely destroy the '.zfs' directory node.
	 */
#ifndef __APPLE__
	if (zfsvfs->z_ctldir != NULL)
		zfsctl_destroy(zfsvfs);
#else

	/*
	 * Note that this work is normally done in zfs_freevfs, but since
	 * there is no VOP_FREEVFS in OSX, we free VFS items here
	 */
	OSDecrementAtomic((SInt32 *)&zfs_active_fs_count);
 	for (i = 0; i != ZFS_OBJ_MTX_SZ; i++)
 		mutex_destroy(&zfsvfs->z_hold_mtx[i]);

 	mutex_destroy(&zfsvfs->z_znodes_lock);
 	list_destroy(&zfsvfs->z_all_znodes);
 	rw_destroy(&zfsvfs->z_unmount_lock);
 	rw_destroy(&zfsvfs->z_unmount_inactive_lock);
#endif /* !__APPLE__ */

	return (0);
}

#ifdef __APPLE__
vnode_t *vnode_getparent(vnode_t *vp);  /* sys/vnode_internal.h */
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vget_internal(zfsvfs_t *zfsvfs, ino64_t ino, vnode_t **vpp)
{
	vnode_t	*vp;
	vnode_t	*dvp = NULL;
	znode_t		*zp;
	int		error;

	*vpp = NULL;

	/*
	 * On Mac OS X we always export the root directory id as 2
	 * and its parent as 1
	 */
	if (ino == 2 || ino == 1)
		ino = zfsvfs->z_root;

	if ((error = zfs_zget(zfsvfs, ino, &zp)))
		goto out;

	/* Don't expose EA objects! */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		vnode_put(ZTOV(zp));
		error = ENOENT;
		goto out;
	}

	*vpp = vp = ZTOV(zp);

	if (vnode_isvroot(vp))
		goto out;

	/*
	 * If this znode didn't just come from the cache then
	 * it won't have a valid identity (parent and name).
	 *
	 * Manually fix its identity here (normally done by namei lookup).
	 */
	if ((dvp = vnode_getparent(vp)) == NULL) {
		if (zp->z_phys->zp_parent != 0 &&
		    zfs_vget_internal(zfsvfs, zp->z_phys->zp_parent, &dvp)) {
			goto out;
		}
		if ( vnode_isdir(dvp) ) {
			char objname[ZAP_MAXNAMELEN];  /* 256 bytes */
			int flags = VNODE_UPDATE_PARENT;

			/* Look for znode's name in its parent's zap */
			if ( zap_value_search(zfsvfs->z_os,
			                      zp->z_phys->zp_parent,
			                      zp->z_id,
			                      ZFS_DIRENT_OBJ(-1ULL),
			                      objname) == 0 ) {
				flags |= VNODE_UPDATE_NAME;
			}

			/* Update the znode's parent and name */
			vnode_update_identity(vp, dvp, objname, 0, 0, flags);
		}
	}
	/* All done with znode's parent */
	vnode_put(dvp);
out:
	return (error);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
/*
 * Get a vnode from a file id (ignoring the generation)
 *
 * Use by NFS Server (readdirplus) and VFS (build_path)
 */
static int
zfs_vfs_vget(struct mount *mp, ino64_t ino, vnode_t **vpp, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	int error;

	ZFS_ENTER(zfsvfs);

	/*
	 * On Mac OS X we always export the root directory id as 2.
	 * So we don't expect to see the real root directory id
	 * from zfs_vfs_vget KPI (unless of course the real id was
	 * already 2).
	 */
	if ((ino == zfsvfs->z_root) && (zfsvfs->z_root != 2)) {
		ZFS_EXIT(zfsvfs);
		return (ENOENT);
	}
	error = zfs_vget_internal(zfsvfs, ino, vpp);

	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vfs_setattr(__unused struct mount *mp, __unused struct vfs_attr *fsap, __unused vfs_context_t context)
{
	// 10a286 bits has an implementation of this
	return (ENOTSUP);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
/*
 * NFS Server File Handle File ID
 */
typedef struct zfs_zfid {
	uint8_t   zf_object[8];		/* obj[i] = obj >> (8 * i) */
	uint8_t   zf_gen[8];		/* gen[i] = gen >> (8 * i) */
} zfs_zfid_t;
#endif /* __APPLE__ */

#ifdef __APPLE__
/*
 * File handle to vnode pointer
 */
static int
zfs_vfs_fhtovp(struct mount *mp, int fhlen, unsigned char *fhp,
               vnode_t **vpp, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	zfs_zfid_t	*zfid = (zfs_zfid_t *)fhp;
	znode_t		*zp;
	uint64_t	obj_num = 0;
	uint64_t	fid_gen = 0;
	uint64_t	zp_gen;
	int 		i;
	int		error;

	*vpp = NULL;

	ZFS_ENTER(zfsvfs);

	if (fhlen < sizeof (zfs_zfid_t)) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Grab the object and gen numbers in an endian neutral manner
	 */
	for (i = 0; i < sizeof (zfid->zf_object); i++)
		obj_num |= ((uint64_t)zfid->zf_object[i]) << (8 * i);

	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		fid_gen |= ((uint64_t)zfid->zf_gen[i]) << (8 * i);

	if ((error = zfs_zget(zfsvfs, obj_num, &zp))) {
		goto out;
	}

	zp_gen = zp->z_phys->zp_gen;
	if (zp_gen == 0)
		zp_gen = 1;

	if (zp->z_unlinked || zp_gen != fid_gen) {
		vnode_put(ZTOV(zp));
		error = EINVAL;
		goto out;
	}
	*vpp = ZTOV(zp);
out:
	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif __APPLE__

#ifdef __APPLE__
/*
 * Vnode pointer to File handle
 *
 * XXX Do we want to check the DSL sharenfs property?
 */
static int
zfs_vfs_vptofh(vnode_t *vp, int *fhlenp, unsigned char *fhp, __unused vfs_context_t context)
{
	zfsvfs_t	*zfsvfs = vfs_fsprivate(vnode_mount(vp));
	zfs_zfid_t	*zfid = (zfs_zfid_t *)fhp;
	znode_t		*zp = VTOZ(vp);
	uint64_t	obj_num;
	uint64_t	zp_gen;
	int		i;
	int		error;

	if (*fhlenp < sizeof (zfs_zfid_t)) {
		return (EOVERFLOW);
	}

	ZFS_ENTER(zfsvfs);

	obj_num = zp->z_id;
	zp_gen = zp->z_phys->zp_gen;
	if (zp_gen == 0)
		zp_gen = 1;

	/*
	 * Store the object and gen numbers in an endian neutral manner
	 */
	for (i = 0; i < sizeof (zfid->zf_object); i++)
		zfid->zf_object[i] = (uint8_t)(obj_num >> (8 * i));

	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		zfid->zf_gen[i] = (uint8_t)(zp_gen >> (8 * i));

	*fhlenp = sizeof (zfs_zfid_t);

	ZFS_EXIT(zfsvfs);
	return (0);
}
#endif /* __APPLE__ */






#ifndef __APPLE__
static int
zfs_vget(vfs_t *vfsp, vnode_t **vpp, fid_t *fidp)
{
	zfsvfs_t	*zfsvfs = vfsp->vfs_data;
	znode_t		*zp;
	uint64_t	object = 0;
	uint64_t	fid_gen = 0;
	uint64_t	gen_mask;
	uint64_t	zp_gen;
	int 		i, err;

	*vpp = NULL;

	ZFS_ENTER(zfsvfs);

	if (fidp->fid_len == LONG_FID_LEN) {
		zfid_long_t	*zlfid = (zfid_long_t *)fidp;
		uint64_t	objsetid = 0;
		uint64_t	setgen = 0;

		for (i = 0; i < sizeof (zlfid->zf_setid); i++)
			objsetid |= ((uint64_t)zlfid->zf_setid[i]) << (8 * i);

		for (i = 0; i < sizeof (zlfid->zf_setgen); i++)
			setgen |= ((uint64_t)zlfid->zf_setgen[i]) << (8 * i);

		ZFS_EXIT(zfsvfs);

		err = zfsctl_lookup_objset(vfsp, objsetid, &zfsvfs);
		if (err)
			return (EINVAL);
		ZFS_ENTER(zfsvfs);
	}

	if (fidp->fid_len == SHORT_FID_LEN || fidp->fid_len == LONG_FID_LEN) {
		zfid_short_t	*zfid = (zfid_short_t *)fidp;

		for (i = 0; i < sizeof (zfid->zf_object); i++)
			object |= ((uint64_t)zfid->zf_object[i]) << (8 * i);

		for (i = 0; i < sizeof (zfid->zf_gen); i++)
			fid_gen |= ((uint64_t)zfid->zf_gen[i]) << (8 * i);
	} else {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/* A zero fid_gen means we are in the .zfs control directories */
	if (fid_gen == 0 &&
	    (object == ZFSCTL_INO_ROOT || object == ZFSCTL_INO_SNAPDIR)) {
		*vpp = zfsvfs->z_ctldir;
		ASSERT(*vpp != NULL);
		if (object == ZFSCTL_INO_SNAPDIR) {
			VERIFY(zfsctl_root_lookup(*vpp, "snapshot", vpp, NULL,
			    0, NULL, NULL) == 0);
		} else {
			VN_HOLD(*vpp);
		}
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	gen_mask = -1ULL >> (64 - 8 * i);

	zdprintf("getting %llu [%u mask %llx]\n", object, fid_gen, gen_mask);
	if (err = zfs_zget(zfsvfs, object, &zp)) {
		ZFS_EXIT(zfsvfs);
		return (err);
	}
	zp_gen = zp->z_phys->zp_gen & gen_mask;
	if (zp_gen == 0)
		zp_gen = 1;
	if (zp->z_unlinked || zp_gen != fid_gen) {
		zdprintf("znode gen (%u) != fid gen (%u)\n", zp_gen, fid_gen);
		VN_RELE(ZTOV(zp));
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	*vpp = ZTOV(zp);
	ZFS_EXIT(zfsvfs);
	return (0);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
static void
zfs_freevfs(vfs_t *vfsp)
{
	zfsvfs_t *zfsvfs = vfsp->vfs_data;
	int i;

	for (i = 0; i != ZFS_OBJ_MTX_SZ; i++)
		mutex_destroy(&zfsvfs->z_hold_mtx[i]);

	mutex_destroy(&zfsvfs->z_znodes_lock);
	list_destroy(&zfsvfs->z_all_znodes);
	rw_destroy(&zfsvfs->z_unmount_lock);
	rw_destroy(&zfsvfs->z_unmount_inactive_lock);
	kmem_free(zfsvfs, sizeof (zfsvfs_t));

	atomic_add_32(&zfs_active_fs_count, -1);
}
#endif /* !__APPLE__ */

/*
 * VFS_INIT() initialization.  Note that there is no VFS_FINI(),
 * so we can't safely do any non-idempotent initialization here.
 * Leave that to zfs_init() and zfs_fini(), which are called
 * from the module's _init() and _fini() entry points.
 */
/*ARGSUSED*/
static int
#ifdef __APPLE__
zfs_vfs_init(__unused struct vfsconf *vfsp)
#else
zfs_vfsinit(int fstype, char *name)
#endif
{
#ifndef __APPLE__
	int error;

	zfsfstype = fstype;

	/*
	 * Setup vfsops and vnodeops tables.
	 */
	error = vfs_setfsops(fstype, zfs_vfsops_template, &zfs_vfsops);
	if (error != 0) {
		cmn_err(CE_WARN, "zfs: bad vfs ops template");
	}

	error = zfs_create_op_tables();
	if (error) {
		zfs_remove_op_tables();
		cmn_err(CE_WARN, "zfs: bad vnode ops template");
		(void) vfs_freevfsops_by_type(zfsfstype);
		return (error);
	}

	mutex_init(&zfs_dev_mtx, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Unique major number for all zfs mounts.
	 * If we run out of 32-bit minors, we'll getudev() another major.
	 */
	zfs_major = ddi_name_to_major(ZFS_DRIVER);
	zfs_minor = ZFS_MIN_MINOR;
#endif /* !__APPLE__ */
	return (0);
}


boolean_t
zfs_fuid_overquota(zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid)
//zfs_fuid_overquota(vfs_t *vfsp, boolean_t isgroup, uint64_t fuid)
{
	char buf[32];
	uint64_t used, quota, usedobj, quotaobj;
	int err;
	//zfsvfs_t *zfsvfs = NULL;
	//zfsvfs = vfsp->vfs_data;

	usedobj = isgroup ? DMU_GROUPUSED_OBJECT : DMU_USERUSED_OBJECT;
	quotaobj = isgroup ? zsb->z_groupquota_obj : zsb->z_userquota_obj;

	if (quotaobj == 0 || zsb->z_replay)
		return (B_FALSE);

	(void) sprintf(buf, "%llx", (longlong_t)fuid);
	err = zap_lookup(zsb->z_os, quotaobj, buf, 8, 1, &quota);
	if (err != 0)
		return (B_FALSE);

	err = zap_lookup(zsb->z_os, usedobj, buf, 8, 1, &used);
	if (err != 0)
		return (B_FALSE);
	return (used >= quota);
}

/*
 * Read a property stored within the master node.
 */
int
zfs_get_zplprop(objset_t *os, zfs_prop_t prop, uint64_t *value)
{
	const char *pname;
	int error = ENOENT;

	/*
	 * Look up the file system's value for the property.  For the
	 * version property, we look up a slightly different string.
	 */
	if (prop == ZFS_PROP_VERSION)
		pname = ZPL_VERSION_STR;
	else
		pname = zfs_prop_to_name(prop);

	if (os != NULL)
		error = zap_lookup(os, MASTER_NODE_OBJ, pname, 8, 1, value);

	if (error == ENOENT) {
		/* No value set, use the default value */
		switch (prop) {
		case ZFS_PROP_VERSION:
			*value = ZPL_VERSION;
			break;
		case ZFS_PROP_NORMALIZE:
		case ZFS_PROP_UTF8ONLY:
			*value = 0;
			break;
		case ZFS_PROP_CASE:
			*value = ZFS_CASE_SENSITIVE;
			break;
		default:
			return (error);
		}
		error = 0;
	}
	return (error);
}


static int
zfs_vfs_start(__unused struct mount *mp, __unused int flags, __unused vfs_context_t context)
{
	return (0);
}

static int
zfs_vfs_quotactl(__unused struct mount *mp, __unused int cmds, __unused uid_t uid, __unused caddr_t datap, __unused vfs_context_t context)
{
	return (ENOTSUP);
}


int zfs_vfsops_init(void)
{
	struct vfs_fsentry vfe;

	vfe.vfe_vfsops = &zfs_vfsops_template;
	vfe.vfe_vopcnt = ZFS_VNOP_TBL_CNT;
	vfe.vfe_opvdescs = zfs_vnodeop_opv_desc_list;

	strlcpy(vfe.vfe_fsname, "zfs", MFSNAMELEN);

	/*
	 * Note: must set VFS_TBLGENERICMNTARGS with VFS_TBLLOCALVOL
	 * to suppress local mount argument handling.
	 */
	vfe.vfe_flags = VFS_TBLTHREADSAFE |
	                VFS_TBLNOTYPENUM |
	                VFS_TBLLOCALVOL |
	                VFS_TBL64BITREADY |
	                VFS_TBLNATIVEXATTR |
	                VFS_TBLGENERICMNTARGS|
			VFS_TBLREADDIR_EXTENDED;
	vfe.vfe_reserv[0] = 0;
	vfe.vfe_reserv[1] = 0;

	if (vfs_fsadd(&vfe, &zfs_vfsconf) != 0)
		return KERN_FAILURE;
	else
		return KERN_SUCCESS;
}

int zfs_vfsops_fini(void)
{
    return vfs_fsremove(zfs_vfsconf);
}

int
zfs_busy(void)
{
	return (zfs_active_fs_count != 0);
}

int
zfs_get_stats(objset_t *os, nvlist_t *nv)
{
	int error;
	uint64_t val;

	error = zap_lookup(os, MASTER_NODE_OBJ, ZPL_VERSION_STR, 8, 1, &val);
	if (error == 0)
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VERSION, val);

	return (error);
}


/*
 * Block out VOPs and close zfs_sb_t::z_os
 *
 * Note, if successful, then we return with the 'z_teardown_lock' and
 * 'z_teardown_inactive_lock' write held.
 */
int
zfs_suspend_fs(zfs_sb_t *zsb)
{
	int error;

	//if ((error = zfs_sb_teardown(zsb, B_FALSE)) != 0)
	//	return (error);
	dmu_objset_disown(zsb->z_os, zsb);

	return (0);
}
EXPORT_SYMBOL(zfs_suspend_fs);




/*
 * Reopen zfs_sb_t::z_os and release VOPs.
 */
int
zfs_resume_fs(zfs_sb_t *zsb, const char *osname)
{
	int err, err2;

	ASSERT(RRW_WRITE_HELD(&zsb->z_teardown_lock));
	ASSERT(RW_WRITE_HELD(&zsb->z_teardown_inactive_lock));

	err = dmu_objset_own(osname, DMU_OST_ZFS, B_FALSE, zsb, &zsb->z_os);
	if (err) {
		zsb->z_os = NULL;
	} else {
		znode_t *zp;
		uint64_t sa_obj = 0;

		err2 = zap_lookup(zsb->z_os, MASTER_NODE_OBJ,
		    ZFS_SA_ATTRS, 8, 1, &sa_obj);

		if ((err || err2) && zsb->z_version >= ZPL_VERSION_SA)
			goto bail;

#if 0
		if ((err = sa_setup(zsb->z_os, sa_obj,
		    zfs_attr_table,  ZPL_END, &zsb->z_attr_table)) != 0)
			goto bail;

		VERIFY(zfs_sb_setup(zsb, B_FALSE) == 0);
#endif

		/*
		 * Attempt to re-establish all the active znodes with
		 * their dbufs.  If a zfs_rezget() fails, then we'll let
		 * any potential callers discover that via ZFS_ENTER_VERIFY_VP
		 * when they try to use their znode.
		 */
		mutex_enter(&zsb->z_znodes_lock);
		for (zp = list_head(&zsb->z_all_znodes); zp;
		    zp = list_next(&zsb->z_all_znodes, zp)) {
			(void) zfs_rezget(zp);
		}
		mutex_exit(&zsb->z_znodes_lock);

	}

bail:
	/* release the VOPs */
	rw_exit(&zsb->z_teardown_inactive_lock);
	rrw_exit(&zsb->z_teardown_lock, FTAG);

	if (err) {
		/*
		 * Since we couldn't reopen zfs_sb_t::z_os, force
		 * unmount this file system.
		 */
		//(void) zfs_umount(zsb->z_sb);
	}
	return (err);
}




static void
fuidstr_to_sid(zfs_sb_t *zsb, const char *fuidstr,
    char *domainbuf, int buflen, uid_t *ridp)
{
	uint64_t fuid;
	const char *domain;

	fuid = strtonum(fuidstr, NULL);

	domain = zfs_fuid_find_by_idx(zsb, FUID_INDEX(fuid));
	if (domain)
		(void) strlcpy(domainbuf, domain, buflen);
	else
		domainbuf[0] = '\0';
	*ridp = FUID_RID(fuid);
}


static uint64_t
zfs_userquota_prop_to_obj(zfs_sb_t *zsb, zfs_userquota_prop_t type)
{
	switch (type) {
	case ZFS_PROP_USERUSED:
		return (DMU_USERUSED_OBJECT);
	case ZFS_PROP_GROUPUSED:
		return (DMU_GROUPUSED_OBJECT);
	case ZFS_PROP_USERQUOTA:
		return (zsb->z_userquota_obj);
	case ZFS_PROP_GROUPQUOTA:
		return (zsb->z_groupquota_obj);
	default:
		return (ENOTSUP);
	}
	return (0);
}


int
zfs_userspace_many(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    uint64_t *cookiep, void *vbuf, uint64_t *bufsizep)
{
	int error;
	zap_cursor_t zc;
	zap_attribute_t za;
	zfs_useracct_t *buf = vbuf;
	uint64_t obj;

	if (!dmu_objset_userspace_present(zsb->z_os))
		return (ENOTSUP);

	obj = zfs_userquota_prop_to_obj(zsb, type);
	if (obj == 0) {
		*bufsizep = 0;
		return (0);
	}

	for (zap_cursor_init_serialized(&zc, zsb->z_os, obj, *cookiep);
	    (error = zap_cursor_retrieve(&zc, &za)) == 0;
	    zap_cursor_advance(&zc)) {
		if ((uintptr_t)buf - (uintptr_t)vbuf + sizeof (zfs_useracct_t) >
		    *bufsizep)
			break;

		fuidstr_to_sid(zsb, za.za_name,
		    buf->zu_domain, sizeof (buf->zu_domain), &buf->zu_rid);

		buf->zu_space = za.za_first_integer;
		buf++;
	}
	if (error == ENOENT)
		error = 0;

	ASSERT3U((uintptr_t)buf - (uintptr_t)vbuf, <=, *bufsizep);
	*bufsizep = (uintptr_t)buf - (uintptr_t)vbuf;
	*cookiep = zap_cursor_serialize(&zc);
	zap_cursor_fini(&zc);
	return (error);
}
EXPORT_SYMBOL(zfs_userspace_many);

/*
 * buf must be big enough (eg, 32 bytes)
 */
static int
id_to_fuidstr(zfs_sb_t *zsb, const char *domain, uid_t rid,
    char *buf, boolean_t addok)
{
	uint64_t fuid;
	int domainid = 0;

	if (domain && domain[0]) {
		domainid = zfs_fuid_find_by_domain(zsb, domain, NULL, addok);
		if (domainid == -1)
			return (ENOENT);
	}
	fuid = FUID_ENCODE(domainid, rid);
	(void) sprintf(buf, "%llx", (longlong_t)fuid);
	return (0);
}


int
zfs_userspace_one(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    const char *domain, uint64_t rid, uint64_t *valp)
{
	char buf[32];
	int err;
	uint64_t obj;

	*valp = 0;

	if (!dmu_objset_userspace_present(zsb->z_os))
		return (ENOTSUP);

	obj = zfs_userquota_prop_to_obj(zsb, type);
	if (obj == 0)
		return (0);

	err = id_to_fuidstr(zsb, domain, rid, buf, B_FALSE);
	if (err)
		return (err);

	err = zap_lookup(zsb->z_os, obj, buf, 8, 1, valp);
	if (err == ENOENT)
		err = 0;
	return (err);
}

// This needs to be OSXified.
int
zfs_set_userquota(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    const char *domain, uint64_t rid, uint64_t quota)
{
	char buf[32];
	int err;
	dmu_tx_t *tx;
	uint64_t *objp;
	boolean_t fuid_dirtied;

	if (type != ZFS_PROP_USERQUOTA && type != ZFS_PROP_GROUPQUOTA)
		return (EINVAL);

	if (zsb->z_version < ZPL_VERSION_USERSPACE)
		return (ENOTSUP);

	objp = (type == ZFS_PROP_USERQUOTA) ? &zsb->z_userquota_obj :
	    &zsb->z_groupquota_obj;

	err = id_to_fuidstr(zsb, domain, rid, buf, B_TRUE);
	if (err)
		return (err);
	fuid_dirtied = zsb->z_fuid_dirty;

	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_zap(tx, *objp ? *objp : DMU_NEW_OBJECT, B_TRUE, NULL);
	if (*objp == 0) {
		dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_TRUE,
		    zfs_userquota_prop_prefixes[type]);
	}
	if (fuid_dirtied)
		zfs_fuid_txhold(zsb, tx);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		return (err);
	}

	mutex_enter(&zsb->z_lock);
	if (*objp == 0) {
		*objp = zap_create(zsb->z_os, DMU_OT_USERGROUP_QUOTA,
		    DMU_OT_NONE, 0, tx);
		VERIFY(0 == zap_add(zsb->z_os, MASTER_NODE_OBJ,
		    zfs_userquota_prop_prefixes[type], 8, 1, objp, tx));
	}
	mutex_exit(&zsb->z_lock);

	if (quota == 0) {
		err = zap_remove(zsb->z_os, *objp, buf, tx);
		if (err == ENOENT)
			err = 0;
	} else {
		err = zap_update(zsb->z_os, *objp, buf, 8, 1, &quota, tx);
	}
	ASSERT(err == 0);
	if (fuid_dirtied)
		zfs_fuid_sync(zsb, tx);
	dmu_tx_commit(tx);
	return (err);
}


int
zfs_set_version(const char *name, uint64_t newvers)
{
	int error;
	objset_t *os;
	dmu_tx_t *tx;
	uint64_t curvers;

	/*
	 * XXX for now, require that the filesystem be unmounted.  Would
	 * be nice to find the zfsvfs_t and just update that if
	 * possible.
	 */

	if (newvers < ZPL_VERSION_INITIAL || newvers > ZPL_VERSION)
		return (EINVAL);

	//error = dmu_objset_open(name, DMU_OST_ZFS, DS_MODE_PRIMARY, &os);
	error = dmu_objset_own(name, DMU_OST_ZFS, B_FALSE, NULL, &os);
	if (error)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZPL_VERSION_STR,
	    8, 1, &curvers);
	if (error)
		goto out;
	if (newvers < curvers) {
		error = EINVAL;
		goto out;
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, 0, ZPL_VERSION_STR);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		goto out;
	}
	error = zap_update(os, MASTER_NODE_OBJ, ZPL_VERSION_STR, 8, 1,
	    &newvers, tx);

	spa_history_internal_log(LOG_DS_UPGRADE,
	    dmu_objset_spa(os), tx, CRED(),
	    "oldver=%llu newver=%llu dataset = %llu", curvers, newvers,
	    dmu_objset_id(os));
	dmu_tx_commit(tx);

out:
    dmu_objset_disown(os, NULL);
	//dmu_objset_close(os);
	return (error);
}

#ifndef __APPLE__
static vfsdef_t vfw = {
	VFSDEF_VERSION,
	MNTTYPE_ZFS,
	zfs_vfsinit,
	VSW_HASPROTO|VSW_CANRWRO|VSW_CANREMOUNT|VSW_VOLATILEDEV|VSW_STATS,
	&zfs_mntopts
};

struct modlfs zfs_modlfs = {
	&mod_fsops, "ZFS filesystem version " SPA_VERSION_STRING, &vfw
};
#endif /* !__APPLE__ */
