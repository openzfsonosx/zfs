/*
 * This file is intended only for use by zfs_vnops_osx.c.  It should contain
 * a library of functions useful for vnode operations.
 */
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/sa.h>
#include <sys/zfs_vnops.h>


/* Originally from illumos:uts/common/sys/vfs.h */
typedef uint64_t vfs_feature_t;
#define	VFSFT_XVATTR		0x100000001	/* Supports xvattr for attrs */
#define	VFSFT_CASEINSENSITIVE	0x100000002	/* Supports case-insensitive */
#define	VFSFT_NOCASESENSITIVE	0x100000004	/* NOT case-sensitive */
#define	VFSFT_DIRENTFLAGS	0x100000008	/* Supports dirent flags */
#define	VFSFT_ACLONCREATE	0x100000010	/* Supports ACL on create */
#define	VFSFT_ACEMASKONACCESS	0x100000020	/* Can use ACEMASK for access */
#define	VFSFT_SYSATTR_VIEWS	0x100000040	/* Supports sysattr view i/f */
#define	VFSFT_ACCESS_FILTER	0x100000080	/* dirents filtered by access */
#define	VFSFT_REPARSE		0x100000100	/* Supports reparse point */
#define	VFSFT_ZEROCOPY_SUPPORTED 0x100000200	/* Supports loaning buffers */

#define	ZFS_SUPPORTED_VATTRS		\
	( VNODE_ATTR_va_mode |		\
	  VNODE_ATTR_va_uid |		\
	  VNODE_ATTR_va_gid |		\
	  VNODE_ATTR_va_fsid |		\
	  VNODE_ATTR_va_fileid |	\
	  VNODE_ATTR_va_nlink |		\
	  VNODE_ATTR_va_data_size |	\
	  VNODE_ATTR_va_total_size |	\
	  VNODE_ATTR_va_rdev |		\
	  VNODE_ATTR_va_gen |		\
	  VNODE_ATTR_va_create_time |	\
	  VNODE_ATTR_va_access_time |	\
	  VNODE_ATTR_va_modify_time |	\
	  VNODE_ATTR_va_change_time |	\
	  VNODE_ATTR_va_flags |		\
	  VNODE_ATTR_va_parentid |	\
	  VNODE_ATTR_va_iosize |	\
	0)

/* For part 1 of zfs_getattr() */
int
zfs_getattr_znode_locked(vattr_t *vap, znode_t *zp, cred_t *cr)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;
    uint64_t times[2];
    uint64_t val;

    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_MODE(zfsvfs),
                     &val, sizeof (val)) == 0);
	vap->va_mode = val & MODEMASK;
    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_UID(zfsvfs),
                     &val, sizeof (val)) == 0);
	vap->va_uid = val;
    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_GID(zfsvfs),
                     &val, sizeof (val)) == 0);
	vap->va_gid = val;
	//vap->va_fsid = zp->z_zfsvfs->z_vfs->vfs_dev;

	/* On OS X, the root directory id is always 2 */
	vap->va_fileid = (zp->z_id == zfsvfs->z_root) ? 2 : zp->z_id;

    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_LINKS(zfsvfs),
                     &val, sizeof (val)) == 0);
	vap->va_nlink = val;

    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_SIZE(zfsvfs),
                     &val, sizeof (val)) == 0);
	vap->va_data_size = val;
	vap->va_total_size = val;

    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_RDEV(zfsvfs),
                     &val, sizeof (val)) == 0);
	vap->va_rdev = val;
    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_GEN(zfsvfs),
                     &val, sizeof (val)) == 0);
	vap->va_gen = val;

    (void) sa_lookup(zp->z_sa_hdl, SA_ZPL_CRTIME(zfsvfs),
                     times, sizeof (times));
	ZFS_TIME_DECODE(&vap->va_create_time, times);
    (void) sa_lookup(zp->z_sa_hdl, SA_ZPL_ATIME(zfsvfs),
                     times, sizeof (times));
	ZFS_TIME_DECODE(&vap->va_access_time, times);
    (void) sa_lookup(zp->z_sa_hdl, SA_ZPL_MTIME(zfsvfs),
                     times, sizeof (times));
	ZFS_TIME_DECODE(&vap->va_modify_time, times);
    (void) sa_lookup(zp->z_sa_hdl, SA_ZPL_CTIME(zfsvfs),
                     times, sizeof (times));
	ZFS_TIME_DECODE(&vap->va_change_time, times);

	if (VATTR_IS_ACTIVE(vap, va_backup_time)) {
		vap->va_backup_time.tv_sec = 0;
		vap->va_backup_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}
	vap->va_flags = zfs_getbsdflags(zp);

	/* On OS X, the root directory id is always 2 and its parent is 1 */
    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
                     &val, sizeof (val)) == 0);
	if (zp->z_id == zfsvfs->z_root)
		vap->va_parentid = 1;
	else if (val == zfsvfs->z_root)
		vap->va_parentid = 2;
	else
		vap->va_parentid = val;

	vap->va_iosize = zp->z_blksz ? zp->z_blksz : zfsvfs->z_max_blksz;
	vap->va_supported |= ZFS_SUPPORTED_VATTRS;

	if (VATTR_IS_ACTIVE(vap, va_nchildren) && vnode_isdir(ZTOV(zp)))
		VATTR_RETURN(vap, va_nchildren, vap->va_nlink - 2);

	if (VATTR_IS_ACTIVE(vap, va_acl)) {

        if (error = sa_lookup(zp->z_sa_hdl, SA_ZPL_ZNODE_ACL(zfsvfs),
                              times, sizeof (times))) {
            //		if (zp->z_phys->zp_acl.z_acl_count == 0) {
			vap->va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;
		} else {
			error = zfs_getacl(zp, &vap->va_acl, B_TRUE, cr);
			if (error)
				return (error);
			VATTR_SET_SUPPORTED(vap, va_acl);
			/*
			 * va_acl implies that va_uuuid and va_guuid are
			 * also supported.
			 */
			VATTR_RETURN(vap, va_uuuid, kauth_null_guid);
			VATTR_RETURN(vap, va_guuid, kauth_null_guid);
		}
	}
	return (0);
}

int
zfs_getattr_znode_unlocked(vattr_t *vap, struct vnode *vp)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	//znode_phys_t *pzp = zp->z_phys;
	int error;

	if (VATTR_IS_ACTIVE(vap, va_data_alloc) ||
	    VATTR_IS_ACTIVE(vap, va_total_alloc)) {
		uint32_t blocksize;
		u_longlong_t nblks;

        sa_object_size(zp->z_sa_hdl, &blocksize, &nblks);
		vap->va_data_alloc = (uint64_t)512LL * (uint64_t)nblks;
		vap->va_total_alloc = vap->va_data_alloc;
		vap->va_supported |= VNODE_ATTR_va_data_alloc;
		vap->va_supported |= VNODE_ATTR_va_total_alloc;
	}
	if (zp->z_blksz == 0) {
		/*
		 * Block size hasn't been set; suggest maximal I/O transfers.
		 */
		vap->va_iosize = zfsvfs->z_max_blksz;
    }
#if 0
	if (VATTR_IS_ACTIVE(vap, va_name) && !vnode_isvroot(vp)) {
		error = zap_value_search(zfsvfs->z_os, pzp->zp_parent, zp->z_id,
		    ZFS_DIRENT_OBJ(-1ULL), vap->va_name);
		if (error == 0)
			VATTR_SET_SUPPORTED(vap, va_name);
	}
#endif
	return (0);
}

boolean_t
vfs_has_feature(vfs_t *vfsp, vfs_feature_t vfsft)
{

	switch(vfsft) {
	case VFSFT_CASEINSENSITIVE:
	case VFSFT_NOCASESENSITIVE:
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
}

struct vnode *
dnlc_lookup(struct vnode *dvp, void *nameptr)
{
	struct componentname *cnp = (struct componentname *)nameptr;
	struct vnode *vp;

	switch(cache_lookup(dvp, &vp, cnp)) {
	case -1:
		break;
	case ENOENT:
		vp = DNLC_NO_VNODE;
		break;
	default:
		vp = NULLVP;
	}
	return (vp);
}

int
zfs_access_native_mode(struct vnode *vp, int *mode, cred_t *cr,
    caller_context_t *ct)
{
	int accmode = *mode & (VREAD|VWRITE|VEXEC/*|VAPPEND*/);
	int error = 0;
    int flag = 0; // FIXME

	if (accmode != 0)
		error = zfs_access(vp, accmode, flag, cr, ct);

	*mode &= ~(accmode);

	return (error);
}

int
zfs_ioflags(int ap_ioflag)
{
	int flags = 0;

	if (ap_ioflag & IO_APPEND)
		flags |= FAPPEND;
	if (ap_ioflag & IO_NDELAY)
		flags |= FNONBLOCK;
	if (ap_ioflag & IO_SYNC)
		flags |= (FSYNC | FDSYNC | FRSYNC);

	return (flags);
}

int
zfs_vnop_ioctl_fullfsync(struct vnode *vp, vfs_context_t ct, zfsvfs_t *zfsvfs)
{
	int error;
	struct vnop_fsync_args fsync_args = {
		.a_vp = vp,
		.a_waitfor = MNT_WAIT,
		.a_context = ct,
	};

	error = zfs_vnop_fsync(&fsync_args);
	if (error)
		return (error);

	if (zfsvfs->z_log != NULL)
		zil_commit(zfsvfs->z_log, 0);
	else
		txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
	return (0);
}
