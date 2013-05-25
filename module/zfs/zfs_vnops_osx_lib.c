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
#include <sys/stat.h>


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
      /* VNODE_ATTR_va_fsid |*/ \
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

        if ((error = sa_lookup(zp->z_sa_hdl, SA_ZPL_ZNODE_ACL(zfsvfs),
                               times, sizeof (times)))) {
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
zfs_getattr_znode_unlocked(struct vnode *vp, vattr_t *vap)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	//znode_phys_t *pzp = zp->z_phys;
	int error = 0;
	uint64_t	parent;
    zfs_acl_phys_t acl;

    //printf("getattr_osx\n");

	ZFS_ENTER(zfsvfs);
	/*
	 * On Mac OS X we always export the root directory id as 2
	 */
	vap->va_fileid = (zp->z_id == zfsvfs->z_root) ? 2 : zp->z_id;
	vap->va_nlink = zp->z_links;
	vap->va_data_size = zp->z_size;
	vap->va_total_size = zp->z_size;
	vap->va_gen = zp->z_gen;

	/*
	 * For Carbon compatibility,pretend to support this legacy/unused attribute
	 */
	if (VATTR_IS_ACTIVE(vap, va_backup_time)) {
		vap->va_backup_time.tv_sec = 0;
		vap->va_backup_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}
	vap->va_flags = zfs_getbsdflags(zp);
	/*
	 * On Mac OS X we always export the root directory id as 2
     * and its parent as 1
	 */
	error = sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
                      &parent, sizeof (parent));

    if (!error) {
        if (zp->z_id == zfsvfs->z_root)
            vap->va_parentid = 1;
        else if (parent == zfsvfs->z_root)
            vap->va_parentid = 2;
        else
            vap->va_parentid = parent;
    }

	vap->va_iosize = zp->z_blksz ? zp->z_blksz : zfsvfs->z_max_blksz;

	vap->va_supported |= ZFS_SUPPORTED_VATTRS;

	/* Don't include '.' and '..' in the number of entries */
	if (VATTR_IS_ACTIVE(vap, va_nchildren) && vnode_isdir(vp)) {
		VATTR_RETURN(vap, va_nchildren, vap->va_nlink - 2);
    }

	if (VATTR_IS_ACTIVE(vap, va_acl)) {
        //printf("want acl\n");
        if (sa_lookup(zp->z_sa_hdl, SA_ZPL_ZNODE_ACL(zfsvfs),
                      &acl, sizeof (zfs_acl_phys_t))) {
            //if (zp->z_acl.z_acl_count == 0) {
			vap->va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;
		} else {
			if ((error = zfs_getacl(zp, &vap->va_acl, B_TRUE, NULL))) {
                dprintf("zfs_getacl returned error %d\n", error);
                error = 0;
				//ZFS_EXIT(zfsvfs);
				//return (error);
			}
		}
		VATTR_SET_SUPPORTED(vap, va_acl);
		/* va_acl implies that va_uuuid and va_guuid are also supported. */
		VATTR_RETURN(vap, va_uuuid, kauth_null_guid);
		VATTR_RETURN(vap, va_guuid, kauth_null_guid);
    }

	if (VATTR_IS_ACTIVE(vap, va_data_alloc) || VATTR_IS_ACTIVE(vap, va_total_alloc)) {
		uint32_t  blksize;
		u_longlong_t  nblks;
        sa_object_size(zp->z_sa_hdl, &blksize, &nblks);
		vap->va_data_alloc = (uint64_t)512LL * (uint64_t)nblks;
		vap->va_total_alloc = vap->va_data_alloc;
		vap->va_supported |= VNODE_ATTR_va_data_alloc |
					VNODE_ATTR_va_total_alloc;
	}

	if (VATTR_IS_ACTIVE(vap, va_name) && !vnode_isvroot(vp)) {
		if (zap_value_search(zfsvfs->z_os, parent, zp->z_id,
			 	    ZFS_DIRENT_OBJ(-1ULL), vap->va_name) == 0)
			VATTR_SET_SUPPORTED(vap, va_name);
	}

	vap->va_iosize = zp->z_blksz;

	ZFS_EXIT(zfsvfs);
	return (error);
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


int pn_alloc(pathname_t *p)
{
    return ENOTSUP;
}

int pn_free(pathname_t *p)
{
    return ENOTSUP;
}

void *tsd_get(unsigned int key)
{
    return 0;
}

int
tsd_set(uint_t key, void *value)
{
    return 1;
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

    error = zfs_fsync(vp, /*syncflag*/0, NULL, (caller_context_t *)ct);
	if (error)
		return (error);

	if (zfsvfs->z_log != NULL)
		zil_commit(zfsvfs->z_log, 0);
	else
		txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
	return (0);
}

uint32_t
zfs_getbsdflags(znode_t *zp)
{
	uint32_t  bsdflags = 0;
    uint64_t zflags;
    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_FLAGS(zp->z_zfsvfs),
                     &zflags, sizeof (zflags)) == 0);

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
    uint64_t zflags;
    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_FLAGS(zp->z_zfsvfs),
                     &zflags, sizeof (zflags)) == 0);

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
    /*
    (void )sa_update(zp->z_sa_hdl, SA_ZPL_FLAGS(zp->z_zfsvfs),
                     (void *)&zp->z_pflags, sizeof (uint64_t), tx);
    */
}

/*
 * Lookup/Create an extended attribute entry.
 *
 * Input arguments:
 *	dzp	- znode for hidden attribute directory
 *	name	- name of attribute
 *	flag	- ZNEW: if the entry already exists, fail with EEXIST.
 *		  ZEXISTS: if the entry does not exist, fail with ENOENT.
 *
 * Output arguments:
 *	vpp	- pointer to the vnode for the entry (NULL if there isn't one)
 *
 * Return value: 0 on success or errno value on failure.
 */
int
zfs_obtain_xattr(znode_t *dzp, const char *name, mode_t mode, cred_t *cr,
                 vnode_t **vpp, int flag)
{
	znode_t  *xzp = NULL;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog;
	zfs_dirlock_t  *dl;
	dmu_tx_t  *tx;
	struct vnode_attr  vattr;
	int error;
	struct componentname cn;

	/* zfs_dirent_lock() expects a component name */
	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)name;
	cn.cn_namelen = strlen(name);

    ZFS_ENTER(zfsvfs);
    ZFS_VERIFY_ZP(dzp);
    zilog = zfsvfs->z_log;

top:
	/* Lock the attribute entry name. */
	if ( (error = zfs_dirent_lock(&dl, dzp, (char *)name, &xzp, flag,
                                  NULL, NULL)) ) {
		goto out;
	}
	/* If the name already exists, we're done. */
	if (xzp != NULL) {
		zfs_dirent_unlock(dl);
		goto out;
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
	dmu_tx_hold_bonus(tx, dzp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, (char *)name);

#if 0 // FIXME
	if (dzp->z_phys->z_flags & ZFS_INHERIT_ACE) {
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, SPA_MAXBLOCKSIZE);
	}
#endif
    zfs_sa_upgrade_txholds(tx, dzp);
    zfs_sa_upgrade_txholds(tx, xzp);
	error = dmu_tx_assign(tx, TXG_NOWAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		if ((error == ERESTART)) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, mode & ~S_IFMT);
	zfs_mknode(dzp, &vattr, tx, cr, 0, &xzp, 0);

/*
	ASSERT(xzp->z_id == zoid);
*/
	(void) zfs_link_create(dl, xzp, tx, ZNEW);
	zfs_log_create(zilog, tx, TX_CREATE, dzp, xzp, (char *)name,
                   NULL /* vsecp */, 0 /*acl_ids.z_fuidp*/, &vattr);
	dmu_tx_commit(tx);

	zfs_dirent_unlock(dl);
out:
	if (error == EEXIST)
		error = ENOATTR;
	if (xzp)
		*vpp = ZTOV(xzp);

    ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * ace_trivial:
 * determine whether an ace_t acl is trivial
 *
 * Trivialness implies that the acl is composed of only
 * owner, group, everyone entries.  ACL can't
 * have read_acl denied, and write_owner/write_acl/write_attributes
 * can only be owner@ entry.
 */
int
ace_trivial_common(void *acep, int aclcnt,
                   uint64_t (*walk)(void *, uint64_t, int aclcnt,
                                    uint16_t *, uint16_t *, uint32_t *))
{
    return 1;
}


void
acl_trivial_access_masks(mode_t mode, boolean_t isdir, trivial_acl_t *masks)
{
    uint32_t read_mask = ACE_READ_DATA;
    uint32_t write_mask = ACE_WRITE_DATA|ACE_APPEND_DATA;
    uint32_t execute_mask = ACE_EXECUTE;

    (void) isdir;   /* will need this later */

    masks->deny1 = 0;
    if (!(mode & S_IRUSR) && (mode & (S_IRGRP|S_IROTH)))
        masks->deny1 |= read_mask;
    if (!(mode & S_IWUSR) && (mode & (S_IWGRP|S_IWOTH)))
        masks->deny1 |= write_mask;
    if (!(mode & S_IXUSR) && (mode & (S_IXGRP|S_IXOTH)))
        masks->deny1 |= execute_mask;

    masks->deny2 = 0;
    if (!(mode & S_IRGRP) && (mode & S_IROTH))
        masks->deny2 |= read_mask;
    if (!(mode & S_IWGRP) && (mode & S_IWOTH))
        masks->deny2 |= write_mask;
    if (!(mode & S_IXGRP) && (mode & S_IXOTH))
        masks->deny2 |= execute_mask;

    masks->allow0 = 0;
    if ((mode & S_IRUSR) && (!(mode & S_IRGRP) && (mode & S_IROTH)))
        masks->allow0 |= read_mask;
    if ((mode & S_IWUSR) && (!(mode & S_IWGRP) && (mode & S_IWOTH)))
        masks->allow0 |= write_mask;
    if ((mode & S_IXUSR) && (!(mode & S_IXGRP) && (mode & S_IXOTH)))
        masks->allow0 |= execute_mask;

    masks->owner = ACE_WRITE_ATTRIBUTES|ACE_WRITE_OWNER|ACE_WRITE_ACL|
        ACE_WRITE_NAMED_ATTRS|ACE_READ_ACL|ACE_READ_ATTRIBUTES|
        ACE_READ_NAMED_ATTRS|ACE_SYNCHRONIZE;
    if (mode & S_IRUSR)
        masks->owner |= read_mask;
    if (mode & S_IWUSR)
        masks->owner |= write_mask;
    if (mode & S_IXUSR)
        masks->owner |= execute_mask;

    masks->group = ACE_READ_ACL|ACE_READ_ATTRIBUTES|ACE_READ_NAMED_ATTRS|
        ACE_SYNCHRONIZE;
    if (mode & S_IRGRP)
        masks->group |= read_mask;
    if (mode & S_IWGRP)
        masks->group |= write_mask;
    if (mode & S_IXGRP)
        masks->group |= execute_mask;

    masks->everyone = ACE_READ_ACL|ACE_READ_ATTRIBUTES|ACE_READ_NAMED_ATTRS|
        ACE_SYNCHRONIZE;
    if (mode & S_IROTH)
        masks->everyone |= read_mask;
    if (mode & S_IWOTH)
        masks->everyone |= write_mask;
    if (mode & S_IXOTH)
        masks->everyone |= execute_mask;
}
