
/*
 * OS X ZFS vnode operation wrappers.
 *
 * The argument structure layouts were obtained from:
 * http://www.opensource.apple.com/source/xnu/xnu-792.13.8/bsd/vfs/vfs_support.c
 * http://code.ohloh.net/project?pid=Ybsxw4FOQb8
 *
 * This file should contain primarily interface points; if an interface
 * definition is more than 100 lines long, parts of it should be refactored
 * into zfs_vnops_osx_lib.c.
 */

/*
 * XXX GENERAL COMPATIBILITY ISSUES
 *
 * 'name' is a common argument, but in OS X (and FreeBSD), we need to pass
 * the componentname pointer, so other things can use them.  We should
 * change the 'name' argument to be an opaque name pointer, and define
 * OS-dependent macros that yield the desired results when needed.
 *
 * On OS X, VFS performs access checks before calling anything, so
 * zfs_zaccess_* calls are not used.  Not true on FreeBSD, though.  Perhaps
 * those calls should be conditionally #if 0'd?
 *
 * On OS X, VFS & I/O objects are often opaque, e.g. uio_t and struct vnode
 * require using functions to access elements of an object.  Should convert
 * the Solaris code to use macros on other platforms.
 *
 * OS X and FreeBSD appear to use similar zfs-vfs interfaces; see Apple's
 * comment in zfs_remove() about the fact that VFS holds the last ref while
 * in Solaris it's the ZFS code that does.  On FreeBSD, the code Apple
 * refers to here results in a panic if the branch is actually taken.
 *
 * OS X uses vnode_put() in place of VN_RELE - needs a #define?
 * (Already is, see vnode.h)
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
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_rlock.h>

#include <sys/xattr.h>
#include <sys/utfconv.h>
#include <sys/ubc.h>

#define	DECLARE_CRED(ap) \
	cred_t *cr = (cred_t *)vfs_context_ucred((ap)->a_context)
#define	DECLARE_CONTEXT(ap) \
	caller_context_t *ct = (caller_context_t *)(ap)->a_context
#define	DECLARE_CRED_AND_CONTEXT(ap)	\
	DECLARE_CRED(ap);		\
	DECLARE_CONTEXT(ap)

#define dprintf printf

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

int zfs_vfs_init(__unused struct vfsconf *vfsp)
{
    return 0;
}

int
zfs_vfs_start(__unused struct mount *mp, __unused int flags, __unused vfs_context_t context)
{
	return (0);
}

int
zfs_vfs_quotactl(__unused struct mount *mp, __unused int cmds, __unused uid_t uid, __unused caddr_t datap, __unused vfs_context_t context)
{
	return (ENOTSUP);
}


static int
zfs_vnop_open(
	struct vnop_open_args /* {
		struct vnode *a_vp;
		int a_mode;
		vfs_context_t a_context;
        } */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);

	return (zfs_open(&ap->a_vp, ap->a_mode, cr, ct));
}

static int
zfs_vnop_close(
	struct vnop_close_args /* {
		struct vnode *a_vp;
		int a_fflag;
		vfs_context_t a_context;
        } */ *ap)
{
	int count = 1;
	int offset = 0;
	DECLARE_CRED_AND_CONTEXT(ap);

	return (zfs_close(ap->a_vp, ap->a_fflag, count, offset, cr, ct));
}

static int
zfs_vnop_ioctl(
	struct vnop_ioctl_args /* {
		struct vnode *a_vp;
		u_long a_command;
		caddr_t a_data;
		int a_fflag;
		kauth_cred_t a_cred;
		struct proc *a_p;
        } */ *ap)
{
	/* OS X has no use for zfs_ioctl(). */
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	user_addr_t useraddr = CAST_USER_ADDR_T(ap->a_data);
	int error;
    DECLARE_CRED_AND_CONTEXT(ap);

	ZFS_ENTER(zfsvfs);

	switch(ap->a_command) {
	case F_FULLFSYNC:
        /* zfs_fsync also calls ZFS_ENTER */
		error = zfs_fsync(ap->a_vp, /*flag*/0, cr, ct);
		break;
	case SPOTLIGHT_GET_MOUNT_TIME:
		error = copyout(&zfsvfs->z_mount_time, useraddr,
		    sizeof(zfsvfs->z_mount_time));
		break;
	case SPOTLIGHT_GET_UNMOUNT_TIME:
		error = copyout(&zfsvfs->z_last_unmount_time, useraddr,
		    sizeof(zfsvfs->z_last_unmount_time));
		break;
	default:
		error = ENOTTY;
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_read(
	struct vnop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
        } */ *ap)
{
	int ioflag = zfs_ioflags(ap->a_ioflag);
    int error;
    //uint64_t resid;

	DECLARE_CRED_AND_CONTEXT(ap);

    //resid=uio_resid(ap->a_uio);
	error = zfs_read(ap->a_vp, ap->a_uio, ioflag, cr, ct);
    //dprintf("vnop_read(%d) ->%d\n", resid, error);
	return error;
}

static int
zfs_vnop_write(
	struct vnop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
        } */ *ap)
{
	int ioflag = zfs_ioflags(ap->a_ioflag);
    int error;
    //uint64_t resid;
	DECLARE_CRED_AND_CONTEXT(ap);

    //resid=uio_resid(ap->a_uio);
	error = zfs_write(ap->a_vp, ap->a_uio, ioflag, cr, ct);
#ifdef __APPLE__
    /* Mac OS X: pageout requires that the UBC file size be current. */
    /* Possibly, we could update it only if size has changed. */
    //    if (tx_bytes != 0) {
    if (!error) {
        ubc_setsize(ap->a_vp, VTOZ(ap->a_vp)->z_size);
    }
#endif /* __APPLE__ */
    return error;
}

static int
zfs_vnop_access(
	struct vnop_access_args /* {
        struct vnodeop_desc *a_desc;
        struct vnode a_vp;
        int a_action;
        vfs_context_t a_context;
        } */ *ap)
{
	int error=ENOTSUP;

    dprintf("vnop_access\n");

#if 0 // FIXME
	int mode = ap->a_mode;

	error = zfs_access_native_mode(ap->a_vp, &mode, ap->a_cred,
	    ap->a_context);

	/* XXX Check for other modes? */
#endif

	return (error);
}

static int
zfs_vnop_lookup(
	struct vnop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
        } */ *ap)
{
	struct componentname *cnp = ap->a_cnp;
	DECLARE_CRED(ap);
	int error;
    char *filename = NULL;


    /*
      extern int    zfs_lookup ( struct vnode *dvp, char *nm, struct vnode **vpp,
                                 struct componentname *cnp, int nameiop,
                                 cred_t *cr, kthread_t *td, int flags);
    */

    /*
     * Darwin uses namelen as an optimisation, for example it can be
     * set to 5 for the string "alpha/beta" to look up "alpha". In this
     * case we need to copy it out to null-terminate.
     */
    if (cnp->cn_nameptr[cnp->cn_namelen] != 0) {
        MALLOC(filename, char *, cnp->cn_namelen+1, M_TEMP, M_WAITOK);
        if (filename == NULL) return ENOMEM;
        bcopy(cnp->cn_nameptr, filename, cnp->cn_namelen);
        filename[cnp->cn_namelen] = '\0';

    }

    dprintf("+vnop_lookup '%s'\n", filename ? filename : cnp->cn_nameptr);

	error = zfs_lookup(ap->a_dvp,
                       filename ? filename : cnp->cn_nameptr,
                       ap->a_vpp, cnp, cnp->cn_nameiop, cr, /*flags*/ 0);
    /* flags can be LOOKUP_XATTR | FIGNORECASE */

    FREE(filename, M_TEMP);

	/* XXX FreeBSD has some namecache stuff here. */

    dprintf("-vnop_lookup %d\n", error);
	return (error);
}

static int
zfs_vnop_create(
	struct vnop_create_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		vfs_context_t a_context;
        } */ *ap)
{
	struct componentname *cnp = ap->a_cnp;
	vattr_t *vap = ap->a_vap;
	DECLARE_CRED(ap);
	vcexcl_t excl;
    int mode=0; // FIXME

    dprintf("vnop_create: '%s'\n", cnp->cn_nameptr);
    /*
      extern int    zfs_create ( struct vnode *dvp, char *name, vattr_t *vap,
                                 int excl, int mode, struct vnode **vpp,
                                 cred_t *cr);
    */
	excl = (vap->va_vaflags & VA_EXCLUSIVE) ? EXCL : NONEXCL;

	return (zfs_create(ap->a_dvp, cnp->cn_nameptr, vap, excl, mode,
                       ap->a_vpp, cr));
}

static int
zfs_vnop_remove(
	struct vnop_remove_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
		int a_flags;
		vfs_context_t a_context;
        } */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);
    dprintf("vnop_remove\n");

    /*
      extern int    zfs_remove ( struct vnode *dvp, char *name,
                                 cred_t *cr, caller_context_t *ct, int flags);
    */
	return (zfs_remove(ap->a_dvp, ap->a_cnp->cn_nameptr, cr, ct, /*flags*/0));
}

static int
zfs_vnop_mkdir(
	struct vnop_mkdir_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);
    int error;
    dprintf("vnop_mkdir '%s'\n", ap->a_cnp->cn_nameptr);

#if 1 // Let's deny OSX fseventd for now */
    if (ap->a_cnp->cn_nameptr && !strcmp(ap->a_cnp->cn_nameptr,".fseventsd"))
        return EINVAL;
#endif
#if 1 //spotlight for now */
    if (ap->a_cnp->cn_nameptr && !strcmp(ap->a_cnp->cn_nameptr,".Spotlight-V100"))
        return EINVAL;
#endif
    /*
      extern int    zfs_mkdir ( struct vnode *dvp, char *dirname, vattr_t *vap,
                           struct vnode **vpp, cred_t *cr,
                           caller_context_t *ct, int flags, vsecattr_t *vsecp);
    */
	error = zfs_mkdir(ap->a_dvp, ap->a_cnp->cn_nameptr, ap->a_vap, ap->a_vpp,
	    cr, ct, /*flags*/0, /*vsecp*/NULL);
    return error;
}

static int
zfs_vnop_rmdir(
	struct vnop_rmdir_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);
    dprintf("vnop_rmdir\n");

    /*
      extern int    zfs_rmdir  ( struct vnode *dvp, char *name, struct vnode *cwd,
                                 cred_t *cr, caller_context_t *ct, int flags);
    */
	return (zfs_rmdir(ap->a_dvp, ap->a_cnp->cn_nameptr, /*cwd*/NULL,
	    cr, ct, /*flags*/0));
}

static int
zfs_vnop_readdir(
	struct vnop_readdir_args /* {
		struct vnode a_vp;
		struct uio *a_uio;
		int a_flags;
		int *a_eofflag;
		int *a_numdirent;
		vfs_context_t a_context;
	} */ *ap)
{
    int error;
	DECLARE_CRED(ap);
	/*
	 * XXX This interface needs vfs_has_feature.
	 * XXX zfs_readdir() also needs to grow support for passing back the
	 *     number of entries (OSX/FreeBSD) and cookies (FreeBSD).
	 *     However, it should be the responsibility of the OS caller to
	 *     malloc/free space for that.
	 */
    /*
      extern int   zfs_readdir( struct vnode *vp, uio_t *uio, cred_t *cr, int *eofp,
                                int flags, int *a_numdirent);
    */
    dprintf("+readdir\n");
	*ap->a_numdirent = 0;
	error = zfs_readdir(ap->a_vp, ap->a_uio, cr, ap->a_eofflag,
                        ap->a_flags, ap->a_numdirent);
    dprintf("-readdir %d (nument %d)\n", error, *ap->a_numdirent);
    return error;
}

static int
zfs_vnop_fsync(
	struct vnop_fsync_args /* {
		struct vnode *a_vp;
		int a_waitfor;
		vfs_context_t a_context;
	} */ *ap)
{
	znode_t *zp = VTOZ(ap->a_vp);
	DECLARE_CRED_AND_CONTEXT(ap);

	/*
	 * Check if this znode has already been synced, freed, and recycled
	 * by znode_pageout_func.
	 *
	 * XXX: What is this?  Substitute for Illumos vn_has_cached_data()?
	 */
	if (zp == NULL)
		return (0);

	return (zfs_fsync(ap->a_vp, /*flag*/0, cr, ct));
}

static int
zfs_vnop_getattr(
	struct vnop_getattr_args /* {
		struct vnode *a_vp;
		struct vnode_vattr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
    int error;
	DECLARE_CRED_AND_CONTEXT(ap);
    dprintf("+vnop_getattr zp %p vp %p\n",
            VTOZ(ap->a_vp), ap->a_vp);

	error = zfs_getattr(ap->a_vp, ap->a_vap, /*flags*/0, cr, ct);

    if (error) return error;

    error = zfs_getattr_znode_unlocked(ap->a_vp, ap->a_vap);

    if (error) dprintf("-vnop_getattr '%p' %d\n", (ap->a_vp),error);
    return error;
}

static int
zfs_vnop_setattr(
	struct vnop_setattr_args /* {
		struct vnode *a_vp;
		struct vnode_vattr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);
    vattr_t *vap = ap->a_vap;
    uint_t		mask = vap->va_mask;
    int error=0;

    // Translate OSX requested mask to ZFS
    if (VATTR_IS_ACTIVE(vap, va_data_size))
        mask |= AT_SIZE;
	if (VATTR_IS_ACTIVE(vap, va_mode) || VATTR_IS_ACTIVE(vap, va_acl))
        mask |= AT_MODE;
    if (VATTR_IS_ACTIVE(vap, va_uid))
        mask |= AT_UID;
    if (VATTR_IS_ACTIVE(vap, va_gid))
        mask |= AT_GID;
    if (VATTR_IS_ACTIVE(vap, va_access_time))
        mask |= AT_ATIME;
    if (VATTR_IS_ACTIVE(vap, va_modify_time))
        mask |= AT_MTIME;
    if (VATTR_IS_ACTIVE(vap, va_create_time))
        mask |= AT_CTIME;
    /*
    if (VATTR_IS_ACTIVE(vap, va_backup_time))
        mask |= AT_BTIME; // really?
    if (VATTR_IS_ACTIVE(vap, va_flags))
        mask |= AT_FLAGS; // really?
    */

    vap->va_mask = mask;
	error = zfs_setattr(ap->a_vp, ap->a_vap, /*flag*/0, cr, ct);

    dprintf("vnop_setattr: called on vp %p with mask %04x, err=%d\n",
            ap->a_vp, mask, error);

    if (!error) {

        // If successful, tell OSX which fields ZFS set.
        if (VATTR_IS_ACTIVE(vap, va_data_size))
            VATTR_SET_SUPPORTED(vap, va_data_size);
        if (VATTR_IS_ACTIVE(vap, va_mode))
            VATTR_SET_SUPPORTED(vap, va_mode);
        if (VATTR_IS_ACTIVE(vap, va_acl))
            VATTR_SET_SUPPORTED(vap, va_acl);
        if (VATTR_IS_ACTIVE(vap, va_uid))
            VATTR_SET_SUPPORTED(vap, va_uid);
        if (VATTR_IS_ACTIVE(vap, va_gid))
            VATTR_SET_SUPPORTED(vap, va_gid);
        if (VATTR_IS_ACTIVE(vap, va_access_time))
            VATTR_SET_SUPPORTED(vap, va_access_time);
        if (VATTR_IS_ACTIVE(vap, va_modify_time))
            VATTR_SET_SUPPORTED(vap, va_modify_time);
        if (VATTR_IS_ACTIVE(vap, va_create_time))
            VATTR_SET_SUPPORTED(vap, va_create_time);
        if (VATTR_IS_ACTIVE(vap, va_backup_time))
            VATTR_SET_SUPPORTED(vap, va_backup_time);
        if (VATTR_IS_ACTIVE(vap, va_flags)) {
            struct znode	*zp = VTOZ(ap->a_vp);
            zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
            ZFS_ENTER_NOERROR(zfsvfs);
            zfs_setbsdflags(zp, vap->va_flags);
            ZFS_EXIT(zfsvfs);
            VATTR_SET_SUPPORTED(vap, va_flags);
        }
    }
    if (error)
        printf("vnop_setattr return failure %d\n", error);

    return error;
}

static int
zfs_vnop_rename(
	struct vnop_rename_args /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;
    dprintf("vnop_rename\n");

    /*
      extern int zfs_rename(struct vnode *sdvp, char *snm, struct vnode *tdvp, char *tnm,
                            cred_t *cr, caller_context_t *ct, int flags);
    */
	error = zfs_rename(ap->a_fdvp, ap->a_fcnp->cn_nameptr, ap->a_tdvp,
                       ap->a_tcnp->cn_nameptr, cr, ct, /*flags*/0);

	return (error);
}

static int
zfs_vnop_symlink(
	struct vnop_symlink_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		char *a_target;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED(ap);
	int error;
    dprintf("vnop_symlink\n");

    /*
      extern int    zfs_symlink( struct vnode *dvp, struct vnode **vpp, char *name,
                                 vattr_t *vap, char *link, cred_t *cr);
    */

	/* OS X doesn't need to set vap->va_mode? */
	error = zfs_symlink(ap->a_dvp, ap->a_vpp, ap->a_cnp->cn_nameptr,
                        ap->a_vap, ap->a_target, cr);

	/* XXX zfs_attach_vnode()? */

	return (error);
}


static int
zfs_vnop_readlink(
	struct vnop_readlink_args /* {
		struct vnode *vp;
		struct uio *uio;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);
    dprintf("vnop_readlink\n");

    /*
      extern int    zfs_readlink(struct vnode *vp, uio_t *uio,
                                 cred_t *cr, caller_context_t *ct);
    */
	return (zfs_readlink(ap->a_vp, ap->a_uio, cr, ct));
}

static int
zfs_vnop_link(
	struct vnop_link_args /* {
		struct vnode *a_vp;
		struct vnode *a_tdvp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);
    int error;
    dprintf("vnop_link\n");

	/* XXX Translate this inside zfs_link() instead. */
	if (vnode_mount(ap->a_vp) != vnode_mount(ap->a_tdvp))
		return (EXDEV);


	/*
	 * XXX Understand why Apple made this comparison in so many places
	 * where others do not.
	 */
	if (ap->a_cnp->cn_namelen >= ZAP_MAXNAMELEN)
		return (ENAMETOOLONG);

    /*
      extern int    zfs_link   ( struct vnode *tdvp, struct vnode *svp, char *name,
                                 cred_t *cr, caller_context_t *ct, int flags);

    */

	error = zfs_link(ap->a_tdvp, ap->a_vp, ap->a_cnp->cn_nameptr,
                     cr, ct, /*flags*/0);
    if (!error)
        vnode_setmultipath(ap->a_vp);

    return error;
}

static int
zfs_vnop_pagein(
	struct vnop_pagein_args /* {
		struct vnode *a_vp;
		upl_t a_pl;
		vm_offset_t a_pl_offset;
		off_t a_foffset;
		size_t a_size;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap)
{
	/* XXX Crib this from the Apple zfs_vnops.c. */
    struct vnode         *vp = ap->a_vp;
    offset_t        off = ap->a_f_offset;
    size_t          len = ap->a_size;
    upl_t           upl = ap->a_pl;
    vm_offset_t     upl_offset = ap->a_pl_offset;
    znode_t         *zp = VTOZ(vp);
    zfsvfs_t        *zfsvfs = zp->z_zfsvfs;
    vm_offset_t     vaddr;
    int             flags = ap->a_flags;
    int             need_unlock = 0;
    int             error = 0;

    dprintf("+vnop_pagein\n");

    if (upl == (upl_t)NULL)
        panic("zfs_vnop_pagein: no upl!");

    if (len <= 0) {
        printf("zfs_vnop_pagein: invalid size %ld", len);
        if (!(flags & UPL_NOCOMMIT))
            (void) ubc_upl_abort(upl, 0);
        return (EINVAL);
    }

    ZFS_ENTER(zfsvfs);

    // Can we trust the z_size here, or do we look it up?
	//error = sa_lookup(zp->z_sa_hdl, SA_ZPL_SIZE(zfsvfs),
    //                &zp->z_size, sizeof (zp->z_size));


    ASSERT(vn_has_cached_data(vp));
    //ASSERT(zp->z_dbuf_held && zp->z_phys);
    /* can't fault past EOF */
    if ((off < 0) || (off >= zp->z_size) ||
        (len & PAGE_MASK) || (upl_offset & PAGE_MASK)) {
        dprintf("past EOF\n");
        ZFS_EXIT(zfsvfs);
        if (!(flags & UPL_NOCOMMIT))
            ubc_upl_abort_range(upl, upl_offset, len,
                                UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
        return (EFAULT);
    }

    /*
     * If we already own the lock, then we must be page faulting
     * in the middle of a write to this file (i.e., we are writing
     * to this file using data from a mapped region of the file).
     */
    if (!rw_write_held(&zp->z_map_lock)) {
        rw_enter(&zp->z_map_lock, RW_WRITER);
        need_unlock = TRUE;
    }

    ubc_upl_map(upl, &vaddr);
    vaddr += upl_offset;
    /*
     * Fill pages with data from the file.
     */
    while (len > 0) {
        if (len < PAGESIZE)
            break;

        error = dmu_read(zp->z_zfsvfs->z_os, zp->z_id, off, PAGESIZE,
                         (void *)vaddr, DMU_READ_PREFETCH);
        if (error) {
            printf("zfs_vnop_pagein: dmu_read err %d\n", error);
            break;
        }
        off += PAGESIZE;
        vaddr += PAGESIZE;
        if (len > PAGESIZE)
            len -= PAGESIZE;
        else
            len = 0;
    }
    ubc_upl_unmap(upl);

    if (!(flags & UPL_NOCOMMIT)) {
        if (error) {
            ubc_upl_abort_range(upl, upl_offset, ap->a_size,
                                UPL_ABORT_ERROR |
                                UPL_ABORT_FREE_ON_EMPTY);
        } else {
            ubc_upl_commit_range(upl, upl_offset, ap->a_size,
                                 UPL_COMMIT_CLEAR_DIRTY |
                                 UPL_COMMIT_FREE_ON_EMPTY);
        }
    }
    ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

    /*
     * We can't grab the range lock for the page as reader which would
     * stop truncation as this leads to deadlock. So we need to recheck
     * the file size.
     */
    if (ap->a_f_offset >= zp->z_size) {
        error = EFAULT;
    }
    if (need_unlock) {
        rw_exit(&zp->z_map_lock);
    }

    ZFS_EXIT(zfsvfs);
    return (error);
}

static int
zfs_vnop_pageout(
	struct vnop_pageout_args /* {
		struct vnode *a_vp;
		upl_t a_pl;
		vm_offset_t a_pl_offset;
		off_t a_foffset;
		size_t a_size;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap)
{
    struct vnode *vp = ap->a_vp;
    int             flags = ap->a_flags;
    upl_t           upl = ap->a_pl;
    vm_offset_t     upl_offset = ap->a_pl_offset;
    size_t          len = ap->a_size;
    offset_t        off = ap->a_f_offset;
    znode_t         *zp = VTOZ(vp);
    zfsvfs_t        *zfsvfs = zp->z_zfsvfs;
    dmu_tx_t        *tx;
    rl_t            *rl;
    uint64_t        filesz;
    int             err;

    dprintf("+vnop_pageout\n");
	/*
	 * XXX Crib this too, although Apple uses parts of zfs_putapage().
	 * Break up that function into smaller bits so it can be reused.
	 */

    if (zfsvfs == NULL) {
        if (!(flags & UPL_NOCOMMIT))
            ubc_upl_abort(upl, UPL_ABORT_DUMP_PAGES |
                          UPL_ABORT_FREE_ON_EMPTY);
        return (ENXIO);
    }

    ZFS_ENTER(zfsvfs);

    ASSERT(vn_has_cached_data(vp));
    ASSERT(zp->z_dbuf_held);

    if (upl == (upl_t)NULL) {
        panic("zfs_vnop_pageout: no upl!");
    }
    if (len <= 0) {
        printf("zfs_vnop_pageout: invalid size %ld", len);
        if (!(flags & UPL_NOCOMMIT))
            (void) ubc_upl_abort(upl, 0);
        err = EINVAL;
        goto exit;
    }
    if (vnode_vfsisrdonly(vp)) {
        if (!(flags & UPL_NOCOMMIT))
            ubc_upl_abort_range(upl, upl_offset, len,
                                UPL_ABORT_FREE_ON_EMPTY);
        err = EROFS;
        goto exit;
    }
    filesz = zp->z_size; /* get consistent copy of zp_size */
    if ((off < 0) || (off >= filesz) ||
        (off & PAGE_MASK_64) || (len & PAGE_MASK)) {
        if (!(flags & UPL_NOCOMMIT))
            ubc_upl_abort_range(upl, upl_offset, len,
                                UPL_ABORT_FREE_ON_EMPTY);
        err = EINVAL;
        goto exit;
    }
    len = MIN(len, filesz - off);
 top:
    rl = zfs_range_lock(zp, off, len, RL_WRITER);
    /*
     * Can't push pages past end-of-file.
     */
    filesz = zp->z_size;
    if (off >= filesz) {
        /* ignore all pages */
        err = 0;
        goto out;
    } else if (off + len > filesz) {
#if 0
        int npages = btopr(filesz - off);
        page_t *trunc;

        page_list_break(&pp, &trunc, npages);
        /* ignore pages past end of file */
        if (trunc)
            pvn_write_done(trunc,  flags);
#endif
        len = filesz - off;
    }

    tx = dmu_tx_create(zfsvfs->z_os);
    dmu_tx_hold_write(tx, zp->z_id, off, len);
    dmu_tx_hold_bonus(tx, zp->z_id);
    err = dmu_tx_assign(tx, TXG_NOWAIT);
    if (err != 0) {
        if (err == ERESTART) {
            zfs_range_unlock(rl);
            dmu_tx_wait(tx);
            dmu_tx_abort(tx);
            goto top;
        }
        dmu_tx_abort(tx);
        goto out;
    }
    if (len <= PAGESIZE) {
        caddr_t va;
        ASSERT3U(len, <=, PAGESIZE);
        ubc_upl_map(upl, (vm_offset_t *)&va);
        va += upl_offset;
        dmu_write(zfsvfs->z_os, zp->z_id, off, len, va, tx);
        ubc_upl_unmap(upl);
    } else {
        err = dmu_write_pages(zfsvfs->z_os, zp->z_id, off, len, upl, tx);
    }

	if (err == 0) {
		uint64_t mtime[2], ctime[2];
		sa_bulk_attr_t bulk[3];
		int count = 0;

		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL,
		    &mtime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL,
		    &ctime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
		    &zp->z_pflags, 8);
		zfs_tstamp_update_setup(zp, CONTENT_MODIFIED, mtime, ctime,
		    B_TRUE);
		zfs_log_write(zfsvfs->z_log, tx, TX_WRITE, zp, off, len, 0);
	}
    dmu_tx_commit(tx);

 out:
    zfs_range_unlock(rl);
    if (flags & UPL_IOSYNC)
        zil_commit(zfsvfs->z_log, zp->z_id);

    if (!(flags & UPL_NOCOMMIT)) {
        if (err)
            ubc_upl_abort_range(upl, upl_offset, ap->a_size,
                                UPL_ABORT_ERROR |
                                UPL_ABORT_FREE_ON_EMPTY);
        else
            ubc_upl_commit_range(upl, upl_offset, ap->a_size,
                                 UPL_COMMIT_CLEAR_DIRTY |
                                 UPL_COMMIT_FREE_ON_EMPTY);
    }
 exit:
    ZFS_EXIT(zfsvfs);

    return (err);

}

static int
zfs_vnop_mmap(
	struct vnop_mmap_args /* {
		struct vnode *a_vp;
		int a_fflags;
		kauth_cred_t a_cred;
		struct proc *a_p;
	} */ *ap)
{
    struct vnode *vp = ap->a_vp;
    znode_t *zp = VTOZ(vp);
    zfsvfs_t *zfsvfs = zp->z_zfsvfs;

    dprintf("+vnop_mmap\n");

    ZFS_ENTER(zfsvfs);

    if ( !vnode_isreg(vp) ) {
        ZFS_EXIT(zfsvfs);
        return (ENODEV);
    }

	mutex_enter(&zp->z_lock);
    zp->z_is_mapped = 1;
	mutex_exit(&zp->z_lock);

    ZFS_EXIT(zfsvfs);
    return (0);
}

static int
zfs_vnop_inactive(
	struct vnop_inactive_args /* {
		struct vnode *a_vp;
		vfs_context_t a_context;
	} */ *ap)
{
	struct vnode *vp = ap->a_vp;
	DECLARE_CRED(ap);

    dprintf("+vnop_inactive\n");
	zfs_inactive(vp, cr, NULL);
    dprintf("-vnop_inactive\n");
	return (0);
}

static int
zfs_vnop_reclaim(
	struct vnop_reclaim_args /* {
		struct vnode *a_vp;
		vfs_context_t a_context;
	} */ *ap)
{
	struct vnode	*vp = ap->a_vp;
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ASSERT(zp != NULL);

    dprintf("+vnop_reclaim %p\n", vp);

	/* Destroy the vm object and flush associated pages. */
#ifndef __APPLE__
	vnode_destroy_vobject(vp);
#endif

	/*
	 * z_teardown_inactive_lock protects from a race with
	 * zfs_znode_dmu_fini in zfsvfs_teardown during
	 * force unmount.
	 */
	rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
    dprintf("reclaim %p\n", zp->z_sa_hdl);
	if (zp->z_sa_hdl == NULL)
		zfs_znode_free(zp);
	else
		zfs_zinactive(zp);
	rw_exit(&zfsvfs->z_teardown_inactive_lock);

#ifndef __APPLE__
	vp->v_data = NULL;
#else
    vnode_clearfsnode(vp); /* vp->v_data = NULL */
	vnode_removefsref(vp); /* ADDREF from vnode_create */
#endif
    dprintf("-reclaim\n");
	return (0);
}

static int
zfs_vnop_mknod(
	struct vnop_mknod_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *vap;
		vfs_context_t a_context;
	} */ *ap)
{

	return (zfs_vnop_create((struct vnop_create_args *)ap));
}

static int
zfs_vnop_allocate(
	struct vnop_allocate_args /* {
		struct vnode *a_vp;
		off_t a_length;
		u_int32_t a_flags;
		off_t *a_bytesallocated;
		off_t a_offset;
		vfs_context_t a_context;
	} */ *ap)
{

	return (0);
}

static int
zfs_vnop_whiteout(
	struct vnop_whiteout_args /* {
		struct vnode *a_dvp;
		struct componentname *a_cnp;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap)
{

	return (0);
}

static int
zfs_vnop_pathconf(
	struct vnop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		register_t *a_retval;
		vfs_context_t a_context;
	} */ *ap)
{

	return (0);
}

static int
zfs_vnop_getxattr(
	struct vnop_getxattr_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_vp;
		char *a_name;
		struct uio *a_uio;
		size_t *a_size;
		int a_options;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
    struct uio *uio = ap->a_uio;
	struct componentname  cn;
	int  error;

    dprintf("+getxattr vp %p\n", ap->a_vp);

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

#if 0
	if (zp->z_xattr == 0) {
		error = ENOATTR;
		goto out;
	}
#endif

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, 0)) ) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	/* Lookup the attribute name. */
	if ( (error = zfs_dirlook(VTOZ(xdvp), ap->a_name, &xvp, 0, NULL, &cn)) ) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	/* Read the attribute data. */
	if (uio == NULL) {
		znode_t  *xzp = VTOZ(xvp);

		mutex_enter(&xzp->z_lock);
		*ap->a_size = (size_t)xzp->z_size;
		mutex_exit(&xzp->z_lock);
	} else {
		error = VNOP_READ(xvp, uio, 0, ap->a_context);
	}
out:
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

    dprintf("-getxattr vp %p : %d\n", ap->a_vp, error);

	return (error);
}

static int
zfs_vnop_setxattr(
	struct vnop_setxattr_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_vp;
		char *a_name;
		struct uio *a_uio;
		int a_options;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio *uio = ap->a_uio;
	int  flag;
	int  error;

    dprintf("+setxattr vp %p\n", ap->a_vp);

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (strlen(ap->a_name) >= ZAP_MAXNAMELEN) {
		error = ENAMETOOLONG;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) ) {
		goto out;
	}

	if (ap->a_options & XATTR_CREATE)
		flag = ZNEW;     /* expect no pre-existing entry */
	else if (ap->a_options & XATTR_REPLACE)
		flag = ZEXISTS;  /* expect an existing entry */
	else
		flag = 0;

	/* Lookup or create the named attribute. */
	error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name,
	                         VTOZ(vp)->z_mode, cr, &xvp, flag);
	if (error)
		goto out;

	/* Write the attribute data. */
	ASSERT(uio != NULL);
	error = VNOP_WRITE(xvp, uio, 0, ap->a_context);

out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	if (xvp) {
		vnode_put(xvp);
	}
	ZFS_EXIT(zfsvfs);

    dprintf("-setxattr vp %p: err %d\n", ap->a_vp, error);

	return (error);
}

static int
zfs_vnop_removexattr(
	struct vnop_removexattr_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_vp;
		char *a_name;
		int a_options;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);

	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct vnop_remove_args  args;
	struct componentname  cn;
	int  error;


    dprintf("+removexattr vp %p\n", ap->a_vp);

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

#if 0
	if (zp->z_phys->zp_xattr == 0) {
		error = ENOATTR;
		goto out;
	}
#endif

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, 0)) ) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = DELETE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	/* Lookup the attribute name. */
	if ( (error = zfs_dirlook(VTOZ(xdvp), ap->a_name, &xvp, 0, NULL, &cn)) ) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	error = zfs_remove(xdvp, ap->a_name, cr, ct, /*flags*/0);

out:
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

    dprintf("-removexattr vp %p: error %d\n", ap->a_vp, error);

	return (error);

}

static int
zfs_vnop_listxattr(
	struct vnop_listxattr_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_vp;
		char *a_name;
		struct uio *a_uio;
		size_t *a_size;
		int a_options;
		vfs_context_t a_context;
	} */ *ap)
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio *uio = ap->a_uio;
	zap_cursor_t  zc;
	zap_attribute_t  za;
	objset_t  *os;
	size_t size = 0;
	char  *nameptr;
	char  nfd_name[ZAP_MAXNAMELEN];
	size_t  namelen;
	int  error = 0;

    dprintf("+listxattr vp %p\n", ap->a_vp);

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	/* Do we even have any attributes? */
#if 0
	if (zp->z_phys->zp_xattr == 0) {
		goto out;  /* all done */
	}
#endif

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}
	os = zfsvfs->z_os;

	for (zap_cursor_init(&zc, os, VTOZ(xdvp)->z_id);
	     zap_cursor_retrieve(&zc, &za) == 0;
	     zap_cursor_advance(&zc)) {

		if (xattr_protected(za.za_name))
			continue;     /* skip */

		/*
		 * Mac OS X: non-ascii names are UTF-8 NFC on disk
		 * so convert to NFD before exporting them.
		 */
		namelen = strlen(za.za_name);
		if (!is_ascii_str(za.za_name) &&
		    utf8_normalizestr((const u_int8_t *)za.za_name, namelen,
				      (u_int8_t *)nfd_name, &namelen,
				      sizeof (nfd_name), UTF_DECOMPOSED) == 0) {
			nameptr = nfd_name;
		} else {
			nameptr = &za.za_name[0];
		}

		++namelen;  /* account for NULL termination byte */
		if (uio == NULL) {
			size += namelen;
		} else {
			if (namelen > uio_resid(uio)) {
				error = ERANGE;
				break;
			}
			error = uiomove((caddr_t)nameptr, namelen, UIO_READ, uio);
			if (error) {
				break;
			}
		}
	}
	zap_cursor_fini(&zc);
out:
	if (uio == NULL) {
		*ap->a_size = size;
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

    dprintf("-listxattr vp %p: error %d\n", ap->a_vp, error);
	return (error);
}

#ifdef HAVE_NAMED_STREAMS
static int
zfs_vnop_getnamedstream(
	struct vnop_getnamedstream_args /* {
		struct vnode *a_vp;
		struct vnode **a_svpp;
		char *a_name;
	} */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode **svpp = ap->a_svpp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct componentname  cn;
	int  error = ENOATTR;

    dprintf("+getnamedstream vp %p\n", ap->a_vp);

	*svpp = NULLVP;
	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0 /*||
                                                                                          zp->z_phys->zp_xattr == 0*/) {
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	/* Lookup the attribute name. */
	if ( (error = zfs_dirlook(VTOZ(xdvp), ap->a_name, svpp, 0, NULL, &cn)) ) {
		if (error == ENOENT)
			error = ENOATTR;
	}
out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

    dprintf("-getnamedstream vp %p: error %d\n", ap->a_vp, error);
	return (error);
}

static int
zfs_vnop_makenamedstream_args(
	struct vnop_makenamedstream_args /* {
		struct vnode *a_vp;
		struct vnode **a_svpp;
		char *a_name;
	} */ *ap)
{
	DECLARE_CRED_AND_CONTEXT(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct componentname  cn;
	struct vnode_attr  vattr;
	struct vnop_create_args  args;
	int  error = 0;

    dprintf("+makenamedstream vp %p\n", ap->a_vp);

	*ap->a_svpp = NULLVP;
	ZFS_ENTER(zfsvfs);

	/* Only regular files can have a resource fork stream. */
	if ( !vnode_isreg(vp) ) {
		error = EPERM;
		goto out;
	}

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) ) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = CREATE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, VTOZ(vp)->z_mode & ~S_IFMT);

	error = zfs_create(xdvp, ap->a_name, &vattr, NONEXCL, VTOZ(vp)->z_mode,
                       ap->a_svpp, cr);

out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

    dprintf("-makenamedstream vp %p: error %d\n", ap->a_vp, error);
	return (error);
}

static int
zfs_vnop_removenamedstream(
	struct vnop_removenamedstream_args /* {
		struct vnode *a_vp;
		struct vnode **a_svpp;
		char *a_name;
	} */ *ap)
{
	struct vnode *svp = ap->a_svp;
	znode_t  *zp = VTOZ(svp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	int error = 0;

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* ### MISING CODE ### */
	printf("zfs_vnop_removenamedstream\n");
	error = EPERM;
out:
	ZFS_EXIT(zfsvfs);

	return (ENOTSUP);
}
#endif /* HAVE_NAMED_STREAMS */

static int
zfs_vnop_exchange(
	struct vnop_exchange_args /* {
		struct vnode *a_fvp;
		struct vnode *a_tvp;
		int a_options;
		vfs_context_t a_context;
	} */ *ap)
{

	return (0);
}

static int
zfs_vnop_revoke(
	struct vnop_revoke_args /* {
		struct vnode *a_vp;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap)
{

	return (vn_revoke(ap->a_vp, ap->a_flags, ap->a_context));
}

static int
zfs_vnop_blktooff(
	struct vnop_blktooff_args /* {
		struct vnode *a_vp;
		daddr64_t a_lblkno;
		off_t *a_offset;
	} */ *ap)
{

	return (0);
}

static int
zfs_vnop_offtoblk(
	struct vnop_offtoblk_args /* {
		struct vnode *a_vp;
		off_t a_offset;
		daddr64_t *a_lblkno;
	} */ *ap)
{
    dprintf("+vnop_offtoblk\n");
	return (ENOTSUP);
}

static int
zfs_vnop_blockmap(
	struct vnop_blockmap_args /* {
		struct vnode *a_vp;
		off_t a_foffset;
		size_t a_size;
		daddr64_t *a_bpn;
		size_t *a_run;
		void *a_poff;
		int a_flags;
	} */ *ap)
{
    dprintf("+vnop_blackmap\n");
	return (ENOTSUP);
}

static int
zfs_vnop_strategy(
	struct vnop_strategy_args /* {
		struct buf *a_bp;
	} */ *ap)
{

	return (0);
}

static int
zfs_vnop_select(
	struct vnop_select_args /* {
		struct vnode *a_vp;
		int a_which;
		int a_fflags;
		kauth_cred_t a_cred;
		void *a_wql;
		struct proc *a_p;
	} */ *ap)
{

	return (0);
}

static int
zfs_vnop_readdirattr(
	struct vnop_readdirattr_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_vp;
		struct attrlist *a_alist;
		struct uio *a_uio;
		u_long a_maxcount;
		u_long a_options;
		u_long *a_newstate;
		int *a_eofflag;
		u_long *a_actualcount;
		vfs_context_t a_context;
	} */ *ap)
{

	return (0);
}


/*
 * Predeclare these here so that the compiler assumes that
 * this is an "old style" function declaration that does
 * not include arguments => we won't get type mismatch errors
 * in the initializations that follow.
 */
static int zfs_inval();
static int zfs_isdir();

static int
zfs_inval()
{
	return ((EINVAL));
}

static int
zfs_isdir()
{
	return ((EISDIR));
}


#define VOPFUNC int (*)(void *)

/* Directory vnode operations template */
int (**zfs_dvnodeops) (void *);
struct vnodeopv_entry_desc zfs_dvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_vnop_mknod},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_write_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_vnop_mkdir},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_vnop_symlink},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{&vnop_readdirattr_desc, (VOPFUNC)zfs_vnop_readdirattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_dvnodeop_opv_desc =
{ &zfs_dvnodeops, zfs_dvnodeops_template };

/* Regular file vnode operations template */
int (**zfs_fvnodeops) (void *);
struct vnodeopv_entry_desc zfs_fvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_pagein_desc,	(VOPFUNC)zfs_vnop_pagein},
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageout},
	{&vnop_mmap_desc,	(VOPFUNC)zfs_vnop_mmap},
	{&vnop_blktooff_desc,	(VOPFUNC)zfs_vnop_blktooff},
	{&vnop_offtoblk_desc,	(VOPFUNC)zfs_vnop_offtoblk},
	{&vnop_blockmap_desc,	(VOPFUNC)zfs_vnop_blockmap},
	{&vnop_strategy_desc,	(VOPFUNC)zfs_vnop_strategy},
	{&vnop_allocate_desc,   (VOPFUNC)zfs_vnop_allocate},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_exchange_desc,	(VOPFUNC)zfs_vnop_exchange},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
#ifdef HAVE_NAMED_STREAMS
	{&vnop_getnamedstream_desc,	(VOPFUNC)zfs_vnop_getnamedstream},
	{&vnop_makenamedstream_desc,	(VOPFUNC)zfs_vnop_makenamedstream},
	{&vnop_removenamedstream_desc,	(VOPFUNC)zfs_vnop_removenamedstream},
#endif
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_fvnodeop_opv_desc =
{ &zfs_fvnodeops, zfs_fvnodeops_template };

/* Symbolic link vnode operations template */
int (**zfs_symvnodeops) (void *);
struct vnodeopv_entry_desc zfs_symvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_readlink_desc,	(VOPFUNC)zfs_vnop_readlink},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_symvnodeop_opv_desc =
{ &zfs_symvnodeops, zfs_symvnodeops_template };

/* Extended attribtue directory vnode operations template */
int (**zfs_xdvnodeops) (void *);
struct vnodeopv_entry_desc zfs_xdvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_inval},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_inval},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_inval},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_xdvnodeop_opv_desc =
{ &zfs_xdvnodeops, zfs_xdvnodeops_template };

/* Error vnode operations template */
int (**zfs_evnodeops) (void *);
struct vnodeopv_entry_desc zfs_evnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_evnodeop_opv_desc =
{ &zfs_evnodeops, zfs_evnodeops_template };






/*
 * Alas, OSX does not let us create a vnode, and assign the vtype later
 * and we do not know what type we want here. Is there a way around this?
 * We could allocate any old vnode, then recycle it to ensure a vnode is
 * spare?
 */
void getnewvnode_reserve(int num)
{
    return;
}

void getnewvnode_drop_reserve()
{
    return;
}

/*
 * Get new vnode for znode.
 *
 * This function uses zp->z_zfsvfs, zp->z_mode, zp->z_flags, zp->z_id
 * and sets zp->z_vnode, zp->z_vid
 */
int zfs_znode_getvnode(znode_t *zp, zfsvfs_t *zfsvfs, struct vnode **vpp)
{
	struct vnode_fsparam vfsp;

    dprintf("getvnode zp %p with vpp %p zfsvfs %p vfs %p\n",
           zp, vpp, zfsvfs, zfsvfs->z_vfs);

    if (zp->z_vnode)
        panic("zp %p vnode already set\n", zp->z_vnode);

	bzero(&vfsp, sizeof (vfsp));
	vfsp.vnfs_str = "zfs";
	vfsp.vnfs_mp = zfsvfs->z_vfs;
	vfsp.vnfs_vtype = IFTOVT((mode_t)zp->z_mode);
	vfsp.vnfs_fsnode = zp;
	vfsp.vnfs_flags = VNFS_ADDFSREF;

	/*
	 * XXX HACK - workaround missing vnode_setnoflush() KPI...
	 */
	/* Tag system files */
#if 0
	if ((zp->z_flags & ZFS_XATTR) &&
	    (zfsvfs->z_last_unmount_time == 0xBADC0DE) &&
	    (zfsvfs->z_last_mtime_synced == zp->z_parent)) {
		vfsp.vnfs_marksystem = 1;
	}
#endif

	/* Tag root directory */
	if (zp->z_id == zfsvfs->z_root) {
		vfsp.vnfs_markroot = 1;
	}

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
        {
            uint64_t rdev;
            VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_RDEV(zfsvfs),
                             &rdev, sizeof (rdev)) == 0);

            vfsp.vnfs_rdev = zfs_cmpldev(rdev);
        }
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

    while (vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, vpp) != 0);

    dprintf("Assigned zp %p with vp %p\n", zp, *vpp);

	vnode_settag(*vpp, VT_ZFS);

	zp->z_vid = vnode_vid(*vpp);
    zp->z_vnode = *vpp;
    /*
     * FreeBSD version does not hold a ref on the new vnode
     */
    //vnode_put(*vpp);
    return 0;
}

/*
 * Maybe these should live in vfsops
 */
int zfs_vfsops_init(void)
{
	struct vfs_fsentry vfe;

    zfs_init();

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

    zfs_fini();

    return vfs_fsremove(zfs_vfsconf);
}


