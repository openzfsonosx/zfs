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
#include <sys/zfs_ctldir.h>

#include <sys/xattr.h>
#include <sys/utfconv.h>
#include <sys/ubc.h>
#include <sys/callb.h>
#include <sys/unistd.h>

#ifdef _KERNEL
#include <sys/sysctl.h>
unsigned int debug_vnop_osx_printf = 0;
unsigned int zfs_vnop_ignore_negatives = 0;
unsigned int zfs_vnop_ignore_positives = 0;
unsigned int zfs_vnop_create_negatives = 1;
/*
 * Default kern.maxvnodes = 66560,
 * allow ZFS to use half the system?
 */
unsigned int zfs_vnop_reclaim_throttle = 33280;
#endif

#define	DECLARE_CRED(ap) \
	cred_t *cr = (cred_t *)vfs_context_ucred((ap)->a_context)
#define	DECLARE_CONTEXT(ap) \
	caller_context_t *ct = (caller_context_t *)(ap)->a_context
#define	DECLARE_CRED_AND_CONTEXT(ap)	\
	DECLARE_CRED(ap);		\
	DECLARE_CONTEXT(ap)

#undef dprintf
#define	dprintf if (debug_vnop_osx_printf) printf
//#define	dprintf(...) if (debug_vnop_osx_printf) {printf(__VA_ARGS__);delay(hz>>2);}

/* Move this somewhere else, maybe autoconf? */
#define	HAVE_NAMED_STREAMS 1

/* #define WITH_SEARCHFS */


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

extern struct vnodeopv_desc zfsctl_ops_root;
extern struct vnodeopv_desc zfsctl_ops_snapdir;
extern struct vnodeopv_desc zfsctl_ops_snapshot;

#define	ZFS_VNOP_TBL_CNT	8

static void zfs_vnop_throttle_reclaim(zfsvfs_t *zfsvfs);


static struct vnodeopv_desc *zfs_vnodeop_opv_desc_list[ZFS_VNOP_TBL_CNT] =
{
	&zfs_dvnodeop_opv_desc,
	&zfs_fvnodeop_opv_desc,
	&zfs_symvnodeop_opv_desc,
	&zfs_xdvnodeop_opv_desc,
	&zfs_evnodeop_opv_desc,
	&zfsctl_ops_root,
	&zfsctl_ops_snapdir,
	&zfsctl_ops_snapshot,
};

static vfstable_t zfs_vfsconf;

int
zfs_vfs_init(__unused struct vfsconf *vfsp)
{
	return (0);
}

int
zfs_vfs_start(__unused struct mount *mp, __unused int flags,
    __unused vfs_context_t context)
{
	return (0);
}

int
zfs_vfs_quotactl(__unused struct mount *mp, __unused int cmds,
    __unused uid_t uid, __unused caddr_t datap, __unused vfs_context_t context)
{
	return (ENOTSUP);
}


static int
zfs_vnop_open(struct vnop_open_args *ap)
#if 0
	struct vnop_open_args {
		struct vnode	*a_vp;
		int		a_mode;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int err = 0;

	err = zfs_open(&ap->a_vp, ap->a_mode, cr, ct);

	if (err) printf("zfs_open() failed %d\n", err);

	return (err);
}

static int
zfs_vnop_close(struct vnop_close_args *ap)
#if 0
	struct vnop_close_args {
		struct vnode	*a_vp;
		int		a_fflag;
		vfs_context_t	a_context;
	};
#endif
{
	int count = 1;
	int offset = 0;
	DECLARE_CRED_AND_CONTEXT(ap);

	return (zfs_close(ap->a_vp, ap->a_fflag, count, offset, cr, ct));
}

static int
zfs_vnop_ioctl(struct vnop_ioctl_args *ap)
#if 0
	struct vnop_ioctl_args {
		struct vnode	*a_vp;
		u_long		a_command;
		caddr_t		a_data;
		int		a_fflag;
		kauth_cred_t	a_cred;
		struct proc	*a_p;
	};
#endif
{
	/* OS X has no use for zfs_ioctl(). */
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error = 0;
	DECLARE_CRED_AND_CONTEXT(ap);

	dprintf("vnop_ioctl %08lx\n", ap->a_command);

	ZFS_ENTER(zfsvfs);

	switch (ap->a_command) {
	case F_FULLFSYNC:
		/* zfs_fsync also calls ZFS_ENTER */
		error = zfs_fsync(ap->a_vp, /* flag */0, cr, ct);
		break;
	case SPOTLIGHT_GET_MOUNT_TIME:
	case SPOTLIGHT_FSCTL_GET_MOUNT_TIME:
		*(uint32_t *)ap->a_data = zfsvfs->z_mount_time;
		break;
	case SPOTLIGHT_GET_UNMOUNT_TIME:
	case SPOTLIGHT_FSCTL_GET_LAST_MTIME:
		*(uint32_t *)ap->a_data = zfsvfs->z_last_unmount_time;
		break;
	case F_RDADVISE:
		dprintf("vnop_ioctl: F_RDADVISE\n");
		break;
	default:
		dprintf("vnop_ioctl: Unknown ioctl %02lx ('%lu' + %lu)\n",
		    ap->a_command, (ap->a_command&0xff00)>>8,
		    ap->a_command&0xff);
		error = ENOTTY;
	}
	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_read(struct vnop_read_args *ap)
#if 0
	struct vnop_read_args {
		struct vnode	*a_vp;
		struct uio	*a_uio;
		int		a_ioflag;
		vfs_context_t	a_context;
	};
#endif
{
	int ioflag = zfs_ioflags(ap->a_ioflag);
	int error;
	/* uint64_t resid; */
	DECLARE_CRED_AND_CONTEXT(ap);

	/* resid = uio_resid(ap->a_uio); */
	error = zfs_read(ap->a_vp, ap->a_uio, ioflag, cr, ct);

	/* dprintf("vnop_read(%d) ->%d\n", resid, error); */
	return (error);
}

static int
zfs_vnop_write(struct vnop_write_args *ap)
#if 0
	struct vnop_write_args {
		struct vnode	*a_vp;
		struct uio	*a_uio;
		int		a_ioflag;
		vfs_context_t	a_context;
	};
#endif
{
	int ioflag = zfs_ioflags(ap->a_ioflag);
	int error;
	/* uint64_t resid; */
	DECLARE_CRED_AND_CONTEXT(ap);

	dprintf("zfs_vnop_write(vp %p, offset 0x%llx size 0x%llx\n",
	    ap->a_vp, uio_offset(ap->a_uio), uio_resid(ap->a_uio));

	/* resid=uio_resid(ap->a_uio); */
	error = zfs_write(ap->a_vp, ap->a_uio, ioflag, cr, ct);

	/*
	 * Mac OS X: pageout requires that the UBC file size be current.
	 * Possibly, we could update it only if size has changed.
	 */
	/* if (tx_bytes != 0) { */
	if (!error) {
		ubc_setsize(ap->a_vp, VTOZ(ap->a_vp)->z_size);
	}

	return (error);
}

static int
zfs_vnop_access(struct vnop_access_args *ap)
#if 0
	struct vnop_access_args {
		struct vnodeop_desc *a_desc;
		struct vnode	a_vp;
		int		a_action;
		vfs_context_t	a_context;
	};
#endif
{
	int error = ENOTSUP;
	int action = ap->a_action;
	int mode = 0;
	DECLARE_CRED_AND_CONTEXT(ap);

	/*
	 * KAUTH_VNODE_READ_EXTATTRIBUTES, as well?
	 * KAUTH_VNODE_WRITE_EXTATTRIBUTES
	 */
	if (action & KAUTH_VNODE_READ_DATA)
		mode |= VREAD;
	if (action & KAUTH_VNODE_WRITE_DATA)
		mode |= VWRITE;
	if (action & KAUTH_VNODE_EXECUTE)
		mode |= VEXEC;

	dprintf("vnop_access: action %04x -> mode %04x\n", action, mode);
	error = zfs_access(ap->a_vp, mode, 0, cr, ct);

	return (error);
}


void
zfs_finder_keep_hardlink(struct vnode *vp, char *filename)
{
	if (vp && VTOZ(vp)) {
		znode_t *zp = VTOZ(vp);

		/*
		 * hard link references?
		 * Read the comment in zfs_getattr_znode_unlocked for the reason
		 * for this hackery.
		 */
		if ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG)) {
			dprintf("keep_hardlink: %p has refs %llu\n", vp,
			    zp->z_links);
			strlcpy(zp->z_finder_hardlink_name, filename,
			    MAXPATHLEN);
		}
	}
}


static int
zfs_vnop_lookup(struct vnop_lookup_args *ap)
#if 0
	struct vnop_lookup_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		vfs_context_t	a_context;
	};
#endif
{
	struct componentname *cnp = ap->a_cnp;
	DECLARE_CRED(ap);
	int error;
	char *filename = NULL;
	int negative_cache = 0;
	int filename_num_bytes = 0;

	*ap->a_vpp = NULL;	/* In case we return an error */

	/*
	 * Darwin uses namelen as an optimisation, for example it can be
	 * set to 5 for the string "alpha/beta" to look up "alpha". In this
	 * case we need to copy it out to null-terminate.
	 */
	if (cnp->cn_nameptr[cnp->cn_namelen] != 0) {
		filename_num_bytes = cnp->cn_namelen + 1;
		filename = (char*)kmem_alloc(filename_num_bytes, KM_SLEEP);
		if (filename == NULL)
			return (ENOMEM);
		bcopy(cnp->cn_nameptr, filename, cnp->cn_namelen);
		filename[cnp->cn_namelen] = '\0';
	}

#if 1
	/*
	 * cache_lookup() returns 0 for no-entry
	 * -1 for cache found (a_vpp set)
	 * ENOENT for negative cache
	 */
	error = cache_lookup(ap->a_dvp, ap->a_vpp, cnp);
	if (error) {
		/* We found a cache entry, positive or negative. */
		if (error == -1) {	/* Positive entry? */
			if (!zfs_vnop_ignore_positives) {
				error = 0;
				goto exit;	/* Positive cache, return it */
			}
			/* Release iocount held by cache_lookip */
			vnode_put(*ap->a_vpp);
		}
		/* Negatives are only followed if not CREATE, from HFS+. */
		if (cnp->cn_nameiop != CREATE) {
			if (!zfs_vnop_ignore_negatives) {
				goto exit; /* Negative cache hit */
			}
			negative_cache = 1;
		}
	}
#endif

	dprintf("+vnop_lookup '%s' %s\n", filename ? filename : cnp->cn_nameptr,
			negative_cache ? "negative_cache":"");

	error = zfs_lookup(ap->a_dvp, filename ? filename : cnp->cn_nameptr,
	    ap->a_vpp, cnp, cnp->cn_nameiop, cr, /* flags */ 0);
	/* flags can be LOOKUP_XATTR | FIGNORECASE */

#if 1
	/*
	 * It appears that VFS layer adds negative cache entries for us, so
	 * we do not need to add them here, or they are duplicated.
	 */
	if ((error == ENOENT) && zfs_vnop_create_negatives) {
		if ((ap->a_cnp->cn_nameiop == CREATE ||
		    ap->a_cnp->cn_nameiop == RENAME) &&
		    (cnp->cn_flags & ISLASTCN)) {
			error = EJUSTRETURN;
			goto exit;
		}
		/* Insert name into cache (as non-existent) if appropriate. */
		if ((cnp->cn_flags & MAKEENTRY) &&
		    ap->a_cnp->cn_nameiop != CREATE) {
			cache_enter(ap->a_dvp, NULL, ap->a_cnp);
			dprintf("Negative-cache made for '%s'\n",
			    filename ? filename : cnp->cn_nameptr);
		}
	} /* ENOENT */
#endif

#if 0
	if (!error && negative_cache) {
		printf("[ZFS] Incorrect negative_cache entry for '%s'\n",
		    filename ? filename : cnp->cn_nameptr);
		cache_purge_negatives(ap->a_dvp);
	}
#endif


exit:
	/* Set both for lookup and positive cache */
	if (!error)
		zfs_finder_keep_hardlink(*ap->a_vpp,
		    filename ? filename : cnp->cn_nameptr);
	if (filename)
		kmem_free(filename, filename_num_bytes);

	if (!error && ap->a_vpp && *ap->a_vpp && VTOZ(*ap->a_vpp))
		zfs_vnop_throttle_reclaim(VTOZ(*ap->a_vpp)->z_zfsvfs);

	dprintf("-vnop_lookup %d\n", error);
	return (error);
}

static int
zfs_vnop_create(struct vnop_create_args *ap)
#if 0
	struct vnop_create_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	struct componentname *cnp = ap->a_cnp;
	vattr_t *vap = ap->a_vap;
	DECLARE_CRED(ap);
	vcexcl_t excl;
	int mode = 0;	/* FIXME */
	int error;

	dprintf("vnop_create: '%s'\n", cnp->cn_nameptr);

	/*
	 * extern int zfs_create(struct vnode *dvp, char *name, vattr_t *vap,
	 *     int excl, int mode, struct vnode **vpp, cred_t *cr);
	 */
	excl = (vap->va_vaflags & VA_EXCLUSIVE) ? EXCL : NONEXCL;

	error = zfs_create(ap->a_dvp, cnp->cn_nameptr, vap, excl, mode,
	    ap->a_vpp, cr);
	if (!error)
		cache_purge_negatives(ap->a_dvp);

	return (error);
}

static int
zfs_vnop_remove(struct vnop_remove_args *ap)
#if 0
	struct vnop_remove_args {
		struct vnode	*a_dvp;
		struct vnode	*a_vp;
		struct componentname *a_cnp;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_remove\n");

	/*
	 * extern int zfs_remove ( struct vnode *dvp, char *name, cred_t *cr,
	 *     caller_context_t *ct, int flags);
	 */
	error = zfs_remove(ap->a_dvp, ap->a_cnp->cn_nameptr, cr, ct,
	    /* flags */0);
	if (!error)
		cache_purge(ap->a_vp);

	return (error);
}

static int
zfs_vnop_mkdir(struct vnop_mkdir_args *ap)
#if 0
	struct vnop_mkdir_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_mkdir '%s'\n", ap->a_cnp->cn_nameptr);

#if 0
	/* Let's deny OS X fseventd for now */
	if (ap->a_cnp->cn_nameptr &&
	    strcmp(ap->a_cnp->cn_nameptr, ".fseventsd") == 0)
		return (EINVAL);
#endif

#if 0
	/* spotlight for now */
	if (ap->a_cnp->cn_nameptr &&
	    strcmp(ap->a_cnp->cn_nameptr, ".Spotlight-V100") == 0)
		return (EINVAL);
#endif
	/*
	 * extern int zfs_mkdir(struct vnode *dvp, char *dirname, vattr_t *vap,
	 *     struct vnode **vpp, cred_t *cr, caller_context_t *ct, int flags,
	 *     vsecattr_t *vsecp);
	 */
	error = zfs_mkdir(ap->a_dvp, ap->a_cnp->cn_nameptr, ap->a_vap,
	    ap->a_vpp, cr, ct, /* flags */0, /* vsecp */NULL);
	if (!error)
		cache_purge_negatives(ap->a_dvp);

	return (error);
}

static int
zfs_vnop_rmdir(struct vnop_rmdir_args *ap)
#if 0
	struct vnop_rmdir_args {
		struct vnode	*a_dvp;
		struct vnode	*a_vp;
		struct componentname *a_cnp;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_rmdir\n");

	/*
	 * extern int zfs_rmdir(struct vnode *dvp, char *name,
	 *     struct vnode *cwd, cred_t *cr, caller_context_t *ct, int flags);
	 */
	error = zfs_rmdir(ap->a_dvp, ap->a_cnp->cn_nameptr, /* cwd */NULL, cr,
	    ct, /* flags */0);
	if (!error)
		cache_purge(ap->a_vp);

	return (error);
}

static int
zfs_vnop_readdir(struct vnop_readdir_args *ap)
#if 0
	struct vnop_readdir_args {
		struct vnode	a_vp;
		struct uio	*a_uio;
		int		a_flags;
		int		*a_eofflag;
		int		*a_numdirent;
		vfs_context_t	a_context;
	};
#endif
{
	int error;
	DECLARE_CRED(ap);

	dprintf("+readdir: %p\n", ap->a_vp);

	/*
	 * XXX This interface needs vfs_has_feature.
	 * XXX zfs_readdir() also needs to grow support for passing back the
	 * number of entries (OS X/FreeBSD) and cookies (FreeBSD). However,
	 * it should be the responsibility of the OS caller to malloc/free
	 * space for that.
	 */

	/*
	 * extern int zfs_readdir(struct vnode *vp, uio_t *uio, cred_t *cr,
	 *     int *eofp, int flags, int *a_numdirent);
	 */
	*ap->a_numdirent = 0;

	error = zfs_readdir(ap->a_vp, ap->a_uio, cr, ap->a_eofflag, ap->a_flags,
	    ap->a_numdirent);

	/* .zfs dirs can be completely empty */
	if (*ap->a_numdirent == 0)
		*ap->a_numdirent = 2; /* . and .. */

	dprintf("-readdir %d (nument %d)\n", error, *ap->a_numdirent);
	return (error);
}

static int
zfs_vnop_fsync(struct vnop_fsync_args *ap)
#if 0
	struct vnop_fsync_args {
		struct vnode	*a_vp;
		int		a_waitfor;
		vfs_context_t	a_context;
	};
#endif
{
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs;
	DECLARE_CRED_AND_CONTEXT(ap);
	int err;

	/*
	 * Check if this znode has already been synced, freed, and recycled
	 * by znode_pageout_func.
	 *
	 * XXX What is this? Substitute for Illumos vn_has_cached_data()?
	 */
	if (zp == NULL)
		return (0);

	zfsvfs = zp->z_zfsvfs;

	if (!zfsvfs)
		return (0);

	/*
	 * Because vnode_create() can end up calling fsync, which means we would
	 * sit around waiting for dmu_tx, while higher up in this thread may
	 * have called vnode_create(), while waiting for dmu_tx. We have wrapped
	 * the vnode_create() call with a lock, so we can ignore fsync while
	 * inside vnode_create().
	 */

	if (zfsvfs->z_vnode_create_depth)
		return (0);

	err = zfs_fsync(ap->a_vp, /* flag */0, cr, ct);

	return (err);
}

static int
zfs_vnop_getattr(struct vnop_getattr_args *ap)
#if 0
	struct vnop_getattr_args {
		struct vnode	*a_vp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	int error;
	DECLARE_CRED_AND_CONTEXT(ap);

	/* dprintf("+vnop_getattr zp %p vp %p\n", VTOZ(ap->a_vp), ap->a_vp); */

	error = zfs_getattr(ap->a_vp, ap->a_vap, /* flags */0, cr, ct);
	if (error)
		return (error);

	error = zfs_getattr_znode_unlocked(ap->a_vp, ap->a_vap);
	if (error)
		dprintf("-vnop_getattr '%p' %d\n", (ap->a_vp), error);
	return (error);
}

static int
zfs_vnop_setattr(struct vnop_setattr_args *ap)
#if 0
	struct vnop_setattr_args {
		struct vnode	*a_vp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	vattr_t *vap = ap->a_vap;
	uint_t mask = vap->va_mask;
	int error = 0;

	/* Translate OS X requested mask to ZFS */
	if (VATTR_IS_ACTIVE(vap, va_data_size))
		mask |= AT_SIZE;
	if (VATTR_IS_ACTIVE(vap, va_mode))
		mask |= AT_MODE;
	if (VATTR_IS_ACTIVE(vap, va_uid))
		mask |= AT_UID;
	if (VATTR_IS_ACTIVE(vap, va_gid))
		mask |= AT_GID;
	if (VATTR_IS_ACTIVE(vap, va_access_time))
		mask |= AT_ATIME;
	if (VATTR_IS_ACTIVE(vap, va_modify_time))
		mask |= AT_MTIME;
	/*
	 * We abuse AT_CTIME here, to function as a place holder for "creation
	 * time," since you are not allowed to change "change time" in POSIX,
	 * and we don't have an AT_CRTIME.
	 */
	if (VATTR_IS_ACTIVE(vap, va_create_time))
		mask |= AT_CTIME;
	/*
	 * if (VATTR_IS_ACTIVE(vap, va_backup_time))
	 *     mask |= AT_BTIME; // really?
	 */
	/*
	 * Both 'flags' and 'acl' can come to setattr, but without 'mode' set.
	 * However, ZFS assumes 'mode' is also set. We need to look up 'mode' in
	 * this case.
	 */
	if ((VATTR_IS_ACTIVE(vap, va_flags) || VATTR_IS_ACTIVE(vap, va_acl)) &&
	    !VATTR_IS_ACTIVE(vap, va_mode)) {
		znode_t *zp = VTOZ(ap->a_vp);
		uint64_t mode;

		mask |= AT_MODE;

		dprintf("fetching MODE for FLAGS or ACL\n");
		ZFS_ENTER(zp->z_zfsvfs);
		ZFS_VERIFY_ZP(zp);
		(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_MODE(zp->z_zfsvfs), &mode,
		    sizeof (mode));
		vap->va_mode = mode;
		ZFS_EXIT(zp->z_zfsvfs);
	}
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		znode_t *zp = VTOZ(ap->a_vp);

		/* Map OS X file flags to zfs file flags */
		zfs_setbsdflags(zp, vap->va_flags);
		dprintf("OS X flags %08x changed to ZFS %04llx\n",
		    vap->va_flags, zp->z_pflags);
		vap->va_flags = zp->z_pflags;

	}
	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		mask |= AT_ACL;
	}

	vap->va_mask = mask;
	error = zfs_setattr(ap->a_vp, ap->a_vap, /* flag */0, cr, ct);

	dprintf("vnop_setattr: called on vp %p with mask %04x, err=%d\n",
	    ap->a_vp, mask, error);

	if (!error) {
		/* If successful, tell OS X which fields ZFS set. */
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
		if (VATTR_IS_ACTIVE(vap, va_change_time))
			VATTR_SET_SUPPORTED(vap, va_change_time);
		if (VATTR_IS_ACTIVE(vap, va_create_time))
			VATTR_SET_SUPPORTED(vap, va_create_time);
		if (VATTR_IS_ACTIVE(vap, va_backup_time))
			VATTR_SET_SUPPORTED(vap, va_backup_time);
		if (VATTR_IS_ACTIVE(vap, va_flags)) {
			VATTR_SET_SUPPORTED(vap, va_flags);
		}
	}

	if (error)
		printf("vnop_setattr return failure %d\n", error);
	return (error);
}

static int
zfs_vnop_rename(struct vnop_rename_args *ap)
#if 0
	struct vnop_rename_args {
		struct vnode	*a_fdvp;
		struct vnode	*a_fvp;
		struct componentname *a_fcnp;
		struct vnode	*a_tdvp;
		struct vnode	*a_tvp;
		struct componentname *a_tcnp;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_rename\n");

	/*
	 * extern int zfs_rename(struct vnode *sdvp, char *snm,
	 *     struct vnode *tdvp, char *tnm, cred_t *cr, caller_context_t *ct,
	 *     int flags);
	 */
	error = zfs_rename(ap->a_fdvp, ap->a_fcnp->cn_nameptr, ap->a_tdvp,
	    ap->a_tcnp->cn_nameptr, cr, ct, /* flags */0);

	if (!error) {
		cache_purge_negatives(ap->a_fdvp);
		cache_purge_negatives(ap->a_tdvp);
		cache_purge(ap->a_fvp);
		if (ap->a_tvp)
			cache_purge(ap->a_tvp);
	}

	return (error);
}
static int
zfs_vnop_symlink(struct vnop_symlink_args *ap)
#if 0
	struct vnop_symlink_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		char		*a_target;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED(ap);
	int error;

	dprintf("vnop_symlink\n");

	/*
	 * extern int zfs_symlink(struct vnode *dvp, struct vnode **vpp,
	 *     char *name, vattr_t *vap, char *link, cred_t *cr);
	 */

	/* OS X doesn't need to set vap->va_mode? */
	error = zfs_symlink(ap->a_dvp, ap->a_vpp, ap->a_cnp->cn_nameptr,
	    ap->a_vap, ap->a_target, cr);
	if (!error)
		cache_purge_negatives(ap->a_dvp);
	/* XXX zfs_attach_vnode()? */

	return (error);
}


static int
zfs_vnop_readlink(struct vnop_readlink_args *ap)
#if 0
	struct vnop_readlink_args {
		struct vnode	*vp;
		struct uio	*uio;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);

	dprintf("vnop_readlink\n");

	/*
	 * extern int zfs_readlink(struct vnode *vp, uio_t *uio, cred_t *cr,
	 *     caller_context_t *ct);
	 */
	return (zfs_readlink(ap->a_vp, ap->a_uio, cr, ct));
}

static int
zfs_vnop_link(struct vnop_link_args *ap)
#if 0
	struct vnop_link_args {
		struct vnode	*a_vp;
		struct vnode	*a_tdvp;
		struct componentname *a_cnp;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_link\n");

	/* XXX Translate this inside zfs_link() instead. */
	if (vnode_mount(ap->a_vp) != vnode_mount(ap->a_tdvp))
		return (EXDEV);

	/*
	 * XXX Understand why Apple made this comparison in so many places where
	 * others do not.
	 */
	if (ap->a_cnp->cn_namelen >= ZAP_MAXNAMELEN)
		return (ENAMETOOLONG);

	/*
	 * extern int zfs_link(struct vnode *tdvp, struct vnode *svp,
	 *     char *name, cred_t *cr, caller_context_t *ct, int flags);
	 */

	error = zfs_link(ap->a_tdvp, ap->a_vp, ap->a_cnp->cn_nameptr, cr, ct,
	    /* flags */0);
	if (!error)
		vnode_setmultipath(ap->a_vp);

	return (error);
}

static int
zfs_vnop_pagein(struct vnop_pagein_args *ap)
#if 0
	struct vnop_pagein_args {
		struct vnode	*a_vp;
		upl_t		a_pl;
		vm_offset_t	a_pl_offset;
		off_t		a_foffset;
		size_t		a_size;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	/* XXX Crib this from the Apple zfs_vnops.c. */
	struct vnode *vp = ap->a_vp;
	offset_t off = ap->a_f_offset;
	size_t len = ap->a_size;
	upl_t upl = ap->a_pl;
	vm_offset_t upl_offset = ap->a_pl_offset;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	caddr_t vaddr = NULL;
	/* vm_offset_t vaddr = NULL; */
	int flags = ap->a_flags;
	int need_unlock = 0;
	int error = 0;

	dprintf("+vnop_pagein: off 0x%llx size 0x%lx\n", off, len);

	if (upl == (upl_t)NULL)
		panic("zfs_vnop_pagein: no upl!");

	if (len <= 0) {
		dprintf("zfs_vnop_pagein: invalid size %ld", len);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, 0);
		return (EINVAL);
	}

	ZFS_ENTER(zfsvfs);

	ASSERT(vn_has_cached_data(vp));
	/* ASSERT(zp->z_dbuf_held && zp->z_phys); */
	/* can't fault passed EOF */
	if ((off < 0) || (off >= zp->z_size) ||
		(len & PAGE_MASK) || (upl_offset & PAGE_MASK)) {
		dprintf("passed EOF or size error\n");
		ZFS_EXIT(zfsvfs);
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			    (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
		return (EFAULT);
	}

	/*
	 * If we already own the lock, then we must be page faulting in the
	 * middle of a write to this file (i.e., we are writing to this file
	 * using data from a mapped region of the file).
	 */
	if (!rw_write_held(&zp->z_map_lock)) {
		rw_enter(&zp->z_map_lock, RW_WRITER);
		need_unlock = TRUE;
	}

	ubc_upl_map(upl, (vm_offset_t *)&vaddr);
	dprintf("vaddr %p with upl_off 0x%lx\n", vaddr, upl_offset);
	vaddr += upl_offset;
	/*
	 * Fill pages with data from the file.
	 */
	while (len > 0) {
		dprintf("pagein from off 0x%llx into address %p (len 0x%lx)\n",
		    off, vaddr, len);
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
		if (len >= PAGESIZE)
			len -= PAGESIZE;
		else
			len = 0;
	}
	ubc_upl_unmap(upl);

	if (!(flags & UPL_NOCOMMIT)) {
		if (error)
			ubc_upl_abort_range(upl, upl_offset, ap->a_size,
			    (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
		else
			ubc_upl_commit_range(upl, upl_offset, ap->a_size,
			    (UPL_COMMIT_CLEAR_DIRTY |
			    UPL_COMMIT_FREE_ON_EMPTY));
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	/*
	 * We can't grab the range lock for the page as reader which would stop
	 * truncation as this leads to deadlock. So we need to recheck the file
	 * size.
	 */
	if (ap->a_f_offset >= zp->z_size)
		error = EFAULT;
	if (need_unlock)
		rw_exit(&zp->z_map_lock);

	ZFS_EXIT(zfsvfs);
	if (error)
		printf("-pagein %d\n", error);
	return (error);
}


/*
 * This function is faulty and is no longer called.
 * Test case: fsx -S 1385394297
 */
int
osx_write_pages(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    struct page *pp, dmu_tx_t *tx)
{
	dmu_buf_t **dbp;
	int numbufs, i;
	int err;

	if (size == 0)
		return (0);

	err = dmu_buf_hold_array(os, object, offset, size, FALSE, FTAG,
	    &numbufs, &dbp);
	if (err)
		return (err);

	for (i = 0; i < numbufs; i++) {
		int tocpy, copied, thiscpy;
		int bufoff;
		dmu_buf_t *db = dbp[i];
		caddr_t va;

		ASSERT(size > 0);
		ASSERT3U(db->db_size, >=, PAGESIZE);

		bufoff = offset - db->db_offset;
		tocpy = (int)MIN(db->db_size - bufoff, size);

		ASSERT(i == 0 || i == numbufs-1 || tocpy == db->db_size);
		if (tocpy == db->db_size)
			dmu_buf_will_fill(db, tx);
		else
			dmu_buf_will_dirty(db, tx);

		ubc_upl_map((upl_t)pp, (vm_offset_t *)&va);
		for (copied = 0; copied < tocpy; copied += PAGESIZE) {
			thiscpy = MIN(PAGESIZE, tocpy - copied);
			bcopy(va, (char *)db->db_data + bufoff, thiscpy);
			va += PAGESIZE;
			bufoff += PAGESIZE;
		}
		ubc_upl_unmap((upl_t)pp);

		if (tocpy == db->db_size)
			dmu_buf_fill_done(db, tx);

		if (err)
			break;

		offset += tocpy;
		size -= tocpy;
	}
	dmu_buf_rele_array(dbp, numbufs, FTAG);

	return (err);
}


static int
zfs_pageout(zfsvfs_t *zfsvfs, znode_t *zp, upl_t upl, vm_offset_t upl_offset,
			offset_t off, size_t size, int flags)
{
	dmu_tx_t *tx;
	rl_t *rl;
	uint64_t filesz;
	int err = 0;
	size_t len = size;

	dprintf("+vnop_pageout: off 0x%llx len 0x%lx upl_off 0x%lx: "
	    "blksz 0x%x, z_size 0x%llx\n", off, len, upl_offset, zp->z_blksz,
	    zp->z_size);

	ZFS_ENTER(zfsvfs);

	ASSERT(vn_has_cached_data(ZTOV(zp)));
	/* ASSERT(zp->z_dbuf_held); */ /* field no longer present in znode. */

	if (upl == (upl_t)NULL)
		panic("zfs_vnop_pageout: no upl!");

	if (len <= 0) {
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, 0);
		err = EINVAL;
		goto exit;
	}
	if (vnode_vfsisrdonly(ZTOV(zp))) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			    UPL_ABORT_FREE_ON_EMPTY);
		err = EROFS;
		goto exit;
	}

	filesz = zp->z_size; /* get consistent copy of zp_size */

	if (off < 0 || off >= filesz || (off & PAGE_MASK_64) ||
	    (len & PAGE_MASK)) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			    UPL_ABORT_FREE_ON_EMPTY);
		err = EINVAL;
		goto exit;
	}

	uint64_t pgsize = roundup(filesz, PAGESIZE);

	/* Any whole pages beyond the end of the file while we abort */
	if ((size + off) > pgsize) {
		printf("pageout: abort outside pages (rounded 0x%llx > UPLlen "
			   "0x%llx\n", pgsize, size + off);
		ubc_upl_abort_range(upl, pgsize,
		    pgsize - (size + off),
		    UPL_ABORT_FREE_ON_EMPTY);
	}

	len = MIN(len, filesz - off);
top:
	rl = zfs_range_lock(zp, off, len, RL_WRITER);
	/*
	 * can't push pages passed end-of-file
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
			pvn_write_done(trunc, flags);
#endif
		len = filesz - off;
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	if (!tx) {
		printf("ZFS: zfs_vnops_osx: NULL TX encountered!\n");
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			    UPL_ABORT_FREE_ON_EMPTY);
		err = EINVAL;
		goto exit;
	}
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

	caddr_t va;

	ubc_upl_map(upl, (vm_offset_t *)&va);
	va += upl_offset;
	while (len >= PAGESIZE) {
		ssize_t sz = PAGESIZE;

		dprintf("pageout: dmu_write off 0x%llx size 0x%lx\n", off, sz);

		dmu_write(zfsvfs->z_os, zp->z_id, off, sz, va, tx);
		va += sz;
		off += sz;
		len -= sz;
	}

	/*
	 * The last, possibly partial block needs to have the data zeroed that
	 * would extend passed the size of the file.
	 */
	if (len > 0) {
		ssize_t sz = len;

		dprintf("pageout: dmu_writeX off 0x%llx size 0x%lx\n", off, sz);
		dmu_write(zfsvfs->z_os, zp->z_id, off, sz, va, tx);

		va += sz;
		off += sz;
		len -= sz;

		/*
		 * Zero out the remainder of the PAGE that didn't fit within
		 * the file size.
		 */
		bzero(va, PAGESIZE-sz);
		dprintf("zero last 0x%lx bytes.\n", PAGESIZE-sz);

	}
	ubc_upl_unmap(upl);

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
		zfs_log_write(zfsvfs->z_log, tx, TX_WRITE, zp, off, len, 0,
		    NULL, NULL);
	}
	dmu_tx_commit(tx);

out:
	zfs_range_unlock(rl);
	if (flags & UPL_IOSYNC)
		zil_commit(zfsvfs->z_log, zp->z_id);

	if (!(flags & UPL_NOCOMMIT)) {
		if (err)
			ubc_upl_abort_range(upl, upl_offset, size,
			    (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
		else
			ubc_upl_commit_range(upl, upl_offset, size,
			    (UPL_COMMIT_CLEAR_DIRTY |
			    UPL_COMMIT_FREE_ON_EMPTY));
	}
exit:
	ZFS_EXIT(zfsvfs);
	if (err)
		printf("pageout err %d\n", err);
	return (err);
}




static int
zfs_vnop_pageout(struct vnop_pageout_args *ap)
#if 0
	struct vnop_pageout_args {
		struct vnode	*a_vp;
		upl_t		a_pl;
		vm_offset_t	a_pl_offset;
		off_t		a_foffset;
		size_t		a_size;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	int flags = ap->a_flags;
	upl_t upl = ap->a_pl;
	vm_offset_t upl_offset = ap->a_pl_offset;
	size_t len = ap->a_size;
	offset_t off = ap->a_f_offset;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = NULL;

	if (!zp || !zp->z_zfsvfs) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort(upl,
			    (UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY));
		return (ENXIO);
	}

	zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_pageout: off 0x%llx len 0x%lx upl_off 0x%lx: "
	    "blksz 0x%x, z_size 0x%llx\n", off, len, upl_offset, zp->z_blksz,
	    zp->z_size);

	/*
	 * XXX Crib this too, although Apple uses parts of zfs_putapage().
	 * Break up that function into smaller bits so it can be reused.
	 */


	/*
	 * Defer syncs if we are coming through vnode_create()
	 * This is an annoyance of XNU, and we can not open a new TX
	 * as we are already in a TX. *this thread* needs to go back
	 * and we launch another to handle this pageout request
	 */
	if (zfsvfs->z_vnode_create_depth) {

		printf("ZFS: Ditching pageout request\n");

		ubc_upl_abort(upl,
					  (UPL_ABORT_UNAVAILABLE | UPL_ABORT_FREE_ON_EMPTY));
		return 0;
	}

	return zfs_pageout(zfsvfs, zp, upl, upl_offset, ap->a_f_offset,
					   len, flags);

}


static int
zfs_vnop_mmap(struct vnop_mmap_args *ap)
#if 0
	struct vnop_mmap_args {
		struct vnode	*a_vp;
		int		a_fflags;
		kauth_cred_t	a_cred;
		struct proc	*a_p;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_mmap\n");

	ZFS_ENTER(zfsvfs);

	if (!vnode_isreg(vp)) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}
	mutex_enter(&zp->z_lock);
	zp->z_is_mapped = 1;
	mutex_exit(&zp->z_lock);

	ZFS_EXIT(zfsvfs);
	dprintf("-vnop_mmap\n");
	return (0);
}

static int
zfs_vnop_mnomap(struct vnop_mnomap_args *ap)
#if 0
	struct vnop_mnomap_args {
		struct vnode	*a_vp;
		int		a_fflags;
		kauth_cred_t	a_cred;
		struct proc	*a_p;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_mnomap\n");

	ZFS_ENTER(zfsvfs);

	if (!vnode_isreg(vp)) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}
	mutex_enter(&zp->z_lock);
	/*
	 * If a file as been mmaped even once, it needs to keep "z_is_mapped"
	 * high because it will potentially keep pages in the UPL cache we need
	 * to update on writes. We can either drop the UPL pages here, or simply
	 * keep updating both places on zfs_write().
	 */
	/* zp->z_is_mapped = 0; */
	mutex_exit(&zp->z_lock);

	ZFS_EXIT(zfsvfs);
	dprintf("-vnop_mnomap\n");
	return (0);
}




static int
zfs_vnop_inactive(struct vnop_inactive_args *ap)
#if 0
	struct vnop_inactive_args {
		struct vnode	*a_vp;
		vfs_context_t	a_context;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	DECLARE_CRED(ap);

	dprintf("vnop_inactive: zp %p vp %p\n", zp, vp);

	if (zfsvfs->z_vnode_create_depth) {
		/*
		 * We can not call inactive at this time, as we are inside
		 * vnode_create, so we must place it on a queue and process
		 * later
		 *
		 * However, we can cheat a little, by looking inside zfs_inactive
		 * we can take the fast exits here as well, and only keep
		 * node around for the syncing case
		 */
		rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
		if (zp->z_sa_hdl == NULL) {
			/*
			 * The fs has been unmounted, or we did a
			 * suspend/resume and this file no longer exists.
			 */
			rw_exit(&zfsvfs->z_teardown_inactive_lock);
			return 0;
		}

		mutex_enter(&zp->z_lock);
		if (zp->z_unlinked) {
			/*
			 * Fast path to recycle a vnode of a removed file.
			 */
			mutex_exit(&zp->z_lock);
			rw_exit(&zfsvfs->z_teardown_inactive_lock);
			return 0;
		}
		mutex_exit(&zp->z_lock);
		rw_exit(&zfsvfs->z_teardown_inactive_lock);

		return (0);
	}


	/* We call call it directly, huzzah! */
	zfs_inactive(vp, cr, NULL);

	/* dprintf("-vnop_inactive\n"); */
	return (0);
}



#ifdef _KERNEL
uint64_t vnop_num_reclaims = 0;
uint64_t vnop_num_vnodes = 0;

/*
 * Thread started to deal with any nodes in z_reclaim_nodes
 */
void
vnop_reclaim_thread(void *arg)
{
	znode_t *zp;
	callb_cpr_t cpr;
	zfsvfs_t *zfsvfs = (zfsvfs_t *)arg;
/*
 * #define VERBOSE_RECLAIM
 */
#ifdef VERBOSE_RECLAIM
	int count = 0;
	printf("ZFS: reclaim %p thread is alive!\n", zfsvfs);
#endif
	CALLB_CPR_INIT(&cpr, &zfsvfs->z_reclaim_thr_lock, callb_generic_cpr,
	    FTAG);
	mutex_enter(&zfsvfs->z_reclaim_thr_lock);
	while (1) {
		while (1) {
			mutex_enter(&zfsvfs->z_reclaim_list_lock);
			zp = list_head(&zfsvfs->z_reclaim_znodes);
			if (zp) {
				list_remove(&zfsvfs->z_reclaim_znodes, zp);
			}
			mutex_exit(&zfsvfs->z_reclaim_list_lock);
			/* Only exit thread once list is empty */
			if (!zp)
				break;
#ifdef VERBOSE_RECLAIM
			count++;
#endif
#ifdef _KERNEL
			atomic_dec_64(&vnop_num_reclaims);
#endif
			rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
			if (zp->z_sa_hdl == NULL)
				zfs_znode_free(zp);
			else
				zfs_zinactive(zp);
			rw_exit(&zfsvfs->z_teardown_inactive_lock);
		} /* until empty */
#ifdef VERBOSE_RECLAIM
		if (count)
			printf("reclaim_thr: %p nodes released: %d "
			    "(in list %llu)\n", zfsvfs, count,
			    vnop_num_reclaims);
		count = 0;
#endif
		/* Allow us to quit, since list is empty */
		if (zfsvfs->z_reclaim_thread_exit == TRUE)
			break;
		/* block until needed, or one second, whichever is shorter */
#if 1
		/* RECLAIM_SIGNAL */
		CALLB_CPR_SAFE_BEGIN(&cpr);
		(void) cv_timedwait_interruptible(&zfsvfs->z_reclaim_thr_cv,
		    &zfsvfs->z_reclaim_thr_lock, (ddi_get_lbolt() + (hz>>1)));
		CALLB_CPR_SAFE_END(&cpr, &zfsvfs->z_reclaim_thr_lock);
#else
		delay(hz>>1);
#endif
	} /* forever */
#ifdef VERBOSE_RECLAIM
	printf("ZFS: reclaim thread %p is quitting!\n", zfsvfs);
#endif
	zfsvfs->z_reclaim_thread_exit = FALSE;
	cv_broadcast(&zfsvfs->z_reclaim_thr_cv);
	CALLB_CPR_EXIT(&cpr); /* drops zfsvfs->z_reclaim_thr_lock */
	thread_exit();
}
#endif



static int
zfs_vnop_reclaim(struct vnop_reclaim_args *ap)
#if 0
	struct vnop_reclaim_args {
		struct vnode	*a_vp;
		vfs_context_t	a_context;
	};
#endif
{
	/*
	 * Care needs to be taken here, we may already have called reclaim
	 * from vnop_inactive, if so, very little needs to be done.
	 */

	struct vnode	*vp = ap->a_vp;
	znode_t	*zp = NULL;
	zfsvfs_t *zfsvfs = NULL;
	static int has_warned = 0;
	ASSERT(zp != NULL);

	dprintf("+vnop_reclaim %p\n", vp);

	/* Destroy the vm object and flush associated pages. */
#ifndef __APPLE__
	vnode_destroy_vobject(vp);
#endif

	/* Already been released? */
	zp = VTOZ(vp);
	if (!zp) goto out;

	zfsvfs = zp->z_zfsvfs;

	/*
	 * Purge old data structures associated with the denode.
	 */
	cache_purge(vp);

	vnode_clearfsnode(vp); /* vp->v_data = NULL */
	vnode_removefsref(vp); /* ADDREF from vnode_create */

	if (!zfsvfs) {
		printf("ZFS: vnop_reclaim with zfsvfs == NULL - tell lundman\n");
		return 0;
	}

	if (zfsctl_is_node(vp)) {
		printf("ZFS: vnop_reclaim with ctldir node - tell lundman\n");
		return 0;
	}


	/*
	 * Calls into vnode_create() can trigger reclaim and since we are
	 * likely to hold locks while inside vnode_create(), we need to defer
	 * reclaims until later.
	 */
	mutex_enter(&zfsvfs->z_znodes_lock);
	zp->z_vnode = NULL;
	list_remove(&zfsvfs->z_all_znodes, zp); /* XXX */
	mutex_exit(&zfsvfs->z_znodes_lock);

	mutex_enter(&zfsvfs->z_reclaim_list_lock);
	list_insert_tail(&zfsvfs->z_reclaim_znodes, zp);
	mutex_exit(&zfsvfs->z_reclaim_list_lock);

#ifdef _KERNEL
	atomic_inc_64(&vnop_num_reclaims);
	atomic_dec_64(&vnop_num_vnodes);

#endif
#if 1
	if (!has_warned && vnop_num_reclaims > 20000) {
		has_warned = 1;
		printf("ZFS: Reclaim thread is being slow (%llu)\n",
		    vnop_num_reclaims);
	}
#endif
	/*
	 * Which is better, the reclaim thread triggering frequently, with
	 * mostly one node to reclaim each time, many times per second, or only
	 * once per second, and about 1,600 nodes?
	 */

	/*
	 * We can either signal the reclaim-thread to wake up for each node or
	 * let it sleep for its own timeout and process nodes in bunches. We
	 * should measure which method is better.
	 */
#ifdef RECLAIM_SIGNAL
	cv_signal(&zfsvfs->z_reclaim_thr_cv);
#endif
  out:

	return (0);
}



static void
zfs_vnop_throttle_reclaim(zfsvfs_t *zfsvfs)
{
	int count = 0;

#ifdef __APPLE__
	/* Don't throttle unmounts */
	if (zfsvfs && zfsvfs->z_vfs && vfs_isunmount(zfsvfs->z_vfs)) return;
#endif

	/*
	 * Attempt to throttle. If the list grows "large" we need to slow down
	 * the vnode_create() process until it is manageable.
	 */
	while (vnop_num_reclaims > zfs_vnop_reclaim_throttle) {
		count++;
		if (zfsvfs)
			cv_signal(&zfsvfs->z_reclaim_thr_cv);
		/*
		 * Instead of a blind delay, should we use cv_timedwait() and
		 * have the reclaim thread signal back once it is under the
		 * limit?
		 */
		delay(hz>>4);
	}

	if (count)
		printf("ZFS: Delaying due to reclaim size "
		    "(vnop_reclaim_throttle) times %u\n", count);
}



static int
zfs_vnop_mknod(struct vnop_mknod_args *ap)
#if 0
	struct vnop_mknod_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *vap;
		vfs_context_t	a_context;
	};
#endif
{
	return (zfs_vnop_create((struct vnop_create_args *)ap));
}

static int
zfs_vnop_allocate(struct vnop_allocate_args *ap)
#if 0
	struct vnop_allocate_args {
		struct vnode	*a_vp;
		off_t		a_length;
		u_int32_t	a_flags;
		off_t		*a_bytesallocated;
		off_t		a_offset;
		vfs_context_t	a_context;
	};
#endif
{
	dprintf("vnop_allocate: 0\n");

	return (0);
}

static int
zfs_vnop_whiteout(struct vnop_whiteout_args *ap)
#if 0
	struct vnop_whiteout_args {
		struct vnode	*a_dvp;
		struct componentname *a_cnp;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	dprintf("vnop_whiteout: ENOTSUP\n");

	return (ENOTSUP);
}

static int
zfs_vnop_pathconf(struct vnop_pathconf_args *ap)
#if 0
	struct vnop_pathconf_args {
		struct vnode	*a_vp;
		int		a_name;
		register_t	*a_retval;
		vfs_context_t	a_context;
	};
#endif
{
	int32_t  *valp = ap->a_retval;
	int error = 0;

	dprintf("+vnop_pathconf a_name %d\n", ap->a_name);

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*valp = INT_MAX;
		break;
	case _PC_PIPE_BUF:
		*valp = PIPE_BUF;
		break;
	case _PC_CHOWN_RESTRICTED:
		*valp = 200112;  /* POSIX */
		break;
	case _PC_NO_TRUNC:
		*valp = 200112;  /* POSIX */
		break;
	case _PC_NAME_MAX:
	case _PC_NAME_CHARS_MAX:
		*valp = ZAP_MAXNAMELEN - 1;  /* 255 */
		break;
	case _PC_PATH_MAX:
	case _PC_SYMLINK_MAX:
		*valp = PATH_MAX;  /* 1024 */
		break;
	case _PC_CASE_SENSITIVE:
		*valp = 1;
		break;
	case _PC_CASE_PRESERVING:
		*valp = 1;
		break;
/*
 * OS X 10.6 does not define this.
 */
#ifndef	_PC_XATTR_SIZE_BITS
#define	_PC_XATTR_SIZE_BITS   26
#endif
/*
 * Even though ZFS has 64 bit limit on XATTR size, there would appear to be a
 * limit in SMB2 that the bit size returned has to be 18, or we will get an
 * error from most XATTR calls (STATUS_ALLOTTED_SPACE_EXCEEDED).
 */
#ifndef	AD_XATTR_SIZE_BITS
#define	AD_XATTR_SIZE_BITS 18
#endif
	case _PC_XATTR_SIZE_BITS:
		*valp = AD_XATTR_SIZE_BITS;
		break;
	case _PC_FILESIZEBITS:
		*valp = 64;
		break;
	default:
		printf("ZFS: unknown pathconf %d called.\n", ap->a_name);
		error = EINVAL;
	}

	dprintf("-vnop_patchconf vp %p : %d\n", ap->a_vp, error);
	return (error);
}


/*
 * This is not static so dtrace can see it
 */
int
zfs_vnop_getxattr(struct vnop_getxattr_args *ap)
#if 0
	struct vnop_getxattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		struct uio	*a_uio;
		size_t		*a_size;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio *uio = ap->a_uio;
	pathname_t cn = { 0 };
	int  error;

	/* dprintf("+getxattr vp %p\n", ap->a_vp); */

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
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, 0))) {
		goto out;
	}

	cn.pn_bufsize = strlen(ap->a_name) + 1;
	cn.pn_buf = (char*)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);

	/* Lookup the attribute name. */
	if ((error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, &xvp, 0, NULL,
	    &cn))) {
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
	if (cn.pn_buf)
		kmem_free(cn.pn_buf, cn.pn_bufsize);
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}

	ZFS_EXIT(zfsvfs);
	/* dprintf("-getxattr vp %p : %d\n", ap->a_vp, error); */
	return (error);
}

/*
 * This is not static so dtrace can see it
 */
int
zfs_vnop_setxattr(struct vnop_setxattr_args *ap)
#if 0
	struct vnop_setxattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		struct uio	*a_uio;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
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
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR))) {
		goto out;
	}

	if (ap->a_options & XATTR_CREATE)
		flag = ZNEW;	 /* expect no pre-existing entry */
	else if (ap->a_options & XATTR_REPLACE)
		flag = ZEXISTS;  /* expect an existing entry */
	else
		flag = 0;

	/* Lookup or create the named attribute. */
	error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name, VTOZ(vp)->z_mode, cr,
	    &xvp, flag);
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
zfs_vnop_removexattr(struct vnop_removexattr_args *ap)
#if 0
	struct vnop_removexattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	pathname_t cn = { 0 };
	int  error;
	uint64_t xattr;

	dprintf("+removexattr vp %p\n", ap->a_vp);

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs), &xattr, sizeof (xattr));
	if (xattr == 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, 0))) {
		goto out;
	}

	cn.pn_bufsize = strlen(ap->a_name)+1;
	cn.pn_buf = (char *)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);

	/* Lookup the attribute name. */
	if ((error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, &xvp, 0, NULL,
	    &cn))) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	error = zfs_remove(xdvp, (char *)ap->a_name, cr, ct, /* flags */0);

out:
	if (cn.pn_buf)
		kmem_free(cn.pn_buf, cn.pn_bufsize);

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
zfs_vnop_listxattr(struct vnop_listxattr_args *ap)
#if 0
	struct vnop_listxattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		struct uio	*a_uio;
		size_t		*a_size;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
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
	uint64_t xattr;
	int force_formd_normalized_output;

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
	if (sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs), &xattr,
	    sizeof (xattr)) || (xattr == 0)) {
		goto out;  /* all done */
	}

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}
	os = zfsvfs->z_os;

	for (zap_cursor_init(&zc, os, VTOZ(xdvp)->z_id);
	    zap_cursor_retrieve(&zc, &za) == 0; zap_cursor_advance(&zc)) {
		if (xattr_protected(za.za_name))
			continue;	 /* skip */
		/*
		 * Mac OS X: non-ascii names are UTF-8 NFC on disk
		 * so convert to NFD before exporting them.
		 */
		namelen = strlen(za.za_name);

		if (zfs_vnop_force_formd_normalized_output &&
		    !is_ascii_str(za.za_name))
			force_formd_normalized_output = 1;
		else
			force_formd_normalized_output = 0;

		if (force_formd_normalized_output &&
		    utf8_normalizestr((const u_int8_t *)za.za_name, namelen,
		    (u_int8_t *)nfd_name, &namelen, sizeof (nfd_name),
		    UTF_DECOMPOSED) == 0) {
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
			error = uiomove((caddr_t)nameptr, namelen, UIO_READ,
			    uio);
			if (error)
				break;
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
zfs_vnop_getnamedstream(struct vnop_getnamedstream_args *ap)
#if 0
	struct vnop_getnamedstream_args {
		struct vnode	*a_vp;
		struct vnode	**a_svpp;
		char		*a_name;
	};
#endif
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode **svpp = ap->a_svpp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	pathname_t cn = { 0 };
	int  error = ENOATTR;
	uint64_t xattr;
	dprintf("+getnamedstream vp %p\n", ap->a_vp);

	*svpp = NULLVP;

	ZFS_ENTER(zfsvfs);

	sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs), &xattr, sizeof (xattr));
	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME,
	    sizeof (XATTR_RESOURCEFORK_NAME)) != 0 || xattr == 0)
		goto out;

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0)
		goto out;

	cn.pn_bufsize = strlen(ap->a_name) + 1;
	cn.pn_buf = (char *)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);

	/* Lookup the attribute name. */
	if ((error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, svpp, 0, NULL,
	    &cn))) {
		if (error == ENOENT)
			error = ENOATTR;
	}

	kmem_free(cn.pn_buf, cn.pn_bufsize);

out:
	if (xdvp)
		vnode_put(xdvp);

	ZFS_EXIT(zfsvfs);
	dprintf("-getnamedstream vp %p: error %d\n", ap->a_vp, error);
	return (error);
}

static int
zfs_vnop_makenamedstream(struct vnop_makenamedstream_args *ap)
#if 0
	struct vnop_makenamedstream_args {
		struct vnode	*a_vp;
		struct vnode	**a_svpp;
		char		*a_name;
	};
#endif
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct componentname  cn;
	struct vnode_attr  vattr;
	int  error = 0;

	dprintf("+makenamedstream vp %p\n", ap->a_vp);

	*ap->a_svpp = NULLVP;

	ZFS_ENTER(zfsvfs);

	/* Only regular files can have a resource fork stream. */
	if (!vnode_isreg(vp)) {
		error = EPERM;
		goto out;
	}

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME,
	    sizeof (XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)))
		goto out;

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = CREATE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, VTOZ(vp)->z_mode & ~S_IFMT);

	error = zfs_create(xdvp, (char *)ap->a_name, &vattr, NONEXCL,
	    VTOZ(vp)->z_mode, ap->a_svpp, cr);

out:
	if (xdvp)
		vnode_put(xdvp);

	ZFS_EXIT(zfsvfs);
	dprintf("-makenamedstream vp %p: error %d\n", ap->a_vp, error);
	return (error);
}

static int
zfs_vnop_removenamedstream(struct vnop_removenamedstream_args *ap)
#if 0
	struct vnop_removenamedstream_args {
		struct vnode	*a_vp;
		struct vnode	**a_svpp;
		char		*a_name;
	};
#endif
{
	struct vnode *svp = ap->a_svp;
	znode_t *zp = VTOZ(svp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error = 0;

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME,
	    sizeof (XATTR_RESOURCEFORK_NAME)) != 0) {
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

/*
 * The Darwin kernel's HFS+ appears to implement this by two methods,
 *
 * if (ap->a_options & FSOPT_EXCHANGE_DATA_ONLY) is set
 *	** Copy the data of the files over (including rsrc)
 *
 * if not set
 *	** exchange FileID between the two nodes, copy over vnode information
 *	   like that of *time records, uid/gid, flags, mode, linkcount,
 *	   finderinfo, c_desc, c_attr, c_flag, and cache_purge().
 *
 * This call is deprecated in 10.8
 */
static int
zfs_vnop_exchange(struct vnop_exchange_args *ap)
#if 0
	struct vnop_exchange_args {
		struct vnode	*a_fvp;
		struct vnode	*a_tvp;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
	vnode_t *fvp = ap->a_fvp;
	vnode_t *tvp = ap->a_tvp;
	znode_t  *fzp;
	zfsvfs_t  *zfsvfs;

	/* The files must be on the same volume. */
	if (vnode_mount(fvp) != vnode_mount(tvp))
		return (EXDEV);

	if (fvp == tvp)
		return (EINVAL);

	/* Only normal files can be exchanged. */
	if (!vnode_isreg(fvp) || !vnode_isreg(tvp))
		return (EINVAL);

	fzp = VTOZ(fvp);
	zfsvfs = fzp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);

	/* ADD MISSING CODE HERE */

	ZFS_EXIT(zfsvfs);
	dprintf("vnop_exchange: ENOTSUP\n");
	return (ENOTSUP);
}

static int
zfs_vnop_revoke(struct vnop_revoke_args *ap)
#if 0
	struct vnop_revoke_args {
		struct vnode	*a_vp;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	return (vn_revoke(ap->a_vp, ap->a_flags, ap->a_context));
}

static int
zfs_vnop_blktooff(struct vnop_blktooff_args *ap)
#if 0
	struct vnop_blktooff_args {
		struct vnode	*a_vp;
		daddr64_t	a_lblkno;
		off_t		*a_offset;
	};
#endif
{
	dprintf("vnop_blktooff: 0\n");

	return (0);
}

static int
zfs_vnop_offtoblk(struct vnop_offtoblk_args *ap)
#if 0
	struct vnop_offtoblk_args {
		struct vnode	*a_vp;
		off_t		a_offset;
		daddr64_t	*a_lblkno;
	};
#endif
{
	znode_t *zp;
	zfsvfs_t *zfsvfs;

	dprintf("+vnop_offtoblk\n");

	if (ap->a_vp == NULL)
		return (EINVAL);
	zp = VTOZ(ap->a_vp);
	if (!zp)
		return (EINVAL);
	zfsvfs = zp->z_zfsvfs;
	if (!zfsvfs)
		return (EINVAL);
	*ap->a_lblkno = (daddr64_t)(ap->a_offset / zfsvfs->z_max_blksz);
	return (0);
}

static int
zfs_vnop_blockmap(struct vnop_blockmap_args *ap)
#if 0
	struct vnop_blockmap_args {
		struct vnode	*a_vp;
		off_t		a_foffset;
		size_t		a_size;
		daddr64_t	*a_bpn;
		size_t		*a_run;
		void		*a_poff;
		int		a_flags;
};
#endif
{
	dprintf("vnop_blockmap\n");

	return (ENOTSUP);
}

static int
zfs_vnop_strategy(struct vnop_strategy_args *ap)
#if 0
	struct vnop_strategy_args {
		struct buf	*a_bp;
	};
#endif
{
	dprintf("vnop_strategy: 0\n");

	return (0);
}

static int
zfs_vnop_select(struct vnop_select_args *ap)
#if 0
	struct vnop_select_args {
		struct vnode	*a_vp;
		int		a_which;
		int		a_fflags;
		kauth_cred_t	a_cred;
		void		*a_wql;
		struct proc	*a_p;
	};
#endif
{
	dprintf("vnop_select: 0\n");

	return (1);
}

static int
zfs_vnop_readdirattr(struct vnop_readdirattr_args *ap)
#if 0
	struct vnop_readdirattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		struct attrlist	*a_alist;
		struct uio	*a_uio;
		u_long		a_maxcount;
		u_long		a_options;
		u_long		*a_newstate;
		int		*a_eofflag;
		u_long		*a_actualcount;
		vfs_context_t	a_context;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	struct attrlist *alp = ap->a_alist;
	struct uio *uio = ap->a_uio;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	zap_cursor_t zc;
	zap_attribute_t zap;
	attrinfo_t attrinfo;
	int maxcount = ap->a_maxcount;
	uint64_t offset = (uint64_t)uio_offset(uio);
	u_int32_t fixedsize;
	u_int32_t maxsize;
	u_int32_t attrbufsize;
	void *attrbufptr = NULL;
	void *attrptr;
	void *varptr;  /* variable-length storage area */
	boolean_t user64 = vfs_context_is64bit(ap->a_context);
	int prefetch = 0;
	int error = 0;

	dprintf("+vnop_readdirattr\n");

	*(ap->a_actualcount) = 0;
	*(ap->a_eofflag) = 0;

	/*
	 * Check for invalid options or invalid uio.
	 */
	if (((ap->a_options & ~(FSOPT_NOINMEMUPDATE | FSOPT_NOFOLLOW)) != 0) ||
		(uio_resid(uio) <= 0) || (maxcount <= 0)) {
		return (EINVAL);
	}
	/*
	 * Reject requests for unsupported attributes.
	 */
	if ((alp->bitmapcount != ZFS_ATTR_BIT_MAP_COUNT) ||
	    (alp->commonattr & ~ZFS_ATTR_CMN_VALID) ||
	    (alp->dirattr & ~ZFS_ATTR_DIR_VALID) ||
	    (alp->fileattr & ~ZFS_ATTR_FILE_VALID) ||
	    (alp->volattr != 0 || alp->forkattr != 0)) {
		return (EINVAL);
	}
	/*
	 * Check if we should prefetch znodes
	 */
	if ((alp->commonattr & ~ZFS_DIR_ENT_ATTRS) ||
		(alp->dirattr != 0) || (alp->fileattr != 0)) {
		prefetch = TRUE;
	}

	/*
	 * Setup a buffer to hold the packed attributes.
	 */
	fixedsize = sizeof (u_int32_t) + getpackedsize(alp, user64);
	maxsize = fixedsize;
	if (alp->commonattr & ATTR_CMN_NAME)
		maxsize += ZAP_MAXNAMELEN + 1;
	attrbufptr = (void*)kmem_alloc(maxsize, KM_SLEEP);
	if (attrbufptr == NULL) {
		return (ENOMEM);
	}
	attrptr = attrbufptr;
	varptr = (char *)attrbufptr + fixedsize;

	attrinfo.ai_attrlist = alp;
	attrinfo.ai_varbufend = (char *)attrbufptr + maxsize;
	attrinfo.ai_context = ap->a_context;

	ZFS_ENTER(zfsvfs);

	/*
	 * Initialize the zap iterator cursor.
	 */

	if (offset <= 3) {
		/*
		 * Start iteration from the beginning of the directory.
		 */
		zap_cursor_init(&zc, zfsvfs->z_os, zp->z_id);
	} else {
		/*
		 * The offset is a serialized cursor.
		 */
		zap_cursor_init_serialized(&zc, zfsvfs->z_os, zp->z_id, offset);
	}

	while (1) {
		ino64_t objnum;
		enum vtype vtype = VNON;
		znode_t *tmp_zp = NULL;

		/*
		 * Note that the low 4 bits of the cookie returned by zap is
		 * always zero. This allows us to use the low nibble for
		 * "special" entries:
		 * We use 0 for '.', and 1 for '..' (ignored here).
		 * If this is the root of the filesystem, we use the offset 2
		 * for the *'.zfs' directory.
		 */
		if (offset <= 1) {
			offset = 2;
			continue;
		} else if (offset == 2 && zfs_show_ctldir(zp)) {
			(void) strlcpy(zap.za_name, ZFS_CTLDIR_NAME,
			    MAXNAMELEN);
			objnum = ZFSCTL_INO_ROOT;
			vtype = VDIR;
		} else {
			/*
			 * Grab next entry.
			 */
			if ((error = zap_cursor_retrieve(&zc, &zap))) {
				*(ap->a_eofflag) = (error == ENOENT);
				goto update;
			}

			if (zap.za_integer_length != 8 ||
				zap.za_num_integers != 1) {
				error = ENXIO;
				goto update;
			}

			objnum = ZFS_DIRENT_OBJ(zap.za_first_integer);
			vtype = DTTOVT(ZFS_DIRENT_TYPE(zap.za_first_integer));
			/* Check if vtype is MIA */
			if ((vtype == 0) && !prefetch && (alp->dirattr ||
			    alp->fileattr ||
			    (alp->commonattr & ATTR_CMN_OBJTYPE))) {
				prefetch = 1;
			}
		}

		/* Grab znode if required */
		if (prefetch) {
			dmu_prefetch(zfsvfs->z_os, objnum, 0, 0);
			if ((error = zfs_zget(zfsvfs, objnum, &tmp_zp)) == 0) {
				if (vtype == VNON) {
					/* SA_LOOKUP? */
					vtype = IFTOVT(tmp_zp->z_mode);
				}
			} else {
				tmp_zp = NULL;
				error = ENXIO;
				goto skip_entry;
				/*
				 * Currently ".zfs" entry is skipped, as we have
				 * no methods to pack that into the attrs (all
				 * helper functions take znode_t *, and .zfs is
				 * not a znode_t *). Add dummy .zfs code here if
				 * it is desirable to show .zfs in Finder.
				 */
			}
		}

		/*
		 * Setup for the next item's attribute list
		 */
		*((u_int32_t *)attrptr) = 0; /* byte count slot */
		attrptr = ((u_int32_t *)attrptr) + 1; /* fixed attr start */
		attrinfo.ai_attrbufpp = &attrptr;
		attrinfo.ai_varbufpp = &varptr;

		/*
		 * Pack entries into attribute buffer.
		 */
		if (alp->commonattr) {
			commonattrpack(&attrinfo, zfsvfs, tmp_zp, zap.za_name,
			    objnum, vtype, user64);
		}
		if (alp->dirattr && vtype == VDIR) {
			dirattrpack(&attrinfo, tmp_zp);
		}
		if (alp->fileattr && vtype != VDIR) {
			fileattrpack(&attrinfo, zfsvfs, tmp_zp);
		}
		/* All done with tmp znode. */
		if (prefetch && tmp_zp) {
			vnode_put(ZTOV(tmp_zp));
			tmp_zp = NULL;
		}
		attrbufsize = ((char *)varptr - (char *)attrbufptr);

		/*
		 * Make sure there's enough buffer space remaining.
		 */
		if (uio_resid(uio) < 0 ||
			attrbufsize > (u_int32_t)uio_resid(uio)) {
			break;
		} else {
			*((u_int32_t *)attrbufptr) = attrbufsize;
			error = uiomove((caddr_t)attrbufptr, attrbufsize,
			    UIO_READ, uio);
			if (error != 0)
				break;
			attrptr = attrbufptr;
			/* Point to variable-length storage */
			varptr = (char *)attrbufptr + fixedsize;
			*(ap->a_actualcount) += 1;

			/*
			 * Move to the next entry, fill in the previous offset.
			 */
		skip_entry:
			if ((offset > 2) || ((offset == 2) &&
			    !zfs_show_ctldir(zp))) {
				zap_cursor_advance(&zc);
				offset = zap_cursor_serialize(&zc);
			} else {
				offset += 1;
			}

			/* Termination checks */
			if (--maxcount <= 0 || uio_resid(uio) < 0 ||
			    (u_int32_t)uio_resid(uio) < (fixedsize +
			    ZAP_AVENAMELEN)) {
				break;
			}
		}
	}
update:
	zap_cursor_fini(&zc);

	if (attrbufptr) {
		kmem_free(attrbufptr, maxsize);
	}
	if (error == ENOENT) {
		error = 0;
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	/* XXX newstate TBD */
	*ap->a_newstate = zp->z_atime[0] + zp->z_atime[1];
	uio_setoffset(uio, offset);

	ZFS_EXIT(zfsvfs);
	dprintf("-readdirattr: error %d\n", error);
	return (error);
}


#ifdef WITH_SEARCHFS
int
zfs_vnop_searchfs(struct vnop_searchfs_args *ap)
#if 0
	struct vnop_searchfs_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		void		*a_searchparams1;
		void		*a_searchparams2;
		struct attrlist	*a_searchattrs;
		u_long		a_maxmatches;
		struct timeval	*a_timelimit;
		struct attrlist	*a_returnattrs;
		u_long		*a_nummatches;
		u_long		a_scriptcode;
		u_long		a_options;
		struct uio	*a_uio;
		struct searchstate *a_searchstate;
		vfs_context_t	a_context;
	};
#endif
{
	printf("vnop_searchfs called, type %d\n", vnode_vtype(ap->a_vp));

	*(ap->a_nummatches) = 0;

	return (ENOTSUP);
}
#endif


/*
 * Predeclare these here so that the compiler assumes that this is an "old
 * style" function declaration that does not include arguments so that we won't
 * get type mismatch errors in the initializations that follow.
 */
static int zfs_inval();
static int zfs_isdir();

static int
zfs_inval()
{
	return (EINVAL);
}

static int
zfs_isdir()
{
	return (EISDIR);
}


#define	VOPFUNC int (*)(void *)

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
	{&vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{&vnop_readdirattr_desc, (VOPFUNC)zfs_vnop_readdirattr},
#ifdef WITH_SEARCHFS
	{&vnop_searchfs_desc,	(VOPFUNC)zfs_vnop_searchfs},
#endif
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
	{&vnop_mnomap_desc,	(VOPFUNC)zfs_vnop_mnomap},
	{&vnop_blktooff_desc,	(VOPFUNC)zfs_vnop_blktooff},
	{&vnop_offtoblk_desc,	(VOPFUNC)zfs_vnop_offtoblk},
	{&vnop_blockmap_desc,	(VOPFUNC)zfs_vnop_blockmap},
	{&vnop_strategy_desc,	(VOPFUNC)zfs_vnop_strategy},
	{&vnop_allocate_desc,   (VOPFUNC)zfs_vnop_allocate},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_exchange_desc,	(VOPFUNC)zfs_vnop_exchange},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
#ifdef HAVE_NAMED_STREAMS
	{&vnop_getnamedstream_desc,	(VOPFUNC)zfs_vnop_getnamedstream},
	{&vnop_makenamedstream_desc,	(VOPFUNC)zfs_vnop_makenamedstream},
	{&vnop_removenamedstream_desc,	(VOPFUNC)zfs_vnop_removenamedstream},
#endif
#ifdef WITH_SEARCHFS
	{&vnop_searchfs_desc,	(VOPFUNC)zfs_vnop_searchfs},
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
	{&vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
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
 * Alas, OS X does not let us create a vnode, and assign the vtype later and we
 * do not know what type we want here. Is there a way around this? We could
 * allocate any old vnode, then recycle it to ensure a vnode is spare?
 */
void
getnewvnode_reserve(int num)
{
}

void
getnewvnode_drop_reserve()
{
}

/*
 * Get new vnode for znode.
 *
 * This function uses zp->z_zfsvfs, zp->z_mode, zp->z_flags, zp->z_id and sets
 * zp->z_vnode and zp->z_vid.
 */
int
zfs_znode_getvnode(znode_t *zp, zfsvfs_t *zfsvfs, struct vnode **vpp)
{
	struct vnode_fsparam vfsp;

	dprintf("getvnode zp %p with vpp %p zfsvfs %p vfs %p\n", zp, vpp,
	    zfsvfs, zfsvfs->z_vfs);

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
		/* FALLTHROUGH */
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
	 * vnode_create() has a habit of calling both vnop_reclaim() and
	 * vnop_fsync(), which can create havok as we are already holding locks.
	 */
	atomic_add_64(&zfsvfs->z_vnode_create_depth, 1);
	while (vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, vpp) != 0)
		;
	atomic_sub_64(&zfsvfs->z_vnode_create_depth, 1);

	atomic_inc_64(&vnop_num_vnodes);

	dprintf("Assigned zp %p with vp %p\n", zp, *vpp);

	vnode_settag(*vpp, VT_ZFS);

	zp->z_vid = vnode_vid(*vpp);
	zp->z_vnode = *vpp;

	/*
	 * OS X Finder is hardlink agnostic, so we need to mark vp's that
	 * are hardlinks, so that it forces a lookup each time, ignoring
	 * the name cache.
	 */
	if ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG))
		vnode_setmultipath(*vpp);

	return (0);
}

/*
 * Maybe these should live in vfsops
 */
int
zfs_vfsops_init(void)
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
	vfe.vfe_flags = VFS_TBLTHREADSAFE | VFS_TBLNOTYPENUM | VFS_TBLLOCALVOL |
	    VFS_TBL64BITREADY | VFS_TBLNATIVEXATTR | VFS_TBLGENERICMNTARGS |
	    VFS_TBLREADDIR_EXTENDED;
	vfe.vfe_reserv[0] = 0;
	vfe.vfe_reserv[1] = 0;

	if (vfs_fsadd(&vfe, &zfs_vfsconf) != 0)
		return (KERN_FAILURE);
	else
		return (KERN_SUCCESS);
}

int
zfs_vfsops_fini(void)
{
	zfs_fini();

	return (vfs_fsremove(zfs_vfsconf));
}
