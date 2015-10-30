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

#include <miscfs/fifofs/fifo.h>
#include <miscfs/specfs/specdev.h>
#include <vfs/vfs_support.h>
#include <sys/ioccom.h>



#ifdef _KERNEL
#include <sys/sysctl.h>
#include <sys/hfs_internal.h>

unsigned int debug_vnop_osx_printf = 0;
unsigned int zfs_vnop_ignore_negatives = 0;
unsigned int zfs_vnop_ignore_positives = 0;
unsigned int zfs_vnop_create_negatives = 1;
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
//#define	dprintf if (debug_vnop_osx_printf) kprintf
//#define dprintf kprintf

//#define	dprintf(...) if (debug_vnop_osx_printf) {printf(__VA_ARGS__);delay(hz>>2);}

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
extern struct vnodeopv_desc zfs_fifonodeop_opv_desc;

extern struct vnodeopv_desc zfsctl_ops_root;
extern struct vnodeopv_desc zfsctl_ops_snapdir;
extern struct vnodeopv_desc zfsctl_ops_snapshot;

#define	ZFS_VNOP_TBL_CNT	8


static struct vnodeopv_desc *zfs_vnodeop_opv_desc_list[ZFS_VNOP_TBL_CNT] =
{
	&zfs_dvnodeop_opv_desc,
	&zfs_fvnodeop_opv_desc,
	&zfs_symvnodeop_opv_desc,
	&zfs_xdvnodeop_opv_desc,
	//&zfs_evnodeop_opv_desc,
	&zfs_fifonodeop_opv_desc,
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



/*
 * All these functions could be declared as 'static' but to assist with
 * dtrace debugging, we do not.
 */

int
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

int
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

int
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

	dprintf("vnop_ioctl %08lx: VTYPE %d\n", ap->a_command,
			vnode_vtype(ZTOV(zp)));

	ZFS_ENTER(zfsvfs);
	if (IFTOVT((mode_t)zp->z_mode) == VFIFO) {
		dprintf("ZFS: FIFO ioctl  %02lx ('%lu' + %lu)\n",
			   ap->a_command, (ap->a_command&0xff00)>>8,
			   ap->a_command&0xff);
		error = fifo_ioctl(ap);
		error = 0;
		ZFS_EXIT(zfsvfs);
		goto out;
	}

	if ((IFTOVT((mode_t)zp->z_mode) == VBLK) ||
		(IFTOVT((mode_t)zp->z_mode) == VCHR)) {
		dprintf("ZFS: spec ioctl  %02lx ('%lu' + %lu)\n",
			   ap->a_command, (ap->a_command&0xff00)>>8,
			   ap->a_command&0xff);
		error = spec_ioctl(ap);
		ZFS_EXIT(zfsvfs);
		goto out;
	}
	ZFS_EXIT(zfsvfs);

	switch (ap->a_command) {

		/* ioctl supported by ZFS and POSIX */

		case F_FULLFSYNC:
			error = zfs_fsync(ap->a_vp, /* flag */0, cr, ct);
			break;

		case F_CHKCLEAN:
			/* normally calls http://fxr.watson.org/fxr/source/bsd/vfs/vfs_cluster.c?v=xnu-2050.18.24#L5839 */
			break;

		case F_RDADVISE:
			dprintf("vnop_ioctl: F_RDADVISE\n");
			break;

		case SPOTLIGHT_GET_MOUNT_TIME:
		case SPOTLIGHT_FSCTL_GET_MOUNT_TIME:
			*(uint32_t *)ap->a_data = zfsvfs->z_mount_time;
			break;

		case SPOTLIGHT_GET_UNMOUNT_TIME:
		case SPOTLIGHT_FSCTL_GET_LAST_MTIME:
			*(uint32_t *)ap->a_data = zfsvfs->z_last_unmount_time;
			break;

		case HFS_SET_ALWAYS_ZEROFILL:
		case HFS_EXT_BULKACCESS_FSCTL:
			/* Required by Spotlight search */
			break;



		/* ioctl required to simulate HFS mimic behavior */


		case 0x80005802:
			/* unknown as to what this is - is from subsystem read, 'X', 2 */
			break;

		case HFS_GETPATH:
			dprintf("ZFS: ioctl(HFS_GETPATH)\n");
  		    {
				struct vfsstatfs *vfsp;
				struct vnode *file_vp;
                ino64_t cnid;
                int  outlen;
                char *bufptr;
                int flags = 0;

				/* Caller must be owner of file system. */
				vfsp = vfs_statfs(zfsvfs->z_vfs);
				/*if (suser((kauth_cred_t)cr, NULL) &&  APPLE denied suser */
				if (proc_suser(current_proc()) &&
					kauth_cred_getuid((kauth_cred_t)cr) != vfsp->f_owner) {
					error = EACCES;
					goto out;
				}
				/* Target vnode must be file system's root. */
				if (!vnode_isvroot(ap->a_vp)) {
					error = EINVAL;
					goto out;
				}

				/* We are passed a string containing a inode number */
				bufptr = (char *)ap->a_data;
                cnid = strtoul(bufptr, NULL, 10);
                if (ap->a_fflag & HFS_GETPATH_VOLUME_RELATIVE) {
					flags |= BUILDPATH_VOLUME_RELATIVE;
                }

				if ((error = zfs_vfs_vget(zfsvfs->z_vfs, cnid, &file_vp,
										  (vfs_context_t)ct))) {
					goto out;
                }
                error = build_path(file_vp, bufptr, MAXPATHLEN,
								   &outlen, flags, (vfs_context_t)ct);
                vnode_put(file_vp);

				dprintf("ZFS: HFS_GETPATH done %d : '%s'\n", error,
					   error ? "" : bufptr);
			}
			break;

		case HFS_TRANSFER_DOCUMENT_ID:
		    {
				u_int32_t to_fd = *(u_int32_t *)ap->a_data;
				file_t *to_fp;
				struct vnode *to_vp;
				znode_t *to_zp;
				dprintf("ZFS: HFS_TRANSFER_DOCUMENT_ID:\n");

				to_fp = getf(to_fd);
				if (to_fp == NULL) {
					error = EBADF;
					goto out;
				}

				to_vp = getf_vnode(to_fp);

				if ( (error = vnode_getwithref(to_vp)) ) {
					releasef(to_fd);
					goto out;
				}

				/* Confirm it is inside our mount */
				if (((zfsvfs_t *)vfs_fsprivate(vnode_mount((to_vp)))) != zfsvfs) {
					error = EXDEV;
					goto transfer_out;
				}

				to_zp = VTOZ(to_vp);

				/* Source should have UF_TRACKED */
				if (!(zp->z_pflags & ZFS_TRACKED)) {
					dprintf("ZFS: source is not TRACKED\n");
					error = EINVAL;
					/* destination should NOT have UF_TRACKED */
				} else if (to_zp->z_pflags & ZFS_TRACKED) {
					dprintf("ZFS: destination is already TRACKED\n");
					error = EEXIST;
					/* should be valid types */
				} else if ((IFTOVT((mode_t)zp->z_mode) == VDIR) ||
						   (IFTOVT((mode_t)zp->z_mode) == VREG) ||
						   (IFTOVT((mode_t)zp->z_mode) == VLNK)) {
					/* Make sure source has a document id  - although it can't*/
					if (!zp->z_document_id)
						zfs_setattr_generate_id(zp, 0, NULL);

					/* transfer over */
					to_zp->z_document_id = zp->z_document_id;
					zp->z_document_id = 0;
					to_zp->z_pflags |= ZFS_TRACKED;
					zp->z_pflags &= ~ZFS_TRACKED;

					/* Commit to disk */
					zfs_setattr_set_documentid(to_zp, B_TRUE);
					zfs_setattr_set_documentid(zp, B_TRUE); /* also update flags */
					dprintf("ZFS: Moved docid %u from id %llu to id %llu\n",
						   to_zp->z_document_id, zp->z_id, to_zp->z_id);
				}
			  transfer_out:
				vnode_put(to_vp);
				releasef(to_fd);
			}
			break;


		case F_MAKECOMPRESSED:
			/*
			 * Not entirely sure what this does, but HFS comments include:
			 * "Make the file compressed; truncate & toggle BSD bits"
			 *
			 */
		    {
				uint32_t gen_counter;

				printf("ZFS: F_MAKECOMPRESSED\n");

				if (vfs_isrdonly(zfsvfs->z_vfs) ||
					!spa_writeable(dmu_objset_spa(zfsvfs->z_os))) {
					error = EROFS;
					goto out;
				}

				if (ap->a_data) {
					/*
					 * Cast the pointer into a uint32_t so we can extract the
					 * supplied generation counter.
					 */
					gen_counter = *((uint32_t*)ap->a_data);
                }
                else {
					error = EINVAL;
					goto out;
                }
				/* Are there any other usecounts/FDs? */
                if (vnode_isinuse(ap->a_vp, 1)) {
					error = EBUSY;
					goto out;
				}
				if (zp->z_pflags & ZFS_IMMUTABLE) {
					error = EINVAL;
					goto out;
				}
				if (zp->z_write_gencount == gen_counter) {
					/*
					 * OK, the gen_counter matched.  Go for it:
					 * Toggle state bits,truncate file, and suppress mtime update
					 */
					// return OK
				} else {
					error = ESTALE;
				}

			}
			break;


		case HFS_PREV_LINK:
		case HFS_NEXT_LINK:
			// HFS has a facility to efficiently iterate the collection
			// of hardlinks pointing to an object, ZFS does not
			// implement something like this.
			//
			// In the mean time, we will just reply with "what hardlink?"
			*(uint32_t *)ap->a_data = 0;
			break;

		case HFS_RESIZE_PROGRESS:
			/* fail as if requested of non-root fs */
			error = EINVAL;
			break;

		case HFS_RESIZE_VOLUME:
			/* fail as if requested of non-root fs */
			error = EINVAL;
			break;

		case HFS_CHANGE_NEXT_ALLOCATION:
			/* fail as if requested of non-root fs */
			error = EINVAL;
			break;

		case HFS_CHANGE_NEXTCNID:
			/* FIXME : fail as though read only */
			error = EROFS;
			break;

		case F_FREEZE_FS:
			/* Dont support freeze */
			error = ENOTSUP;
			break;

		case F_THAW_FS:
			/* dont support fail as though insufficient privilege */
			error = EACCES;
			break;

		case HFS_BULKACCESS_FSCTL:
			/* Respond as if HFS_STANDARD flag is set */
			error = EINVAL;
			break;

		case HFS_FSCTL_GET_VERY_LOW_DISK:
			*(uint32_t*)ap->a_data = zfsvfs->z_freespace_notify_dangerlimit;
			break;

		case HFS_FSCTL_SET_VERY_LOW_DISK:
			if (*(uint32_t *)ap->a_data >= zfsvfs->z_freespace_notify_warninglimit) {
				error = EINVAL;
			} else {
				zfsvfs->z_freespace_notify_dangerlimit = *(uint32_t *)ap->a_data;
            }
			break;

		case HFS_FSCTL_GET_LOW_DISK:
			*(uint32_t*)ap->a_data = zfsvfs->z_freespace_notify_warninglimit;
			break;

		case HFS_FSCTL_SET_LOW_DISK:
			if (   *(uint32_t *)ap->a_data >= zfsvfs->z_freespace_notify_desiredlevel
				   || *(uint32_t *)ap->a_data <= zfsvfs->z_freespace_notify_dangerlimit) {
				error = EINVAL;
			} else {
				zfsvfs->z_freespace_notify_warninglimit = *(uint32_t *)ap->a_data;
			}
			break;

		case HFS_FSCTL_GET_DESIRED_DISK:
			*(uint32_t*)ap->a_data = zfsvfs->z_freespace_notify_desiredlevel;
			break;

		case HFS_FSCTL_SET_DESIRED_DISK:
			if (*(uint32_t *)ap->a_data <= zfsvfs->z_freespace_notify_warninglimit) {
				error = EINVAL;
			} else {
				zfsvfs->z_freespace_notify_desiredlevel = *(uint32_t *)ap->a_data;
			}
			break;

		case HFS_VOLUME_STATUS:
			/* For now we always reply "all ok" */
			*(uint32_t *)ap->a_data = zfsvfs->z_notification_conditions;
			break;

		case HFS_SET_BOOT_INFO:
		case HFS_GET_BOOT_INFO:
		case HFS_MARK_BOOT_CORRUPT:
			/* ZFS booting is not supported, mimic selection of a non-root HFS volume */
			*(uint32_t *)ap->a_data = 0;
			error = EINVAL;
			break;

		case HFS_FSCTL_GET_JOURNAL_INFO:
			/* Respond as though journal is empty/disabled */
		{
		    struct hfs_journal_info *jip;
		    jip = (struct hfs_journal_info*)ap->a_data;
		    jip->jstart = 0;
		    jip->jsize = 0;
		}
		break;

		case HFS_DISABLE_METAZONE:
			/* fail as though insufficient privs */
			error = EACCES;
			break;

#ifdef HFS_GET_FSINFO
		case HFS_GET_FSINFO:
			break;
#endif
			/* End HFS mimic ioctl */


		default:
			printf("vnop_ioctl: Unknown ioctl %02lx ('%lu' + %lu)\n",
				   ap->a_command, (ap->a_command&0xff00)>>8,
				   ap->a_command&0xff);
			error = ENOTTY;
	}

  out:
	if (error)
		printf("vnop_ioctl failing ioctl: %02lx ('%lu' + %lu) returned %d\n",
			ap->a_command, (ap->a_command&0xff00)>>8,
			ap->a_command&0xff,
			error);

	return (error);
}


int
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

int
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

int
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
	if ((vp != NULL) && !zfsctl_is_node(vp)) {
		znode_t *zp = VTOZ(vp);
		if (zp != NULL) {
			/*
			 * hard link references? Read the comment in
			 * zfs_getattr_znode_unlocked for the reason for this
			 * hackery.
			 */
			if ((zp->z_links > 1) &&
			    (IFTOVT((mode_t)zp->z_mode) == VREG)) {
				dprintf("keep_hardlink: %p has refs %llu\n", vp,
				    zp->z_links);
				strlcpy(zp->z_finder_hardlink_name, filename,
				    MAXPATHLEN);
			}
		} //zp
	} //vp
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

int
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

	dprintf("-vnop_lookup %d\n", error);
	return (error);
}

int
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

int
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

	dprintf("vnop_remove: %p (%s)\n", ap->a_vp, ap->a_cnp->cn_nameptr);

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

int
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

int
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

int
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

int
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
	 * If we come here via vnode_create()->vclean() we can not end up in
	 * zil_commit() or we will deadlock. But we know that vnop_reclaim will
	 * be called next, so we just return success.
	 */
	// this might not be needed now
	//if (vnode_isrecycled(ap->a_vp)) return 0;

	err = zfs_fsync(ap->a_vp, /* flag */0, cr, ct);

	return (err);
}

int
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

	if (!error)
		error = zfs_getattr_znode_unlocked(ap->a_vp, ap->a_vap);

	if (error)
		dprintf("-vnop_getattr '%p' %d\n", (ap->a_vp), error);

	return (error);
}

int
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

		/* If TRACKED is wanted, and not previously set, go set DocumentID */
		if ((vap->va_flags & UF_TRACKED) && !(zp->z_pflags & ZFS_TRACKED)) {
			zfs_setattr_generate_id(zp, 0, NULL);
			zfs_setattr_set_documentid(zp, B_FALSE); /* flags updated in vnops */
		}

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
		if (VATTR_IS_ACTIVE(vap, va_data_size)) {
			dprintf("ZFS: setattr new size %llx %llx\n", vap->va_size,
					ubc_getsize(ap->a_vp));
			ubc_setsize(ap->a_vp, vap->va_size);
			VATTR_SET_SUPPORTED(vap, va_data_size);
		}
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

#if 0
	uint64_t missing = 0;
	missing = (vap->va_active ^ (vap->va_active & vap->va_supported));
	if ( missing != 0) {
		printf("vnop_setattr:: asked %08llx replied %08llx       missing %08llx\n",
			   vap->va_active, vap->va_supported,
			   missing);
	}
#endif

	if (error)
		printf("ZFS: vnop_setattr return failure %d\n", error);
	return (error);
}

int
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
int
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


int
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

int
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

int
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

	dprintf("+vnop_pagein: %p/%p off 0x%llx size 0x%lx filesz 0x%llx\n",
			zp, vp, off, len, zp->z_size);

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


	if (ubc_upl_map(upl, (vm_offset_t *)&vaddr) != KERN_SUCCESS) {
		dprintf("zfs_vnop_pagein: failed to ubc_upl_map");
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, 0);
		if (need_unlock)
			rw_exit(&zp->z_map_lock);
		ZFS_EXIT(zfsvfs);
		return (ENOMEM);
	}

	dprintf("vaddr %p with upl_off 0x%lx\n", vaddr, upl_offset);
	vaddr += upl_offset;

	/* Can't read beyond EOF - but we need to zero those extra bytes. */
	if (off + len > zp->z_size) {
		uint64_t newend = zp->z_size - off;

		dprintf("ZFS: pagein zeroing offset 0x%llx for 0x%llx bytes.\n",
				newend, len - newend);
		memset(&vaddr[newend], 0, len - newend);
		len = newend;
	}
	/*
	 * Fill pages with data from the file.
	 */
	while (len > 0) {
		uint64_t readlen;

		readlen = MIN(PAGESIZE, len);

		dprintf("pagein from off 0x%llx len 0x%llx into address %p (len 0x%lx)\n",
				off, readlen, vaddr, len);

		error = dmu_read(zp->z_zfsvfs->z_os, zp->z_id, off, readlen,
		    (void *)vaddr, DMU_READ_PREFETCH);
		if (error) {
			printf("zfs_vnop_pagein: dmu_read err %d\n", error);
			break;
		}
		off += readlen;
		vaddr += readlen;
		len -= readlen;
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




static int
zfs_pageout(zfsvfs_t *zfsvfs, znode_t *zp, upl_t upl, vm_offset_t upl_offset,
			offset_t off, size_t size, int flags)
{
	dmu_tx_t *tx;
	rl_t *rl;
	uint64_t filesz;
	int err = 0;
	size_t len = size;

	dprintf("+vnop_pageout: %p/%p off 0x%llx len 0x%lx upl_off 0x%lx: "
			"blksz 0x%x, z_size 0x%llx upl %p flags 0x%x\n", zp, ZTOV(zp),
			off, len, upl_offset, zp->z_blksz,
			zp->z_size, upl, flags);

	if (upl == (upl_t)NULL) {
		dprintf("ZFS: vnop_pageout: failed on NULL upl\n");
		return EINVAL;
	}
	/*
	 * We can't leave this function without either calling upl_commit or
	 * upl_abort. So use the non-error version.
	 */
	ZFS_ENTER_NOERROR(zfsvfs);
	if (zfsvfs->z_unmounted) {
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY);
		dprintf("ZFS: vnop_pageout: abort on z_unmounted\n");
		ZFS_EXIT(zfsvfs);
		return EIO;
	}


	ASSERT(vn_has_cached_data(ZTOV(zp)));
	/* ASSERT(zp->z_dbuf_held); */ /* field no longer present in znode. */

	if (len <= 0) {
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY);
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
		printf("ZFS: pageout abort outside pages (rounded 0x%llx > UPLlen "
			   "0x%llx\n", pgsize, size + off);
		ubc_upl_abort_range(upl, pgsize,
		    pgsize - (size + off),
		    UPL_ABORT_FREE_ON_EMPTY);
	}

	//len = MIN(len, filesz - off);
	dprintf("ZFS: starting with size %lx\n", len);
	//if (off + len > zp->z_size) {
	//	dprintf("ZFS: Extending file to %llx\n", off+len);
	//	zfs_freesp(zp, off+len, 0, 0, TRUE);
	//}


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

	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	zfs_sa_upgrade_txholds(tx, zp);
	err = dmu_tx_assign(tx, TXG_WAIT);
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

	if (ubc_upl_map(upl, (vm_offset_t *)&va) != KERN_SUCCESS) {
		err = EINVAL;
		goto out;
	}

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
	 * would extend past the size of the file.
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
		//bzero(va, PAGESIZE-sz);
		//dprintf("zero last 0x%lx bytes.\n", PAGESIZE-sz);

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
		printf("ZFS: pageout failed %d\n", err);
	return (err);
}



int
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
			    (UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY));
		printf("ZFS: vnop_pageout: null zp or zfsvfs\n");
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
	return zfs_pageout(zfsvfs, zp, upl, upl_offset, ap->a_f_offset,
					   len, flags);

}


static int bluster_pageout(zfsvfs_t *zfsvfs, znode_t *zp, upl_t upl,
					upl_offset_t upl_offset, off_t f_offset, int size,
						   uint64_t filesize, int flags, caddr_t vaddr,
						   dmu_tx_t *tx)
{
	int           io_size;
	int           rounded_size;
	off_t         max_size;
	int           is_clcommit = 0;

	if ((flags & UPL_NOCOMMIT) == 0)
		is_clcommit = 1;

	/*
	 * If they didn't specify any I/O, then we are done...
	 * we can't issue an abort because we don't know how
	 * big the upl really is
	 */
	if (size <= 0)
		return (EINVAL);

	if (vnode_vfsisrdonly(ZTOV(zp))) {
		if (is_clcommit)
			ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
		return (EROFS);
	}

	/*
	 * can't page-in from a negative offset
	 * or if we're starting beyond the EOF
	 * or if the file offset isn't page aligned
	 * or the size requested isn't a multiple of PAGE_SIZE
	 */
	if (f_offset < 0 || f_offset >= filesize ||
		(f_offset & PAGE_MASK_64) || (size & PAGE_MASK)) {
		if (is_clcommit)
			ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
		return (EINVAL);
	}
	max_size = filesize - f_offset;


	if (size < max_size)
		io_size = size;
	else
		io_size = max_size;

	rounded_size = (io_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	if (size > rounded_size) {
		if (is_clcommit)
			ubc_upl_abort_range(upl, upl_offset + rounded_size, size - rounded_size,
								UPL_ABORT_FREE_ON_EMPTY);
	}

#if 1
	if (f_offset + size > filesize) {
		dprintf("ZFS: lowering size %u to %llu\n",
			   size, f_offset > filesize ? 0 : filesize - f_offset);
		if (f_offset > filesize)
			size = 0;
		else
			size = filesize - f_offset;
	}
#endif


	dmu_write(zfsvfs->z_os, zp->z_id, f_offset, size, &vaddr[upl_offset], tx);

	return 0;
}




/*
 * In V2 of vnop_pageout, we are given a NULL upl, so that we can
 * grab the file locks first, then request the upl to lock down pages.
 */
int
zfs_vnop_pageoutv2(struct vnop_pageout_args *ap)
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
	int a_flags = ap->a_flags;
	vm_offset_t	a_pl_offset = ap->a_pl_offset;
	size_t a_size = ap->a_size;
	upl_t upl = ap->a_pl;
	upl_page_info_t* pl;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = NULL;
	int error = 0;
	uint64_t filesize;
	rl_t *rl;
	dmu_tx_t *tx;
	caddr_t vaddr = NULL;
	int merror = 0;

	/* We can still get into this function as non-v2 style, by the default
	 * pager (ie, swap - when we eventually support it)
	 */
	if (upl) {
		printf("ZFS: Relaying vnop_pageoutv2 to vnop_pageout\n");
		return zfs_vnop_pageout(ap);
	}

	if (!zp || !zp->z_zfsvfs || !zp->z_sa_hdl) {
		printf("ZFS: vnop_pageout: null zp or zfsvfs\n");
		return ENXIO;
	}

	zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_pageout2: off 0x%llx len 0x%lx upl_off 0x%lx: "
		   "blksz 0x%x, z_size 0x%llx\n", ap->a_f_offset, a_size,
			a_pl_offset, zp->z_blksz,
			zp->z_size);


	/* Start the pageout request */
	/*
	 * We can't leave this function without either calling upl_commit or
	 * upl_abort. So use the non-error version.
	 */
	ZFS_ENTER_NOERROR(zfsvfs);
	if (zfsvfs->z_unmounted) {
		dprintf("ZFS: vnop_pageoutv2: abort on z_unmounted\n");
		error = EIO;
		goto exit_abort;
	}

	ASSERT(vn_has_cached_data(ZTOV(zp)));
	/* ASSERT(zp->z_dbuf_held); */ /* field no longer present in znode. */

	rl = zfs_range_lock(zp, ap->a_f_offset, a_size, RL_WRITER);


	/* Grab UPL now */
	int request_flags;

	/*
	 * we're in control of any UPL we commit
	 * make sure someone hasn't accidentally passed in UPL_NOCOMMIT
	 */
	a_flags &= ~UPL_NOCOMMIT;
	a_pl_offset = 0;

	if (a_flags & UPL_MSYNC) {
		request_flags = UPL_UBC_MSYNC | UPL_RET_ONLY_DIRTY;
	}
	else {
		request_flags = UPL_UBC_PAGEOUT | UPL_RET_ONLY_DIRTY;
	}

	error = ubc_create_upl(vp, ap->a_f_offset, ap->a_size, &upl, &pl,
						   request_flags );
	if (error || (upl == NULL)) {
		printf("ZFS: Failed to create UPL! %d\n", error);
		goto pageout_done;
	}


  top:
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_write(tx, zp->z_id, ap->a_f_offset, ap->a_size);

	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	zfs_sa_upgrade_txholds(tx, zp);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error != 0) {
		dmu_tx_abort(tx);
		if (vaddr) {
			ubc_upl_unmap(upl);
			vaddr = NULL;
		}
		ubc_upl_abort(upl,  (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
		goto pageout_done;
	}



	off_t f_offset;
	int64_t offset;
	int64_t isize;
	int64_t pg_index;

	filesize = zp->z_size; /* get consistent copy of zp_size */

	isize = ap->a_size;
	f_offset = ap->a_f_offset;

    /*
	 * Scan from the back to find the last page in the UPL, so that we
	 * aren't looking at a UPL that may have already been freed by the
	 * preceding aborts/completions.
	 */
	for (pg_index = ((isize) / PAGE_SIZE); pg_index > 0;) {
		if (upl_page_present(pl, --pg_index))
			break;
		if (pg_index == 0) {
			printf("ZFS: failed on pg_index\n");
			dmu_tx_commit(tx);
			if (vaddr) {
				ubc_upl_unmap(upl);
				vaddr = NULL;
			}
			ubc_upl_abort_range(upl, 0, isize, UPL_ABORT_FREE_ON_EMPTY);
			goto pageout_done;
		}
	}

	dprintf("ZFS: isize %llu pg_index %llu\n", isize, pg_index);
	/*
	 * initialize the offset variables before we touch the UPL.
	 * a_f_offset is the position into the file, in bytes
	 * offset is the position into the UPL, in bytes
	 * pg_index is the pg# of the UPL we're operating on.
	 * isize is the offset into the UPL of the last non-clean page.
	 */
	isize = ((pg_index + 1) * PAGE_SIZE);

	offset = 0;
	pg_index = 0;
	while (isize>0) {
		int64_t  xsize;
		int64_t  num_of_pages;

		//printf("isize %d for page %d\n", isize, pg_index);

		if ( !upl_page_present(pl, pg_index)) {
			/*
			 * we asked for RET_ONLY_DIRTY, so it's possible
			 * to get back empty slots in the UPL.
			 * just skip over them
			 */
			f_offset += PAGE_SIZE;
			offset   += PAGE_SIZE;
			isize    -= PAGE_SIZE;
			pg_index++;

			continue;
		}
		if ( !upl_dirty_page(pl, pg_index)) {
			/* hfs has a call to panic here, but we trigger this *a lot* so
			 * unsure what is going on */
			printf ("zfs_vnop_pageoutv2: unforeseen clean page @ index %lld for UPL %p\n", pg_index, upl);
			f_offset += PAGE_SIZE;
			offset   += PAGE_SIZE;
			isize    -= PAGE_SIZE;
			pg_index++;
			continue;
		}

		/*
		 * We know that we have at least one dirty page.
		 * Now checking to see how many in a row we have
		 */
		num_of_pages = 1;
		xsize = isize - PAGE_SIZE;

		while (xsize>0) {
			if ( !upl_dirty_page(pl, pg_index + num_of_pages))
				break;
			num_of_pages++;
			xsize -= PAGE_SIZE;
		}
		xsize = num_of_pages * PAGE_SIZE;

		if (!vnode_isswap(vp)) {
			off_t end_of_range;

			end_of_range = f_offset + xsize - 1;
			if (end_of_range >= filesize) {
				end_of_range = (off_t)(filesize - 1);
			}
#if 0 // hfs
			if (f_offset < filesize) {
				rl_remove(f_offset, end_of_range, &fp->ff_invalidranges);
				cp->c_flag |= C_MODIFIED;  /* leof is dirty */
			}
#endif
		}

		// Map it if needed
		if (!vaddr) {
			if (ubc_upl_map(upl, (vm_offset_t *)&vaddr) != KERN_SUCCESS) {
				error = EINVAL;
				printf("ZFS: unable to map\n");
				goto out;
			}
			dprintf("ZFS: Mapped %p\n", vaddr);
		}


		dprintf("ZFS: bluster offset %lld fileoff %lld size %lld filesize %lld\n",
			   offset, f_offset, xsize, filesize);
		merror = bluster_pageout(zfsvfs, zp, upl, offset, f_offset, xsize,
								 filesize, a_flags, vaddr, tx);
		/* remember the first error */
		if ((error == 0) && (merror))
			error = merror;

		f_offset += xsize;
		offset   += xsize;
		isize    -= xsize;
		pg_index += num_of_pages;
	} // while isize

	/* finish off transaction */
	if (error == 0) {
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
		zfs_log_write(zfsvfs->z_log, tx, TX_WRITE, zp, ap->a_f_offset,
					  a_size, 0,
		    NULL, NULL);
	}
	dmu_tx_commit(tx);

  out:
	// unmap
	if (vaddr) {
		ubc_upl_unmap(upl);
		vaddr = NULL;
	}

	zfs_range_unlock(rl);
	if (a_flags & UPL_IOSYNC)
		zil_commit(zfsvfs->z_log, zp->z_id);

	if (error)
		ubc_upl_abort(upl,  (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
	else
		ubc_upl_commit_range(upl, 0, a_size, UPL_COMMIT_FREE_ON_EMPTY);

	upl = NULL;

	ZFS_EXIT(zfsvfs);
	if (error)
		printf("ZFS: pageoutv2 failed %d\n", error);
	return (error);

  pageout_done:
	zfs_range_unlock(rl);

  exit_abort:
	printf("ZFS: pageoutv2 aborted %d\n", error);
	//VERIFY(ubc_create_upl(vp, off, len, &upl, &pl, flags) == 0);
	//ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
	if (zfsvfs)
		ZFS_EXIT(zfsvfs);
	return (error);
}






int
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
	zfsvfs_t *zfsvfs;

	if (!zp) return ENODEV;

	zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_mmap: %p\n", ap->a_vp);

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

int
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

	dprintf("+vnop_mnomap: %p\n", ap->a_vp);

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




int
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
	zfsvfs_t *zfsvfs = NULL;
	DECLARE_CRED(ap);

	dprintf("vnop_inactive: zp %p vp %p type %u\n", zp, vp, vnode_vtype(vp));

	if (!zp) return 0; /* zfs_remove will clear it in fastpath */

	zfsvfs = zp->z_zfsvfs;

	if (vnode_isrecycled(ap->a_vp)) {
		/*
		 * We can not call inactive at this time, as we are inside
		 * vnode_create()->vclean() path. But since we are only here to
		 * sync out atime, and we know vnop_reclaim will called next.
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


	/* We can call it directly, huzzah! */
	zfs_inactive(vp, cr, NULL);

	/* dprintf("-vnop_inactive\n"); */
	return (0);
}



#ifdef _KERNEL
uint64_t vnop_num_reclaims = 0;
uint64_t vnop_num_vnodes = 0;
#endif


int
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
	boolean_t fastpath;
	ASSERT(zp != NULL);


	/* Destroy the vm object and flush associated pages. */
#ifndef __APPLE__
	vnode_destroy_vobject(vp);
#endif

	/* Already been released? */
	zp = VTOZ(vp);
	dprintf("+vnop_reclaim zp %p/%p type %d\n", zp, vp, vnode_vtype(vp));
	if (!zp) goto out;

	zfsvfs = zp->z_zfsvfs;

	if (!zfsvfs) {
		printf("ZFS: vnop_reclaim with zfsvfs == NULL - tell lundman\n");
		return 0;
	}

	if (zfsctl_is_node(vp)) {
		printf("ZFS: vnop_reclaim with ctldir node - tell lundman\n");
		return 0;
	}

	ZTOV(zp) = NULL;

	/*
	 * Purge old data structures associated with the denode.
	 */
	vnode_clearfsnode(vp); /* vp->v_data = NULL */
	vnode_removefsref(vp); /* ADDREF from vnode_create */
	atomic_dec_64(&vnop_num_vnodes);

	fastpath = zp->z_fastpath;

	dprintf("+vnop_reclaim zp %p/%p fast %d unlinked %d unmount %d sa_hdl %p\n",
		   zp, vp, zp->z_fastpath, zp->z_unlinked,
			zfsvfs->z_unmounted, zp->z_sa_hdl);
	/*
	 * This will release as much as it can, based on reclaim_reentry,
	 * if we are from fastpath, we do not call free here, as zfs_remove
	 * calls zfs_znode_delete() directly.
	 * zfs_zinactive() will leave earlier if z_reclaim_reentry is true.
	 */
	if (fastpath == B_FALSE) {
		rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
		if (zp->z_sa_hdl == NULL)
			zfs_znode_free(zp);
		else
			zfs_zinactive(zp);
		rw_exit(&zfsvfs->z_teardown_inactive_lock);
	}

	/* Direct zfs_remove? We are done */
	if (fastpath == B_TRUE) goto out;


#ifdef _KERNEL
	atomic_inc_64(&vnop_num_reclaims);
#endif

  out:
	return (0);
}





int
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
	int error;
	error = zfs_vnop_create((struct vnop_create_args *)ap);
	return error;
}

int
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

int
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

int
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
	{
		znode_t *zp = VTOZ(ap->a_vp);
		*valp = 1;
		if (zp && zp->z_zfsvfs) {
			zfsvfs_t *zfsvfs = zp->z_zfsvfs;
			*valp = (zfsvfs->z_case == ZFS_CASE_SENSITIVE) ? 1 : 0;
		}
	}
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
	int  error = 0;
	struct uio *finderinfo_uio = NULL;

	/* dprintf("+getxattr vp %p\n", ap->a_vp); */

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return ENOTSUP;
	}

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

	mutex_enter(&zp->z_lock);
	if (zp->z_xattr_cached == NULL)
		error = -zfs_sa_get_xattr(zp);
	mutex_exit(&zp->z_lock);

	if (zfsvfs->z_use_sa && zp->z_is_sa) {
		uint64_t size = uio_resid(uio);
		char *value;

		if (!size) { /* Lookup size */

			error = zpl_xattr_get_sa(vp, ap->a_name, NULL, 0);
			if (error > 0) {
				dprintf("ZFS: returning XATTR size %d\n", error);
				*ap->a_size = error;
				error = 0;
				goto out;
			}
		}

		value = kmem_alloc(size, KM_SLEEP);
		if (value) {
			error = zpl_xattr_get_sa(vp, ap->a_name, value, size);
			//dprintf("ZFS: SA XATTR said %d\n", error);

			if (error > 0) {
				uiomove((const char*)value, error, 0, uio);
				error = 0;
			}
			kmem_free(value, size);

			if (error != -ENOENT)
				goto out;
		}
	}


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

	/*
	 * If we are dealing with FinderInfo, we duplicate the UIO first
	 * so that we can uiomove to/from it to modify contents.
	 */
	if (!error && uio &&
		bcmp(ap->a_name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
		if ((user_size_t)uio_resid(uio) < 32) {/* FinderInfo is 32 bytes */
			error = ERANGE;
			goto out;
		}

		finderinfo_uio = uio_duplicate(uio);
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


	/*
	 * Handle FinderInfo
	 */
	if ((error == 0) && (finderinfo_uio != NULL)) {
		u_int8_t finderinfo[32];
		size_t bytes;

		/* Copy in the data we just read */
		uiocopy((const char *)&finderinfo, 32, UIO_WRITE,
				finderinfo_uio, &bytes);
		if (bytes != 32) {
			error = ERANGE;
			goto out;
		}

		finderinfo_update((uint8_t *)&finderinfo, zp);

		/* Copy out the data we just modified */
		uiomove((const char*)&finderinfo, 32, 0, finderinfo_uio);

	}



out:
	if (finderinfo_uio) uio_free(finderinfo_uio);

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
	int  error = 0;

	dprintf("+setxattr vp %p '%s' enabled? %d\n", ap->a_vp,
		   ap->a_name, zfsvfs->z_xattr);

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return ENOTSUP;
	}

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

	if (ap->a_options & XATTR_CREATE)
		flag = ZNEW;	 /* expect no pre-existing entry */
	else if (ap->a_options & XATTR_REPLACE)
		flag = ZEXISTS;  /* expect an existing entry */
	else
		flag = 0;

	mutex_enter(&zp->z_lock);
	if (zp->z_xattr_cached == NULL)
		error = -zfs_sa_get_xattr(zp);
	mutex_exit(&zp->z_lock);

	/* Preferentially store the xattr as a SA for better performance */
	if (zfsvfs->z_use_sa && zfsvfs->z_xattr_sa && zp->z_is_sa) {
		char *value;
		uint64_t size;

		/* New, expect it to not exist .. */
		if ((flag | ZNEW) &&
			(zpl_xattr_get_sa(vp, ap->a_name, NULL, 0) > 0)) {
			error = EEXIST;
			goto out;
		}

		/* Replace, XATTR must exist .. */
		if ((flag | ZEXISTS) &&
			((error = zpl_xattr_get_sa(vp, ap->a_name, NULL, 0)) <= 0) &&
			error != -ENOENT) {
			error = ENOATTR;
			goto out;
		}

		size = uio_resid(uio);
		value = kmem_alloc(size, KM_SLEEP);
		if (value) {
			size_t bytes;

			/* Copy in the xattr value */
			uiocopy((const char *)value, size, UIO_WRITE,
					uio, &bytes);

			error = zpl_xattr_set_sa(vp, ap->a_name,
									 value, bytes,
									 flag, cr);
			kmem_free(value, size);

			if (error == 0)
				goto out;
		}
		dprintf("ZFS: zpl_xattr_set_sa failed %d\n", error);
	}

	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR))) {
		goto out;
	}

	/* Lookup or create the named attribute. */
	error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name, VTOZ(vp)->z_mode, cr,
	    &xvp, flag);
	if (error)
		goto out;

	/* Write the attribute data. */
	ASSERT(uio != NULL);
	error = zfs_freesp(VTOZ(xvp), 0, 0, VTOZ(vp)->z_mode, TRUE);

    /*
	 * TODO:
	 * When writing FINDERINFO, we need to replace the ADDEDTIME date
	 * with actual crtime and not let userland overwrite it.
	 */

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

int
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

	dprintf("+removexattr vp %p '%s'\n", ap->a_vp, ap->a_name);

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return ENOTSUP;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}


	mutex_enter(&zp->z_lock);
	if (zp->z_xattr_cached == NULL)
		error = -zfs_sa_get_xattr(zp);
	mutex_exit(&zp->z_lock);

	if (zfsvfs->z_use_sa && zfsvfs->z_xattr_sa && zp->z_is_sa) {
        nvlist_t *nvl;

		nvl = zp->z_xattr_cached;

		error = -nvlist_remove(nvl, ap->a_name, DATA_TYPE_BYTE_ARRAY);

		dprintf("ZFS: removexattr nvlist_remove said %d\n", error);
		if (!error) {
			/* Update the SA for additions, modifications, and removals. */
			error = -zfs_sa_set_xattr(zp);
			goto out;
		}
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

int
zfs_vnop_listxattr(struct vnop_listxattr_args *ap)
#if 0
	struct vnop_listxattr_args {
		struct vnodeop_desc *a_desc;
        vnode_t a_vp;
        uio_t a_uio;
        size_t *a_size;
        int a_options;
        vfs_context_t a_context;
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

	dprintf("+listxattr vp %p: \n", ap->a_vp);

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return EINVAL;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	mutex_enter(&zp->z_lock);
	if (zp->z_xattr_cached == NULL)
		error = -zfs_sa_get_xattr(zp);
	mutex_exit(&zp->z_lock);

	if (zfsvfs->z_use_sa && zp->z_is_sa && zp->z_xattr_cached) {
        nvpair_t *nvp = NULL;

		while ((nvp = nvlist_next_nvpair(zp->z_xattr_cached, nvp)) != NULL) {
			ASSERT3U(nvpair_type(nvp), ==, DATA_TYPE_BYTE_ARRAY);

			namelen = strlen(nvpair_name(nvp)) + 1; /* Null byte */

			/* Just checking for space requirements? */
			if (uio == NULL) {
				size += namelen;
			} else {
				if (namelen > uio_resid(uio)) {
					error = ERANGE;
					break;
				}
				printf("ZFS: listxattr '%s'\n", nvpair_name(nvp));
				error = uiomove((caddr_t)nvpair_name(nvp), namelen,
								UIO_READ, uio);
				if (error)
					break;
			}
		} /* while nvlist */
	} /* SA xattr */
	if (error) goto out;

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
	dprintf("-listxattr vp %p: error %d size %ld\n", ap->a_vp, error, size);
	return (error);
}

#ifdef HAVE_NAMED_STREAMS
int
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

int
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

int
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
int
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

int
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

int
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

int
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

int
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

int
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

int
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

#ifdef WITH_READDIRATTR
int
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

	printf("+vnop_readdirattr\n");

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
#endif


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
	dprintf("ZFS: Bad vnop: returning EINVAL\n");
	return (EINVAL);
}

static int
zfs_isdir()
{
	dprintf("ZFS: Bad vnop: returning EISDIR\n");
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
	{&vnop_bwrite_desc, (VOPFUNC)zfs_isdir},
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
#ifdef WITH_READDIRATTR
	{&vnop_readdirattr_desc, (VOPFUNC)zfs_vnop_readdirattr},
#endif
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
	{&vnop_bwrite_desc, (VOPFUNC)zfs_inval},
	{&vnop_pagein_desc,	(VOPFUNC)zfs_vnop_pagein},
#if	HAVE_PAGEOUT_V2
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageoutv2},
#else
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageout},
#endif
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

int (**zfs_fifonodeops)(void *);
struct vnodeopv_entry_desc zfs_fifonodeops_template[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)fifo_lookup },            /* lookup */
	{ &vnop_create_desc, (VOPFUNC)fifo_create },            /* create */
	{ &vnop_mknod_desc, (VOPFUNC)fifo_mknod },              /* mknod */
	{ &vnop_open_desc, (VOPFUNC)fifo_open },                        /* open
																	 */
	{ &vnop_close_desc, (VOPFUNC)fifo_close },           /* close */
	{ &vnop_getattr_desc, (VOPFUNC)zfs_vnop_getattr },      /* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)zfs_vnop_setattr },      /* setattr */
	{ &vnop_read_desc, (VOPFUNC)fifo_read },             /* read */
	{ &vnop_write_desc, (VOPFUNC)fifo_write },           /* write */
	{ &vnop_ioctl_desc, (VOPFUNC)fifo_ioctl },              /* ioctl */
	{ &vnop_select_desc, (VOPFUNC)fifo_select },            /* select */
	{ &vnop_revoke_desc, (VOPFUNC)fifo_revoke },            /* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)fifo_mmap },                        /* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)zfs_vnop_fsync },          /* fsync */
	{ &vnop_remove_desc, (VOPFUNC)fifo_remove },            /* remove */
	{ &vnop_link_desc, (VOPFUNC)fifo_link },                        /* link */
	{ &vnop_rename_desc, (VOPFUNC)fifo_rename },            /* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)fifo_mkdir },              /* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)fifo_rmdir },              /* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)fifo_symlink },          /* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)fifo_readdir },          /* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)fifo_readlink },                /* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)zfs_vnop_inactive },    /* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)zfs_vnop_reclaim },      /* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)fifo_strategy },                /* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)fifo_pathconf },                /* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)err_advlock },           /* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)zfs_inval },
	{ &vnop_pagein_desc, (VOPFUNC)zfs_vnop_pagein },                /* Pagein */
#if	HAVE_PAGEOUT_V2
	{ &vnop_pageout_desc, (VOPFUNC)zfs_vnop_pageoutv2 },      /* Pageout */
#else
	{ &vnop_pageout_desc, (VOPFUNC)zfs_vnop_pageout },      /* Pageout */
#endif
	{ &vnop_copyfile_desc, (VOPFUNC)err_copyfile },                 /* copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)zfs_vnop_blktooff },    /* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)zfs_vnop_offtoblk },    /* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)zfs_vnop_blockmap },            /* blockmap */
	{ &vnop_getxattr_desc, (VOPFUNC)zfs_vnop_getxattr},
	{ &vnop_setxattr_desc, (VOPFUNC)zfs_vnop_setxattr},
	{ &vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{ &vnop_listxattr_desc, (VOPFUNC)zfs_vnop_listxattr},
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_fifonodeop_opv_desc =
	{ &zfs_fifonodeops, zfs_fifonodeops_template };






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
zfs_znode_getvnode(znode_t *zp, zfsvfs_t *zfsvfs)
{
	struct vnode_fsparam vfsp;
	struct vnode *vp = NULL;

	dprintf("getvnode zp %p with vp %p zfsvfs %p vfs %p\n", zp, vp,
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
	case VSOCK:
		vfsp.vnfs_vops = zfs_fvnodeops;
		break;
	case VFIFO:
		vfsp.vnfs_vops = zfs_fifonodeops;
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
		vfsp.vnfs_vops = zfs_fvnodeops;
		printf("ZFS: Warning, error-vnops selected: vtype %d\n",vfsp.vnfs_vtype);
		break;
	}

	/*
	 * vnode_create() has a habit of calling both vnop_reclaim() and
	 * vnop_fsync(), which can create havok as we are already holding locks.
	 */

	/* So pageout can know if it is called recursively, add this thread to list*/
	while (vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &vp) != 0) {
		kpreempt(KPREEMPT_SYNC);
	}
	atomic_inc_64(&vnop_num_vnodes);

	dprintf("Assigned zp %p with vp %p\n", zp, vp);

	vnode_settag(vp, VT_ZFS);

	zp->z_vid = vnode_vid(vp);
	zp->z_vnode = vp;

	/*
	 * OS X Finder is hardlink agnostic, so we need to mark vp's that
	 * are hardlinks, so that it forces a lookup each time, ignoring
	 * the name cache.
	 */
	if ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG))
		vnode_setmultipath(vp);

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
#if	HAVE_PAGEOUT_V2
	vfe.vfe_flags |= VFS_TBLVNOP_PAGEOUTV2;
#endif
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
