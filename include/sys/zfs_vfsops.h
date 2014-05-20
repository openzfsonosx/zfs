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
 */

#ifndef	_SYS_FS_ZFS_VFSOPS_H
#define	_SYS_FS_ZFS_VFSOPS_H

#include <sys/isa_defs.h>
#include <sys/types32.h>
#include <sys/list.h>
#include <sys/vfs.h>
#include <sys/zil.h>
#include <sys/sa.h>
#include <sys/rrwlock.h>
#include <sys/zfs_ioctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Structure defining a mount option for a filesystem.
 * option names are found in mntent.h
 */


typedef struct mntopt {
        char    *mo_name;       /* option name */
        char    **mo_cancel;    /* list of options cancelled by this one */
        char    *mo_arg;        /* argument string for this option */
        int     mo_flags;       /* flags for this mount option */
        void    *mo_data;       /* filesystem specific data */
} mntopt_t;

/*
 * Structure holding mount option strings for the mounted file system.
 */
typedef struct mntopts {
	uint_t		mo_count;		/* number of entries in table */
	mntopt_t	*mo_list;		/* list of mount options */
} mntopts_t;


typedef struct vfssw {
	char		*vsw_name;	/* type name -- max len _ST_FSTYPSZ */
	int		(*vsw_init) (int, char *);
				/* init routine (for non-loadable fs only) */
	int		vsw_flag;	/* flags */
	mntopts_t	vsw_optproto;	/* mount options table prototype */
	uint_t		vsw_count;	/* count of references */
	kmutex_t	vsw_lock;	/* lock to protect vsw_count */
//	vfsops_t	vsw_vfsops;	/* filesystem operations vector */
} vfssw_t;

typedef struct vfsdef_v5 {
	int		def_version;	/* structure version, must be first */
	char		*name;		/* filesystem type name */
	int		(*init) (int, char *);	/* init routine */
	int		flags;		/* filesystem flags */
	mntopts_t	*optproto;	/* mount options table prototype */
} vfsdef_v5;

typedef struct vfsdef_v5 vfsdef_t;

enum {
	VFSDEF_VERSION = 5
};

/*
 * flags for vfssw and vfsdef
 */
#define	VSW_HASPROTO	0x01	/* struct has a mount options prototype */
#define	VSW_CANRWRO	0x02	/* file system can transition from rw to ro */
#define	VSW_CANREMOUNT	0x04	/* file system supports remounts */
#define	VSW_NOTZONESAFE	0x08	/* zone_enter(2) should fail for these files */
#define	VSW_VOLATILEDEV	0x10	/* vfs_dev can change each time fs is mounted */
#define	VSW_STATS	0x20	/* file system can collect stats */
#define	VSW_XID		0x40	/* file system supports extended ids */
#define	VSW_CANLOFI	0x80	/* file system supports lofi mounts */
#define	VSW_ZMOUNT	0x100	/* file system always allowed in a zone */

#define	VSW_INSTALLED	0x8000	/* this vsw is associated with a file system */

/*
 * Flags that apply to mount options
 */

#define	MO_SET		0x01		/* option is set */
#define	MO_NODISPLAY	0x02		/* option not listed in mnttab */
#define	MO_HASVALUE	0x04		/* option takes a value */
#define	MO_IGNORE	0x08		/* option ignored by parser */
#define	MO_DEFAULT	MO_SET		/* option is on by default */
#define	MO_TAG		0x10		/* flags a tag set by user program */
#define	MO_EMPTY	0x20		/* empty space in option table */

#define	VFS_NOFORCEOPT	0x01		/* honor MO_IGNORE (don't set option) */
#define	VFS_DISPLAY	0x02		/* Turn off MO_NODISPLAY bit for opt */
#define	VFS_NODISPLAY	0x04		/* Turn on MO_NODISPLAY bit for opt */
#define	VFS_CREATEOPT	0x08		/* Create the opt if it's not there */

typedef struct zfsvfs zfsvfs_t;

//Move
//usr/src/uts/common/sys/vfs.h
#ifdef illumos
void	vfs_parsemntopts(mntopts_t *, char *, int);
struct mntopt *vfs_hasopt(const mntopts_t *, const char *);
void    vfs_clearmntopt(struct vfs *, const char *);
void    vfs_setmntopt(struct vfs *, const char *, const char *, int);
int	vfs_optionisset(const struct vfs *, const char *, char **);
#endif
#ifdef __APPLE__
void	vfs_mergeopttbl(const mntopts_t *, const mntopts_t *, mntopts_t *);
void	vfs_copyopttbl(const mntopts_t *, mntopts_t *);
void	vfs_freeopttbl(mntopts_t *);
struct vfssw *vfs_getvfssw(const char *);
struct vfssw *vfs_getvfsswbyname(const char *);
void	vfs_refvfssw(struct vfssw *);
void	vfs_parsemntopts(mntopts_t *, char *, int);
struct mntopt *vfs_hasopt(const mntopts_t *, const char *);
void    vfs_clearmntopt(zfsvfs_t *, const char *);
void    vfs_setmntopt(zfsvfs_t *, const char *, const char *, int);
int	vfs_optionisset(const zfsvfs_t *, const char *, char **);

extern struct vfssw vfssw[];		/* table of filesystem types */
extern const int nfstype;		/* # of elements in vfssw array */
extern const mntopts_t vfs_mntopts;	/* globally recognized options */

//void    vfs_clearmntopt(struct mount *, const char *);
//void    vfs_setmntopt(struct mount *, const char *, const char *, int);
#endif

struct zfs_sb;
struct znode;


struct zfsvfs {
        vfs_t           *z_vfs;         /* generic fs struct */
        zfsvfs_t        *z_parent;      /* parent fs */
        objset_t        *z_os;          /* objset reference */
        uint64_t        z_root;         /* id of root znode */
        uint64_t        z_unlinkedobj;  /* id of unlinked zapobj */
        uint64_t        z_max_blksz;    /* maximum block size for files */
        uint64_t	    z_fuid_obj;	    /* fuid table object number */
        uint64_t	    z_fuid_size;	/* fuid table size */
     	avl_tree_t   	z_fuid_idx;	    /* fuid tree keyed by index */
        avl_tree_t	    z_fuid_domain;	/* fuid tree keyed by domain */
        krwlock_t	    z_fuid_lock;	/* fuid lock */
        boolean_t	    z_fuid_loaded;	/* fuid tables are loaded */
        boolean_t	    z_fuid_dirty;   /* need to sync fuid table ? */
        struct zfs_fuid_info    *z_fuid_replay; /* fuid info for replay */
        uint64_t        z_assign;       /* TXG_NOWAIT or set by zil_replay() */
        zilog_t         *z_log;         /* intent log pointer */
        uint_t          z_acl_mode;     /* acl chmod/mode behavior */
        uint_t          z_acl_inherit;  /* acl inheritance behavior */
        zfs_case_t      z_case;         /* case-sense */
        boolean_t       z_utf8;         /* utf8-only */
        int             z_norm;         /* normalization flags */
        boolean_t       z_atime;        /* enable atimes mount option */
        boolean_t       z_unmounted;    /* unmounted */
	    rrwlock_t	    z_teardown_lock;
        krwlock_t	    z_teardown_inactive_lock;
        list_t          z_all_znodes;   /* all vnodes in the fs */
        kmutex_t        z_znodes_lock;  /* lock for z_all_znodes */
        struct vnode   *z_ctldir;      /* .zfs directory pointer */
        time_t          z_mount_time;           /* mount timestamp (for Spotlight) */
        time_t          z_last_unmount_time;    /* unmount timestamp (for Spotlight) */
        time_t          z_last_mtime_synced;    /* last fs mtime synced to disk */
        struct vnode   *z_mtime_vp;            /* znode utilized for the fs mtime. */
        boolean_t       z_show_ctldir;  /* expose .zfs in the root dir */
        boolean_t       z_issnap;       /* true if this is a snapshot */
        boolean_t	    z_use_fuids;	/* version allows fuids */
        boolean_t       z_replay;       /* set during ZIL replay */
        boolean_t       z_use_sa;       /* version allow system attributes */
        uint64_t        z_version;
        uint64_t        z_shares_dir;   /* hidden shares dir */
        kmutex_t	    z_lock;
        kmutex_t	    z_reclaim_list_lock; /* lock for using z_reclaim_list*/
        uint64_t        z_vnode_create_depth;/* inc/dec before/after vnode_create */
        list_t          z_reclaim_znodes;/* all reclaimed vnodes in the fs*/
        boolean_t       z_reclaim_thread_exit;
        kmutex_t		z_reclaim_thr_lock;
        kcondvar_t	    z_reclaim_thr_cv;	/* used to signal reclaim thr */
    	uint64_t	    z_userquota_obj;
        uint64_t	    z_groupquota_obj;
        uint64_t	    z_replay_eof;	/* New end of file - replay only */
        sa_attr_type_t  *z_attr_table;  /* SA attr mapping->id */
#define ZFS_OBJ_MTX_SZ  256
        kmutex_t        z_hold_mtx[ZFS_OBJ_MTX_SZ];     /* znode hold locks */
#ifdef __APPLE__
	mntopts_t	vfs_mntopts;
	boolean_t	z_nbmand;
#endif
};


#define	ZFS_SUPER_MAGIC	0x2fc12fc1

#define	ZSB_XATTR	0x0001		/* Enable user xattrs */

/*
 * Allow a maximum number of links.  While ZFS does not internally limit
 * this the inode->i_nlink member is defined as an unsigned int.  To be
 * safe we use 2^31-1 as the limit.
 */
#define	ZFS_LINK_MAX		((1U << 31) - 1U)

/*
 * Normal filesystems (those not under .zfs/snapshot) have a total
 * file ID size limited to 12 bytes (including the length field) due to
 * NFSv2 protocol's limitation of 32 bytes for a filehandle.  For historical
 * reasons, this same limit is being imposed by the Solaris NFSv3 implementation
 * (although the NFSv3 protocol actually permits a maximum of 64 bytes).  It
 * is not possible to expand beyond 12 bytes without abandoning support
 * of NFSv2.
 *
 * For normal filesystems, we partition up the available space as follows:
 *	2 bytes		fid length (required)
 *	6 bytes		object number (48 bits)
 *	4 bytes		generation number (32 bits)
 *
 * We reserve only 48 bits for the object number, as this is the limit
 * currently defined and imposed by the DMU.
 */
typedef struct zfid_short {
	uint16_t	zf_len;
	uint8_t		zf_object[6];		/* obj[i] = obj >> (8 * i) */
	uint8_t		zf_gen[4];		/* gen[i] = gen >> (8 * i) */
} zfid_short_t;

/*
 * Filesystems under .zfs/snapshot have a total file ID size of 22 bytes
 * (including the length field).  This makes files under .zfs/snapshot
 * accessible by NFSv3 and NFSv4, but not NFSv2.
 *
 * For files under .zfs/snapshot, we partition up the available space
 * as follows:
 *	2 bytes		fid length (required)
 *	6 bytes		object number (48 bits)
 *	4 bytes		generation number (32 bits)
 *	6 bytes		objset id (48 bits)
 *	4 bytes		currently just zero (32 bits)
 *
 * We reserve only 48 bits for the object number and objset id, as these are
 * the limits currently defined and imposed by the DMU.
 */
typedef struct zfid_long {
	zfid_short_t	z_fid;
	uint8_t		zf_setid[6];		/* obj[i] = obj >> (8 * i) */
	uint8_t		zf_setgen[4];		/* gen[i] = gen >> (8 * i) */
} zfid_long_t;

#define	SHORT_FID_LEN	(sizeof (zfid_short_t) - sizeof (uint16_t))
#define	LONG_FID_LEN	(sizeof (zfid_long_t) - sizeof (uint16_t))

extern uint_t zfs_fsyncer_key;

extern int zfs_suspend_fs(zfsvfs_t *zfsvfs);
extern int zfs_resume_fs(zfsvfs_t *zfsvfs, const char *osname);
extern int zfs_userspace_one(zfsvfs_t *zfsvfs, zfs_userquota_prop_t type,
    const char *domain, uint64_t rid, uint64_t *valuep);
extern int zfs_userspace_many(zfsvfs_t *zfsvfs, zfs_userquota_prop_t type,
    uint64_t *cookiep, void *vbuf, uint64_t *bufsizep);
extern int zfs_set_userquota(zfsvfs_t *zfsvfs, zfs_userquota_prop_t type,
    const char *domain, uint64_t rid, uint64_t quota);
extern boolean_t zfs_owner_overquota(zfsvfs_t *zfsvfs, struct znode *,
    boolean_t isgroup);
extern boolean_t zfs_fuid_overquota(zfsvfs_t *zfsvfs, boolean_t isgroup,
    uint64_t fuid);
extern int zfs_set_version(zfsvfs_t *zfsvfs, uint64_t newvers);

extern int zfs_get_zplprop(objset_t *os, zfs_prop_t prop,
    uint64_t *value);
extern int zfs_sb_create(const char *name, zfsvfs_t **zfsvfsp);
extern int zfs_sb_setup(zfsvfs_t *zfsvfs, boolean_t mounting);
extern void zfs_sb_free(zfsvfs_t *zfsvfs);
extern int zfs_check_global_label(const char *dsname, const char *hexsl);
extern boolean_t zfs_is_readonly(zfsvfs_t *zfsvfs);




extern int  zfs_vfs_init (struct vfsconf *vfsp);
extern int  zfs_vfs_start (struct mount *mp, int flags, vfs_context_t context);
extern int  zfs_vfs_mount (struct mount *mp, vnode_t *devvp, user_addr_t data, vfs_context_t context);
extern int  zfs_vfs_unmount (struct mount *mp, int mntflags, vfs_context_t context);
extern int  zfs_vfs_root (struct mount *mp, vnode_t **vpp, vfs_context_t context);
extern int  zfs_vfs_vget (struct mount *mp, ino64_t ino, vnode_t **vpp, vfs_context_t context);
extern int  zfs_vfs_getattr (struct mount *mp, struct vfs_attr *fsap, vfs_context_t context);
extern int  zfs_vfs_setattr (struct mount *mp, struct vfs_attr *fsap, vfs_context_t context);
extern int  zfs_vfs_sync (struct mount *mp, int waitfor, vfs_context_t context);
extern int  zfs_vfs_fhtovp (struct mount *mp, int fhlen, unsigned char *fhp, vnode_t **vpp, vfs_context_t context);
extern int  zfs_vfs_vptofh (vnode_t *vp, int *fhlenp, unsigned char *fhp, vfs_context_t context);
extern int  zfs_vfs_sysctl (int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp,  user_addr_t newp, size_t newlen, vfs_context_t context);
extern int  zfs_vfs_quotactl ( struct mount *mp, int cmds, uid_t uid, caddr_t datap, vfs_context_t context);

extern void zfs_init(void);
extern void zfs_fini(void);

extern int  zfs_vnode_lock(vnode_t *vp, int flags);
extern void zfs_freevfs(struct mount *vfsp);

extern int  zfsvfs_create(const char *osname, zfsvfs_t **zfvp);
extern void zfsvfs_free(zfsvfs_t *zfsvfs);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_VFSOPS_H */
