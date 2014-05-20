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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include_next <sys/vfs.h>

#ifndef _ZFS_SYS_VFS_H
#define	_ZFS_SYS_VFS_H

#ifdef illumos

/* The following functions are not for general use by filesystems */

void	vfs_createopttbl(mntopts_t *, const char *);
void	vfs_copyopttbl(const mntopts_t *, mntopts_t *);
void	vfs_mergeopttbl(const mntopts_t *, const mntopts_t *, mntopts_t *);
void	vfs_freeopttbl(mntopts_t *);
void	vfs_parsemntopts(mntopts_t *, char *, int);
int	vfs_buildoptionstr(const mntopts_t *, char *, int);
struct mntopt *vfs_hasopt(const mntopts_t *, const char *);
void	vfs_mnttab_modtimeupd(void);

void	vfs_clearmntopt(struct vfs *, const char *);
void	vfs_setmntopt(struct vfs *, const char *, const char *, int);
void	vfs_setresource(struct vfs *, const char *, uint32_t);
void	vfs_setmntpoint(struct vfs *, const char *, uint32_t);
refstr_t *vfs_getresource(const struct vfs *);
refstr_t *vfs_getmntpoint(const struct vfs *);
int	vfs_optionisset(const struct vfs *, const char *, char **);

/*
 * Globals.
 */

extern struct vfssw vfssw[];		/* table of filesystem types */
extern krwlock_t vfssw_lock;
extern char rootfstype[];		/* name of root fstype */
extern const int nfstype;		/* # of elements in vfssw array */
extern vfsops_t *EIO_vfsops;		/* operations for vfs being torn-down */

/*
 * The following variables are private to the the kernel's vfs layer.  File
 * system implementations should not access them.
 */
extern struct vfs *rootvfs;		/* ptr to root vfs structure */
typedef struct {
	struct vfs *rvfs_head;		/* head vfs in chain */
	kmutex_t rvfs_lock;		/* mutex protecting this chain */
	uint32_t rvfs_len;		/* length of this chain */
} rvfs_t;
extern rvfs_t *rvfs_list;
extern int vfshsz;			/* # of elements in rvfs_head array */
extern const mntopts_t vfs_mntopts;	/* globally recognized options */

#elif __APPLE__

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

/*
 * Structure holding mount option strings for the mounted file system.
 */
typedef struct mntopts {
	uint_t		mo_count;		/* number of entries in table */
	mntopt_t	*mo_list;		/* list of mount options */
} mntopts_t;

typedef struct illumos_vfs {
	mntopts_t	vfs_mntopts;		/* options mounted with */
} illumos_vfs_t;

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

struct vfssw *vfs_getvfssw(const char *);
struct vfssw *vfs_getvfsswbyname(const char *);
void	vfs_refvfssw(struct vfssw *);

//void	vfs_createopttbl(mntopts_t *, const char *);
void	vfs_copyopttbl(const mntopts_t *, mntopts_t *);
void	vfs_mergeopttbl(const mntopts_t *, const mntopts_t *, mntopts_t *);
void	vfs_freeopttbl(mntopts_t *);
void	vfs_parsemntopts(mntopts_t *, char *, int);
int	vfs_buildoptionstr(const mntopts_t *, char *, int);
struct mntopt *vfs_hasopt(const mntopts_t *, const char *);
//void	vfs_mnttab_modtimeupd(void);

void	vfs_clearmntopt(struct illumos_vfs *, const char *);
void	vfs_setmntopt(struct illumos_vfs *, const char *, const char *, int);
//void	vfs_setresource(struct illumos_vfs *, const char *, uint32_t);
//void	vfs_setmntpoint(struct illumos_vfs *, const char *, uint32_t);
//refstr_t *vfs_getresource(const struct vfs *);
//refstr_t *vfs_getmntpoint(const struct vfs *);
int	vfs_optionisset(const struct illumos_vfs *, const char *, char **);

void vfs_setmntopt_nolock(mntopts_t *, const char *, const char *, int, int);
int  vfs_optionisset_nolock(const mntopts_t *, const char *, char **);
void vfs_swapopttbl_nolock(mntopts_t *, mntopts_t *);
void vfs_swapopttbl(mntopts_t *, mntopts_t *);


extern struct vfssw vfssw[];		/* table of filesystem types */
extern const int nfstype;		/* # of elements in vfssw array */

extern const mntopts_t vfs_mntopts;	/* globally recognized options */

//void    vfs_clearmntopt(struct mount *, const char *);
//void    vfs_setmntopt(struct mount *, const char *, const char *, int);

#endif

#endif	/* _ZFS_SYS_VFS_H */
