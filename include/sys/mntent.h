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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *		All Rights Reserved
 */

#ifndef _SYS_MNTENT_H
#define	_SYS_MNTENT_H

#ifdef illumos
#ifdef	__cplusplus
extern "C" {
#endif

#define	MNTTAB		"/etc/mnttab"
#define	VFSTAB		"/etc/vfstab"
#define	MNTMAXSTR	128

#define	MNTTYPE_ZFS	"zfs"		/* ZFS file system */
#define	MNTTYPE_UFS	"ufs"		/* Unix file system */
#define	MNTTYPE_SMBFS	"smbfs"		/* SMBFS file system */
#define	MNTTYPE_NFS	"nfs"		/* NFS file system */
#define	MNTTYPE_NFS3	"nfs3"		/* NFS Version 3 file system */
#define	MNTTYPE_NFS4	"nfs4"		/* NFS Version 4 file system */
#define	MNTTYPE_CACHEFS	"cachefs"	/* Cache File System */
#define	MNTTYPE_PCFS	"pcfs"		/* PC (MSDOS) file system */
#define	MNTTYPE_PC	MNTTYPE_PCFS	/* Deprecated name; use MNTTYPE_PCFS */
#define	MNTTYPE_LOFS	"lofs"		/* Loop back file system */
#define	MNTTYPE_LO	MNTTYPE_LOFS	/* Deprecated name; use MNTTYPE_LOFS */
#define	MNTTYPE_HSFS	"hsfs"		/* High Sierra (9660) file system */
#define	MNTTYPE_SWAP	"swap"		/* Swap file system */
#define	MNTTYPE_TMPFS	"tmpfs"		/* Tmp volatile file system */
#define	MNTTYPE_AUTOFS	"autofs"	/* Automounter ``file'' system */
#define	MNTTYPE_MNTFS	"mntfs"		/* In-kernel mnttab */
#define	MNTTYPE_DEV	"dev"		/* /dev file system */
#define	MNTTYPE_CTFS	"ctfs"		/* Contract file system */
#define	MNTTYPE_OBJFS	"objfs"		/* Kernel object file system */
#define	MNTTYPE_SHAREFS	"sharefs"	/* Kernel sharetab file system */


#define	MNTOPT_RO	"ro"		/* Read only */
#define	MNTOPT_RW	"rw"		/* Read/write */
#define	MNTOPT_RQ	"rq"		/* Read/write with quotas */
#define	MNTOPT_QUOTA	"quota"		/* Check quotas */
#define	MNTOPT_NOQUOTA	"noquota"	/* Don't check quotas */
#define	MNTOPT_ONERROR	"onerror"	/* action to taken on error */
#define	MNTOPT_SOFT	"soft"		/* Soft mount */
#define	MNTOPT_SEMISOFT	"semisoft"	/* partial soft, uncommited interface */
#define	MNTOPT_HARD	"hard"		/* Hard mount */
#define	MNTOPT_SUID	"suid"		/* Both setuid and devices allowed */
#define	MNTOPT_NOSUID	"nosuid"	/* Neither setuid nor devices allowed */
#define	MNTOPT_DEVICES	"devices"	/* Device-special allowed */
#define	MNTOPT_NODEVICES	"nodevices"	/* Device-special disallowed */
#define	MNTOPT_SETUID	"setuid"	/* Set uid allowed */
#define	MNTOPT_NOSETUID	"nosetuid"	/* Set uid not allowed */
#define	MNTOPT_GRPID	"grpid"		/* SysV-compatible gid on create */
#define	MNTOPT_REMOUNT	"remount"	/* Change mount options */
#define	MNTOPT_NOSUB	"nosub"		/* Disallow mounts on subdirs */
#define	MNTOPT_MULTI	"multi"		/* Do multi-component lookup */
#define	MNTOPT_INTR	"intr"		/* Allow NFS ops to be interrupted */
#define	MNTOPT_NOINTR	"nointr"	/* Don't allow interrupted ops */
#define	MNTOPT_PORT	"port"		/* NFS server IP port number */
#define	MNTOPT_SECURE	"secure"	/* Secure (AUTH_DES) mounting */
#define	MNTOPT_RSIZE	"rsize"		/* Max NFS read size (bytes) */
#define	MNTOPT_WSIZE	"wsize"		/* Max NFS write size (bytes) */
#define	MNTOPT_TIMEO	"timeo"		/* NFS timeout (1/10 sec) */
#define	MNTOPT_RETRANS	"retrans"	/* Max retransmissions (soft mnts) */
#define	MNTOPT_ACTIMEO	"actimeo"	/* Attr cache timeout (sec) */
#define	MNTOPT_ACREGMIN	"acregmin"	/* Min attr cache timeout (files) */
#define	MNTOPT_ACREGMAX	"acregmax"	/* Max attr cache timeout (files) */
#define	MNTOPT_ACDIRMIN	"acdirmin"	/* Min attr cache timeout (dirs) */
#define	MNTOPT_ACDIRMAX	"acdirmax"	/* Max attr cache timeout (dirs) */
#define	MNTOPT_NOAC	"noac"		/* Don't cache attributes at all */
#define	MNTOPT_NOCTO	"nocto"		/* No close-to-open consistency */
#define	MNTOPT_BG	"bg"		/* Do mount retries in background */
#define	MNTOPT_FG	"fg"		/* Do mount retries in foreground */
#define	MNTOPT_RETRY	"retry"		/* Number of mount retries */
#define	MNTOPT_DEV	"dev"		/* Device id of mounted fs */
#define	MNTOPT_POSIX	"posix"		/* Get static pathconf for mount */
#define	MNTOPT_MAP	"map"		/* Automount map */
#define	MNTOPT_DIRECT	"direct"	/* Automount   direct map mount */
#define	MNTOPT_INDIRECT	"indirect"	/* Automount indirect map mount */
#define	MNTOPT_LLOCK	"llock"		/* Local locking (no lock manager) */
#define	MNTOPT_IGNORE	"ignore"	/* Ignore this entry */
#define	MNTOPT_VERS	"vers"		/* protocol version number indicator */
#define	MNTOPT_PROTO	"proto"		/* protocol network_id indicator */
#define	MNTOPT_SEC	"sec"		/* Security flavor indicator */
#define	MNTOPT_SYNCDIR	"syncdir"	/* Synchronous local directory ops */
#define	MNTOPT_NOSETSEC	"nosec"		/* Do no allow setting sec attrs */
#define	MNTOPT_NOPRINT	"noprint"	/* Do not print messages */
#define	MNTOPT_LARGEFILES "largefiles"	/* allow large files */
#define	MNTOPT_NOLARGEFILES "nolargefiles" /* don't allow large files */
#define	MNTOPT_FORCEDIRECTIO "forcedirectio" /* Force DirectIO on all files */
#define	MNTOPT_NOFORCEDIRECTIO "noforcedirectio" /* No Force DirectIO */
#define	MNTOPT_DISABLEDIRECTIO "disabledirectio" /* Disable DirectIO ioctls */
#define	MNTOPT_PUBLIC	"public"	/* Use NFS public file handlee */
#define	MNTOPT_LOGGING "logging" 	/* enable logging */
#define	MNTOPT_NOLOGGING "nologging" 	/* disable logging */
#define	MNTOPT_ATIME	"atime"		/* update atime for files */
#define	MNTOPT_NOATIME  "noatime"	/* do not update atime for files */
#define	MNTOPT_GLOBAL	"global"	/* Cluster-wide global mount */
#define	MNTOPT_NOGLOBAL	"noglobal"	/* Mount local to single node */
#define	MNTOPT_DFRATIME	"dfratime"	/* Deferred access time updates */
#define	MNTOPT_NODFRATIME "nodfratime"	/* No Deferred access time updates */
#define	MNTOPT_NBMAND	"nbmand"	/* allow non-blocking mandatory locks */
#define	MNTOPT_NONBMAND	"nonbmand"	/* deny non-blocking mandatory locks */
#define	MNTOPT_XATTR	"xattr"		/* enable extended attributes */
#define	MNTOPT_NOXATTR	"noxattr"	/* disable extended attributes */
#define	MNTOPT_EXEC	"exec"		/* enable executables */
#define	MNTOPT_NOEXEC	"noexec"	/* disable executables */
#define	MNTOPT_RESTRICT	"restrict"	/* restricted autofs mount */
#define	MNTOPT_BROWSE	"browse"	/* browsable autofs mount */
#define	MNTOPT_NOBROWSE	"nobrowse"	/* non-browsable autofs mount */
#define	MNTOPT_ZONE	"zone"	/* zone name - set only for non global zones */

#ifdef	__cplusplus
}
#endif

#elif __APPLE__

#define	MNTMAXSTR	128

#define	MNTTYPE_ZFS	"zfs"		/* ZFS file system */

#define	MNTOPT_RW	"rw"		/* Read/write */
#define	MNTOPT_RDONLY	"rdonly"	/* read only filesystem */
#define	MNTOPT_SYNCHRONOUS "sync"	/* file system written synchronously */
#define	MNTOPT_EXEC	"exec"		/* enable executables */
#define	MNTOPT_NOEXEC	"noexec"	/* can't exec from filesystem */
#define	MNTOPT_SUID	"suid"		/* Set uid allowed */
#define	MNTOPT_NOSUID	"nosuid"	/* don't honor setuid bits on fs */
#define	MNTOPT_DEV	"dev"		/* Device-special allowed */
#define	MNTOPT_NODEV	"nodev"		/* don't interpret special files */
#define	MNTOPT_UNION	"union"		/* union with underlying filesystem */
#define	MNTOPT_ASYNC	"async"		/* file system written asynchronously */
#if 0
#define	MNT_CPROTECT	0x00000080	/* file system supports content protection */
#endif

/*
 * NFS export related mount options.
 */
#if 0
#define	MNT_EXPORTED	0x00000100	/* file system is exported */
#endif

/*
 * MAC labeled / "quarantined" flag
 */
#if 0
#define	MNT_QUARANTINE	0x00000400	/* file system is quarantined */
#endif

/*
 * Flags set by internal operations.
 */
#if 0
#define	MNT_LOCAL	0x00001000	/* filesystem is stored locally */
#define	MNT_QUOTA	0x00002000	/* quotas are enabled on filesystem */
#define	MNT_ROOTFS	0x00004000	/* identifies the root filesystem */
#define	MNT_DOVOLFS	0x00008000	/* FS supports volfs (deprecated flag in Mac OS X 10.5) */
#endif


#define	MNTOPT_BROWSE	"browse"	/* file system is not appropriate path to user data */
#define	MNTOPT_DONTBROWSE "nobrowse"	/* file system is not appropriate path to user data */
#define	MNTOPT_IGNORE_OWNERSHIP "noowners"	/* VFS will ignore ownership information on filesystem objects */
#define	MNTOPT_DONTIGNORE_OWNERSHIP "owners"	/* VFS will not ignore ownership information on filesystem objects */
#define	MNTOPT_AUTOMOUNTED "auto"	/* filesystem was mounted by automounter */
#define	MNTOPT_NOAUTOMOUNTED "noauto"	/* This filesystem should be skipped when mount is run with the -a flag. */
#if 0
#define	MNT_JOURNALED	0x00800000	/* filesystem is journaled */
#endif
#define	MNTOPT_USERXATTR	"xattr"	/* Don't allow user extended attributes */
#define	MNTOPT_NOUSERXATTR	"noxattr" /* Don't allow user extended attributes */
#if 0
#define	MNT_DEFWRITE	0x02000000	/* filesystem should defer writes */
#define	MNT_MULTILABEL	0x04000000	/* MAC support for individual labels */
#endif
#define	MNTOPT_ATIME	"atime"		/* update atime for files */
#define	MNTOPT_NOATIME	"noatime"	/* disable update of file access time */
#if 0
#ifdef BSD_KERNEL_PRIVATE
#define	MNT_IMGSRC_BY_INDEX	0x20000000 see sys/imgsrc.h */
#endif /* BSD_KERNEL_PRIVATE */

/* backwards compatibility only */
#define	MNT_UNKNOWNPERMISSIONS	MNT_IGNORE_OWNERSHIP

/*
 * XXX I think that this could now become (~(MNT_CMDFLAGS))
 * but the 'mount' program may need changing to handle this.
 */
#define	MNT_VISFLAGMASK	(MNT_RDONLY	| MNT_SYNCHRONOUS | MNT_NOEXEC	| \
			MNT_NOSUID	| MNT_NODEV	| MNT_UNION	| \
			MNT_ASYNC	| MNT_EXPORTED	| MNT_QUARANTINE | \
			MNT_LOCAL	| MNT_QUOTA | \
			MNT_ROOTFS	| MNT_DOVOLFS	| MNT_DONTBROWSE | \
			MNT_IGNORE_OWNERSHIP | MNT_AUTOMOUNTED | MNT_JOURNALED | \
			MNT_NOUSERXATTR | MNT_DEFWRITE	| MNT_MULTILABEL | \
			MNT_NOATIME | MNT_CPROTECT)
#endif
/*
 * External filesystem command modifier flags.
 * Unmount can use the MNTOPT_FORCE flag.
 * XXX These are not STATES and really should be somewhere else.
 * External filesystem control flags.
 */
#define	MNTOPT_UPDATE	"update"	/* not a real mount, just an update */
#if 0
#define	MNT_NOBLOCK	0x00020000	/* don't block unmount if not responding */
#define	MNT_RELOAD	0x00040000	/* reload filesystem data */
#endif
#define	MNTOPT_FORCE	"force"	/* force unmount or readonly change */
#if 0
#define	MNT_CMDFLAGS	(MNT_UPDATE|MNT_NOBLOCK|MNT_RELOAD|MNT_FORCE)
#endif

#define	MNTOPT_NBMAND	"nbmand"	/* allow non-blocking mandatory locks */
#define	MNTOPT_NONBMAND	"nonbmand"	/* deny non-blocking mandatory locks */
#define	MNTOPT_REMOUNT	"remount"	/* Change mount options */

#define	MNTOPT_RO	MNTOPT_RDONLY
#define	MNTOPT_DEVICES	MNTOPT_DEV
#define	MNTOPT_NODEVICES MNTOPT_NODEV
#define	MNTOPT_SETUID	MNTOPT_SUID
#define	MNTOPT_NOSETUID	MNTOPT_NOSUID
#define	MNTOPT_NODEVICES MNTOPT_NODEV
#define	MNTOPT_DEVICES	MNTOPT_DEV
#define	MNTOPT_XATTR	MNTOPT_USERXATTR
#define	MNTOPT_NOXATTR	MNTOPT_NOUSERXATTR
#define MNTOPT_NOBROWSE	MNTOPT_DONTBROWSE
#define MNTOPT_OWNERS	MNTOPT_DONTIGNORE_OWNERSHIP
#define MNTOPT_NOOWNERS	MNTOPT_IGNORE_OWNERSHIP

#endif /* illumos */

#endif	/* _SYS_MNTENT_H */
