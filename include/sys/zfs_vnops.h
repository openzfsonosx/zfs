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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_FS_ZFS_VNOPS_H
#define	_SYS_FS_ZFS_VNOPS_H

#include <sys/vnode.h>
#include <sys/xvattr.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Spotlight specific fcntl()'s
 */
#define SPOTLIGHT_GET_MOUNT_TIME	(FCNTL_FS_SPECIFIC_BASE + 0x00002)
#define SPOTLIGHT_GET_UNMOUNT_TIME	(FCNTL_FS_SPECIFIC_BASE + 0x00003)


extern int    zfs_open   ( vnode_t **vpp, int flag,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_close  ( vnode_t *vp, int flag, int count, offset_t offset,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_ioctl  ( vnode_t *vp, u_long com, intptr_t data, int flag,
                           cred_t *cred, int *rvalp, caller_context_t *ct);
extern int    zfs_read   ( vnode_t *vp, uio_t *uio, int ioflag,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_write  ( vnode_t *vp, uio_t *uio, int ioflag,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_lookup ( vnode_t *dvp, char *nm, vnode_t **vpp,
                           struct componentname *cnp, int nameiop,
                           cred_t *cr, int flags);
extern int    zfs_create ( vnode_t *dvp, char *name, vattr_t *vap,
                           int excl, int mode, vnode_t **vpp,
                           cred_t *cr);
extern int    zfs_remove ( vnode_t *dvp, char *name,
                           cred_t *cr, caller_context_t *ct, int flags);
extern int    zfs_mkdir  ( vnode_t *dvp, char *dirname, vattr_t *vap,
                           vnode_t **vpp, cred_t *cr,
                           caller_context_t *ct, int flags, vsecattr_t *vsecp);
extern int    zfs_rmdir  ( vnode_t *dvp, char *name, vnode_t *cwd,
                           cred_t *cr, caller_context_t *ct, int flags);
extern int    zfs_readdir( vnode_t *vp, uio_t *uio, cred_t *cr, int *eofp,
                           int flags, int *a_numdirent);
extern int    zfs_fsync  ( vnode_t *vp, int syncflag,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_getattr( vnode_t *vp, vattr_t *vap, int flags,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_setattr( vnode_t *vp, vattr_t *vap, int flags,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_rename ( vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm,
                           cred_t *cr, caller_context_t *ct, int flags);
extern int    zfs_symlink( vnode_t *dvp, vnode_t **vpp, char *name,
                           vattr_t *vap, char *link, cred_t *cr);
extern int    zfs_readlink(vnode_t *vp, uio_t *uio,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_link   ( vnode_t *tdvp, vnode_t *svp, char *name,
                           cred_t *cr, caller_context_t *ct, int flags);
extern int    zfs_access ( vnode_t *vp, int mode, int flag, cred_t *cr,
                           caller_context_t *ct);
extern void   zfs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct);
extern int    zfs_space  ( vnode_t *vp, int cmd, struct flock *bfp, int flag,
                           offset_t offset, cred_t *cr, caller_context_t *ct);
extern int    zfs_setsecattr(vnode_t *vp, vsecattr_t *vsecp, int flag,
                             cred_t *cr, caller_context_t *ct);

/* zfs_vops_osx.c calls */
extern int    zfs_znode_getvnode( znode_t *zp, zfsvfs_t *zfsvfs,
                                  struct vnode **vpp);
extern void   getnewvnode_reserve( int num );
extern void   getnewvnode_drop_reserve( void );
extern int    zfs_vfsops_init(void);
extern int    zfs_vfsops_fini(void);

/* zfs_vnops_osx_lib calls */
extern int    zfs_ioflags( int ap_ioflag );
extern int    zfs_getattr_znode_unlocked ( struct vnode *vp, vattr_t *vap );
extern int    pn_alloc   ( pathname_t *p );
extern int    pn_free    ( pathname_t *p );
extern int    ace_trivial_common(void *acep, int aclcnt,
                                 uint64_t (*walk)(void *, uint64_t, int aclcnt,
                                         uint16_t *, uint16_t *, uint32_t *));
extern void   acl_trivial_access_masks(mode_t mode, boolean_t isdir,
                                       trivial_acl_t *masks);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_VNOPS_H */
