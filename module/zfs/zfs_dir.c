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
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#ifndef __APPLE__
#include <sys/mode.h>
#endif /*!__APPLE__*/
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/random.h>
#ifndef __APPLE__
#include <sys/policy.h>
#endif /*!__APPLE__*/
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/fs/zfs.h>
#ifndef __APPLE__
#include "fs/fs_subr.h"
#endif /*!__APPLE__*/
#include <sys/zap.h>
#include <sys/dmu.h>
#include <sys/atomic.h>
#include <sys/zfs_ctldir.h>
#include <sys/dnlc.h>

#ifdef __APPLE__
#include <sys/spa.h>
#include <sys/callb.h>
#include <sys/dirent.h>
#include <sys/utfconv.h>
#endif

/*
 * Lock a directory entry.  A dirlock on <dzp, name> protects that name
 * in dzp's directory zap object.  As long as you hold a dirlock, you can
 * assume two things: (1) dzp cannot be reaped, and (2) no other thread
 * can change the zap entry for (i.e. link or unlink) this name.
 *
 * Input arguments:
 *	dzp	- znode for directory
 *	name	- name of entry to lock
 *	flag	- ZNEW: if the entry already exists, fail with EEXIST.
 *		  ZEXISTS: if the entry does not exist, fail with ENOENT.
 *		  ZSHARED: allow concurrent access with other ZSHARED callers.
 *		  ZXATTR: we want dzp's xattr directory
 *
 * Output arguments:
 *	zpp	- pointer to the znode for the entry (NULL if there isn't one)
 *	dlpp	- pointer to the dirlock for this entry (NULL on error)
 *
 * Return value: 0 on success or errno on failure.
 *
 * NOTE: Always checks for, and rejects, '.' and '..'.
 */
int
#ifdef __APPLE__
zfs_dirent_lock(zfs_dirlock_t **dlpp, znode_t *dzp, struct componentname *cnp,
	znode_t **zpp, int flag)
#else
zfs_dirent_lock(zfs_dirlock_t **dlpp, znode_t *dzp, char *name, znode_t **zpp,
	int flag)
#endif
{
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zfs_dirlock_t	*dl;
	uint64_t	zoid;
	int		error;
	vnode_t		*vp;
#ifdef __APPLE__
	char		*name;
	u_int8_t	*nfc_name = NULL;  /* NFC form of name */
	int		nfc_namesize = 0;
#endif

	*zpp = NULL;
	*dlpp = NULL;

#ifdef __APPLE__
	/* Note: cnp will be NULL for ZXATTR case */
	name = cnp ? cnp->cn_nameptr : "";
	if (cnp)
		ASSERT(name[cnp->cn_namelen] == '\0');
#endif
	/*
	 * Verify that we are not trying to lock '.', '..', or '.zfs'
	 */
	if (name[0] == '.' &&
	    (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')) ||
	    zfs_has_ctldir(dzp) && strcmp(name, ZFS_CTLDIR_NAME) == 0)
		return (EEXIST);

#ifdef __APPLE__
	/*
	 * Mac OS X: store non-ascii names in UTF-8 NFC (pre-composed) on disk.
	 *
	 * The NFC name ptr is stored in dl->dl_name (allocated here)
	 * and its freed by zfs_dirent_unlock (since dl_namesize != 0).
	 *
	 * Since NFC size will not expand, we can allocate the same sized buffer.
	 */
	if (!is_ascii_str(name)) {
		size_t outlen;

		nfc_namesize = strlen(name) + 1;
		nfc_name = kmem_alloc(nfc_namesize, KM_SLEEP);

		if (utf8_normalizestr((const u_int8_t *)name, nfc_namesize, nfc_name,
		                      &outlen, nfc_namesize, UTF_PRECOMPOSED) == 0) {

			/* Normalization succeeded, switch to NFC name. */
			name = (char *)nfc_name;
		} else {
			/* Normalization failed, just use input name as-is. */
			kmem_free(nfc_name, nfc_namesize);
			nfc_name = NULL;
		}
	}
#endif
	/*
	 * Wait until there are no locks on this name.
	 */
	rw_enter(&dzp->z_name_lock, RW_READER);
	mutex_enter(&dzp->z_lock);
	for (;;) {
		if (dzp->z_unlinked) {
			mutex_exit(&dzp->z_lock);
			rw_exit(&dzp->z_name_lock);
#ifdef __APPLE__
			/* Release any unused NFC name before returning */
			if (nfc_name) {
				kmem_free(nfc_name, nfc_namesize);
			}
#endif
			return (ENOENT);
		}
		for (dl = dzp->z_dirlocks; dl != NULL; dl = dl->dl_next)
			if (strcmp(name, dl->dl_name) == 0)
				break;
		if (dl == NULL)	{
			/*
			 * Allocate a new dirlock and add it to the list.
			 */
			dl = kmem_alloc(sizeof (zfs_dirlock_t), KM_SLEEP);
			cv_init(&dl->dl_cv, NULL, CV_DEFAULT, NULL);
			dl->dl_name = name;
			dl->dl_sharecnt = 0;
			dl->dl_namesize = 0;
			dl->dl_dzp = dzp;
			dl->dl_next = dzp->z_dirlocks;
			dzp->z_dirlocks = dl;
#ifdef __APPLE__
			/*
			 * Keep the NFC name around in dir lock by tagging it
			 * (setting nfc_namesize).
			 */
			if (nfc_name) {
				dl->dl_namesize = nfc_namesize;
				nfc_name = NULL;  /* its now part of the dir lock */
			}
#endif
			break;
		}
		if ((flag & ZSHARED) && dl->dl_sharecnt != 0)
			break;
		cv_wait(&dl->dl_cv, &dzp->z_lock);
	}

#ifdef __APPLE__
	/*
	 * Release any unused NFC name (ie if we found a pre-existing lock entry)
	 */
	if (nfc_name) {
		kmem_free(nfc_name, nfc_namesize);
		nfc_name = NULL;
	}
#endif
	if ((flag & ZSHARED) && ++dl->dl_sharecnt > 1 && dl->dl_namesize == 0) {
		/*
		 * We're the second shared reference to dl.  Make a copy of
		 * dl_name in case the first thread goes away before we do.
		 * Note that we initialize the new name before storing its
		 * pointer into dl_name, because the first thread may load
		 * dl->dl_name at any time.  He'll either see the old value,
		 * which is his, or the new shared copy; either is OK.
		 */
		dl->dl_namesize = strlen(dl->dl_name) + 1;
		name = kmem_alloc(dl->dl_namesize, KM_SLEEP);
		bcopy(dl->dl_name, name, dl->dl_namesize);
		dl->dl_name = name;
	}

	mutex_exit(&dzp->z_lock);

	/*
	 * We have a dirlock on the name.  (Note that it is the dirlock,
	 * not the dzp's z_lock, that protects the name in the zap object.)
	 * See if there's an object by this name; if so, put a hold on it.
	 */
	if (flag & ZXATTR) {
		zoid = dzp->z_phys->zp_xattr;
		error = (zoid == 0 ? ENOENT : 0);
	} else {
#ifdef __APPLE__
		/*
		 * Lookup an entry in the vnode name cache
		 *
		 * If the lookup succeeds, the vnode is returned in *vpp,
		 * and a status of -1 is returned.
		 *
		 * If the lookup determines that the name does not exist
		 * (negative caching), a status of ENOENT is returned.
		 *
		 * If the lookup fails, a status of zero is returned.
		 */
		switch ( cache_lookup(ZTOV(dzp), &vp, cnp) ) {
		case -1:
			break;
		case ENOENT:
			vp = DNLC_NO_VNODE;
			break;
		default:
			vp = NULLVP;
		}
#else
		vp = dnlc_lookup(ZTOV(dzp), name);
#endif /* __APPLE__ */
		if (vp == DNLC_NO_VNODE) {
			VN_RELE(vp);
			error = ENOENT;
		} else if (vp) {
			if (flag & ZNEW) {
				zfs_dirent_unlock(dl);
				VN_RELE(vp);
				return (EEXIST);
			}
			*dlpp = dl;
			*zpp = VTOZ(vp);
			return (0);
		} else {
			error = zap_lookup(zfsvfs->z_os, dzp->z_id, name,
			    8, 1, &zoid);
			zoid = ZFS_DIRENT_OBJ(zoid);
			if (error == ENOENT)
#ifdef __APPLE__
				/*
				 * Add a negative entry into the VFS name cache
				 */
				if ((flag & ZNEW) == 0 &&
				    (dzp->z_phys->zp_flags & ZFS_XATTR) == 0 &&
					(cnp) &&
				    (cnp->cn_flags & MAKEENTRY) &&
				    (cnp->cn_nameiop != CREATE) &&
				    (cnp->cn_nameiop != RENAME)) {
					cache_enter(ZTOV(dzp), NULLVP, cnp);
				}
#else
				dnlc_update(ZTOV(dzp), name, DNLC_NO_VNODE);
#endif /* __APPLE__ */
		}
	}
	if (error) {
		if (error != ENOENT || (flag & ZEXISTS)) {
			zfs_dirent_unlock(dl);
			return (error);
		}
	} else {
		if (flag & ZNEW) {
			zfs_dirent_unlock(dl);
			return (EEXIST);
		}
		error = zfs_zget(zfsvfs, zoid, zpp);
		if (error) {
			zfs_dirent_unlock(dl);
			return (error);
		}
		if (!(flag & ZXATTR))
#ifdef __APPLE__
			if (cnp && cnp->cn_flags & MAKEENTRY)
				cache_enter(ZTOV(dzp), ZTOV(*zpp), cnp);
#else
			dnlc_update(ZTOV(dzp), name, ZTOV(*zpp));
#endif /* __APPLE__ */
	}

	*dlpp = dl;

	return (0);
}

/*
 * Unlock this directory entry and wake anyone who was waiting for it.
 */
void
zfs_dirent_unlock(zfs_dirlock_t *dl)
{
	znode_t *dzp = dl->dl_dzp;
	zfs_dirlock_t **prev_dl, *cur_dl;

	mutex_enter(&dzp->z_lock);
	rw_exit(&dzp->z_name_lock);
	if (dl->dl_sharecnt > 1) {
		dl->dl_sharecnt--;
		mutex_exit(&dzp->z_lock);
		return;
	}
	prev_dl = &dzp->z_dirlocks;
	while ((cur_dl = *prev_dl) != dl)
		prev_dl = &cur_dl->dl_next;
	*prev_dl = dl->dl_next;
	cv_broadcast(&dl->dl_cv);
	mutex_exit(&dzp->z_lock);

	/* Mac OS X: note dl_name can contain NFC name. */
	if (dl->dl_namesize != 0)
		kmem_free(dl->dl_name, dl->dl_namesize);
	cv_destroy(&dl->dl_cv);
	kmem_free(dl, sizeof (*dl));
}

/*
 * Look up an entry in a directory.
 *
 * NOTE: '.' and '..' are handled as special cases because
 *	no directory entries are actually stored for them.  If this is
 *	the root of a filesystem, then '.zfs' is also treated as a
 *	special pseudo-directory.
 */
int
#ifdef __APPLE__
zfs_dirlook(znode_t *dzp, struct componentname *cnp, vnode_t **vpp)
#else
zfs_dirlook(znode_t *dzp, char *name, vnode_t **vpp)
#endif
{
	zfs_dirlock_t *dl;
	znode_t *zp;
	int error = 0;
#ifdef __APPLE__
	char *name = cnp->cn_nameptr;
#endif

	if (name[0] == 0 || (name[0] == '.' && name[1] == 0)) {
		*vpp = ZTOV(dzp);
		VN_HOLD(*vpp);
	} else if (name[0] == '.' && name[1] == '.' && name[2] == 0) {
		zfsvfs_t *zfsvfs = dzp->z_zfsvfs;
		/*
		 * If we are a snapshot mounted under .zfs, return
		 * the vp for the snapshot directory.
		 */
		if (dzp->z_phys->zp_parent == dzp->z_id &&
		    zfsvfs->z_parent != zfsvfs) {
			error = zfsctl_root_lookup(zfsvfs->z_parent->z_ctldir,
			    "snapshot", vpp, NULL, 0, NULL, kcred);
			return (error);
		}
		rw_enter(&dzp->z_parent_lock, RW_READER);
		error = zfs_zget(zfsvfs, dzp->z_phys->zp_parent, &zp);
		if (error == 0)
			*vpp = ZTOV(zp);
		rw_exit(&dzp->z_parent_lock);
	} else if (zfs_has_ctldir(dzp) && strcmp(name, ZFS_CTLDIR_NAME) == 0) {
		*vpp = zfsctl_root(dzp);
	} else {
#ifdef __APPLE__
		error = zfs_dirent_lock(&dl, dzp, cnp, &zp, ZEXISTS | ZSHARED);
#else
		error = zfs_dirent_lock(&dl, dzp, name, &zp, ZEXISTS | ZSHARED);
#endif
		if (error == 0) {
			*vpp = ZTOV(zp);
			zfs_dirent_unlock(dl);
			dzp->z_zn_prefetch = B_TRUE; /* enable prefetching */
		}
	}

	return (error);
}

static char *
zfs_unlinked_hexname(char namebuf[17], uint64_t x)
{
	char *name = &namebuf[16];
	const char digits[16] = "0123456789abcdef";

	*name = '\0';
	do {
		*--name = digits[x & 0xfULL];
		x >>= 4;
	} while (x != 0);

	return (name);
}

/*
 * unlinked Set (formerly known as the "delete queue") Error Handling
 *
 * When dealing with the unlinked set, we dmu_tx_hold_zap(), but we
 * don't specify the name of the entry that we will be manipulating.  We
 * also fib and say that we won't be adding any new entries to the
 * unlinked set, even though we might (this is to lower the minimum file
 * size that can be deleted in a full filesystem).  So on the small
 * chance that the nlink list is using a fat zap (ie. has more than
 * 2000 entries), we *may* not pre-read a block that's needed.
 * Therefore it is remotely possible for some of the assertions
 * regarding the unlinked set below to fail due to i/o error.  On a
 * nondebug system, this will result in the space being leaked.
 */
void
zfs_unlinked_add(znode_t *zp, dmu_tx_t *tx)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	char obj_name[17];
	int error;

#ifdef ZFS_DEBUG
	znode_stalker(zp, N_zfs_nolink_add);
#endif
	ASSERT(zp->z_unlinked);
	ASSERT3U(zp->z_phys->zp_links, ==, 0);

	error = zap_add(zfsvfs->z_os, zfsvfs->z_unlinkedobj,
	    zfs_unlinked_hexname(obj_name, zp->z_id), 8, 1, &zp->z_id, tx);
	ASSERT3U(error, ==, 0);
}

/*
 * Clean up any znodes that had no links when we either crashed or
 * (force) umounted the file system.
 */
void
zfs_unlinked_drain(zfsvfs_t *zfsvfs)
{
	zap_cursor_t	zc;
	zap_attribute_t zap;
	dmu_object_info_t doi;
	znode_t		*zp;
	int		error;

	/*
	 * Interate over the contents of the unlinked set.
	 */
	for (zap_cursor_init(&zc, zfsvfs->z_os, zfsvfs->z_unlinkedobj);
	    zap_cursor_retrieve(&zc, &zap) == 0;
	    zap_cursor_advance(&zc)) {

		/*
		 * See what kind of object we have in list
		 */

		error = dmu_object_info(zfsvfs->z_os,
		    zap.za_first_integer, &doi);
		if (error != 0)
			continue;

		ASSERT((doi.doi_type == DMU_OT_PLAIN_FILE_CONTENTS) ||
		    (doi.doi_type == DMU_OT_DIRECTORY_CONTENTS));
		/*
		 * We need to re-mark these list entries for deletion,
		 * so we pull them back into core and set zp->z_unlinked.
		 */
		error = zfs_zget(zfsvfs, zap.za_first_integer, &zp);

		/*
		 * We may pick up znodes that are already marked for deletion.
		 * This could happen during the purge of an extended attribute
		 * directory.  All we need to do is skip over them, since they
		 * are already in the system marked z_unlinked.
		 */
		if (error != 0)
			continue;

		zp->z_unlinked = B_TRUE;
		VN_RELE(ZTOV(zp));
	}
	zap_cursor_fini(&zc);
}

/*
 * Delete the entire contents of a directory.  Return a count
 * of the number of entries that could not be deleted.
 *
 * NOTE: this function assumes that the directory is inactive,
 *	so there is no need to lock its entries before deletion.
 *	Also, it assumes the directory contents is *only* regular
 *	files.
 */
static int
zfs_purgedir(znode_t *dzp)
{
	zap_cursor_t	zc;
	zap_attribute_t	zap;
	znode_t		*xzp;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zfs_dirlock_t	dl;
	int skipped = 0;
	int error;

	for (zap_cursor_init(&zc, zfsvfs->z_os, dzp->z_id);
	    (error = zap_cursor_retrieve(&zc, &zap)) == 0;
	    zap_cursor_advance(&zc)) {
#ifdef __APPLE__
		error = zfs_zget_sans_vnode(zfsvfs,  ZFS_DIRENT_OBJ(zap.za_first_integer), &xzp);
		ASSERT3U(error, ==, 0);

		ASSERT(S_ISREG(xzp->z_phys->zp_mode) || S_ISLNK(xzp->z_phys->zp_mode));
#else
		error = zfs_zget(zfsvfs,
		    ZFS_DIRENT_OBJ(zap.za_first_integer), &xzp);
		ASSERT3U(error, ==, 0);

		ASSERT((ZTOV(xzp)->v_type == VREG) ||
		    (ZTOV(xzp)->v_type == VLNK));
#endif /* __APPLE__ */
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_bonus(tx, dzp->z_id);
		dmu_tx_hold_zap(tx, dzp->z_id, FALSE, zap.za_name);
		dmu_tx_hold_bonus(tx, xzp->z_id);
		dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
#ifdef __APPLE__
			if (ZTOV(xzp) == NULL) {
				zfs_zinactive(xzp);
			} else {
				VN_RELE(ZTOV(xzp));
			}
#else
			VN_RELE(ZTOV(xzp));
#endif /* __APPLE__ */
			skipped += 1;
			continue;
		}
		bzero(&dl, sizeof (dl));
		dl.dl_dzp = dzp;
		dl.dl_name = zap.za_name;

		error = zfs_link_destroy(&dl, xzp, tx, 0, NULL);
		ASSERT3U(error, ==, 0);
		dmu_tx_commit(tx);

#ifdef __APPLE__
		if (ZTOV(xzp) == NULL) {
			zfs_zinactive(xzp);
		} else {
			VN_RELE(ZTOV(xzp));
		}
#else
		VN_RELE(ZTOV(xzp));
#endif /* __APPLE__ */
	}
	zap_cursor_fini(&zc);
	ASSERT(error == ENOENT);
	return (skipped);
}

void
zfs_rmnode(znode_t *zp)
{
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os = zfsvfs->z_os;
	znode_t		*xzp = NULL;
	char		obj_name[17];
	dmu_tx_t	*tx;
	uint64_t	acl_obj;
	int		error;

#ifndef __APPLE__
	ASSERT(ZTOV(zp)->v_count == 0);
#endif /*!__APPLE__*/
	ASSERT(zp->z_phys->zp_links == 0);

#ifdef ZFS_DEBUG
	znode_stalker(zp, N_zfs_rmnode);
#endif

	/*
	 * If this is an attribute directory, purge its contents.
	 */
#ifdef __APPLE__
	if (S_ISDIR(zp->z_phys->zp_mode) && (zp->z_phys->zp_flags & ZFS_XATTR))
#else
	if (ZTOV(zp)->v_type == VDIR && (zp->z_phys->zp_flags & ZFS_XATTR))
#endif
	{
		if (zfs_purgedir(zp) != 0) {
			/*
			 * Not enough space to delete some xattrs.
			 * Leave it on the unlinked set.
			 */
			return;
		}
	}

	/*
	 * If the file has extended attributes, we're going to unlink
	 * the xattr dir.
	 */
	if (zp->z_phys->zp_xattr) {
		error = zfs_zget(zfsvfs, zp->z_phys->zp_xattr, &xzp);
		ASSERT(error == 0);
	}

	acl_obj = zp->z_phys->zp_acl.z_acl_extern_obj;

	/*
	 * Set up the transaction.
	 */
	tx = dmu_tx_create(os);
	dmu_tx_hold_free(tx, zp->z_id, 0, DMU_OBJECT_END);
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	if (xzp) {
		dmu_tx_hold_bonus(tx, xzp->z_id);
		dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, TRUE, NULL);
	}
	if (acl_obj)
		dmu_tx_hold_free(tx, acl_obj, 0, DMU_OBJECT_END);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		/*
		 * Not enough space to delete the file.  Leave it in the
		 * unlinked set, leaking it until the fs is remounted (at
		 * which point we'll call zfs_unlinked_drain() to process it).
		 */
		dmu_tx_abort(tx);
#ifdef __APPLE__
		/*XXX NOEL: double check this path logic. see radar 5182217.
		 * This may be disturbing some of the evict logic
		 * and hence causing the NULL ptr drefs seen every great while
		 * in some of the test cases*/
		zp->z_dbuf_held = 0;
		ZFS_OBJ_HOLD_EXIT(zfsvfs, zp->z_id);
		dmu_buf_rele(zp->z_dbuf, NULL);
#endif /* __APPLE__ */
		return;
	}

	if (xzp) {
		dmu_buf_will_dirty(xzp->z_dbuf, tx);
		mutex_enter(&xzp->z_lock);
		xzp->z_unlinked = B_TRUE;	/* mark xzp for deletion */
		xzp->z_phys->zp_links = 0;	/* no more links to it */
		mutex_exit(&xzp->z_lock);
		zfs_unlinked_add(xzp, tx);
	}

	/* Remove this znode from the unlinked set */
	error = zap_remove(os, zfsvfs->z_unlinkedobj,
	    zfs_unlinked_hexname(obj_name, zp->z_id), tx);
	ASSERT3U(error, ==, 0);

	zfs_znode_delete(zp, tx);

	dmu_tx_commit(tx);

	if (xzp)
		VN_RELE(ZTOV(xzp));
}

static uint64_t
zfs_dirent(znode_t *zp)
{
	uint64_t de = zp->z_id;
#ifdef __APPLE__
	/* XXX Mac OS X has supported dirent types since version 1 */
	if (zp->z_zfsvfs->z_version >= ZPL_VERSION_1)
#else
	if (zp->z_zfsvfs->z_version >= ZPL_VERSION_DIRENT_TYPE)
#endif
		de |= IFTODT((zp)->z_phys->zp_mode) << 60;
	return (de);
}

/*
 * Link zp into dl.  Can only fail if zp has been unlinked.
 */
int
zfs_link_create(zfs_dirlock_t *dl, znode_t *zp, dmu_tx_t *tx, int flag)
{
	znode_t *dzp = dl->dl_dzp;
#ifdef __APPLE__
	uint64_t value;
	/* OSX - don't access the vnode here since it might not be attached yet. */
	int zp_is_dir = S_ISDIR(zp->z_phys->zp_mode);
#else
	vnode_t *vp = ZTOV(zp);
	uint64_t value;
	int zp_is_dir = (vp->v_type == VDIR);
#endif
	int error;

	dmu_buf_will_dirty(zp->z_dbuf, tx);
	mutex_enter(&zp->z_lock);

	if (!(flag & ZRENAMING)) {
		if (zp->z_unlinked) {	/* no new links to unlinked zp */
			ASSERT(!(flag & (ZNEW | ZEXISTS)));
			mutex_exit(&zp->z_lock);
			return (ENOENT);
		}
		zp->z_phys->zp_links++;
	}
	zp->z_phys->zp_parent = dzp->z_id;	/* dzp is now zp's parent */

	if (!(flag & ZNEW))
		zfs_time_stamper_locked(zp, STATE_CHANGED, tx);
	mutex_exit(&zp->z_lock);

	dmu_buf_will_dirty(dzp->z_dbuf, tx);
	mutex_enter(&dzp->z_lock);
	dzp->z_phys->zp_size++;			/* one dirent added */
	dzp->z_phys->zp_links += zp_is_dir;	/* ".." link from zp */
	zfs_time_stamper_locked(dzp, CONTENT_MODIFIED, tx);
	mutex_exit(&dzp->z_lock);

	value = zfs_dirent(zp);
	error = zap_add(zp->z_zfsvfs->z_os, dzp->z_id, dl->dl_name,
	    8, 1, &value, tx);
	ASSERT(error == 0);

#ifndef __APPLE__
	/* On Mac OS X, this is done up in VFS layer. */
	dnlc_update(ZTOV(dzp), dl->dl_name, vp);
#endif
	return (0);
}

/*
 * Unlink zp from dl, and mark zp for deletion if this was the last link.
 * Can fail if zp is a mount point (EBUSY) or a non-empty directory (EEXIST).
 * If 'unlinkedp' is NULL, we put unlinked znodes on the unlinked list.
 * If it's non-NULL, we use it to indicate whether the znode needs deletion,
 * and it's the caller's job to do it.
 */
int
zfs_link_destroy(zfs_dirlock_t *dl, znode_t *zp, dmu_tx_t *tx, int flag,
	boolean_t *unlinkedp)
{
	znode_t *dzp = dl->dl_dzp;
	vnode_t *vp = ZTOV(zp);
#ifdef __APPLE__
	int zp_is_dir = S_ISDIR(zp->z_phys->zp_mode);
#else
	int zp_is_dir = (vp->v_type == VDIR);
#endif
	boolean_t unlinked = B_FALSE;
	int error;

#ifndef __APPLE__
	dnlc_remove(ZTOV(dzp), dl->dl_name);
#endif

	if (!(flag & ZRENAMING)) {
		dmu_buf_will_dirty(zp->z_dbuf, tx);

#ifdef __APPLE__
		if (vp) {
#endif /* __APPLE__ */
		if (vn_vfswlock(vp))		/* prevent new mounts on zp */
			return (EBUSY);

		if (vn_ismntpt(vp)) {		/* don't remove mount point */
			vn_vfsunlock(vp);
			return (EBUSY);
		}
#ifdef __APPLE__
		} /* if (vp) */
#endif /* __APPLE__ */

		mutex_enter(&zp->z_lock);
		if (zp_is_dir && !zfs_dirempty(zp)) {	/* dir not empty */
			mutex_exit(&zp->z_lock);
#ifdef __APPLE__
			return (ENOTEMPTY);
#else
			vn_vfsunlock(vp);
			return (EEXIST);
#endif
		}
		if (zp->z_phys->zp_links <= zp_is_dir) {
#ifndef __APPLE__
			zfs_panic_recover("zfs: link count on %s is %u, "
			    "should be at least %u",
			    zp->z_vnode->v_path ? zp->z_vnode->v_path :
			    "<unknown>", (int)zp->z_phys->zp_links,
			    zp_is_dir + 1);
#endif
			zp->z_phys->zp_links = zp_is_dir + 1;
		}
		if (--zp->z_phys->zp_links == zp_is_dir) {
			zp->z_unlinked = B_TRUE;
			zp->z_phys->zp_links = 0;
			unlinked = B_TRUE;
		} else {
			zfs_time_stamper_locked(zp, STATE_CHANGED, tx);
		}
		mutex_exit(&zp->z_lock);
#ifndef __APPLE__
		vn_vfsunlock(vp);
#endif
	}

	dmu_buf_will_dirty(dzp->z_dbuf, tx);
	mutex_enter(&dzp->z_lock);
	dzp->z_phys->zp_size--;			/* one dirent removed */
	dzp->z_phys->zp_links -= zp_is_dir;	/* ".." link from zp */
	zfs_time_stamper_locked(dzp, CONTENT_MODIFIED, tx);
	mutex_exit(&dzp->z_lock);

	error = zap_remove(zp->z_zfsvfs->z_os, dzp->z_id, dl->dl_name, tx);
	ASSERT(error == 0);

	if (unlinkedp != NULL)
		*unlinkedp = unlinked;
	else if (unlinked)
		zfs_unlinked_add(zp, tx);

	return (0);
}

/*
 * Indicate whether the directory is empty.  Works with or without z_lock
 * held, but can only be consider a hint in the latter case.  Returns true
 * if only "." and ".." remain and there's no work in progress.
 */
boolean_t
zfs_dirempty(znode_t *dzp)
{
	return (dzp->z_phys->zp_size == 2 && dzp->z_dirlocks == 0);
}

int
zfs_make_xattrdir(znode_t *zp, vattr_t *vap, vnode_t **xvpp, cred_t *cr)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	znode_t *xzp;
	dmu_tx_t *tx;
	uint64_t xoid;
	int error;
    zfs_acl_ids_t acl_ids;

	*xvpp = NULL;

#ifndef __APPLE__
	/* In Mac OS X access preflighting is done above the file system. */
	if (error = zfs_zaccess(zp, ACE_WRITE_NAMED_ATTRS, cr))
		return (error);
#endif /*!__APPLE__*/

    if ((error = zfs_acl_ids_create(zp, IS_XATTR, vap, cr, NULL,
                                    &acl_ids)) != 0)
        return (error);
    if (zfs_acl_ids_overquota(zfsvfs, &acl_ids)) {
        zfs_acl_ids_free(&acl_ids);
        return (EDQUOT);
    }

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, zp->z_id);
	dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT)
			dmu_tx_wait(tx);
        zfs_acl_ids_free(&acl_ids);
		dmu_tx_abort(tx);
		return (error);
	}
	//zfs_mknode(zp, vap, &xoid, tx, cr, IS_XATTR, &xzp, 0);
	zfs_mknode(zp, vap, tx, cr, IS_XATTR, &xzp, &acl_ids);
	ASSERT(xzp->z_id == xoid);
	ASSERT(xzp->z_phys->zp_parent == zp->z_id);
	dmu_buf_will_dirty(zp->z_dbuf, tx);
	zp->z_phys->zp_xattr = xoid;

	(void) zfs_log_create(zfsvfs->z_log, tx, TX_MKXATTR, zp, xzp, "",
                          NULL, acl_ids.z_fuidp, vap);
    zfs_acl_ids_free(&acl_ids);
	dmu_tx_commit(tx);
#ifdef __APPLE__
	/*
	 * Obtain and attach the vnode after committing the transaction
	 */
	zfs_attach_vnode(xzp);
#endif
	*xvpp = ZTOV(xzp);

	return (0);
}

/*
 * Return a znode for the extended attribute directory for zp.
 * ** If the directory does not already exist, it is created **
 *
 *	IN:	zp	- znode to obtain attribute directory from
 *		cr	- credentials of caller
 *		flags	- flags from the VOP_LOOKUP call
 *
 *	OUT:	xzpp	- pointer to extended attribute znode
 *
 *	RETURN:	0 on success
 *		error number on failure
 */
int
zfs_get_xattrdir(znode_t *zp, vnode_t **xvpp, cred_t *cr, int flags)
{
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	znode_t		*xzp;
	zfs_dirlock_t	*dl;
	vattr_t		va;
	int		error;
top:
#ifdef __APPLE__
	error = zfs_dirent_lock(&dl, zp, NULL, &xzp, ZXATTR);
#else
	error = zfs_dirent_lock(&dl, zp, "", &xzp, ZXATTR);
#endif
	if (error)
		return (error);

	if (xzp != NULL) {
		*xvpp = ZTOV(xzp);
		zfs_dirent_unlock(dl);
		return (0);
	}

	ASSERT(zp->z_phys->zp_xattr == 0);

	if (!(flags & CREATE_XATTR_DIR)) {
		zfs_dirent_unlock(dl);
		return (ENOENT);
	}

#ifdef __APPLE__
	if (vfs_isrdonly(zfsvfs->z_vfs))
#else
	if (zfsvfs->z_vfs->vfs_flag & VFS_RDONLY)
#endif
	{
		zfs_dirent_unlock(dl);
		return (EROFS);
	}

	/*
	 * The ability to 'create' files in an attribute
	 * directory comes from the write_xattr permission on the base file.
	 *
	 * The ability to 'search' an attribute directory requires
	 * read_xattr permission on the base file.
	 *
	 * Once in a directory the ability to read/write attributes
	 * is controlled by the permissions on the attribute file.
	 */
	va.va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;
	va.va_type = VDIR;
	va.va_mode = S_IFDIR | S_ISVTX | 0777;
	va.va_uid = (uid_t)zp->z_phys->zp_uid;
	va.va_gid = (gid_t)zp->z_phys->zp_gid;

	error = zfs_make_xattrdir(zp, &va, xvpp, cr);
	zfs_dirent_unlock(dl);

	if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
		/* NB: we already did dmu_tx_wait() if necessary */
		goto top;
	}

	return (error);
}

/*
 * Decide whether it is okay to remove within a sticky directory.
 *
 * In sticky directories, write access is not sufficient;
 * you can remove entries from a directory only if:
 *
 *	you own the directory,
 *	you own the entry,
 *	the entry is a plain file and you have write access,
 *	or you are privileged (checked in secpolicy...).
 *
 * The function returns 0 if remove access is granted.
 */
int
zfs_sticky_remove_access(znode_t *zdp, znode_t *zp, cred_t *cr)
{
	uid_t  		uid;

	if (zdp->z_zfsvfs->z_assign >= TXG_INITIAL)	/* ZIL replay */
		return (0);

	if ((zdp->z_phys->zp_mode & S_ISVTX) == 0 ||
	    (uid = crgetuid(cr)) == zdp->z_phys->zp_uid ||
	    uid == zp->z_phys->zp_uid ||
		(
#ifdef __APPLE__
	    vnode_isreg(ZTOV(zp)) &&
#else
	    ZTOV(zp)->v_type == VREG &&
#endif
		zfs_zaccess(zp, ACE_WRITE_DATA, 0, B_FALSE, cr) == 0)
	)
		return (0);
	else
		return (secpolicy_vnode_remove(cr));
}
