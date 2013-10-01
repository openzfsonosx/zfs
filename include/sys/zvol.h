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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_ZVOL_H
#define	_SYS_ZVOL_H

#include <sys/zfs_context.h>
#include <sys/zfs_znode.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ZVOL_OBJ		1ULL
#define	ZVOL_ZAP_OBJ		2ULL


#ifdef _KERNEL

/*
 * zvol specific flags
 */
#define	ZVOL_RDONLY	0x1
#define	ZVOL_DUMPIFIED	0x2
#define	ZVOL_EXCL	0x4
#define	ZVOL_WCE	0x8


/*
 * The in-core state of each volume.
 */
typedef struct zvol_state {
	char		zv_name[MAXPATHLEN]; /* pool/dd name */
	uint64_t	zv_volsize;	/* amount of space we advertise */
	uint64_t	zv_volblocksize; /* volume block size */
	minor_t		zv_minor;	/* minor number */
	uint8_t		zv_min_bs;	/* minimum addressable block shift */
	uint8_t		zv_flags;	/* readonly, dumpified, etc. */
	objset_t	*zv_objset;	/* objset handle */
	uint32_t	zv_open_count[OTYPCNT];	/* open counts */
	uint32_t	zv_total_opens;	/* total open count */
	zilog_t		*zv_zilog;	/* ZIL handle */
	list_t		zv_extents;	/* List of extents for dump */
	znode_t		zv_znode;	/* for range locking */
	dmu_buf_t	*zv_dbuf;	/* bonus handle */
    void        *zv_iokitdev; /* C++ reference to IOKit class */
    uint64_t    zv_openflags; /* Remember flags used at open */
	char		zv_bsdname[MAXPATHLEN]; /* 'rdiskX' name, use [1] for diskX */
} zvol_state_t;


extern int zvol_check_volsize(uint64_t volsize, uint64_t blocksize);
extern int zvol_check_volblocksize(uint64_t volblocksize);
extern int zvol_get_stats(objset_t *os, nvlist_t *nv);
extern boolean_t zvol_is_zvol(const char *);
extern void zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx);
extern int zvol_create_minor(const char *);
extern int zvol_create_minors(char *);
extern int zvol_remove_minor(const char *);
extern void zvol_remove_minors(const char *);
extern int zvol_set_volsize(const char *, uint64_t);
extern int zvol_set_volblocksize(const char *, uint64_t);
extern int zvol_set_snapdev(const char *, uint64_t);

extern int zvol_open(dev_t dev, int flag, int otyp, cred_t *cr);
extern int zvol_close(dev_t dev, int flag, int otyp, cred_t *cr);
extern int zvol_read(dev_t dev, uio_t *uiop, cred_t *cr);
extern int zvol_write(dev_t dev, uio_t *uiop, cred_t *cr);

extern int zvol_init(void);
extern void zvol_fini(void);

    /* C helper functions for C++ */
extern int zvol_open_impl(zvol_state_t *zv, int flag, int otyp, cred_t *cr);
extern int zvol_close_impl(zvol_state_t *zv, int flag, int otyp, cred_t *cr);

extern int zvol_read_iokit (zvol_state_t *zv, uint64_t offset, uint64_t count,
                            void *iomem);
extern int zvol_write_iokit(zvol_state_t *zv, uint64_t offset, uint64_t count,
                            void *iomem);

extern void zvol_add_symlink(zvol_state_t *zv, const char *bsd_disk,
                             const char *bsd_rdisk);
extern void zvol_remove_symlink(zvol_state_t *zv);

    /* These functions live in zvolIO.cpp to be called from C */
extern uint64_t zvolIO_kit_read (void *iomem, uint64_t offset, char *address, uint64_t len);
extern uint64_t zvolIO_kit_write(void *iomem, uint64_t offset, char *address, uint64_t len);
extern int      zvolRemoveDevice(zvol_state_t *zv);
extern int      zvolCreateNewDevice(zvol_state_t *zv);
extern int      zvolSetVolsize(zvol_state_t *zv);

extern int zvol_busy(void);



#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ZVOL_H */
