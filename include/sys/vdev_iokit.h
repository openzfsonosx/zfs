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
 * Copyright (C) 2008-2010 Lawrence Livermore National Security, LLC.
 * Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 * Written by Brian Behlendorf <behlendorf1@llnl.gov>.
 * LLNL-CODE-403049.
 */

#ifndef _SYS_VDEV_IOKIT_H
#define	_SYS_VDEV_IOKIT_H

#ifdef _KERNEL
#include <sys/vdev.h>
#include <sys/zio.h>

#ifdef __cplusplus
extern "C" {
#endif /* C++ */

typedef struct vdev_iokit {
	void * vd_iokit_hl;			/* IOMedia service handle */
	void * vd_zfs_hl;			/* IOProvider zfs handle */
#if 0
	void * in_command_pool;		/* IOCommandPool for reads */
	void * out_command_pool;	/* IOCommandPool for writes */
	void * command_set;			/* OSSet to hold all commands */
#endif
} vdev_iokit_t;

/*
 * C language interfaces
 */

extern void vdev_iokit_log(const char *);
extern void vdev_iokit_log_str(const char *, const char *);
extern void vdev_iokit_log_ptr(const char *, const void *);
extern void vdev_iokit_log_num(const char *, const uint64_t);

int vdev_iokit_alloc(vdev_iokit_t **);
void vdev_iokit_free(vdev_iokit_t **);

#if 0 /* Disabled */
extern int vdev_iokit_context_pool_alloc(vdev_iokit_t *);
extern int vdev_iokit_context_pool_free(vdev_iokit_t *);
#endif	/* Disabled */

extern void * vdev_iokit_get_context(vdev_iokit_t *, zio_t *);
extern void vdev_iokit_return_context(zio_t *, void *);

extern void vdev_iokit_hold(vdev_t *);

extern void vdev_iokit_rele(vdev_t *);

extern void vdev_iokit_state_change(vdev_t *, int, int);

extern int vdev_iokit_open_by_path(vdev_iokit_t *, char *, uint64_t);

extern int vdev_iokit_open_by_guid(vdev_iokit_t *, uint64_t);

extern int vdev_iokit_find_by_path(vdev_iokit_t *, char *, uint64_t);

extern int vdev_iokit_find_by_guid(vdev_iokit_t *, uint64_t);

extern int vdev_iokit_find_pool(vdev_iokit_t *, char *);

extern int vdev_iokit_physpath(vdev_t *);

extern int vdev_iokit_open(vdev_t *, uint64_t *, uint64_t *, uint64_t *);

extern void vdev_iokit_close(vdev_t *);

extern int vdev_iokit_handle_open(vdev_iokit_t *, int);

extern int vdev_iokit_handle_close(vdev_iokit_t *, int);

extern int vdev_iokit_sync(vdev_iokit_t *, zio_t *);

extern char * vdev_iokit_get_path(vdev_iokit_t * dvd);

extern int vdev_iokit_get_size(vdev_iokit_t *,
				uint64_t *, uint64_t *, uint64_t *);

extern void * vdev_iokit_get_service();

extern int vdev_iokit_status(vdev_iokit_t *);

extern int vdev_iokit_ioctl(vdev_iokit_t *, zio_t *);

extern int vdev_iokit_strategy(vdev_iokit_t *, zio_t *);

extern void vdev_iokit_io_intr(void *, void *, kern_return_t, UInt64);

extern int vdev_iokit_read_label(vdev_iokit_t *, nvlist_t **);

extern int vdev_iokit_read_rootlabel(char *, char *, nvlist_t **);

/*
 * Extern for raidz dumps, not needed
 *	extern int vdev_iokit_physio(vdev_iokit_t *,
 *			void *, size_t, uint64_t, int, boolean_t);
 */

/*
 * Since vdev_iokit.c is not compiled into libzpool,
 *	this function should only be defined in the zfs
 *	kernel module.
 */
#ifdef _KERNEL
extern int vdev_iokit_physio(vdev_iokit_t *, void *, size_t, uint64_t, int);
#endif

#ifdef __cplusplus
}	/* extern "C" */
#endif /* C++ */

#endif /* _KERNEL */
#endif /* _SYS_VDEV_IOKIT_H */
