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

#ifndef _SYS_VDEV_DISK_H
#define	_SYS_VDEV_DISK_H

#include <sys/vdev.h>
#ifdef _KERNEL
#include <sys/ldi_osx.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef _KERNEL
typedef struct vdev_disk {
#ifdef illumos
	ddi_devid_t	vd_devid;
	char		*vd_minor;
#endif
	ldi_handle_t	vd_lh;
	list_t		vd_ldi_cbs;
	boolean_t	vd_ldi_offline;
} vdev_disk_t;
#endif /* _KERNEL */

/*
 * The vdev_buf_t is used to translate between zio_t and buf_t, and back again.
 */
typedef struct vdev_buf {
#ifdef illumos
	buf_t		vb_buf;	/* buffer that describes the io */
#else
	ldi_buf_t	vb_buf;	/* LDI buffer that describes the io */
#endif
	zio_t		*vb_io;	/* pointer back to the original zio_t */
} vdev_buf_t;

extern int vdev_disk_physio(vdev_t *,
    caddr_t, size_t, uint64_t, int, boolean_t);

/*
 * Since vdev_disk.c is not compiled into libzpool, this function should only be
 * defined in the zfs kernel module.
 */
#ifdef _KERNEL
extern int vdev_disk_ldi_physio(ldi_handle_t, caddr_t, size_t, uint64_t, int);
#endif
#ifdef  __cplusplus
}
#endif

#endif /* _SYS_VDEV_DISK_H */
