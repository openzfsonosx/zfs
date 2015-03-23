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

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/vdev.h>

typedef struct vdev_disk {
	char *vd_minor;
	struct vnode *vd_devvp;
	uint64_t vd_ashift;
	boolean_t vd_offline;
} vdev_disk_t;

/* calculates (bytes / DEV_BSIZE) */
#define	lbtodb(bytes) \
	((unsigned long long)(bytes) >> DEV_BSHIFT)
/* calculates (db * DEV_BSIZE) */
#define	ldbtob(db) \
	((unsigned long long)(db) << DEV_BSHIFT)

#endif /* _KERNEL */

extern void vdev_disk_close(vdev_t *vd);

#ifdef  __cplusplus
}
#endif

#endif /* _SYS_VDEV_DISK_H */
