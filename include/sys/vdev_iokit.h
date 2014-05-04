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

typedef struct vdev_iokit {
//    char            *vd_minor;
//    struct vnode    *vd_devvp;
    void *      vd_iokit_hl;    /* vdev IOKit handle */
    uint64_t	vd_ashift;      /* ashift alignment */
} vdev_iokit_t;

#ifndef lbtodb
#define lbtodb(bytes)                   /* calculates (bytes / DEV_BSIZE) */ \
        ((unsigned long long)(bytes) >> DEV_BSHIFT)
#endif /* lbtodb */
#ifndef ldbtob
#define ldbtob(db)                      /* calculates (db * DEV_BSIZE) */ \
        ((unsigned long long)(db) << DEV_BSHIFT)
#endif /* ldbtob */

/*
 * C language interfaces
 */

bool vdev_iokit_handle_open (vdev_t * vd, uint64_t *size, uint64_t *max_size, uint64_t *ashift);
bool vdev_iokit_handle_close (vdev_t * vd);
bool vdev_iokit_strategy( vdev_t * vd, zio_t * zio );

#endif /* _KERNEL */
#endif /* _SYS_VDEV_IOKIT_H */
