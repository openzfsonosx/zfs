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
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

typedef struct vdev_io_context {
    IOBufferMemoryDescriptor *      buffer;
    zio_t *                         zio;
    IOStorageCompletion             completion;
} vdev_io_context_t;

#endif /* C++ */

#ifdef __cplusplus
extern "C" {
#endif /* C++ */

typedef struct vdev_iokit {
//    char            *vd_minor;
//    struct vnode    *vd_devvp;
    uintptr_t *     vd_iokit_hl;    /* IOMedia service handle */
    uintptr_t *     vd_client_hl;   /* IOProvider zfs handle */
    uint64_t        vd_ashift;      /* ashift alignment */
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

extern void vdev_iokit_log( char * logString );
extern void vdev_iokit_log_ptr( char * logString, void * logPtr );
extern void vdev_iokit_log_num( char * logString, uint64_t logNum );
    
extern uintptr_t * vdev_iokit_find_by_path( vdev_t * vd, char * diskPath );

extern uintptr_t * vdev_iokit_find_by_guid( vdev_t * vd );

extern int vdev_iokit_handle_open (vdev_t * vd, uint64_t *size, uint64_t *max_size, uint64_t *ashift);

extern int vdev_iokit_handle_close (vdev_t * vd);
    
extern int vdev_iokit_ioctl( vdev_t * vd, zio_t * zio );

extern int vdev_iokit_sync( vdev_t * vd, zio_t * zio );

extern void vdev_iokit_ioctl_done(void *zio_arg, const int error);
    
extern int vdev_iokit_strategy( vdev_t * vd, zio_t * zio );

extern void vdev_iokit_io_intr( void * target, void * parameter, kern_return_t status, UInt64 actualByteCount );
    
#ifdef __cplusplus
}   /* extern "C" */
#endif /* C++ */

#endif /* _KERNEL */
#endif /* _SYS_VDEV_IOKIT_H */
