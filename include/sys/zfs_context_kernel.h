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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#ifndef _SYS_ZFS_CONTEXT_KERNEL_H
#define	_SYS_ZFS_CONTEXT_KERNEL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

    //#include <sys/note.h>
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/taskq_impl.h>
#include <sys/buf.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/kobj.h>
#include <sys/conf.h>
#include <sys/disp.h>
#include <sys/debug.h>
#include <sys/random.h>
#include <sys/byteorder.h>
#include <sys/systm.h>
#include <sys/list.h>
#include <sys/uio_impl.h>
#include <sys/dirent.h>
#include <sys/time.h>
#include <vm/seg_kmem.h>
#include <sys/zone.h>
#include <sys/sdt.h>
#include <sys/zfs_debug.h>
#include <sys/zfs_delay.h>
#include <sys/fm/fs/zfs.h>
#include <sys/sunddi.h>
#include <sys/ctype.h>
#include <sys/disp.h>
#include <sys/atomic.h>
//#include <linux/dcache_compat.h>

// There are to be found in spl/include/sys/kmem.h
//typedef enum kmem_cbrc {
//	KMEM_CBRC_YES,
//	KMEM_CBRC_NO,
//	KMEM_CBRC_LATER,
//	KMEM_CBRC_DONT_NEED,
//	KMEM_CBRC_DONT_KNOW
//} kmem_cbrc_t;

#define	KMC_KMEM		0x0
#define	KMC_VMEM		0x0

#define noinline

typedef struct dirent dirent_t;
typedef struct direntry dirent64_t;

#define DIRENT_RECLEN(namelen, ext)  \
        ((ext) ?  \
        ((sizeof(dirent64_t) + (namelen) - (MAXPATHLEN-1) + 7) & ~7)  \
        :  \
        ((sizeof(dirent_t) - (NAME_MAX+1)) + (((namelen)+1 + 7) &~ 7)))

#define        CREATE_XATTR_DIR        0x04    /* Create extended attr dir */
#define	kpreempt_disable()	((void)0)
#define	kpreempt_enable()	((void)0)

/* Buffer flags not used in Mac OS X */
#define B_FAILFAST  0

/* Pre-faulting pages not yet supported for Mac OS X */
#define zfs_prefault_write(n, uio)

#define SEC_TO_TICK(sec)        ((sec) * hz)
#define MSEC_TO_TICK(msec)      ((msec) / (MILLISEC / hz))
#define USEC_TO_TICK(usec)      ((usec) / (MICROSEC / hz))
#define NSEC_TO_TICK(usec)      ((usec) / (NANOSEC / hz))


#define IS_INDEXABLE(arg) (sizeof(arg[0]))
#define IS_ARRAY(arg) (IS_INDEXABLE(arg) && (((void *) &arg) == ((void *) arg)))
#define ARRAY_SIZE(arr) (IS_ARRAY(arr) ? (sizeof(arr) / sizeof(arr[0])) : 0)

#define PRId64 "lld"

// Cheat a little here
#define	ddi_strtoll ddi_strtol

#define isalpha(C) ((C) >= 'A' && (C) <= 'Z') || ((C) >= 'a' && (C) <= 'z')
#define isdigit(C) ((C) >= '0' && (C) <= '9')
#define isalnum(C) isalpha((C)) || isdigit((C))

/*
  Copyright (c) 2005 David Schultz <das@FreeBSD.ORG>
*/
#define IDX(c)  ((u_char)(c) / LONG_BIT)
#define BIT(c)  ((u_long)1 << ((u_char)(c) % LONG_BIT))

static inline size_t
strspn(const char *s, const char *charset)
{
	const char *s1;
	u_long bit;
	u_long tbl[(UCHAR_MAX + 1) / LONG_BIT];
	int idx;
	if(*s == '\0')
		return (0);
	tbl[3] = tbl[2] = tbl[1] = tbl[0] = 0;
	for (; *charset != '\0'; charset++) {
		idx = IDX(*charset);
		bit = BIT(*charset);
		tbl[idx] |= bit;
	}
	for(s1 = s; ; s1++) {
		idx = IDX(*s1);
		bit = BIT(*s1);
		if ((tbl[idx] & bit) == 0)
			break;
	}
	return (s1 - s);
}

/*
 *  dtrace_glue.c 2002-01-24  gvdl    Initial implementation of strstr
 */
static inline const char *
strstr(const char *in, const char *str)
{
	char c;
    size_t len;
    c = *str++;
    if (!c)
        return (const char *) in;
    len = strlen(str);
    do {
        char sc;
        do {
            sc = *in++;
            if (!sc)
                return (char *) 0;
        } while (sc != c);
    } while (strncmp(in, str, len) != 0);
    return (const char *) (in - 1);
}

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ZFS_CONTEXT_H */
