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
 * Copyright (c) 2015, Evan Susarret.  All rights reserved.
 *
 * OS X implementation of ldi_ named functions for ZFS written by
 * Evan Susarret in 2015.
 */

#ifndef _SYS_LDI_BUF_H
#define	_SYS_LDI_BUF_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Buffer context for LDI strategy
 */
typedef struct ldi_buf {
	/* Internal */
	union {
			void *iomem;	/* IOKit IOMemoryDescriptor */
			buf_t *bp;	/* vnode buf_t */
	} b_buf;
	void		*b_ioattr;	/* struct IOStorageAttributes */
	void		*b_iocompletion;/* struct IOStorageCompletion */

	/* For client use */
	void		*b_data;	/* Passed buffer address */
	uint64_t	b_bcount;	/* Size of IO */
	uint64_t	b_bufsize;	/* Size of buffer */
	uint64_t	b_offset;	/* IO offset */
	uint64_t	b_resid;	/* Remaining IO size */
	int		b_flags;	/* Read or write, options */
	int		b_error;	/* IO error code */
	int		(*b_iodone)(struct ldi_buf *, void *arg);
					/* Completion callback */
	void		*b_iodoneparam;	/* Passed to callback */
} ldi_buf_t;

/* Redefine B_BUSY */
#define	B_BUSY	B_PHYS

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* _SYS_LDI_BUF_H */
