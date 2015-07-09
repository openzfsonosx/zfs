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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */
/*
 * Copyright (c) 2015, Evan Susarret.  All rights reserved.
 */
/*
 * Portions of this document are copyright Oracle and Joyent.
 * OS X implementation of ldi_ named functions for ZFS written by
 * Evan Susarret in 2015.
 */

/*
 * ZFS internal
 */
#include <sys/zfs_context.h>

/*
 * LDI Includes
 */
#include <sys/ldi_impl_osx.h>

/* Debug prints */
#ifdef DEBUG

#ifdef dprintf
#undef dprintf
#endif

#define	dprintf ldi_log

#define	ldi_log(fmt, ...) do {		\
	printf(fmt, __VA_ARGS__);	\
	/* delay(hz>>1); */		\
_NOTE(CONSTCOND) } while (0)
#endif

/*
 * Check, set, and clear vnode_mountedon flag.
 * Previously we 'checked' this flag after successful vnode_open, however the
 * open would have failed if the flag was set (so was never being checked).
 * The correct way to check this is by doing vnode_lookup prior to vnode_open
 * (or by checking with vnode_lookup after a failed open).
 * We were not setting or clearing the mountedon flag either, but it has
 * limited usefulness.
 * Specifically, setting vnode_mountedon disallows a separate read-only open
 * while we have a read-write open, which breaks shared spare vdevs.
 */
// #define	LDI_VNODE_MOUNTEDON

/*
 * Use vnode_getwithref and vnode_put for each IO or state change.
 * This takes a usecount on the vnode, which allows us to drop the iocount.
 * Previously an iocount and refcount were held from vnode_open through
 * vnode_close.
 * The iocount is intended to be dropped as soon as possible, and usecount
 * may be held for extended periods of time.
 * We could also save the vnode's VID and use vnode_getwithvid (like
 * vdev_file does).
 */
#define	LDI_VNODE_REF
#define	LDI_VNODE_PUT

int
handle_close_vnode(struct ldi_handle *lhp)
{
	vnode_t *devvp = NULLVP;
	vfs_context_t context = 0;
	int error = EINVAL;

	ASSERT3U(lhp, !=, NULL);
	ASSERT3U(lhp->lh_type, ==, LDI_TYPE_VNODE);
	ASSERT3U(lhp->lh_un.media, !=, NULL);
	ASSERT3U(lhp->lh_status, ==, LDI_STATUS_CLOSING);

	/* Validate devvp vnode */
	if ((devvp = lhp->lh_un.devvp) == NULLVP) {
		dprintf("%s invalid vnode devvp\n", __func__);
		return (ENODEV);
		/* goto handle_closed; */
	}

	/* Validate context */
	if ((context = vfs_context_create(
	    spl_vfs_context_kernel())) == NULL) {
		dprintf("%s couldn't create VFS context\n", __func__);
		return (ENOMEM);
	}

#ifdef LDI_VNODE_REF
	/* Take an iocount on devvp vnode. */
	if (0 != (error = vnode_getwithref(devvp))) {
		dprintf("%s vnode_getwithref error %d\n",
		    __func__, error);
		/*
		 * Clear handle devvp vnode pointer.
		 * If getwithref failed, we can't call vnode_close.
		 */
		lhp->lh_un.devvp = devvp = NULLVP;
		error = ENODEV;
		goto vnode_out;
	}
	/* All code paths from here must vnode_put. */
#endif

	/* For read-write, clear mountedon flag and wait for writes */
	if (lhp->lh_fmode & FWRITE) {
#ifdef LDI_VNODE_MOUNTEDON
		/* Clear the vnode mountedon flag (returns void) */
		vnode_clearmountedon(devvp);
#endif

		/* Wait for writes to complete */
		error = vnode_waitforwrites(devvp, 0, 0, 0,
		    "ldi:handle_close");

		if (error != 0) {
			dprintf("%s waitforwrites returned %d\n",
			    __func__, error);
		}
	}

#ifdef LDI_VNODE_REF
	/* Drop usecount */
	vnode_rele(devvp);
#endif

	/* Drop iocount and refcount */
	if (0 != (error = vnode_close(devvp,
	    (lhp->lh_fmode & FWRITE ? FWASWRITTEN : 0), context))) {
		dprintf("%s vnode_close error %d\n",
		    __func__, error);
		/* Preserve error */
	}

	/* Clear handle devvp vnode pointer */
	lhp->lh_un.devvp = devvp = NULLVP;

vnode_out:
#ifdef LDI_VNODE_PUT
	/* devvp will be cleared if vnode_close succeeds */
	if (devvp) {
		/* Release iocount on vnode (still has usecount) */
		vnode_put(devvp);
	}
#endif

	if (context) {
		vfs_context_rele(context);
		context = 0;
	}

	/* Return error from close */
	return (error);
}

static int
handle_open_vnode(struct ldi_handle *lhp, char *path)
{
	vfs_context_t context = 0;
	vnode_t *devvp = NULLVP;
	int flags, error = EINVAL;
	boolean_t has_iocount = B_FALSE;
	boolean_t has_usecount = B_FALSE;

	ASSERT3U(lhp, !=, NULL);
	ASSERT3U(path, !=, NULL);
	ASSERT3U(lhp->lh_type, ==, LDI_TYPE_VNODE);
	ASSERT3U(lhp->lh_status, ==, LDI_STATUS_OPENING);

	/* Find length of string plus null character */
	if (!path || strlen(path) <= 1) {
		dprintf("%s missing path\n", __func__);
		return (EINVAL);
	}

	/* Validate context */
	context = vfs_context_create(spl_vfs_context_kernel());
	if (context == NULL) {
		dprintf("%s couldn't create VFS context\n", __func__);
		return (ENOMEM);
	}

	/* Valid LDI open modes are read-only or read-write. */
	flags = FREAD | (lhp->lh_fmode & FWRITE ? FWRITE : 0);

	/* Try to open the device by path (takes iocount) */
	error = vnode_open(path, flags, 0, 0, &devvp, context);
	if (error != 0) {
		dprintf("%s vnode_open error %d\n", __func__, error);
		/* Return error from vnode_open */
		goto vnode_out;
	}
	has_iocount = B_TRUE;

#ifdef LDI_VNODE_REF
	/* Increase usecount, saving error. */
	error = vnode_ref(devvp);
	if (error != 0) {
		dprintf("%s couldn't vnode_ref devvp\n", __func__);
		/* Pass error for return */
		goto vnode_out;
	}
	has_usecount = B_TRUE;
#endif

#if 0
#ifdef LDI_VNODE_MOUNTEDON
/*
 * XXX Disabled mountedon check as this will not even be reached if the
 * mountedon flag is set - vnode_open would fail and devvp would be NULLVP.
 * Only useful if checking devvp by vnode_lookup prior to vnode_open.
 * For example: vnode_lookup, check mountedon, vnode_put, then vnode_open.
 */
	/*
	 * Disallow opening of a device that is currently in use.
	 */
	error = vfs_mountedon(devvp);
	if (error != 0) {
		dprintf("%s vfs mountedon returned %d for %s\n",
		    __func__, error, path);

		error = EBUSY;
		goto vnode_out;
	}
#endif /* LDI_VNODE_MOUNTEDON */
#endif /* if 0 */

	/* Verify vnode refers to a block device */
	if (!vnode_isblk(devvp)) {
		dprintf("%s %s is not a block device\n",
		    __func__, path);

		error = ENOTBLK;
		goto vnode_out;
	}

#if 0
#ifdef LDI_VNODE_MOUNTEDON
/*
 * XXX Disabled setting mountedon flag as it breaks shared spare
 * vdevs and libzfs probing of in-use devices.
 */
	/*
	 * This marks the device as having a filesystem mounted
	 * on it, which prevents other clients from opening it.
	 */
	if (flags & FWRITE) {
		dprintf("%s calling vnode_setmountedon\n",
		    __func__);
		vnode_setmountedon(devvp);
	}
#endif /* LDI_VNODE_MOUNTEDON */
#endif /* if 0 */

#ifdef LDI_VNODE_PUT
	/* Drop iocount on vnode (still has usecount) */
	vnode_put(devvp);
#endif

vnode_out:
	/* Set error if devvp is missing */
	if (error == 0 && devvp == NULLVP) {
		error = ENODEV;
	}

	/* If error and devvp is still set, cleanup */
	if (error != 0 && devvp != NULLVP) {
		if (has_usecount) {
			/* Drop usecount taken by vnode_ref */
			vnode_rele(devvp);
		}
		if (has_iocount) {
			/* Close (drops iocount), clear devvp */
			vnode_close(devvp, flags, context);
		}
		devvp = NULLVP;
	}
	if (context) {
		vfs_context_rele(context);
		context = 0;
	}

	/* If successful, assign devvp vnode */
	if (error == 0 && devvp != NULLVP) {
		lhp->lh_un.devvp = devvp;
		devvp = NULLVP;
	}

	/* Pass error */
	return (error);
}

int
handle_get_size_vnode(struct ldi_handle *lhp,
    uint64_t *dev_size, uint64_t *blocksize)
{
	vfs_context_t context = 0;
	vnode_t *devvp = NULLVP;
	uint64_t blkcnt;
	uint32_t blksize;
	int error = EINVAL;

	/* Validate devvp vnode */
	if (NULLVP == (devvp = lhp->lh_un.devvp)) {
		dprintf("%s invalid vnode devvp\n", __func__);
		return (ENODEV);
	}

	/* Validate context */
	if ((context = vfs_context_create(
	    spl_vfs_context_kernel())) == NULL) {
		dprintf("%s couldn't create VFS context\n",
		    __func__);
		return (ENOMEM);
	}

#ifdef LDI_VNODE_REF
	/* Take an iocount on devvp vnode. */
	if (0 != (error = vnode_getwithref(devvp))) {
		dprintf("%s vnode_getwithref error %d\n",
		    __func__, error);
		devvp = NULLVP;
		error = ENODEV;
		goto vnode_out;
	}
	/* All code paths from here must vnode_put. */
#endif

	/* Fetch the blocksize */
	error = VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE,
	    (caddr_t)&blksize, 0, context);
	if (error != 0) {
		dprintf("%s %s %d %d\n", __func__,
		    "getblocksize error, value", error, blksize);
		error = ENOENT;
		goto vnode_out;
	}

	if (blksize == 0) {
		dprintf("%s using default DEV_BSIZE\n", __func__);
		/* Set to default of 512-bytes */
		blksize = DEV_BSIZE;
	}
	ASSERT3U(blksize, ==, (1ULL<<(highbit(blksize)-1)));

	/* If pointer was provided, copy in value */
	if (blocksize != 0) {
		/* Cast from 32-bit to 64 */
		*blocksize = (uint64_t)blksize;
	}

	if (dev_size == 0) {
		/* blocksize has been successfully set */
		error = 0;
		goto vnode_out;
	}

	/* Fetch the block count */
	error = VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT,
	    (caddr_t)&blkcnt, 0, context);
	if (error != 0 || blkcnt == 0) {
		dprintf("%s getblockcount failed %d %llu\n", __func__,
		    error, blkcnt);
		error = ENOENT;
		goto vnode_out;
	}

	/* Cast both to 64-bit then multiply */
	*dev_size = ((uint64_t)blksize * (uint64_t)blkcnt);
	if (*dev_size == 0) {
		dprintf("%s invalid blksize %u or blkcnt %llu\n", __func__,
		    blksize, blkcnt);
		error = ENODEV;
		goto vnode_out;
	}

	/* Success */
	error = 0;

vnode_out:
#ifdef LDI_VNODE_PUT
	if (devvp != NULLVP) {
		/* Release iocount on vnode (still has usecount) */
		vnode_put(devvp);
		devvp = NULLVP;
	}
#endif

	if (context) {
		vfs_context_rele(context);
		context = 0;
	}

	return (error);
}

int
handle_sync_vnode(struct ldi_handle *lhp)
{
	vfs_context_t context = 0;
	vnode_t *devvp = NULLVP;
	int error = EINVAL;

	/* Validate devvp vnode */
	if (NULLVP == (devvp = lhp->lh_un.devvp)) {
		dprintf("%s invalid vnode devvp\n", __func__);
		return (ENODEV);
	}

	/* Validate context */
	context = vfs_context_create(spl_vfs_context_kernel());
	if (!context) {
		dprintf("%s couldn't create VFS context\n",
		    __func__);
		return (ENOMEM);
	}

#ifdef LDI_VNODE_REF
	/* Take an iocount on devvp vnode. */
	if (0 != (error = vnode_getwithref(devvp))) {
		dprintf("%s vnode_getwithref error %d\n",
		    __func__, error);
		/* Clear devvp to avoid vnode_put */
		devvp = NULLVP;
		error = ENODEV;
		goto vnode_out;
	}
	/* All code paths from here must vnode_put. */
#endif

	/*
	 * Flush out any old buffers remaining from a previous use.
	 * buf_invalidateblks flushes UPL buffers, VNOP_FSYNC informs
	 * the disk device to flush write buffers to disk.
	 */
	if (0 != (error = buf_invalidateblks(devvp,
	    BUF_WRITE_DATA, 0, 0))) {
		dprintf("%s buf_invalidateblks error %d\n",
		    __func__, error);
		error = EIO;
		goto vnode_out;
	}
	if (0 != (error = VNOP_FSYNC(devvp, MNT_WAIT,
	    context))) {
		dprintf("%s VNOP_FSYNC error %d\n",
		    __func__, error);
		error = ENOTBLK;
		goto vnode_out;
	}

	/* Success */
	error = 0;

vnode_out:
#ifdef LDI_VNODE_PUT
	if (devvp) {
		/* Release iocount on vnode (still has usecount) */
		vnode_put(devvp);
		devvp = NULLVP;
	}
#endif

	if (context) {
		vfs_context_rele(context);
		context = 0;
	}

	return (error);
}

/* vnode_lookup, find dev_t info */
dev_t
dev_from_path(char *path)
{
	vfs_context_t context;
	vnode_t *devvp = NULLVP;
	dev_t device;
	int error = EINVAL;

	/* Validate path */
	if (path == 0 || strlen(path) <= 1 || path[0] != '/') {
		dprintf("%s invalid path provided\n", __func__);
		return (0);
	}
	dprintf("%s path %s\n", __func__, path);

	/* Validate context */
	if ((context = vfs_context_create(
	    spl_vfs_context_kernel())) == NULL) {
		dprintf("%s couldn't create VFS context\n",
		    __func__);
		return (0);
	}

	/* Try to lookup the vnode by path */
	if ((error = vnode_lookup(path, 0, &devvp, context)) != 0 ||
	    devvp == NULLVP) {
		dprintf("%s vnode_lookup failed %d\n",
		    __func__, error);
		vfs_context_rele(context);
		return (0);
	}

	/* Get the rdev of this vnode */
	device = vnode_specrdev(devvp);

	/* Drop iocount on devvp and clear */
	vnode_put(devvp);
	devvp = NULLVP;

	/* Drop vfs_context */
	vfs_context_rele(context);
	context = 0;

	/* Validate dev_t */
	if (device == 0) {
		dprintf("%s invalid device\n",
		    __func__);
	}

	/* Return 0 or valid dev_t */
	return (device);
}

/* Completion handler for vnode strategy */
static void
ldi_vnode_io_intr(buf_t bp, void *arg)
{
	ldi_buf_t *obp = (struct ldi_buf *)arg;
#ifdef DEBUG
	vnode_t *devvp = buf_vnode(bp);
#endif

	ASSERT3U(bp, !=, NULL);
	ASSERT3U(obp, !=, NULL);
	ASSERT3U(devvp, !=, NULLVP);

	/* Copyout error and resid */
	obp->b_error = buf_error(bp);
	obp->b_resid = buf_resid(bp);

#ifdef DEBUG
	if (obp->b_error || obp->b_resid != 0) {
		dprintf("%s io error %d resid %llu\n", __func__,
		    obp->b_error, obp->b_resid);
	}
#endif

	/* Teardown */
	obp->b_buf.bp = 0;
	buf_free(bp);

	/* Call original completion function */
	if (obp->b_iodone) {
		obp->b_iodone(obp, obp->b_iodoneparam);
	}
}

/*
 * Uses IOMedia::read asynchronously or IOStorage::read synchronously.
 * virtual void read(IOService *	client,
 *     UInt64				byteStart,
 *     IOMemoryDescriptor *		buffer,
 *     IOStorageAttributes *		attributes,
 *     IOStorageCompletion *		completion);
 * virtual IOReturn read(IOService *	client,
 *     UInt64				byteStart,
 *     IOMemoryDescriptor *		buffer,
 *     IOStorageAttributes *		attributes = 0,
 *     UInt64 *				actualByteCount = 0);
 */

int
buf_strategy_vnode(ldi_buf_t *bp, struct ldi_handle *lhp)
{
	int error = EINVAL;
	/* vnode */
	vfs_context_t context = 0;
	vnode_t *devvp = NULLVP;
	buf_t newbp = 0;
	uint64_t blkno;
	int flags;
	boolean_t sync;

	ASSERT3U(bp, !=, NULL);
	ASSERT3U(lhp, !=, NULL);

	/* Validate devvp vnode */
	if (NULLVP == (devvp = lhp->lh_un.devvp)) {
		dprintf("%s invalid vnode devvp\n",
		    __func__);
		return (ENODEV);
	}

	/* Validate context */
	if ((context = vfs_context_create(
	    spl_vfs_context_kernel())) == NULL) {
		dprintf("%s couldn't create VFS context\n",
		    __func__);
		return (ENOMEM);
	}

	/* For synchronous IO */
	sync = (bp->b_iodone == NULL);
	/* Read/write and nocache flags */
	flags = (bp->b_flags & B_READ ? B_READ : B_WRITE);
	flags |= B_NOCACHE;
	/* Get block number */
	blkno = (bp->b_offset >> DEV_BSHIFT);

	/* Allocate and verify buf_t */
	if (NULL == (newbp = buf_alloc(devvp))) {
		dprintf("%s %s\n", __func__,
		    "couldn't allocate buf_t");
		error = ENOMEM;
		goto vnode_out;
	}

	/* Setup buffer */
	buf_setflags(newbp, flags);
	buf_setcount(newbp, bp->b_bcount);
	buf_setdataptr(newbp, (uintptr_t)bp->b_data);
	buf_setblkno(newbp, blkno);
	buf_setlblkno(newbp, blkno);
	buf_setsize(newbp, bp->b_bufsize);

	/* For asynchronous IO */
	if (!sync) {
		buf_setcallback(newbp, &ldi_vnode_io_intr, bp);
	}

#ifdef DEBUG
	if (bp->b_bcount != bp->b_bufsize) {
		dprintf("%s vnode buf_t with flags %d, data %p,"
		    " bcount %llx, blkno %llx, resid %x\n",
		    __func__, flags, bp->b_data, bp->b_bcount, blkno,
		    buf_resid(newbp));
	}
#endif

	/* Recheck instantaneous value of handle status */
	if (lhp->lh_status != LDI_STATUS_ONLINE) {
		dprintf("%s device not online\n", __func__);
		error = ENODEV;
		goto vnode_out;
	}

#ifdef LDI_VNODE_REF
	/* Take an iocount on devvp vnode. */
	if (0 != (error = vnode_getwithref(devvp))) {
		dprintf("%s vnode_getwithref error %d\n",
		    __func__, error);
		error = ENODEV;
		goto vnode_out;
	}
	/* All code paths from here must vnode_put. */
#endif

	/* Assign newbp to bp */
	bp->b_buf.bp = &newbp;

	if (!(bp->b_flags & B_READ)) {
		vnode_startwrite(devvp);
	}
	/* Issue the IO, preserving error */
	error = VNOP_STRATEGY(newbp);

	if (error != 0) {
		dprintf("%s VNOP_STRATEGY error %d\n",
		    __func__, error);
		/* Reclaim write count on vnode */
		if (!(bp->b_flags & B_READ)) {
			vnode_writedone(devvp);
		}
		error = EIO;
		goto vnode_out;
	}

	/* Clear pointer to avoid releasing in-use buf_t */
	newbp = 0;

	/* For synchronous IO, call completion */
	if (sync) {
		ldi_vnode_io_intr(newbp, (void*)bp);
	}

vnode_out:
#ifdef LDI_VNODE_PUT
	if (devvp != NULLVP) {
		/* Release iocount on vnode (still has usecount) */
		vnode_put(devvp);
		devvp = NULLVP;
	}
#endif
	if (context) {
		vfs_context_rele(context);
		context = 0;
	}
	/* On success, newbp pointer was assigned to bp and cleared */
	if (newbp) {
		buf_free(newbp);
		newbp = 0;
	}

	/* Pass error from VNOP_STRATEGY */
	return (error);
}

/* Client interface, alloc and open vnode handle by pathname */
int
ldi_open_vnode_by_path(char *path, dev_t device,
    int fmode, ldi_handle_t *lhp)
{
	struct ldi_handle *retlhp;
	ldi_status_t status;
	int error;

	/* Validate arguments */
	if (!path || strlen(path) <= 1 || device == 0 || !lhp) {
		dprintf("%s invalid argument %p %d %p\n", __func__,
		    path, device, lhp);
		if (path) {
			dprintf("*path string is %s\n", path);
		}
		return (EINVAL);
	}
	/* In debug build, be loud if we potentially leak a handle */
	ASSERT3U(*(struct ldi_handle **)lhp, ==, NULL);

	/* Allocate handle with path */
	retlhp = handle_alloc_vnode(device, fmode);
	if (retlhp == NULL) {
		dprintf("%s couldn't allocate vnode handle\n", __func__);
		return (ENOMEM);
	}

	/* Mark the handle as Opening, or increment openref */
	status = handle_open_start(retlhp);
	if (status == LDI_STATUS_ONLINE) {
		dprintf("%s already online, refs %d, openrefs %d\n", __func__,
		    retlhp->lh_ref, retlhp->lh_openref);
		/* Cast retlhp and assign to lhp (may be 0) */
		*lhp = (ldi_handle_t)retlhp;
		/* Successfully incremented open ref in open_start */
		return (0);
	}

	/* If state is now Opening, try to open device by vnode */
	if (status != LDI_STATUS_OPENING ||
	    (error = handle_open_vnode(retlhp, path)) != 0) {
		dprintf("%s Couldn't open handle\n", __func__);
		handle_open_done(retlhp, LDI_STATUS_CLOSED);
		handle_release(retlhp);
		retlhp = 0;
		return (EIO);
	}

	/* XXX Should get and cache blocksize for lbtodb */

	handle_open_done(retlhp, LDI_STATUS_ONLINE);

	/* Register for disk notifications */
	handle_register_notifier(retlhp);

	/* Cast retlhp and assign to lhp (may be 0) */
	*lhp = (ldi_handle_t)retlhp;
	/* Pass error from open */
	return (error);
}
