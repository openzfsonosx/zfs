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
 * Apple IOKit (c++)
 */
#include <IOKit/IOLib.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/storage/IOMedia.h>

/*
 * ZFS internal
 */
#include <sys/zfs_context.h>

/* Debug prints */
#ifdef DEBUG

#ifdef dprintf
#undef dprintf
#endif

#define	dprintf ldi_log

#define	ldi_log(fmt, ...) do {		\
	printf(fmt, __VA_ARGS__);	\
	/* delay(hz>>1); */		\
	/* IOSleep(10); */		\
_NOTE(CONSTCOND) } while (0)
#endif

/* Attach created IOService objects to the IORegistry under ZFS. */
// #define LDI_IOREGISTRY_ATTACH

/*
 * Globals
 */
static IOService		*ldi_zfs_handle;

/* Exposed to c callers */
extern "C" {

/*
 * LDI Includes
 */
#include <sys/ldi_impl_osx.h>

int
handle_free_ioservice(struct ldi_handle *lhp)
{
	IOService *client;

	/* Validate handle pointer */
	ASSERT3U(lhp, !=, NULL);
	if (!lhp) {
		dprintf("%s missing handle\n", __func__);
		return (EINVAL);
	}

	/* Clear IOService client */
	client = OSDynamicCast(IOService, (OSObject *)lhp->lh_client);
	if (!client) {
		dprintf("%s couldn't cast IOService client\n", __func__);
		return (ENOENT);
	}

	/* Clear handle client then stop */
	lhp->lh_client = 0;
	client->stop(ldi_zfs_handle);

	/* Detach client from ZFS in IORegistry */
#ifdef LDI_IOREGISTRY_ATTACH
	client->detach(ldi_zfs_handle);
#endif

	/* Release and free memory */
	client->release();
	client = 0;
	return (0);
}

int
handle_alloc_ioservice(struct ldi_handle *lhp)
{
	IOService *client;

	/* Validate handle pointer */
	ASSERT3U(lhp, !=, NULL);
	if (lhp == NULL) {
		dprintf("%s missing handle\n", __func__);
		return (EINVAL);
	}

	/* Allocate and init an IOService client for open/close */
	if ((client = new IOService) == NULL) {
		dprintf("%s couldn't allocate new IOService\n", __func__);
		return (ENOMEM);
	}
	if (client->init(0) != true) {
		dprintf("%s IOService init failed\n", __func__);
		client->release();
		return (ENOMEM);
	}

	/* Attach client to ZFS in IORegistry */
#ifdef LDI_IOREGISTRY_ATTACH
	if (client->attach(ldi_zfs_handle) != true) {
		dprintf("%s IOService attach failed\n", __func__);
		client->release();
		return (ENOMEM);
	}
#endif

	/* Start service */
	if (client->start(ldi_zfs_handle) != true) {
		dprintf("%s IOService attach failed\n", __func__);
		/* Detach client from ZFS in IORegistry */
#ifdef LDI_IOREGISTRY_ATTACH
		client->detach(ldi_zfs_handle);
#endif
		client->release();
		return (ENOMEM);
	}

	lhp->lh_client = client;
	return (0);
}

/* Set status to Offline and post event */
static bool
handle_media_terminate_cb(void* target, void* refCon,
    IOService* newService, IONotifier* notifier)
{
	struct ldi_handle *lhp = (struct ldi_handle *)refCon;
	int error;

	if (!lhp) {
		dprintf("%s missing refCon ldi_handle\n", __func__);
		return (false);
	}

	/* Take hold on handle to prevent removal */
	handle_hold(lhp);

	dprintf("%s setting lhp %p to Offline status\n", __func__, lhp);
	error = handle_status_change(lhp, LDI_STATUS_OFFLINE);

	handle_release(lhp);

	return (true);
}

int
handle_close_iokit(struct ldi_handle *lhp)
{
	IOMedia *media;
	IOService *client;

	ASSERT3U(lhp, !=, NULL);
	ASSERT3U(lhp->lh_type, ==, LDI_TYPE_IOKIT);
	ASSERT3U(lhp->lh_un.media, !=, NULL);
	ASSERT3U(lhp->lh_status, ==, LDI_STATUS_CLOSING);

	/* Validate IOService client */
	client = OSDynamicCast(IOService, (OSObject *)lhp->lh_client);
	if (client == NULL) {
		dprintf("%s couldn't cast IOService client\n",
		    __func__);
		return (ENODEV);
	}
	/* No need to retain client, owned by handle */

	/* Validate IOMedia */
	media = OSDynamicCast(IOMedia, (OSObject *)lhp->lh_un.media);
	if (media == NULL) {
		dprintf("%s missing IOMedia handle\n", __func__);
		return (ENODEV);
	}
	media->retain();

	/* Clear handle IOMedia pointer */
	lhp->lh_un.media = 0;

	/* Call IOMedia::close */
	media->close(client);
	media->release();

	return (0);
}

static int
handle_open_iokit(struct ldi_handle *lhp, IOMedia *media)
{
	IOService *client;
	IOStorageAccess iomode;
	boolean_t retval;

	ASSERT3U(lhp, !=, NULL);
	ASSERT3U(media, !=, NULL);
	ASSERT3U(lhp->lh_type, ==, LDI_TYPE_IOKIT);
	ASSERT3U(lhp->lh_status, ==, LDI_STATUS_OPENING);

	/* Validate IOService client */
	client = OSDynamicCast(IOService,
	    (OSObject *)lhp->lh_client);
	if (client == NULL) {
		dprintf("%s couldn't cast IOService client\n", __func__);
		return (ENODEV);
	}
	/* No need to retain client, owned by new handle */

	/* Validate IOMedia */
	if (!OSDynamicCast(IOMedia, media)) {
		dprintf("%s couldn't cast IOMedia\n", __func__);
		return (ENODEV);
	}
	/* Retain until open or error */
	media->retain();

	/*
	 * If read/write mode is requested, check that the
	 * device is actually writeable.
	 */
	if (lhp->lh_fmode & FWRITE && media->isWritable() == false) {
		dprintf("%s read-write requested on %s\n",
		    __func__, "read-only IOMedia");
		media->release();
		return (EPERM);
	}

	/* Only valid modes are read-only or read-write */
	iomode = (lhp->lh_fmode & FWRITE ? kIOStorageAccessReaderWriter :
	    kIOStorageAccessReader);

	/* Call open with the IOService client handle */
	retval = media->IOMedia::open(client, 0, iomode);
	media->release();

	/* Error check open */
	if (retval == false) {
		dprintf("%s IOMedia->open failed\n", __func__);
		return (EIO);
	}

	/* Assign IOMedia device */
	lhp->lh_un.media = media;

	return (0);
}

int
handle_get_size_iokit(struct ldi_handle *lhp,
    uint64_t *dev_size, uint64_t *blocksize)
{
	IOMedia *media = 0;

	/* Validate IOMedia */
	media = OSDynamicCast(IOMedia,
	    (OSObject *)lhp->lh_un.media);
	if (!media) {
		dprintf("%s no IOMedia\n", __func__);
		return (ENODEV);
	}

	/* If pointer was provided, copy the value in */
	if (dev_size != 0) {
		*dev_size = media->getSize();
		if (*dev_size == 0) {
			dprintf("%s %s\n", __func__,
			    "IOMedia getSize returned 0");
			return (EINVAL);
		}
	}

	/* If pointer was not provided */
	if (blocksize == 0) {
		/* Successfully set dev_size */
		return (0);
	}

	/* Get blocksize from device */
	*blocksize = media->getPreferredBlockSize();
	if (*blocksize == 0) {
		dprintf("%s using default DEV_BSIZE\n", __func__);
		/* Set to default of 512-bytes */
		*blocksize = DEV_BSIZE;
	}
	ASSERT3U(*blocksize, ==, (1ULL<<(highbit64(*blocksize)-1)));

	return (0);
}

int
handle_sync_iokit(struct ldi_handle *lhp)
{
	IOMedia *media = 0;
	IOService *client = 0;
	IOReturn result = kIOReturnError;

	/* Validate IOMedia and client */
	if (NULL == (media = OSDynamicCast(IOMedia,
	    (OSObject *)lhp->lh_un.media))) {
		dprintf("%s invalid IOKit handle\n", __func__);
		return (ENODEV);
	}
	if (NULL == (client = OSDynamicCast(IOService,
	    (OSObject *)lhp->lh_client))) {
		dprintf("%s invalid IOService client\n", __func__);
		return (ENODEV);
	}

	/* Issue device sync */
	result = media->synchronizeCache(client);
	if (result != kIOReturnSuccess) {
		dprintf("%s %s %d %d\n", __func__,
		    "IOMedia synchronizeCache failed", result,
		    media->errnoFromReturn(result));
		return (ENOTSUP);
	}

	/* Success */
	return (0);
}

static dev_t
dev_from_media(IOMedia *media)
{
	dev_t device = 0;
	uint32_t major, minor;
	OSObject *property;
	OSNumber *number;

	/* Validate media */
	if (!media || !OSDynamicCast(IOMedia, media)) {
		dprintf("%s no device\n", __func__);
		return (0);
	}
	media->retain();

	/* Get device major */
	if (NULL == (property = media->getProperty(kIOBSDMajorKey,
	    gIOServicePlane, kIORegistryIterateRecursively)) ||
	    NULL == (number = OSDynamicCast(OSNumber, property))) {
		dprintf("%s couldn't get BSD major\n", __func__);
		media->release();
		return (0);
	}
	major = number->unsigned32BitValue();
	number = NULL;
	property = NULL;

	/* Get device minor */
	if (NULL == (property = media->getProperty(kIOBSDMinorKey,
	    gIOServicePlane, kIORegistryIterateRecursively)) ||
	    NULL == (number = OSDynamicCast(OSNumber, property))) {
		dprintf("%s couldn't get BSD major\n", __func__);
		media->release();
		return (0);
	}
	minor = number->unsigned32BitValue();
	number = NULL;
	property = NULL;

	/* Cleanup */
	media->release();
	media = NULL;

	device = makedev(major, minor);

	/* Return 0 or valid dev_t */
	return (device);
}

/* Returns NULL or dictionary with a retain count */
static OSDictionary *
media_matchdict_from_dev(dev_t device)
{
	OSDictionary *matchDict;
	OSNumber *majorNum, *minorNum;

	/* Validate dev_t */
	if (device == 0) {
		dprintf("%s no dev_t provided\n", __func__);
		return (NULL);
	}

	/* Allocate OSNumbers for BSD major and minor (32-bit) */
	if (NULL == (majorNum = OSNumber::withNumber(major(device), 32)) ||
	    NULL == (minorNum = OSNumber::withNumber(minor(device), 32))) {
		dprintf("%s couldn't alloc major/minor as OSNumber\n",
		    __func__);
		if (majorNum) {
			majorNum->release();
		}
		return (NULL);
	}

	/* Match on IOMedia */
	if (NULL == (matchDict = IOService::serviceMatching("IOMedia")) ||
	    !(matchDict->setObject(kIOBSDMajorKey, majorNum)) ||
	    !(matchDict->setObject(kIOBSDMinorKey, minorNum))) {
		dprintf("%s couldn't get matching dictionary\n", __func__);
		if (matchDict) {
			matchDict->release();
		}
		majorNum->release();
		minorNum->release();
		return (NULL);
	}
	majorNum->release();
	minorNum->release();

	/* Return NULL or valid OSDictionary with retain count */
	return (matchDict);
}

/* Returns NULL or dictionary with a retain count */
static OSDictionary *
media_matchdict_from_path(char *path)
{
	OSDictionary *matchDict;
	OSString *bsdName;

	/* Validate path */
	if (path == 0 || strlen(path) <= 1) {
		dprintf("%s no path provided\n", __func__);
		return (NULL);
	}
	if (strncmp(path, "/dev/", 5) != 0) {
		dprintf("%s path %s doesn't start with '/dev/'\n",
		    __func__, path);
		return (NULL);
	}

	/* Validate path and alloc bsdName */
	if (strncmp(path+5, "disk", 4) == 0) {
		bsdName = OSString::withCString(path + 5);
	} else if (strncmp(path+5, "rdisk", 5) == 0) {
		bsdName = OSString::withCString(path + 6);
	} else {
		bsdName = NULL;
	}
	if (!bsdName) {
		dprintf("%s Invalid path (or alloc failed) %s\n",
		    __func__, path);
		return (NULL);
	}

	/* Match on IOMedia by BSD disk name */
	matchDict = IOService::serviceMatching("IOMedia");
	if (!matchDict ||
	    matchDict->setObject(kIOBSDNameKey, bsdName) == false) {
		dprintf("%s couldn't get matching dictionary\n", __func__);
		bsdName->release();
		return (NULL);
	}
	bsdName->release();

	/* Return NULL or valid OSDictionary with retain count */
	return (matchDict);
}

/* Returns NULL or matched IOMedia with a retain count */
static IOMedia *
media_from_matchdict(OSDictionary *matchDict)
{
	IOMedia *media;
	OSIterator *iter;
	OSObject *obj;

	if (!matchDict) {
		dprintf("%s missing matching dictionary\n", __func__);
		return (NULL);
	}

	/*
	 * We could instead use copyMatchingService, since
	 * there should only be one match.
	 */
	iter = IOService::getMatchingServices(matchDict);
	if (!iter) {
		dprintf("%s No iterator from getMatchingServices\n",
		    __func__);
		return (NULL);
	}

	/* Get first object from iterator */
	obj = iter->getNextObject();
	if (!obj) {
		dprintf("%s no match found\n", __func__);
		iter->release();
		return (NULL);
	}
	obj->retain();
#ifdef DEBUG
	/* Report if there were additional matches */
	if (iter->getNextObject() != NULL) {
		dprintf("%s Had more than one match\n", __func__);
	}
#endif
	iter->release();
	iter = 0;

	/* Cast from IOService to IOMedia or release */
	media = OSDynamicCast(IOMedia, obj);
	if (!media) {
		dprintf("%s couldn't cast match as IOMedia\n", __func__);
		obj->release();
	}

	/* Return NULL or valid media with retain count */
	return (media);
}

/*
 * media_from_dev is intended to be called by ldi_open_by_name
 * and ldi_open_by_dev with a dev_t, and returns NULL or an IOMedia
 * device with a retain count that should be released on open.
 */
static IOMedia *
media_from_dev(dev_t device = 0)
{
	IOMedia *media;
	OSDictionary *matchDict;

	/* Get matchDict, will need to be released */
	matchDict = media_matchdict_from_dev(device);
	if (!matchDict) {
		dprintf("%s couldn't get matching dictionary\n", __func__);
		return (NULL);
	}

	/* Get first matching IOMedia */
	media = media_from_matchdict(matchDict);
	matchDict->release();
	matchDict = 0;
	if (!media) {
		dprintf("%s no IOMedia found for dev_t %d\n", __func__,
		    device);
	}

	/* Return NULL or valid media with retain count */
	return (media);
}

/*
 * media_from_path is intended to be called by ldi_open_by_name
 * with a char* path, and returns NULL or an IOMedia device with a
 * retain count that should be released on open.
 */
static IOMedia *
media_from_path(char *path = 0)
{
	IOMedia *media;
	OSDictionary *matchDict;

	/* Validate path */
	if (path == 0 || strlen(path) <= 1) {
		dprintf("%s no path provided\n", __func__);
		return (NULL);
	}

	matchDict = media_matchdict_from_path(path);
	if (!matchDict) {
		dprintf("%s couldn't get matching dictionary\n", __func__);
		return (NULL);
	}

	media = media_from_matchdict(matchDict);
	if (!media) {
		dprintf("%s no IOMedia found for path %s\n", __func__, path);
	}

	/* Return NULL or valid media with retain count */
	return (media);
}

/* Completion handler for IOKit strategy */
static void
ldi_iokit_io_intr(void *target, void *parameter, IOReturn status,
    UInt64 actualByteCount)
{
	ldi_buf_t *bp = (ldi_buf_t *)parameter;
	IOMemoryDescriptor *iomem = 0;

	/* In debug builds, verify buffer pointers */
	ASSERT3U(bp, !=, 0);
	ASSERT3U(bp->b_buf.iomem, !=, 0);
	ASSERT3U(bp->b_bcount, >=, actualByteCount);
#ifdef DEBUG
	if (actualByteCount == 0 ||
	    actualByteCount != bp->b_bcount ||
	    status != kIOReturnSuccess) {
		dprintf("%s %s %llx / %llx\n", __func__,
		    "actualByteCount != bp->b_bcount",
		    actualByteCount, bp->b_bcount);
		dprintf("%s status %d %d %s\n", __func__, status,
		    ldi_zfs_handle->errnoFromReturn(status),
		    ldi_zfs_handle->stringFromReturn(status));
	}
#endif

	/* Cast IOMemoryDescriptor buffer */
	iomem = OSDynamicCast(IOMemoryDescriptor,
	    (OSObject *)bp->b_buf.iomem);
	ASSERT3U(iomem, !=, 0);
	/* Complete, release, and clear */
	iomem->complete();
	iomem->release();
	iomem = 0;

	/* Compute resid */
	bp->b_resid = (bp->b_bcount - actualByteCount);
	ASSERT3U(bp->b_bcount, >=, actualByteCount);

	/* Set error status */
	if (status == kIOReturnSuccess &&
	    actualByteCount != 0 && bp->b_resid == 0) {
		bp->b_error = 0;
	} else {
		bp->b_error = EIO;
	}

	/* Clear IOKit structs */
	if (bp->b_iocompletion) {
		kmem_free(bp->b_iocompletion, sizeof (IOStorageCompletion));
		bp->b_iocompletion = 0;
	}
	if (bp->b_ioattr) {
		kmem_free(bp->b_ioattr, sizeof (IOStorageAttributes));
		bp->b_ioattr = 0;
	}

	/* Call original completion function */
	if (bp->b_iodone) {
		(void) bp->b_iodone(bp, bp->b_iodoneparam);
	}
}

int
buf_strategy_iokit(ldi_buf_t *bp, struct ldi_handle *lhp)
{
	/* IOKit */
	IOMedia *media = 0;
	IOMemoryDescriptor * buffer = 0;
	IODirection dir;
	IOReturn result;
	UInt64 actualByteCount = 0;
	boolean_t sync;

	ASSERT3U(bp, !=, NULL);
	ASSERT3U(lhp, !=, NULL);

	/* Validate IOMedia */
	media = OSDynamicCast(IOMedia,
	    (OSObject *)lhp->lh_un.media);
	if (!media) {
		dprintf("%s invalid IOKit handle [%p]\n",
		    __func__, media);
		return (ENODEV);
	}

	/* For synchronous IO */
	sync = (bp->b_iodone == NULL);

	/* Allocate a buffer pointing to the data address */
	dir = (bp->b_flags & B_READ ? kIODirectionIn : kIODirectionOut);

	buffer = IOMemoryDescriptor::withAddress(
	    bp->b_data, bp->b_bcount, dir);
	/* Verify the buffer is allocated */
	if (!buffer || buffer->getLength() != bp->b_bcount ||
	    (result = buffer->prepare(dir)) != kIOReturnSuccess) {
		dprintf("%s couldn't allocate IO buffer\n",
		    __func__);
		if (buffer) {
			buffer->release();
			buffer = 0;
		}
		result = kIOReturnError;
		return (ENOMEM);
	}

	/* Assign buffer to bp */
	bp->b_buf.iomem = (void *)buffer;

	/* Recheck instantaneous value of handle status */
	if (lhp->lh_status != LDI_STATUS_ONLINE) {
		dprintf("%s device not online\n", __func__);
		buffer->complete();
		buffer->release();
		buffer = 0;
		return (ENODEV);
	}

	/* Read or write */
	if (dir == kIODirectionIn) {
		if (sync) {
			result = media->IOStorage::read(ldi_zfs_handle,
			    bp->b_offset, buffer,
			    (IOStorageAttributes *)bp->b_ioattr,
			    &actualByteCount);
		} else {
			media->IOMedia::read(ldi_zfs_handle,
			    bp->b_offset, buffer,
			    (IOStorageAttributes *)bp->b_ioattr,
			    (IOStorageCompletion *)bp->b_iocompletion);
		}
		/* Clear pointer to avoid releasing in-use buffer */
		buffer = 0;
	} else {
		if (sync) {
			result = media->IOStorage::write(ldi_zfs_handle,
			    bp->b_offset, buffer,
			    (IOStorageAttributes *)bp->b_ioattr,
			    &actualByteCount);
		} else {
			media->IOMedia::write(ldi_zfs_handle,
			    bp->b_offset, buffer,
			    (IOStorageAttributes *)bp->b_ioattr,
			    (IOStorageCompletion *)bp->b_iocompletion);
		}
		/* Clear pointer to avoid releasing in-use buffer */
		buffer = 0;
	}

	/* For synchronous IO, call completion */
	if (sync) {
		ldi_iokit_io_intr(NULL, (void *)bp, result, actualByteCount);
	}

	/* On success, buffer pointer was assigned to bp and cleared */
	if (buffer) {
		buffer->release();
		buffer = 0;
	}

	return (0);
}

/* Client interface, alloc and open IOKit handle */
int
ldi_open_by_media(IOMedia *media = 0, dev_t device = 0,
    int fmode = 0, ldi_handle_t *lhp = 0)
{
	struct ldi_handle *retlhp;
	ldi_status_t status;
	int error;

	/* Validate IOMedia */
	if (!media || !lhp) {
		dprintf("%s invalid argument %p or %p\n",
		    __func__, media, lhp);
		return (EINVAL);
	}

	/* Get dev_t if not supplied */
	if (device == 0 && (device = dev_from_media(media)) == 0) {
		dprintf("%s dev_from_media failed: %p %d\n", __func__,
		    media, device);
		return (ENODEV);
	}

	/* In debug build, be loud if we potentially leak a handle */
	ASSERT3U(*(struct ldi_handle **)lhp, ==, NULL);

	/* Allocate IOKit handle */
	retlhp = handle_alloc_iokit(device, fmode);
	if (retlhp == NULL) {
		dprintf("%s couldn't allocate IOKit handle\n", __func__);
	}

	/* Try to open device with IOMedia */
	status = handle_open_start(retlhp);
	if (status == LDI_STATUS_ONLINE) {
		dprintf("%s already online, refs %d, openrefs %d\n", __func__,
		    retlhp->lh_ref, retlhp->lh_openref);
		/* Cast retlhp and assign to lhp (may be 0) */
		*lhp = (ldi_handle_t)retlhp;
		/* Successfully incremented open ref */
		return (0);
	}
	if (status != LDI_STATUS_OPENING ||
	    (error = handle_open_iokit(retlhp, media)) != 0) {
		dprintf("%s Couldn't open handle\n", __func__);
		/* Call handle_open_done with fmode=0 */
		handle_open_done(retlhp, LDI_STATUS_CLOSED);
		handle_release(retlhp);
		retlhp = 0;
		return (EIO);
	}
	handle_open_done(retlhp, LDI_STATUS_ONLINE);

	/* Register for disk notifications */
	handle_register_notifier(retlhp);

	/* Cast retlhp and assign to lhp (may be 0) */
	*lhp = (ldi_handle_t)retlhp;
	/* Pass error from open */
	return (error);
}

/* Client interface, find IOMedia from dev_t, alloc and open handle */
int
ldi_open_media_by_dev(dev_t device = 0, int fmode = 0,
    ldi_handle_t *lhp = 0)
{
	IOMedia *media = 0;
	int error = EINVAL;

	/* Validate arguments */
	if (!lhp || device == 0) {
		dprintf("%s missing argument %p %d\n",
		    __func__, lhp, device);
		return (EINVAL);
	}
	/* In debug build, be loud if we potentially leak a handle */
	ASSERT3U(*((struct ldi_handle **)lhp), ==, NULL);

dprintf("%s dev_t %d fmode %d\n", __func__, device, fmode);

	/* Get IOMedia from major/minor */
	if ((media = media_from_dev(device)) == NULL) {
		dprintf("%s media_from_dev error %d\n",
		    __func__, error);
		return (ENODEV);
	}

	/* Try to open by media */
	error = ldi_open_by_media(media, device, fmode, lhp);

	/* Release IOMedia and clear */
	media->release();
	media = 0;

	/* Pass error from open */
	return (error);
}

/* Client interface, find dev_t and IOMedia/vnode, alloc and open handle */
int
ldi_open_media_by_path(char *path = 0, int fmode = 0,
    ldi_handle_t *lhp = 0)
{
	IOMedia *media = 0;
	dev_t device = 0;
	int error = EINVAL;

	/* Validate arguments */
	if (!lhp || !path) {
		dprintf("%s %s %p %s %d\n", __func__,
		    "missing lhp or path", lhp, path, fmode);
		return (EINVAL);
	}
	/* In debug build, be loud if we potentially leak a handle */
	ASSERT3U(*((struct ldi_handle **)lhp), ==, NULL);

dprintf("%s dev_t %d fmode %d\n", __func__, device, fmode);

	/* For /dev/disk*, until InvariantDisk is supported */
	media = media_from_path(path);
	if ((media) == NULL) {
		dprintf("%s media_from_path failed\n", __func__);
		return (ENODEV);
	}

	error = ldi_open_by_media(media, device, fmode, lhp);

	/* Release IOMedia and clear */
	media->release();
	media = 0;

	/* Error check open */
	if (error) {
		dprintf("%s ldi_open_by_media failed %d\n",
		    __func__, error);
	}

	return (error);
}

int
handle_remove_notifier(struct ldi_handle *lhp)
{
	IONotifier *notifier;

	if (!lhp || (notifier = OSDynamicCast(IONotifier,
	    (OSObject *)lhp->lh_notifier)) == NULL) {
		dprintf("%s missing handle or notifier\n", __func__);
		return (EINVAL);
	}

dprintf("%s removing notifier %p from lhp %p\n", __func__, notifier, lhp);
	lhp->lh_notifier = 0;
	notifier->remove();
	return (0);
}

int
handle_register_notifier(struct ldi_handle *lhp)
{
	OSDictionary *matchDict;
	IONotifier *notifier;

	/* Make sure we have a handle and dev_t */
	if (!lhp || lhp->lh_dev == 0) {
		dprintf("%s no handle or missing dev_t\n", __func__);
		return (EINVAL);
	}

	/* Get matchDict, will need to be released */
	matchDict = media_matchdict_from_dev(lhp->lh_dev);
	if (!matchDict) {
		dprintf("%s couldn't get matching dictionary\n", __func__);
		return (EINVAL);
	}

	/* Register IOMedia termination notification */
	notifier = IOService::addMatchingNotification(gIOTerminatedNotification,
	    matchDict, handle_media_terminate_cb, /* target */ 0,
	    /* refCon */ (void *)lhp, /* priority */ 0);
	matchDict->release();

	/* Error check notifier */
	if (notifier == NULL) {
		dprintf("%s addMatchingNotification failed\n",
		    __func__);
		return (ENOMEM);
	}

dprintf("%s assigning notifier %p to lhp %p\n", __func__, notifier, lhp);
	/* Assign notifier to handle */
	lhp->lh_notifier = notifier;

	return (0);
}

/* Should be called with struct allocated */
int
ldi_bioinit_iokit(ldi_buf_t *bp)
{
	IOStorageCompletion *io_completion;
	size_t len;

	if (!bp) {
		dprintf("%s missing argument bp %p\n",
		    __func__, bp);
		return (EINVAL);
	}

	/* Allocate completion struct */
	len = sizeof (struct IOStorageCompletion);
	io_completion = (IOStorageCompletion *)kmem_alloc(len, KM_SLEEP);
	if (!io_completion) {
		dprintf("%s couldn't allocate IO completion\n",
		    __func__);
		kmem_free(bp, sizeof (struct ldi_buf));
		return (ENOMEM);
	}
#ifdef LDI_ZERO
	bzero(io_completion, len);
#endif

	/* Set completion parameter and callback */
	io_completion->target = 0;
	io_completion->parameter = bp;
	io_completion->action = &ldi_iokit_io_intr;

	/* Assign completion to bp */
	bp->b_iocompletion = io_completion;
	io_completion = 0;

	/* XXX We may need some IOStorageAttributes */
#if 0
	IOStorageAttributes *io_attr;

	/* Allocate attributes struct */
	len = sizeof (IOStorageAttributes);
	io_attr = (IOStorageAttributes *)kmem_alloc(len, KM_SLEEP);
	if (!io_attr) {
		dprintf("%s couldn't allocate IO completion\n",
		    __func__);
		/* Also free the IOStorageCompletion struct */
		kmem_free(io_completion,
		    sizeof (struct IOStorageCompletion));
		kmem_free(bp, sizeof (struct ldi_buf));
		return (ENOMEM);
	}
#ifdef LDI_ZERO
	bzero(io_attr, len);
#endif

	io_attr->options = 0;
	io_attr->priority = 0;
	io_attr->bufattr = 0;
	/* Set IO attributes */
	/*
	 * XXX for example
	 * io_attr->IOStorageOptions =
	 *     kIOStorageOptionForceUnitAccess |
	 * //    kIOStorageOptionIsEncrypted |
	 *     kIOStorageOptionIsStatic;
	 * io_attr->IOStoragePriority =
	 *     kIOStorageStoragePriorityHigh;
	 */

	/* Assign attr to bp */
	bp->b_ioattr = io_attr;
	io_attr = 0;
#endif
	bp->b_ioattr = 0;

	/* Return success */
	return (0);
}

} /* extern "C" */
