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
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOStorageDeviceCharacteristics.h>

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
_NOTE(CONSTCOND) } while (0)
#endif

/* Attach created IOService objects to the IORegistry under ZFS. */
// #define	LDI_IOREGISTRY_ATTACH

/*
 * Globals
 */
static IOService		*ldi_zfs_handle;

/* Exposed to c callers */
extern "C" {

struct _handle_iokit {
	IOMedia			*media;
	IOService		*client;
};	/* 16b */

struct _handle_notifier {
	IONotifier		*obj;
};	/* 8b */

#define	LH_MEDIA(lhp)		lhp->lh_tsd.iokit_tsd->media
#define	LH_CLIENT(lhp)		lhp->lh_tsd.iokit_tsd->client
#define	LH_NOTIFIER(lhp)	lhp->lh_notifier->obj

void
handle_free_iokit(struct ldi_handle *lhp) {
	if (!lhp) {
		dprintf("%s missing lhp\n", __func__);
		return;
	}

	if (!lhp->lh_tsd.iokit_tsd) {
		dprintf("%s missing iokit_tsd\n", __func__);
		return;
	}

	/* Free IOService client */
	if (handle_free_ioservice(lhp) != 0) {
		dprintf("%s lhp %p client %s\n",
		    __func__, lhp, "couldn't be removed");
	}

	kmem_free(lhp->lh_tsd.iokit_tsd, sizeof (struct _handle_iokit));
	lhp->lh_tsd.iokit_tsd = 0;
}

/* Returns handle with lock still held */
struct ldi_handle *
handle_alloc_iokit(dev_t device, int fmode)
{
	struct ldi_handle *lhp, *retlhp;

	/* Search for existing handle */
	if ((retlhp = handle_find(device, fmode, B_TRUE)) != NULL) {
		dprintf("%s found handle before alloc\n", __func__);
		return (retlhp);
	}

	/* Allocate an LDI IOKit handle */
	if ((lhp = handle_alloc_common(LDI_TYPE_IOKIT, device,
	    fmode)) == NULL) {
		dprintf("%s couldn't allocate handle\n", __func__);
		return (NULL);
	}

	/* Allocate and clear type-specific device data */
	lhp->lh_tsd.iokit_tsd = (struct _handle_iokit *)kmem_alloc(
	    sizeof (struct _handle_iokit), KM_SLEEP);
	LH_MEDIA(lhp) = 0;
	LH_CLIENT(lhp) = 0;

	/* Allocate an IOService client for open/close */
	if (handle_alloc_ioservice(lhp) != 0) {
		dprintf("%s couldn't allocate IOService client\n", __func__);
		handle_release(lhp);
		return (NULL);
	}

	/* Add the handle to the list, or return match */
	if ((retlhp = handle_add(lhp)) == NULL) {
		dprintf("%s handle_add failed\n", __func__);
		handle_release(lhp);
		return (NULL);
	}

	/* Check if new or found handle was returned */
	if (retlhp != lhp) {
		dprintf("%s found handle after alloc\n", __func__);
		handle_release(lhp);
		lhp = 0;
	}

	return (retlhp);
}

int
handle_free_ioservice(struct ldi_handle *lhp)
{
	/* Validate handle pointer */
	ASSERT3U(lhp, !=, NULL);
#ifdef DEBUG
	if (!lhp) {
		dprintf("%s missing handle\n", __func__);
		return (EINVAL);
	}
	if (!LH_CLIENT(lhp)) {
		dprintf("%s missing client\n", __func__);
		return (ENODEV);
	}
#endif

#ifdef LDI_IOREGISTRY_ATTACH
	/* Detach client from ZFS in IORegistry */
	LH_CLIENT(lhp)->detach(ldi_zfs_handle);
#endif

	LH_CLIENT(lhp)->stop(ldi_zfs_handle);
	LH_CLIENT(lhp)->release();
	LH_CLIENT(lhp) = 0;

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

#ifdef LDI_IOREGISTRY_ATTACH
	/* Attach client to ZFS in IORegistry */
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

	LH_CLIENT(lhp) = client;
	return (0);
}

/* Set status to Offline and post event */
static bool
handle_media_terminate_cb(void* target, void* refCon,
    IOService* newService, IONotifier* notifier)
{
	struct ldi_handle *lhp = (struct ldi_handle *)refCon;

#ifdef DEBUG
	if (!lhp) {
		dprintf("%s missing refCon ldi_handle\n", __func__);
		return (false);
	}
#endif

	/* Take hold on handle to prevent removal */
	handle_hold(lhp);

	dprintf("%s setting lhp %p to Offline status\n", __func__, lhp);
	if (handle_status_change(lhp, LDI_STATUS_OFFLINE) != 0) {
		dprintf("%s handle_status_change failed\n", __func__);
		handle_release(lhp);
		return (false);
	}

	handle_release(lhp);
	return (true);
}

int
handle_close_iokit(struct ldi_handle *lhp)
{
#ifdef DEBUG
	ASSERT3U(lhp, !=, NULL);
	ASSERT3U(lhp->lh_type, ==, LDI_TYPE_IOKIT);
	ASSERT3U(lhp->lh_status, ==, LDI_STATUS_CLOSING);

	/* Validate IOMedia and IOService client */
	if (!OSDynamicCast(IOMedia, LH_MEDIA(lhp)) ||
	    !OSDynamicCast(IOService, LH_CLIENT(lhp))) {
		dprintf("%s invalid IOMedia or client\n", __func__);
		return (ENODEV);
	}
#endif /* DEBUG */

	LH_MEDIA(lhp)->close(LH_CLIENT(lhp));
	LH_MEDIA(lhp) = 0;
	return (0);
}

static int
handle_open_iokit(struct ldi_handle *lhp, IOMedia *media)
{
#ifdef DEBUG
	ASSERT3U(lhp, !=, NULL);
	ASSERT3U(media, !=, NULL);
	ASSERT3U(lhp->lh_type, ==, LDI_TYPE_IOKIT);
	ASSERT3U(lhp->lh_status, ==, LDI_STATUS_OPENING);

	/* Validate IOMedia and IOService client */
	if (!OSDynamicCast(IOMedia, media) ||
	    !OSDynamicCast(IOService, LH_CLIENT(lhp))) {
		dprintf("%s invalid IOMedia or client\n", __func__);
		return (ENODEV);
	}
#endif /* DEBUG */
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

	/* Call open with the IOService client handle */
	if (media->IOMedia::open(LH_CLIENT(lhp), 0,
	    (lhp->lh_fmode & FWRITE ?  kIOStorageAccessReaderWriter :
	    kIOStorageAccessReader)) == false) {
		dprintf("%s IOMedia->open failed\n", __func__);
		media->release();
		return (EIO);
	}
	media->release();

	/* Assign IOMedia device */
	LH_MEDIA(lhp) = media;
	return (0);
}

int
handle_get_size_iokit(struct ldi_handle *lhp, uint64_t *dev_size)
{
	if (!lhp || !dev_size) {
		dprintf("%s missing lhp or dev_size\n", __func__);
		return (EINVAL);
	}

#ifdef DEBUG
	/* Validate IOMedia */
	if (!OSDynamicCast(IOMedia, LH_MEDIA(lhp))) {
		dprintf("%s no IOMedia\n", __func__);
		return (ENODEV);
	}
#endif

	*dev_size = LH_MEDIA(lhp)->getSize();
	if (*dev_size == 0) {
		dprintf("%s %s\n", __func__,
		    "IOMedia getSize returned 0");
		return (EINVAL);
	}

	return (0);
}

int
handle_sync_iokit(struct ldi_handle *lhp)
{
#ifdef DEBUG
	/* Validate IOMedia and client */
	if (!OSDynamicCast(IOMedia, LH_MEDIA(lhp)) ||
	    !OSDynamicCast(IOService, LH_CLIENT(lhp))) {
		dprintf("%s invalid IOMedia or client\n", __func__);
		return (ENODEV);
	}
#endif

	/* Issue device sync */
	if (LH_MEDIA(lhp)->synchronizeCache(LH_CLIENT(lhp)) !=
	    kIOReturnSuccess) {
		dprintf("%s %s\n", __func__,
		    "IOMedia synchronizeCache failed");
		return (ENOTSUP);
	}

	/* Success */
	return (0);
}

static dev_t
dev_from_media(IOMedia *media)
{
	OSObject *property;
	OSNumber *number;
	uint32_t major, minor;
	dev_t device = 0;

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
	if (!OSDynamicCast(IOMedia, obj)) {
		dprintf("%s couldn't cast match as IOMedia\n", __func__);
		obj->release();
		return (NULL);
	}

	/* Return valid IOMedia with retain count */
	return (OSDynamicCast(IOMedia, obj));
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
	matchDict->release();
	matchDict = 0;

	if (!media) {
		dprintf("%s no IOMedia found for path %s\n", __func__, path);
	}

	/* Return NULL or valid media with retain count */
	return (media);
}

/* Define an IOKit buffer for buf_strategy_iokit */
typedef struct ldi_iokit_buf {
	IOMemoryDescriptor	*iomem;
	IOStorageCompletion	iocompletion;
	IOStorageAttributes	ioattr;
} ldi_iokit_buf_t;		/* XXX Currently 64b */

/* Completion handler for IOKit strategy */
static void
ldi_iokit_io_intr(void *target, void *parameter,
    IOReturn status, UInt64 actualByteCount)
{
	ldi_iokit_buf_t *iobp = (ldi_iokit_buf_t *)target;
	ldi_buf_t *lbp = (ldi_buf_t *)parameter;

#ifdef DEBUG
	/* In debug builds, verify buffer pointers */
	ASSERT3U(lbp, !=, 0);
	ASSERT3U(iobp, !=, 0);
	ASSERT3U(iobp->iomem, !=, 0);
	if (actualByteCount == 0 ||
	    actualByteCount != lbp->b_bcount ||
	    status != kIOReturnSuccess) {
		dprintf("%s %s %llx / %llx\n", __func__,
		    "actualByteCount != lbp->b_bcount",
		    actualByteCount, lbp->b_bcount);
		dprintf("%s status %d %d %s\n", __func__, status,
		    ldi_zfs_handle->errnoFromReturn(status),
		    ldi_zfs_handle->stringFromReturn(status));
	}
	if (!iobp || !lbp) {
		dprintf("%s missing a buffer\n", __func__);
		return;
	}
#endif

	/* Complete and release IOMemoryDescriptor */
	iobp->iomem->complete();
	iobp->iomem->release();
	iobp->iomem = 0;

	/* Compute resid */
	ASSERT3U(lbp->b_bcount, >=, actualByteCount);
	lbp->b_resid = (lbp->b_bcount - actualByteCount);

	/* Set error status */
	if (status == kIOReturnSuccess &&
	    actualByteCount != 0 && lbp->b_resid == 0) {
		lbp->b_error = 0;
	} else {
		lbp->b_error = EIO;
	}

	/* Free IOKit buffer */
	kmem_free(iobp, sizeof (ldi_iokit_buf_t));

	/* Call original completion function */
	if (lbp->b_iodone) {
		(void) lbp->b_iodone(lbp);
	}
}

/* Synchronous IO, called by buf_strategy_iokit */
static int
buf_sync_strategy_iokit(ldi_buf_t *lbp, ldi_iokit_buf_t *iobp,
    struct ldi_handle *lhp)
{
	UInt64 actualByteCount = 0;
	IOReturn result;

	/* Read or write */
	if (lbp->b_flags & B_READ) {
		result = LH_MEDIA(lhp)->IOStorage::read(LH_CLIENT(lhp),
		    dbtolb(lbp->b_lblkno), iobp->iomem,
		    &iobp->ioattr, &actualByteCount);
	} else {
		result = LH_MEDIA(lhp)->IOStorage::write(LH_CLIENT(lhp),
		    dbtolb(lbp->b_lblkno), iobp->iomem,
		    &iobp->ioattr, &actualByteCount);
	}

	/* Call completion */
	ldi_iokit_io_intr((void *)iobp, (void *)lbp,
	    result, actualByteCount);

	/* Return success based on result */
	return (result == kIOReturnSuccess ? 0 : EIO);
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
buf_strategy_iokit(ldi_buf_t *lbp, struct ldi_handle *lhp)
{
	ldi_iokit_buf_t *iobp = 0;

	ASSERT3U(lbp, !=, NULL);
	ASSERT3U(lhp, !=, NULL);

#ifdef DEBUG
	/* Validate IOMedia */
	if (!OSDynamicCast(IOMedia, LH_MEDIA(lhp)) ||
	    !OSDynamicCast(IOService, LH_CLIENT(lhp))) {
		dprintf("%s invalid IOMedia or client\n", __func__);
		return (ENODEV);
	}
#endif /* DEBUG */

	/* Allocate an IOKit buffer */
	iobp = (ldi_iokit_buf_t *)kmem_alloc(sizeof (ldi_iokit_buf_t),
	    KM_SLEEP);
	if (!iobp) {
		dprintf("%s couldn't allocate buf_iokit_t\n", __func__);
		return (ENOMEM);
	}
#ifdef LDI_ZERO
	/* Zero the new buffer struct */
	bzero(iobp, sizeof (ldi_iokit_buf_t));
#endif

	/* Set completion and attributes for async IO */
	if (lbp->b_iodone != NULL) {
		iobp->iocompletion.target = iobp;
		iobp->iocompletion.parameter = lbp;
		iobp->iocompletion.action = &ldi_iokit_io_intr;
	}

/* XXX Zeroed above if LDI_ZERO, otherwise here */
#ifndef LDI_ZERO
	/* XXX Zero the ioattr struct */
	bzero(&iobp->ioattr, sizeof (IOStorageAttributes));
#endif

	/* Allocate a memory descriptor pointing to the data address */
	iobp->iomem = IOMemoryDescriptor::withAddress(
	    lbp->b_un.b_addr, lbp->b_bcount,
	    (lbp->b_flags & B_READ ? kIODirectionIn : kIODirectionOut));

	/* Verify the buffer */
	if (!iobp->iomem || iobp->iomem->getLength() != lbp->b_bcount ||
	    iobp->iomem->prepare() != kIOReturnSuccess) {
		dprintf("%s couldn't allocate IO buffer\n",
		    __func__);
		if (iobp->iomem) {
			iobp->iomem->release();
		}
		kmem_free(iobp, sizeof (ldi_iokit_buf_t));
		return (ENOMEM);
	}

	/* Recheck instantaneous value of handle status */
	if (lhp->lh_status != LDI_STATUS_ONLINE) {
		dprintf("%s device not online\n", __func__);
		iobp->iomem->complete();
		iobp->iomem->release();
		kmem_free(iobp, sizeof (ldi_iokit_buf_t));
		return (ENODEV);
	}

	/* Synchronous or async */
	if (lbp->b_iodone == NULL) {
		return (buf_sync_strategy_iokit(lbp, iobp, lhp));
	}

	/* Read or write */
	if (lbp->b_flags & B_READ) {
		LH_MEDIA(lhp)->IOMedia::read(LH_CLIENT(lhp),
		    dbtolb(lbp->b_lblkno), iobp->iomem,
		    &iobp->ioattr, &iobp->iocompletion);
	} else {
		LH_MEDIA(lhp)->IOMedia::write(LH_CLIENT(lhp),
		    dbtolb(lbp->b_lblkno), iobp->iomem,
		    &iobp->ioattr, &iobp->iocompletion);
	}

	/* Return success, will call io_intr when done */
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

	/* Retain for duration of open */
	media->retain();

	/* Get dev_t if not supplied */
	if (device == 0 && (device = dev_from_media(media)) == 0) {
		dprintf("%s dev_from_media failed: %p %d\n", __func__,
		    media, device);
		media->release();
		return (ENODEV);
	}

	/* In debug build, be loud if we potentially leak a handle */
	ASSERT3U(*(struct ldi_handle **)lhp, ==, NULL);

	/* Allocate IOKit handle */
	retlhp = handle_alloc_iokit(device, fmode);
	if (retlhp == NULL) {
		dprintf("%s couldn't allocate IOKit handle\n", __func__);
		media->release();
		return (ENOMEM);
	}

	/* Try to open device with IOMedia */
	status = handle_open_start(retlhp);
	if (status == LDI_STATUS_ONLINE) {
		dprintf("%s already online, refs %d, openrefs %d\n", __func__,
		    retlhp->lh_ref, retlhp->lh_openref);
		/* Cast retlhp and assign to lhp (may be 0) */
		*lhp = (ldi_handle_t)retlhp;
		media->release();
		/* Successfully incremented open ref */
		return (0);
	}
	if (status != LDI_STATUS_OPENING) {
		dprintf("%s invalid status %d\n", __func__, status);
		handle_release(retlhp);
		retlhp = 0;
		media->release();
		return (ENODEV);
	}

	error = handle_open_iokit(retlhp, media);
	media->release();

	if (error) {
		dprintf("%s Couldn't open handle\n", __func__);
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
	handle_notifier_t notifier;

#ifdef DEBUG
	if (!lhp) {
		dprintf("%s missing handle\n", __func__);
		return (EINVAL);
	}
#endif

	if (lhp->lh_notifier == 0) {
		dprintf("%s no notifier installed\n", __func__);
		return (0);
	}

	/* First clear notifier pointer */
	notifier = lhp->lh_notifier;
	lhp->lh_notifier = 0;

#ifdef DEBUG
	/* Validate IONotifier object */
	if (!OSDynamicCast(IONotifier, notifier->obj)) {
		dprintf("%s %p is not an IONotifier\n", __func__,
		    notifier->obj);
		return (EINVAL);
	}
#endif

	notifier->obj->remove();
	kmem_free(notifier, sizeof (handle_notifier_t));
	return (0);
}

int
handle_register_notifier(struct ldi_handle *lhp)
{
	OSDictionary *matchDict;
	handle_notifier_t notifier;

	/* Make sure we have a handle and dev_t */
	if (!lhp || lhp->lh_dev == 0) {
		dprintf("%s no handle or missing dev_t\n", __func__);
		return (EINVAL);
	}

	notifier = (handle_notifier_t)kmem_alloc(sizeof (
	    struct _handle_notifier), KM_SLEEP);
	if (!notifier) {
		dprintf("%s couldn't alloc notifier struct\n", __func__);
		return (ENOMEM);
	}

	/* Get matchDict, will need to be released */
	matchDict = media_matchdict_from_dev(lhp->lh_dev);
	if (!matchDict) {
		dprintf("%s couldn't get matching dictionary\n", __func__);
		kmem_free(notifier, sizeof (handle_notifier_t));
		return (EINVAL);
	}

	/* Register IOMedia termination notification */
	notifier->obj = IOService::addMatchingNotification(
	    gIOTerminatedNotification, matchDict,
	    handle_media_terminate_cb, /* target */ 0,
	    /* refCon */ (void *)lhp, /* priority */ 0);
	matchDict->release();

	/* Error check notifier */
	if (!notifier->obj) {
		dprintf("%s addMatchingNotification failed\n",
		    __func__);
		kmem_free(notifier, sizeof (handle_notifier_t));
		return (ENOMEM);
	}

	/* Assign notifier to handle */
	lhp->lh_notifier = notifier;
	return (0);
}

/* Supports both IOKit and vnode handles by finding IOMedia from dev_t */
int
handle_set_wce_iokit(struct ldi_handle *lhp, int *wce)
{
	IOMedia *media;
	IORegistryEntry *parent;
	IOBlockStorageDevice *device;
	IOReturn result;
	bool value;

	if (!lhp || !wce) {
		return (EINVAL);
	}

	switch (lhp->lh_type) {
	case LDI_TYPE_IOKIT:
		if ((media = LH_MEDIA(lhp)) == NULL) {
			dprintf("%s couldn't get IOMedia\n", __func__);
			return (ENODEV);
		}
		/* Add a retain count */
		media->retain();
		break;
	case LDI_TYPE_VNODE:
		if (lhp->lh_dev == 0 ||
		    (media = media_from_dev(lhp->lh_dev)) == 0) {
			dprintf("%s couldn't find IOMedia for dev_t %d\n",
			    __func__, lhp->lh_dev);
			return (ENODEV);
		}
		/* Returned media has a retain count */
		break;
	default:
		dprintf("%s invalid handle\n", __func__);
		return (EINVAL);
	}

	/* Walk the parents of this media */
	for (parent = media->getParentEntry(gIOServicePlane);
	    parent != NULL;
	    parent = parent->getParentEntry(gIOServicePlane)) {
		/* Until a valid device is found */
		device = OSDynamicCast(IOBlockStorageDevice, parent);
		if (device != NULL) {
			device->retain();
			break;
		}
		/* Next parent */
	}
	media->release();
	media = 0;

	/* If no matching device was found */
	if (!device) {
		dprintf("%s no IOBlockStorageDevice found\n", __func__);
		return (ENODEV);
	}

	result = device->getWriteCacheState(&value);
	if (result != kIOReturnSuccess) {
		dprintf("%s couldn't get current write cache state %d\n",
		    __func__, ldi_zfs_handle->errnoFromReturn(result));
		return (ENXIO);
	}

	/* If requested value does not match current */
	if (value != *wce) {
		value = (*wce == 1);
		/* Attempt to change the value */
		result = device->setWriteCacheState(value);
	}

	/* Set error and wce to return */
	if (result != kIOReturnSuccess) {
		dprintf("%s couldn't set write cache %d\n",
		    __func__, ldi_zfs_handle->errnoFromReturn(result));
		/* Flip wce to indicate current status */
		*wce = !(*wce);
		return (ENXIO);
	}

	return (0);
}

int
handle_get_media_info_iokit(struct ldi_handle *lhp,
    struct dk_minfo *dkm)
{
	uint32_t blksize;
	uint64_t blkcount;

	if (!lhp || !dkm) {
		return (EINVAL);
	}

	/* Validate IOMedia */
	if (!OSDynamicCast(IOMedia, LH_MEDIA(lhp))) {
		dprintf("%s invalid IOKit handle\n", __func__);
		return (ENODEV);
	}

	LH_MEDIA(lhp)->retain();

	if ((blksize = LH_MEDIA(lhp)->getPreferredBlockSize()) == 0) {
		dprintf("%s invalid blocksize\n", __func__);
		LH_MEDIA(lhp)->release();
		return (ENXIO);
	}

	if ((blkcount = LH_MEDIA(lhp)->getSize() / blksize) == 0) {
		dprintf("%s invalid block count\n", __func__);
		LH_MEDIA(lhp)->release();
		return (ENXIO);
	}

	LH_MEDIA(lhp)->release();

	/* Set the return values */
	dkm->dki_capacity = blkcount;
	dkm->dki_lbsize = blksize;

	return (0);
}

int
handle_get_media_info_ext_iokit(struct ldi_handle *lhp,
    struct dk_minfo_ext *dkmext)
{
	OSObject *prop;
	OSNumber *number;
	uint32_t blksize, pblksize;
	uint64_t blkcount;

	if (!lhp || !dkmext) {
		dprintf("%s missing lhp or dkmext\n", __func__);
		return (EINVAL);
	}

	/* Validate IOMedia */
	if (!OSDynamicCast(IOMedia, LH_MEDIA(lhp))) {
		dprintf("%s invalid IOKit handle\n", __func__);
		return (ENODEV);
	}

	LH_MEDIA(lhp)->retain();

	prop = LH_MEDIA(lhp)->getProperty(kIOPropertyPhysicalBlockSizeKey,
	    gIOServicePlane, kIORegistryIterateRecursively |
	    kIORegistryIterateParents);

	number = OSDynamicCast(OSNumber, prop);
	if (!prop || !number) {
		dprintf("%s couldn't get physical blocksize\n", __func__);
		LH_MEDIA(lhp)->release();
		return (ENXIO);
	}

	pblksize = number->unsigned32BitValue();
	number = 0;
	prop = 0;

	if ((blksize = LH_MEDIA(lhp)->getPreferredBlockSize()) == 0) {
		dprintf("%s invalid blocksize\n", __func__);
		LH_MEDIA(lhp)->release();
		return (ENXIO);
	}

	if ((blkcount = LH_MEDIA(lhp)->getSize() / blksize) == 0) {
		dprintf("%s invalid block count\n", __func__);
		LH_MEDIA(lhp)->release();
		return (ENXIO);
	}

	LH_MEDIA(lhp)->release();

#ifdef DEBUG
	dprintf("%s phys blksize %u, logical blksize %u, blockcount %llu\n",
	    __func__, pblksize, blksize, blkcount);
#endif

	/* Set the return values */
	dkmext->dki_capacity = blkcount;
	dkmext->dki_lbsize = blksize;
	dkmext->dki_pbsize = pblksize;

	return (0);
}

int
handle_check_media_iokit(struct ldi_handle *lhp, int *status)
{
	/* Validate arguments */
	if (!lhp || !status) {
		return (EINVAL);
	}

	/* Validate IOMedia */
	if (!OSDynamicCast(IOMedia, LH_MEDIA(lhp))) {
		dprintf("%s invalid IOKit handle\n", __func__);
		return (ENODEV);
	}

	LH_MEDIA(lhp)->retain();

	/* Validate device size */
	if (LH_MEDIA(lhp)->getSize() == 0) {
		dprintf("%s media reported 0 size\n", __func__);
		LH_MEDIA(lhp)->release();
		return (ENXIO);
	}

	/* Validate write status if handle fmode is read-write */
	if ((lhp->lh_fmode & FWRITE) &&
	    LH_MEDIA(lhp)->isWritable() == false) {
		dprintf("%s media is not writeable\n", __func__);
		LH_MEDIA(lhp)->release();
		return (EPERM);
	}

	LH_MEDIA(lhp)->release();

	/* Success */
	status = 0;
	return (0);
}

} /* extern "C" */
