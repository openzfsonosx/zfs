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
 * Copyright (c) 2016, Evan Susarret.  All rights reserved.
 */

#ifndef	ZFS_BOOT_H_INCLUDED
#define	ZFS_BOOT_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif	/* __cplusplus */

/* Link data vdevs to virtual devices */
int zfs_boot_update_bootinfo(spa_t *spa);

#if 0
#ifdef ZFS_BOOT
/* At boot time, get path from ZFSBootDevice */
int zfs_boot_get_path(char *, int);
#endif /* ZFS_BOOT */
#endif

int zfs_attach_devicedisk(zfsvfs_t *zfsvfs);
int zfs_detach_devicedisk(zfsvfs_t *zfsvfs);
int zfs_devdisk_get_path(void *, char *, int);


#ifdef __cplusplus
} /* extern "C" */

#if 0
/* C++ struct, C uses opaque pointer reference */
typedef struct zfs_bootinfo {
	OSArray *info_array;
} zfs_bootinfo_t;
#endif

#ifdef ZFS_BOOT
/* Remainder is only needed for booting */

#include <IOKit/IOService.h>
bool zfs_boot_init(IOService *);
void zfs_boot_fini();

#if 0
#pragma mark - ZFSBootDevice
#include <IOKit/storage/IOBlockStorageDevice.h>

class ZFSBootDevice : public IOBlockStorageDevice {
	OSDeclareDefaultStructors(ZFSBootDevice);
public:

	bool setDatasetName(const char *);

	virtual bool init(OSDictionary *);
	virtual void free();

	virtual IOReturn doSynchronizeCache(void);
	virtual IOReturn doAsyncReadWrite(IOMemoryDescriptor *,
	    UInt64, UInt64, IOStorageAttributes *,
	    IOStorageCompletion *);
	virtual UInt32 doGetFormatCapacities(UInt64 *,
	    UInt32) const;
	virtual IOReturn doFormatMedia(UInt64 byteCapacity);
	virtual IOReturn doEjectMedia();
	virtual char * getVendorString();
	virtual char * getProductString();
	virtual char * getRevisionString();
	virtual char * getAdditionalDeviceInfoString();
	virtual IOReturn reportWriteProtection(bool *);
	virtual IOReturn reportRemovability(bool *);
	virtual IOReturn reportMediaState(bool *, bool *);
	virtual IOReturn reportBlockSize(UInt64 *);
	virtual IOReturn reportEjectability(bool *);
	virtual IOReturn reportMaxValidBlock(UInt64 *);

	virtual IOReturn setWriteCacheState(bool enabled);
	virtual IOReturn getWriteCacheState(bool *enabled);

private:
	/* These are declared class static to share across instances */
	static char vendorString[4];
	static char revisionString[4];
	static char infoString[12];
	/* These are per-instance */
	char *productString;
	bool isReadOnly;
};
#endif	/* 0 */
#endif	/* ZFS_BOOT */
#endif	/* __cplusplus */

#endif /* ZFS_BOOT_H_INCLUDED */
