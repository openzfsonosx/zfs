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
 * Copyright (c) 2013, 2016 Jorgen Lundman <lundman@lundman.net>
 */

#ifndef	ZVOLIO_H_INCLUDED
#define	ZVOLIO_H_INCLUDED

#include <IOKit/IOService.h>
#include <sys/zvol.h>

class net_lundman_zfs_zvol : public IOService
{
	OSDeclareDefaultStructors(net_lundman_zfs_zvol)

private:

public:
	OSDictionary *IOBSDNameMatching( const char * name );

	virtual bool init(OSDictionary* dictionary = NULL);
	virtual void free(void);
	virtual IOService* probe(IOService* provider, SInt32* score);
	virtual bool start(IOService* provider);
	virtual void stop(IOService* provider);
	virtual IOReturn doEjectMedia(void *nub);
	virtual bool createBlockStorageDevice(zvol_state_t *zv);
	virtual bool destroyBlockStorageDevice(zvol_state_t *zv);
	virtual bool updateVolSize(zvol_state_t *zv);

	virtual bool createPseudoDevices(char *poolname, uint64_t bytes,
									 uint64_t block, boolean_t rdonly,
									 uint64_t pool_guid,
									 uint64_t dataset_guid);
	virtual bool  destroyPseudoDevices(char *poolname);
	virtual char *findDataset(char *dev);
	virtual int mountSnapshot(char *snapname);
};

#include <IOKit/storage/IOBlockStorageDevice.h>

class net_lundman_zfs_zvol_device : public IOBlockStorageDevice
{
	OSDeclareDefaultStructors(net_lundman_zfs_zvol_device)

private:
	net_lundman_zfs_zvol *m_provider;
	zvol_state_t *zv;
	int ejected = 0;

public:
	virtual bool init(zvol_state_t *c_zv,
	    OSDictionary* properties = 0);

	virtual bool attach(IOService* provider);
	virtual void detach(IOService* provider);
	virtual IOReturn doEjectMedia(void);
	virtual IOReturn doFormatMedia(UInt64 byteCapacity);
	virtual UInt32 doGetFormatCapacities(UInt64 * capacities,
	    UInt32 capacitiesMaxCount) const;

	virtual IOReturn doLockUnlockMedia(bool doLock);
	virtual IOReturn doSynchronizeCache(void);
	virtual char *getVendorString(void);
	virtual char *getProductString(void);
	virtual char *getRevisionString(void);
	virtual char *getAdditionalDeviceInfoString(void);
	virtual IOReturn reportBlockSize(UInt64 *blockSize);
	virtual IOReturn reportEjectability(bool *isEjectable);
	virtual IOReturn reportLockability(bool *isLockable);
	virtual IOReturn reportMaxValidBlock(UInt64 *maxBlock);
	virtual IOReturn reportMediaState(bool *mediaPresent,
	    bool *changedState);

	virtual IOReturn reportPollRequirements(bool *pollRequired,
	    bool *pollIsExpensive);

	virtual IOReturn reportRemovability(bool *isRemovable);
	virtual IOReturn reportWriteProtection(bool *isWriteProtected);
	virtual IOReturn getWriteCacheState(bool *enabled);
	virtual IOReturn setWriteCacheState(bool enabled);
	virtual IOReturn doAsyncReadWrite(IOMemoryDescriptor *buffer,
	    UInt64 block, UInt64 nblks,
	    IOStorageAttributes *attributes,
	    IOStorageCompletion *completion);

	virtual IOReturn doDiscard(UInt64 block, UInt64 nblks);
	virtual IOReturn doUnmap(IOBlockStorageDeviceExtent *extents,
	    UInt32 extentsCount, UInt32 options);

	virtual bool handleOpen(IOService *client,
	    IOOptionBits options, void *access);

	virtual void handleClose(IOService *client,
	    IOOptionBits options);

	virtual int getBSDName();

	virtual IOReturn newUserClient(task_t owningTask,
								   void* securityID, UInt32 type,
								   OSDictionary* properties,
								   IOUserClient** handler);

};

#endif
