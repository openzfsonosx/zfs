#ifndef	ZVOLIO_H_INCLUDED
#define	ZVOLIO_H_INCLUDED

#include <IOKit/IOService.h>
#include <sys/zvol.h>

class net_lundman_zfs_zvol : public IOService
{
	OSDeclareDefaultStructors(net_lundman_zfs_zvol)

private:
	bool zvol_unmap_enabled;
	bool mountedRootPool;
	IOTimerEventSource* mountTimer;
	OSSet* disksInUse;

public:
	virtual bool init(OSDictionary* dictionary = NULL);
	virtual void free(void);
	virtual IOService* probe(IOService* provider, SInt32* score);
	virtual bool start(IOService* provider);
	virtual void stop(IOService* provider);
	virtual IOReturn doEjectMedia(void *nub);
	virtual bool createBlockStorageDevice(zvol_state_t *zv);
	virtual bool destroyBlockStorageDevice(zvol_state_t *zv);
	virtual bool updateVolSize(zvol_state_t *zv);

	virtual bool registerDisk(IOService* newDisk);
	virtual bool unregisterDisk(IOService* oldDisk);
	virtual bool isDiskUsed(IOService* checkDisk);

	virtual bool zfs_check_mountroot();
	virtual bool zfs_mountroot();
	virtual bool isRootMounted();
	virtual void clearMountTimer();
	static void mountTimerFired(OSObject*, IOTimerEventSource*);
};

#include <IOKit/storage/IOBlockStorageDevice.h>

class net_lundman_zfs_zvol_device : public IOBlockStorageDevice
{
	OSDeclareDefaultStructors(net_lundman_zfs_zvol_device)

private:
	net_lundman_zfs_zvol *m_provider;
	zvol_state_t *zv;
	bool zvol_unmap_enabled;

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

	virtual void setUnmapEnabled(bool enabled);
	virtual IOReturn doDiscard(UInt64 block, UInt64 nblks);
	virtual IOReturn doUnmap(IOBlockStorageDeviceExtent *extents,
	    UInt32 extentsCount, UInt32 options);

	virtual bool handleOpen(IOService *client,
	    IOOptionBits options, void *access);

	virtual void handleClose(IOService *client,
	    IOOptionBits options);

	virtual int getBSDName();
};

#endif
