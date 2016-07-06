
#ifdef ZFS_BOOT
#ifndef	ZFS_BOOT_H_INCLUDED
#define	ZFS_BOOT_H_INCLUDED

#if 0
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOTimerEventSource.h>
#endif

#ifdef __cplusplus
#include <IOKit/IOService.h>
#include <IOKit/storage/IOBlockStorageDevice.h>

extern "C" {

#endif

//static uint16_t mount_attempts = 0;
#define ZFS_MOUNTROOT_RETRIES	50
#define ZFS_BOOTLOG_DELAY	100

//#ifdef ZFS_DEBUG
#define	zfs_boot_log(fmt, ...) {	\
	printf(fmt, __VA_ARGS__);	\
	IOSleep(ZFS_BOOTLOG_DELAY);	\
	}
//#else
//#define	zfs_boot_log(fmt, ...)
//#endif

#if 0
bool mountedRootPool;
IOTimerEventSource* mountTimer;
OSSet* disksInUse;

bool zfs_check_mountroot(char *, uint64_t *);
bool start_mount_timer(void);
bool registerDisk(IOService* newDisk);
bool unregisterDisk(IOService* oldDisk);
bool isDiskUsed(IOService* checkDisk);
bool zfs_mountroot(void);
bool isRootMounted(void);
void mountTimerFired(OSObject* owner, IOTimerEventSource* sender);
void clearMountTimer(void);
#endif

bool zfs_boot_init(IOService *);
void zfs_boot_fini();
//void zfs_boot_free(pool_list_t *pools);

int zfs_boot_get_path(char *, int);

} /* extern "C" */

#if 0
class ZFSBootDeviceNub : public IOService {
	OSDeclareDefaultStructors(ZFSBootDeviceNub);
public:
	virtual bool init(OSDictionary *dict = 0);
	virtual void free();
	virtual bool attach(IOService *);
	virtual void detach(IOService *);
	virtual bool start(IOService *);
	virtual void stop(IOService *);
	virtual IOService* probe(IOService *, SInt32 *);

private:
	char *boot_dataset;
	char *boot_uuid;
};
#endif

class ZFSBootDevice : public IOBlockStorageDevice {
	OSDeclareDefaultStructors(ZFSBootDevice);
public:

	bool setDatasetName(const char *);

	virtual bool init(OSDictionary *);
	virtual void free();
#if 0
	virtual bool attach(IOService *);
	virtual void detach(IOService *);
	virtual bool start(IOService *);
	virtual void stop(IOService *);
	virtual IOService* probe(IOService *, SInt32 *);
#endif

	virtual IOReturn doSynchronizeCache(void);
	virtual IOReturn doAsyncReadWrite(IOMemoryDescriptor *,
	    UInt64, UInt64, IOStorageAttributes *,
	    IOStorageCompletion *);
	virtual UInt32 doGetFormatCapacities(UInt64 *,
	    UInt32) const;
	virtual IOReturn doFormatMedia(UInt64 byteCapacity);
	virtual IOReturn doEjectMedia();
	virtual char* getVendorString();
	virtual char* getProductString();
	virtual char* getRevisionString();
	virtual char* getAdditionalDeviceInfoString();
	virtual IOReturn reportWriteProtection(bool *);
	virtual IOReturn reportRemovability(bool *);
	virtual IOReturn reportMediaState(bool *, bool *);
	virtual IOReturn reportBlockSize(UInt64 *);
	virtual IOReturn reportEjectability(bool *);
	virtual IOReturn reportMaxValidBlock(UInt64 *);
#if 0
	virtual IOReturn unmap(IOService *,
	    IOStorageExtent *, UInt32,
	    IOStorageUnmapOptions);
	virtual IOReturn synchronize(IOService *,
	    UInt64, UInt64,
	    IOStorageSynchronizeOptions);
	virtual void write(IOService *,
	    UInt64 byteStart, IOMemoryDescriptor *,
	    IOStorageAttributes *, IOStorageCompletion *);
	virtual void read(IOService *,
	    UInt64, IOMemoryDescriptor *,
	    IOStorageAttributes *, IOStorageCompletion *);
#endif

private:
	char *vendorString;
	char *productString;
	char *revisionString;
	char *additionalString;
};

#endif /* ZFS_BOOT_H_INCLUDED */
#endif /* ZFS_BOOT */
