
#ifndef	ZFS_BOOT_H_INCLUDED
#define	ZFS_BOOT_H_INCLUDED

#ifdef ZFS_BOOT

#ifdef __cplusplus
#include <IOKit/IOService.h>
#include <IOKit/storage/IOBlockStorageDevice.h>

extern "C" {

#endif	/* __cplusplus */

#define ZFS_MOUNTROOT_RETRIES	50
#define ZFS_BOOTLOG_DELAY	100

int zfs_boot_get_path(char *, int);
int zfs_boot_update_bootinfo(spa_t *spa);

#ifdef __cplusplus
} /* extern "C" */

typedef struct zfs_bootinfo {
	OSArray *info_array;
} zfs_bootinfo_t;

bool zfs_boot_init(IOService *);
void zfs_boot_fini();

#pragma mark - ZFSBootDevice

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

private:
	/* These are declared class static to share across instances */
	static char vendorString[4];
	static char revisionString[4];
	static char infoString[12];
	/* These are per-instance */
	char *productString;
	bool isReadOnly;
};
#endif	/* __cplusplus */

#endif /* ZFS_BOOT */
#endif /* ZFS_BOOT_H_INCLUDED */
