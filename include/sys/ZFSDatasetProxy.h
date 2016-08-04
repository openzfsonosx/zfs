/*
 * ZFSDatasetProxy.h
 * Copyright 2016 Evan Susarret
 */

#ifndef ZFSDATASETPROXY_H_INCLUDED
#define	ZFSDATASETPROXY_H_INCLUDED

#include <IOKit/storage/IOBlockStorageDevice.h>

class ZFSDatasetProxy : public IOBlockStorageDevice
{
	OSDeclareDefaultStructors(ZFSDatasetProxy);
public:

	virtual void free(void);
	virtual bool init(OSDictionary *properties);
	virtual bool start(IOService *provider);

	/* IOBlockStorageDevice */
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

#if 0
	virtual void read(IOService *client, UInt64 byteStart,
	    IOMemoryDescriptor *buffer, IOStorageAttributes *attr,
	    IOStorageCompletion *completion);
	virtual void write(IOService *client, UInt64 byteStart,
	    IOMemoryDescriptor *buffer, IOStorageAttributes *attr,
	    IOStorageCompletion *completion);
#endif

protected:
private:
	/* These are declared class static to share across instances */
	const char *vendorString;
	const char *revisionString;
	const char *infoString;
	/* These are per-instance */
	const char *productString;
	uint64_t _pool_bcount;
	bool isReadOnly;
};

#endif /* ZFSDATASETPROXY_H_INCLUDED */
