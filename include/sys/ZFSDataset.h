/*
 * ZFSDataset - proxy disk for legacy and com.apple.devicenode mounts.
 * Copyright 2016 Evan Susarret
 */

#ifndef ZFSDATASET_H_INCLUDED
#define	ZFSDATASET_H_INCLUDED

#ifdef __cplusplus

#include <IOKit/storage/IOMedia.h>

#ifdef super
#undef super
#endif
#define super IOMedia

//#define	kZFSContentHint		"6A898CC3-1DD2-11B2-99A6-080020736631"
#define	kZFSContentHint		"ZFS_Dataset"

#define	kZFSIOMediaPrefix	"ZFS "
#define	kZFSIOMediaSuffix	" Media"
#define	kZFSDatasetNameKey	"ZFS Dataset"
#define	kZFSDatasetClassKey	"ZFSDataset"

class ZFSDataset : public IOMedia
{
	OSDeclareDefaultStructors(ZFSDataset)
public:
#if 0
	/* XXX Only for debug tracing */
	virtual bool open(IOService *client,
	    IOOptionBits options, IOStorageAccess access = 0);
	virtual bool isOpen(const IOService *forClient = 0) const;
	virtual void close(IOService *client,
	    IOOptionBits options);

	virtual bool handleOpen(IOService *client,
	    IOOptionBits options, void *access);
	virtual bool handleIsOpen(const IOService *client) const;
	virtual void handleClose(IOService *client,
	    IOOptionBits options);

	virtual bool attach(IOService *provider);
	virtual void detach(IOService *provider);

	virtual bool start(IOService *provider);
	virtual void stop(IOService *provider);
#endif

	virtual bool init(UInt64 base, UInt64 size,
	    UInt64 preferredBlockSize,
	    IOMediaAttributeMask attributes,
	    bool isWhole, bool isWritable,
	    const char *contentHint = 0,
	    OSDictionary *properties = 0);
	virtual void free();

	static ZFSDataset * withDatasetNameAndSize(const char *name,
	    uint64_t size);

	virtual void read(IOService *client,
	    UInt64 byteStart, IOMemoryDescriptor *buffer,
	    IOStorageAttributes *attributes,
	    IOStorageCompletion *completion);
	virtual void write(IOService *client,
	    UInt64 byteStart, IOMemoryDescriptor *buffer,
	    IOStorageAttributes *attributes,
	    IOStorageCompletion *completion);

	virtual IOReturn synchronize(IOService *client,
	    UInt64 byteStart, UInt64 byteCount,
	    IOStorageSynchronizeOptions options = 0);
	virtual IOReturn unmap(IOService *client,
	    IOStorageExtent *extents, UInt32 extentsCount,
	    IOStorageUnmapOptions options = 0);

	virtual bool lockPhysicalExtents(IOService *client);
	virtual IOStorage *copyPhysicalExtent(IOService *client,
	    UInt64 *byteStart, UInt64 *byteCount);
	virtual void unlockPhysicalExtents(IOService *client);

	virtual IOReturn setPriority(IOService *client,
	    IOStorageExtent *extents, UInt32 extentsCount,
	    IOStoragePriority priority);

	virtual UInt64 getPreferredBlockSize() const;
	virtual UInt64 getSize() const;
	virtual UInt64 getBase() const;

	virtual bool isEjectable() const;
	virtual bool isFormatted() const;
	virtual bool isWhole() const;
	virtual bool isWritable() const;

	virtual const char * getContent() const;
	virtual const char * getContentHint() const;
	virtual IOMediaAttributeMask getAttributes() const;

protected:
private:
	bool setDatasetName(const char *);
};

#endif /* __cplusplus */

#endif /* ZFSDATASET_H_INCLUDED */
