#include <IOKit/storage/IOPartitionScheme.h>

#pragma once

#define SamplePartitionIdentifier "Sample Partition Scheme"

//struct SamplePartitionEntry {
//    UInt64          blockStart;
//    UInt64          blockCount;
//};



//struct SamplePartitionTable {
//    char                                    partitionIdentifier[24];
//    UInt64                                  partitionCount;
//    SamplePartitionEntry                    partitionEntries[30];
//};

//we probably have some type we can reuse for this
struct ZFSFilesystemEntry {
    char                                    filesystemName[24];
};


class ZFSProxyMediaScheme : public IOPartitionScheme
{
	OSDeclareDefaultStructors(ZFSProxyMediaScheme)

protected:
//	IOMedia*		m_device;
	OSSet*          m_child_filesystems;

//	struct ReadCompletionParams {
//		IOStorageCompletion		completion;
//		IOMemoryDescriptor*		buffer;
//	};

    virtual OSSet*      scan(SInt32 * score);
    virtual IOMedia*    instantiateMediaObject(ZFSFilesystemEntry* sampleEntry, unsigned index);
    //bool                            isPartitionCorrupt (SamplePartitionEntry* sampleEntry)          { return false; }
//	static void			readCompleted (void* target, void* parameter, IOReturn status, UInt64 actualByteCount);

public:
    virtual IOService*  probe(IOService* provider, SInt32* score);
	virtual bool		start (IOService* provider);
	virtual void		stop (IOService* provider);
	virtual void		free (void);

	virtual void		add_pool(char *);
    //virtual IOReturn        requestProbe(IOOptionBits options);

//	virtual void		read (IOService* client, UInt64 byteStart, IOMemoryDescriptor* buffer, IOStorageAttributes* attributes, IOStorageCompletion* completion);
//	virtual void		write (IOService* client, UInt64 byteStart, IOMemoryDescriptor* buffer, IOStorageAttributes* attributes, IOStorageCompletion* completion);

//	static IOReturn				decryptBuffer (IOMemoryDescriptor* buffer, UInt64 actualByteCount);
//	static IOMemoryDescriptor*	encryptBuffer (IOMemoryDescriptor* buffer);
};
