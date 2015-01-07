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

    virtual OSSet*      scan(SInt32 * score, char *);
    //bool                            isPartitionCorrupt (SamplePartitionEntry* sampleEntry)          { return false; }
//	static void			readCompleted (void* target, void* parameter, IOReturn status, UInt64 actualByteCount);

public:
    virtual IOService*  probe(IOService* provider, SInt32* score);
    virtual IOService*  probe(IOService* provider, SInt32* score, char *);
	virtual bool		start (IOService* provider);
	virtual void		stop (IOService* provider);
    virtual IOMedia*    instantiateMediaObject(ZFSFilesystemEntry* sampleEntry, unsigned index);

	virtual IOReturn newUserClient(task_t owningTask,
								   void* securityID, UInt32 type,
								   OSDictionary* properties,
								   IOUserClient** handler);
	virtual IOReturn setDONTMOUNTME(OSString value);

};
