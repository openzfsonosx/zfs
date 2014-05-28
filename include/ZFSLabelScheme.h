#include <IOKit/storage/IOFilterScheme.h>

#pragma once

class ZFSLabelScheme : public IOFilterScheme
{
	OSDeclareDefaultStructors(ZFSLabelScheme)
	
protected:
	IOMedia*		m_device;
	IOMedia*		m_pool_proxy;
	
	struct ReadCompletionParams {
		IOStorageCompletion		completion;
		IOMemoryDescriptor*		buffer;
	};
	
    virtual IOMedia*      scan(SInt32 * score);
	IOMedia*			instantiateMediaObject ();
	static void			readCompleted (void* target, void* parameter, IOReturn status, UInt64 actualByteCount);
	
public:
    virtual IOService*  probe(IOService* provider, SInt32* score);
	virtual bool		start (IOService* provider);
	virtual void		stop (IOService* provider);
	virtual void		free (void);
    
    //virtual UInt64          getSize();
    //virtual UInt64          getPreferredBlockSize();
    //IOMediaAttributeMask    getAttributes();
    //bool                    isWritable();
	
	virtual void		read (IOService* client, UInt64 byteStart, IOMemoryDescriptor* buffer, IOStorageAttributes* attributes, IOStorageCompletion* completion);
	virtual void		write (IOService* client, UInt64 byteStart, IOMemoryDescriptor* buffer, IOStorageAttributes* attributes, IOStorageCompletion* completion);
	
	static IOReturn				decryptBuffer (IOMemoryDescriptor* buffer, UInt64 actualByteCount);
	static IOMemoryDescriptor*	encryptBuffer (IOMemoryDescriptor* buffer);
};
