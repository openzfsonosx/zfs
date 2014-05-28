#include "ZFSLabelScheme.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

// Define the superclass
#define super IOFilterScheme

OSDefineMetaClassAndStructors(ZFSLabelScheme, IOFilterScheme)

IOService* ZFSLabelScheme::probe(IOService* provider, SInt32* score)
{
    if (super::probe(provider, score) == 0)
        return 0;
    /*
     * Since Core Storage does not allow a custom Content Hint, we need to match against
     * whole device Journaled HFS+ and return NULL if we don't find a ZFS label so
     * that OS X has a chance to recognize the device if it actually is HFS+.
     */
    
    //m_devices = scan(score);
    // Scan the IOMedia for a supported partition table
    m_pool_proxy = scan(score);
    
    // If no partition table was found, return NULL
    //return m_partitions ? this : NULL;
    printf("probe: this %p : m_pool_proxy %p\n", this, m_pool_proxy);
    return m_pool_proxy ? this : NULL;
    //return this;
}

bool ZFSLabelScheme::start (IOService *provider)
{
	if (super::start(provider) == false)
		return false;
	
    if(m_pool_proxy == NULL)
        return false;
    
	if (m_pool_proxy->attach(this) == false)
		return false;
    printf("hello\n");
	m_pool_proxy->registerService();
    this->registerService(); //why?

	return true;
}

void ZFSLabelScheme::stop(IOService* provider)
{	
	super::stop(provider);
}

void ZFSLabelScheme::free (void)
{
	if (m_pool_proxy != NULL)
		m_pool_proxy->release();
	
	super::free();
}

IOMedia*  ZFSLabelScheme::scan(SInt32* score)
{
    IOMedia*                                        media                   = getProvider();
    m_device = OSDynamicCast(IOMedia, media);
    printf("Content is %s\n", m_device->getContent());
	printf("ContentHint is %s\n", m_device->getContentHint());
    printf("Name is %s\n", m_device->getName());
    m_device->setName("zfs vdev for 'mymir'");
    printf("Name is %s\n", m_device->getName());
    if (m_device == NULL)
		return false;

//Fix me
//ZFS
    //Need to grab the existing zfs_pool_proxy if another device made it first
    //if (someone else already made it ...)
        //
    //else
        m_pool_proxy = instantiateMediaObject();
    
	if (m_pool_proxy == NULL)
		return false;
    
    return m_pool_proxy;
}

IOMedia* ZFSLabelScheme::instantiateMediaObject ()
{
	IOMedia*	newMedia;
	
	newMedia = new IOMedia;
	if ( newMedia )
	{
		if ( newMedia->init(0,
							m_device->getSize(),
							m_device->getPreferredBlockSize(),
							m_device->getAttributes(),
							true,
							m_device->isWritable(),
							"zfs_pool_proxy"))
		{
            //Fix me: get pool guid and vdev guid from the label
            uint32_t zfs_pool_guid = 16504178780918792917UL;
            uint32_t zfs_vdev_guid = 7851727243200360649UL;
            
            newMedia->setProperty("ZFS_POOL_GUID", zfs_pool_guid, 32);
            newMedia->setProperty("ZFS_VDEV_GUID", zfs_vdev_guid, 32);
		}
		else
		{
			newMedia->release();
			newMedia = NULL;
		}
	}
	
	return newMedia;
}

//UInt64 ZFSLabelScheme::getSize()
//{
//    return m_device->getSize();
//}

//UInt64 ZFSLabelScheme::getPreferredBlockSize()
//{
//    return m_device->getPreferredBlockSize();
//}


//IOMediaAttributeMask ZFSLabelScheme::getAttributes()
//{
//    return m_device->getAttributes();
//}

//bool ZFSLabelScheme::isWritable()
//{
//    return m_device->isWritable();
//}

void	ZFSLabelScheme::read (IOService* client, UInt64 byteStart, IOMemoryDescriptor* buffer, IOStorageAttributes* attributes, IOStorageCompletion* completion)
{
	ReadCompletionParams*	context;
	IOStorageCompletion		newCompletion;
	
	context = (ReadCompletionParams*)IOMalloc(sizeof(ReadCompletionParams));
	if (context == NULL)
	{
		complete(completion, kIOReturnNoMemory);
		return;
	}
	
	context->completion = *completion;
	context->buffer = buffer;
	context->buffer->retain();
	
	newCompletion.target = this;
	newCompletion.action = readCompleted;
	newCompletion.parameter = context;
	
	m_device->read(client, byteStart, buffer, attributes, &newCompletion);
}

void	ZFSLabelScheme::readCompleted (void* target, void* parameter, IOReturn status, UInt64 actualByteCount)
{
	ReadCompletionParams*	context = (ReadCompletionParams*)parameter;

	// Decrypt the data read from disk.
	if (status == kIOReturnSuccess)
		status = decryptBuffer(context->buffer, actualByteCount);

	// If  either the read from disk or the decryption operation failed, set the actualByteCount value to 0.
	if (status != kIOReturnSuccess)
		actualByteCount = 0;

	// Call the original caller’s completion function.
	complete(&context->completion, status, actualByteCount);

	context->buffer->release();
	IOFree(context, sizeof(ReadCompletionParams));
}

IOReturn	ZFSLabelScheme::decryptBuffer (IOMemoryDescriptor* buffer, UInt64 actualByteCount)
{
	bool			didPrepare = false;
	IOMemoryMap*	map = NULL;
	uint32_t*		nextWord;
	IOReturn		status;
	
	status = buffer->prepare(buffer->getDirection());
	if (status != kIOReturnSuccess)
		goto bail;
	didPrepare = true;
	map = buffer->map();
	if (map == NULL)
	{
		status = kIOReturnError;
		goto bail;
	}
	
	// Decrypt the data
	UInt64		remainingWords;
	remainingWords = actualByteCount / sizeof(uint32_t);
	nextWord = (uint32_t*)map->getVirtualAddress();
	while (remainingWords--)
	{
		*nextWord ^= 0xFFFFFFFF;
		nextWord++;
	}
	
	// Fall-through on success
bail:
	
	if (map != NULL)
		map->release();
	if (didPrepare == true)
		buffer->complete();
	
	return status;
}


void	ZFSLabelScheme::write (IOService* client, UInt64 byteStart, IOMemoryDescriptor* buffer, IOStorageAttributes* attributes, IOStorageCompletion* completion)
{
	IOMemoryDescriptor*		newDesc;
	
	newDesc = encryptBuffer(buffer);
	if (newDesc == NULL)
	{
		complete(completion, kIOReturnNoMemory);
		return;
	}
	
	m_device->write(client, byteStart, newDesc, attributes, completion);
	
	newDesc->release();
}

IOMemoryDescriptor*	ZFSLabelScheme::encryptBuffer (IOMemoryDescriptor* buffer)
{
	IOBufferMemoryDescriptor*	newDesc;
	
	// Allocate a buffer to hold the encrypted contents
	newDesc = IOBufferMemoryDescriptor::withCapacity(buffer->getLength(), buffer->getDirection());
	if (newDesc != NULL)
	{
		uint32_t*		nextWord;
		UInt64			remainingWords;
		
		nextWord = (uint32_t*)newDesc->getBytesNoCopy();
		
		// Read the source buffer into the new memory descriptor
		buffer->readBytes(0, nextWord, buffer->getLength());
		
		// Encrypt the buffer
		remainingWords = buffer->getLength() / sizeof(uint32_t);
		while (remainingWords--)
		{
			*nextWord ^= 0xFFFFFFFF;
			nextWord++;
		}
	}
	
	return newDesc;
}
