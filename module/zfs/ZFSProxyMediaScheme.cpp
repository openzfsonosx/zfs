#include "ZFSProxyMediaScheme.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

// Define the superclass
#define super IOPartitionScheme

OSDefineMetaClassAndStructors(ZFSProxyMediaScheme, IOPartitionScheme)


IOService* ZFSProxyMediaScheme::probe(IOService* provider, SInt32* score)
{
	printf("ZFSProxyMediaScheme::probe\n");

    if (super::probe(provider, score) == 0)
        return 0;

    //find first level of child filesystems.
    m_child_filesystems = scan(score);

    //If this filesystem has no children, then return NULL
    printf("probe: this %p : m_child_filesystems %p\n", this, m_child_filesystems);

    return m_child_filesystems ? this : NULL;
    return NULL;
}

bool ZFSProxyMediaScheme::start (IOService *provider)
{
    IOMedia*                child_filesystem;
    OSIterator*             child_filesystemIterator;

	printf("ZFSProxyMediaScheme::start\n");

	if (super::start(provider) == false)
		return false;

    if(m_child_filesystems == NULL)
        return false;

    // Create an iterator for the IOMedia objects that were found and instantiated during probe
    child_filesystemIterator = OSCollectionIterator::withCollection(m_child_filesystems);
    if (child_filesystemIterator == NULL)
        return false;


    // Attach and register each IOMedia object (representing found partitions)
    while ((child_filesystem = (IOMedia*)child_filesystemIterator->getNextObject()))
    {
        if (child_filesystem->attach(this))
        {
            //attachMediaObjectToDeviceTree(child_filesystem);
            child_filesystem->registerService();
        }
    }
    child_filesystemIterator->release();

    //this->registerService(); //why?

    return true;
}
#pragma warning "Watch out, this program uses c++!\n"

void ZFSProxyMediaScheme::stop(IOService* provider)
{
	IOMedia*		child_filesystem;
	OSIterator*		child_filesystemIterator;

	// Detach the media objects we previously attached to the device tree.
	child_filesystemIterator = OSCollectionIterator::withCollection(m_child_filesystems);
	if (child_filesystemIterator)
	{
		while ((child_filesystem = (IOMedia*)child_filesystemIterator->getNextObject()))
		{
			//detachMediaObjectFromDeviceTree(child_filesystem);
		}

		child_filesystemIterator->release();
	}

	super::stop(provider);
}


OSSet*  ZFSProxyMediaScheme::scan(SInt32* score)
{
    //IOBufferMemoryDescriptor*       buffer                  = NULL;
    //SamplePartitionTable*           sampleTable;
	IOMedia *media                   = getProvider();

    UInt64 child_filesystem_count;

    printf("ZFSProxyMediaScheme::scan : provider Content is %s\n", media->getContent());
    printf("ZFSProxyMediaScheme::scan : provider ContentHint is %s\n", media->getContentHint());
    printf("ZFSProxyMediaScheme::scan : provider Name is %s\n", media->getName());

    if (strcmp(media->getContentHint(), "zfs_pool_proxy") == 0) {
        printf("ZFSProxyMediaScheme::scan : it's a zfs_pool_proxy\n");
        child_filesystem_count = 2;
    } else if (strcmp(media->getContentHint(), "zfs_filesystem_proxy") == 0){
        printf("ZFSProxyMediaScheme::scan : it's a zfs_filesystem_proxy\n");
        child_filesystem_count = 0;
    } else {
        printf("uh oh, unrecognized provider");
    }

//    UInt64                                          mediaBlockSize  = media->getPreferredBlockSize();
//    bool                                            mediaIsOpen             = false;
    OSSet*                                          child_filesystems       = NULL;
//    IOReturn                                        status;

    // Determine whether this media is formatted.
    //if (media->isFormatted() == false)
    //    goto bail;

    // Allocate a sector-sized buffer to hold data read from disk
    //buffer = IOBufferMemoryDescriptor::withCapacity(mediaBlockSize, kIODirectionIn);
    //if (buffer == NULL)
    //    goto bail;

    // Allocate a set to hold the media objects representing partitions
    child_filesystems = OSSet::withCapacity(8);
    if (child_filesystems == NULL)
        goto bail;

    // Open the media with read access
//    mediaIsOpen = open(this, 0, kIOStorageAccessReader);
//    if (mediaIsOpen == false)
//        goto bail;

    // Read the first sector of the disk
//    status = media->read(this, 0, buffer);
//    if (status != kIOReturnSuccess)
//        goto bail;
//    sampleTable = (SamplePartitionTable*)buffer->getBytesNoCopy();

    // Determine whether the protective map signature is present.
//    if (strcmp(sampleTable->partitionIdentifier, SamplePartitionIdentifier) != 0)
//        goto bail;

    // Scan for valid partition entries in the protective map.
    //UInt64 child_filesystem_count = sampleTable->partitionCount;

    for (unsigned index = 0; index < child_filesystem_count; index++)
    {
//        if (isPartitionCorrupt(&sampleTable->partitionEntries[index]))
//            goto bail;
        ZFSFilesystemEntry foo;
        snprintf(foo.filesystemName, sizeof(foo.filesystemName), "foo %d", (int) index);
        IOMedia*        newMedia = instantiateMediaObject(&foo, 1+index);

        printf("Content is %s\n", newMedia->getContent());
        printf("ContentHint is %s\n", newMedia->getContentHint());
        printf("Name is %s\n", newMedia->getName());

        if ( newMedia )
        {
            child_filesystems->setObject(newMedia);
            newMedia->release();
        }
    }

    // Release temporary resources
    close(this);
  //  buffer->release();

    return child_filesystems;

bail:
    // Release all allocated objects
//    if ( mediaIsOpen )          close(this);
    if ( child_filesystems )    child_filesystems->release();
 //   if ( buffer )               buffer->release();

    return NULL;
}

IOMedia* ZFSProxyMediaScheme::instantiateMediaObject(ZFSFilesystemEntry* fsEntry, unsigned index)
{
	IOMedia*        media          = getProvider();

    //We can get fancier than passthrough if we want
    UInt64                  partitionBase   = 0;
    UInt64                  partitionSize   = media->getSize();
    UInt64                  mediaBlockSize  = media->getPreferredBlockSize();
    IOMediaAttributeMask    mediaAttributes = media->getAttributes();
    bool                    isMediaWritable = media->isWritable();
    IOMedia*                newMedia;

    newMedia = new IOMedia;
    if ( newMedia )
    {
        if ( newMedia->init(partitionBase,
							partitionSize,
							mediaBlockSize,
							mediaAttributes,
							false, //it's a "partition" now
							isMediaWritable,
							"zfs_filesystem_proxy"))
		{

            //Fix me get file system name so we can set it.
            //ZFS
            // Set a name for this partition
            //char name[24];
            //snprintf(name, sizeof(name), "Untitled %d", (int) index);
            //newMedia->setName(name);

            newMedia->setName(fsEntry->filesystemName);

            // Set a location value (the partition number) for this partition
            char location[12];
            snprintf(location, sizeof(location), "%d", (int)index);
            newMedia->setLocation(location);

            // Set the "Partition ID" key for this partition
            newMedia->setProperty(kIOMediaPartitionIDKey, index, 32);


            //ZFS
            //Fix me: get pool guid and dataset guid from the label
            uint64_t zfs_pool_guid = 16504178780918792917UL;
            uint64_t zfs_dataset_guid = 17572052293026476543UL;

            newMedia->setProperty("ZFS_POOL_GUID", zfs_pool_guid, 64);
            newMedia->setProperty("ZFS_DATASET_GUID", zfs_dataset_guid, 64);
		}
		else
		{
			newMedia->release();
			newMedia = NULL;
		}
    }
    return newMedia;
}

#if 0
/*

void	ZFSProxyMediaScheme::read (IOService* client, UInt64 byteStart, IOMemoryDescriptor* buffer, IOStorageAttributes* attributes, IOStorageCompletion* completion)
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

void	ZFSProxyMediaScheme::readCompleted (void* target, void* parameter, IOReturn status, UInt64 actualByteCount)
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

IOReturn	ZFSProxyMediaScheme::decryptBuffer (IOMemoryDescriptor* buffer, UInt64 actualByteCount)
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


void	ZFSProxyMediaScheme::write (IOService* client, UInt64 byteStart, IOMemoryDescriptor* buffer, IOStorageAttributes* attributes, IOStorageCompletion* completion)
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

IOMemoryDescriptor*	ZFSProxyMediaScheme::encryptBuffer (IOMemoryDescriptor* buffer)
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
 */
#endif
