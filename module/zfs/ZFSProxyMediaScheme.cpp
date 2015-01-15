#include "ZFSProxyMediaScheme.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <sys/zvolIO.h>
#include <sys/osx_pseudo.h>

// Define the superclass
#define super IOPartitionScheme

OSDefineMetaClassAndStructors(ZFSProxyMediaScheme, IOPartitionScheme)


IOService* ZFSProxyMediaScheme::probe(IOService* provider, SInt32* score, char *snapshot)
{
	printf("ZFSProxyMediaScheme::probe\n");

    if (super::probe(provider, score) == 0)
        return 0;

    //find first level of child filesystems.
    m_child_filesystems = scan(score, snapshot);

    //If this filesystem has no children, then return NULL
    printf("probe: this %p : m_child_filesystems %p: provider %p\n",
		   this, m_child_filesystems, provider);

	IOMedia *up = OSDynamicCast(IOMedia, provider);
	if (up) {
		net_lundman_zfs_pseudo_device *pseudo;

		printf("UP ok: name '%s': provider %p: pprovider %p\n",
			   up->getName(),
			   up->getProvider(),
			   up->getProvider()->getProvider());

		pseudo = OSDynamicCast(net_lundman_zfs_pseudo_device,
							   up->getProvider()->getProvider());
		// Save ptr to us, so we can call probe in future.
		if (pseudo)
			pseudo->registerPool(this);
	}


    return m_child_filesystems ? this : NULL;
    return NULL;
}

IOService* ZFSProxyMediaScheme::probe(IOService* provider, SInt32* score)
{
	return probe(provider, score, NULL);
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


    this->registerService(); //why?

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


struct holder_s
{
	char *poolname;
	unsigned int index;
	OSSet*child_filesystems;
	ZFSProxyMediaScheme *object;
	int snapshot;
};

int
spa_osx_create_devs(const char *dsname, void *arg)
{
	struct holder_s *holder = (struct holder_s *)arg;
	int startnamelen;
	int dsnamelen;
	const char *part;

	// Skip if impossible happens, or "ourself".
	if (!arg || !dsname) return 0;

	startnamelen = strlen(holder->poolname);
	dsnamelen = strlen(dsname);

	// Skip outselves
	if (dsnamelen <= startnamelen) {
		printf("  skipping '%s' ('%s')\n", dsname, holder->poolname);
		return 0;
	}

	// If it has a trailing slash, its a child, skip that too.
	// startname = "BOOM"
	// dsname    = "BOOM/hello" then check from "h" to see if there
	// are "/" following.
	part = &dsname[startnamelen];
	while(*part == '/') part++; // Skip leading slash

	if (strchr(part, '/')) {
		printf("  skipping '%s' due to slash (from '%s')\n", dsname, part);
		return 0;
	}


	// Check if it already exists, so we do an update
	OSCollectionIterator *iter;

	iter = OSCollectionIterator::withCollection(holder->child_filesystems);
	if (iter) {
		IOMedia *media;
		while ((media = (IOMedia *)iter->getNextObject())) {
			OSObject *sobj;
			sobj = media->getProperty("DATASET");
			OSString*osstr = OSDynamicCast(OSString, sobj);
			if (osstr->isEqualTo(dsname)) {
				printf("Already has '%s' -- skipping\n", dsname);
				iter->release();
				return 0;
			}
		}

		iter->release();
	}

	printf("Creating '%s' (remainer '%s')\n", dsname, part);
	ZFSFilesystemEntry foo;
	snprintf(foo.filesystemName, sizeof(foo.filesystemName), "%s",
			 dsname);
	IOMedia *newMedia;
	newMedia = static_cast<ZFSProxyMediaScheme*>(holder->object)->instantiateMediaObject(
		&foo,
		1+holder->index,
		holder->snapshot ? "zfs_snapshot_proxy" : "zfs_filesystem_proxy");

	if ( newMedia )
	{
		printf("Content is %s\n", newMedia->getContent());
		printf("ContentHint is %s\n", newMedia->getContentHint());
		printf("Name is %s\n", newMedia->getName());

		newMedia->setProperty("DATASET", dsname);
		if (holder->snapshot)
			newMedia->setProperty("autodiskmount", true);

		holder->child_filesystems->setObject(newMedia);
		newMedia->release();
	}

	holder->index++;

	return 0;
}

extern "C" {
#include <sys/dmu.h>
}

OSSet*  ZFSProxyMediaScheme::scan(SInt32* score, char *snapshot)
{
    //IOBufferMemoryDescriptor*       buffer                  = NULL;
    //SamplePartitionTable*           sampleTable;
	IOMedia *media                   = getProvider();
	int highest, id;
	IOMedia*		child_filesystem;
	OSIterator*		child_filesystemIterator;

    UInt64 child_filesystem_count;
	int rlen = 0;

    printf("ZFSProxyMediaScheme::scan : provider Content is %s\n", media->getContent());
    printf("ZFSProxyMediaScheme::scan : provider ContentHint is %s\n", media->getContentHint());
    printf("ZFSProxyMediaScheme::scan : provider Name is %s: this %p\n", media->getName(), this);

    if (strcmp(media->getContentHint(), "zfs_pool_proxy") == 0) {
        printf("ZFSProxyMediaScheme::scan : it's a zfs_pool_proxy\n");
    } else if (strcmp(media->getContentHint(), "zfs_filesystem_proxy") == 0){
        printf("ZFSProxyMediaScheme::scan : it's a zfs_filesystem_proxy\n");
        child_filesystem_count = 0;
    } else if (strcmp(media->getContentHint(), "zfs_snapshot_proxy") == 0){
        printf("ZFSProxyMediaScheme::scan : it's a zfs_snapshot_proxy\n");
        child_filesystem_count = 0;
    } else {
        printf("uh oh, unrecognized provider");
    }



	struct holder_s holder = { 0 };

	// Assign existing list, so we can add to it
	if (!m_child_filesystems)
		holder.child_filesystems = OSSet::withCapacity(1);
	else
		holder.child_filesystems = m_child_filesystems;

	if (holder.child_filesystems == NULL)
		goto bail;

	/* If we are passed a snapshot to add, figure out the dataset name
	 * part for easy comparison
	 */
	if (snapshot) {
		char *r;
		r = strchr(snapshot, '@'); // ZFS guarantee us 1 '@'
		if (r) {
			rlen = r - snapshot;
		}
	}



	printf("Looking for deletions \n");

	/* Here we will loop through the child_filesystem list, and look
	 * up each name in ZFS. If failed, remove from IOKit. (deletions)
	 * We do this before adding any new nodes, so we know they were
	 * registered, and thus, needs to be unregistered
	 */
	child_filesystemIterator = OSCollectionIterator::withCollection(holder.child_filesystems);
	if (child_filesystemIterator) {
		while ((child_filesystem = (IOMedia*)child_filesystemIterator->getNextObject())) {
			OSString *dset;

			dset = (OSString *)child_filesystem->getProperty("DATASET");
			printf("Looking up '%s'\n", dset->getCStringNoCopy());

			objset_t *os;

			if (dmu_objset_hold(dset->getCStringNoCopy(), FTAG, &os) == 0) {
				dmu_objset_rele(os, FTAG);
			} else {
				printf("Told to delete '%s':\n",
					   dset->getCStringNoCopy());
				child_filesystem->terminate();

				holder.child_filesystems->removeObject(child_filesystem);

			}
		}

		child_filesystemIterator->release();
	}








	// Find highest index
	highest = 0;

	child_filesystemIterator = OSCollectionIterator::withCollection(m_child_filesystems);
	if (child_filesystemIterator) {
		while ((child_filesystem = (IOMedia*)child_filesystemIterator->getNextObject())) {
			id = ((OSNumber *)child_filesystem->getProperty("Partition ID"))->unsigned64BitValue();

			if (id > highest) highest = id;
		}

		child_filesystemIterator->release();
	}
	printf("Highest existing ID %u\n", highest);
	holder.index = highest;


	//holder.poolname = media->getName();
	OSObject *sobj;
	sobj = media->getProperty("DATASET");
	if (sobj) {
		OSString*osstr = OSDynamicCast(OSString, sobj);
		if (osstr) {

			holder.poolname = (char *)osstr->getCStringNoCopy();

			printf("Looking for direct children of '%s'\n",
				   holder.poolname);

			holder.object = this;

			dmu_objset_find(holder.poolname, spa_osx_create_devs,
							&holder, DS_FIND_CHILDREN);

			/* Add a snapshot ? */
			if (rlen)
				printf("ZFS: Comparing '%s' to '%s' for %d bytes\n",
					   snapshot, holder.poolname, rlen);
			if (rlen /*&& !strncmp(snapshot, holder.poolname, rlen)*/) {
				printf("ZFS: Attempting to add snapshot '%s'\n", snapshot);
				holder.snapshot = 1;
				spa_osx_create_devs(snapshot, &holder);
				snapshot = NULL;
			}

		}

	}

    // Release temporary resources
    close(this);
  //  buffer->release();


	if (snapshot) printf("ZFS: Should add snapshot '%s' here.\n", snapshot);

	return holder.child_filesystems;

bail:
    // Release all allocated objects
//    if ( mediaIsOpen )          close(this);
    if ( holder.child_filesystems )    holder.child_filesystems->release();
 //   if ( buffer )               buffer->release();

    return NULL;
}

IOMedia* ZFSProxyMediaScheme::instantiateMediaObject(ZFSFilesystemEntry* fsEntry, unsigned index, const char *type)
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
							type))
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

#if 0
            //ZFS
            //Fix me: get pool guid and dataset guid from the label
            uint64_t zfs_pool_guid = 16504178780918792917UL;
            uint64_t zfs_dataset_guid = 17572052293026476543UL;

            newMedia->setProperty("ZFS_POOL_GUID", zfs_pool_guid, 64);
            newMedia->setProperty("ZFS_DATASET_GUID", zfs_dataset_guid, 64);
#endif
		}
		else
		{
			newMedia->release();
			newMedia = NULL;
		}
    }
    return newMedia;
}


IOReturn ZFSProxyMediaScheme::setDONTMOUNTME(OSString value)
{
	IOMedia *media;
    //media = OSDynamicCast(IOMedia, m_child_filesystems);
	//media->setProperty("DONTMOUNTME", value);
	return 0;
}

IOReturn
ZFSProxyMediaScheme::newUserClient(task_t owningTask,
										   void* securityID, UInt32 type,
										   OSDictionary* properties,
										   IOUserClient** handler)
{
	IOReturn ret;

	ret = super::newUserClient(owningTask, securityID, type, properties,
							   handler);
	printf("XXXnewUserClient: ret %d and *handler %p\n", ret, *handler);

	return ret;
}
