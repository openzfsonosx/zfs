
/*
 * Apple IOKit (c++)
 */
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOMedia.h>

/*
 * IOKit C++ functions
 */

/*
 * We want to match on all disks or volumes that
 * do not contain a partition map / raid / LVM
 * - Caller must release the returned object
 */
OSOrderedSet * vdev_iokit_get_disks()
{
    IORegistryIterator * registryIterator = 0;
    IORegistryEntry * currentEntry = 0;
    OSOrderedSet * allEntries = 0;
    OSOrderedSet * allDisks = 0;
    bool result = false;

    registryIterator = IORegistryIterator::iterateOver( IORegistryEntry::getPlane( kIODeviceTreePlane ),
                                                       kIORegistryIterateRecursively );
    
    if(!registryIterator) {
        IOLog( "ZFS: vdev_iokit_get_disks: could not get ioregistry iterator from IOKit\n");
        registryIterator = 0;
        return false;
    }
    
    /* 
     * The registry iterator may be invalid by the time
     * we've copied all the records. If so, try again
     */
    do {
        /* Reset allEntries if needed */
        if(allEntries) {
            allEntries->release();
            allEntries = 0;
        }
        
        /* Grab all records */
        allEntries = registryIterator->iterateAll();
        
    } while ( ! registryIterator->isValid() );
    
    if (registryIterator) {
        /* clean up */
        registryIterator->release();
        registryIterator = 0;
    }
    
    if (allEntries && allEntries->getCount() > 0 ) {
        /*
         * Pre-allocate a few records
         *  Most systems will have at least 
         *  2 or 3 'leaf' IOMedia objects-
         *  and the set will allocate more
         */
        allDisks = OSOrderedSet::withCapacity(3);
    }
    
    /* Loop through all the items in allEntries */
    while ( allEntries->getCount() > 0 ) {
        
        /*
         * Grab the first object in the set.
         * (could just as well be the last object)
         */
        currentEntry = OSDynamicCast( IORegistryEntry, allEntries->getFirstObject() );
        
        if(!currentEntry) {
            /* clean up */
            currentEntry = 0;
            allEntries->release();
            allEntries = 0;
            return false;
        }
        
        /* Remove current item from ordered set */
        allEntries->removeObject( currentEntry );
        
        /*
         * XXX - TO DO
         *
         *  Also filter out CoreStorage PVs but not LVMs?
         */
        
        /* Check 'Leaf' property */
        matchBool = OSDynamicCast( OSBoolean, currentEntry->getProperty(kIOMediaLeafKey) );
        
        result =     ( matchBool && matchBool->getValue() == true );
        
        IOLog( "ZFS: vdev_iokit_get_disks: matchBool release...\n"); IOSleep(1000);
        matchBool->release();
        matchBool = 0;
        
        if( result ) {
            allDisks->setLastObject( currentEntry );
        }
        
        IOLog( "ZFS: vdev_iokit_get_disks: currentEntry release...\n"); IOSleep(1000);
        currentEntry->release();
        currentEntry = 0;
        
    }
    
    if (allEntries)
        allEntries->release();
    allEntries = 0;
    
    return allDisks;
}

bool vdev_iokit_find_by_path( vdev_t * vd, void * diskIOMedia )
{
    OSOrderedSet * allDisks = 0;
    IORegistryEntry * currentDisk;
    OSObject * matchedObject;
    UInt64 labelSize;
    
    char diskPath[MAXPATHLEN];
    
    char * diskName = 0;
    
    if ( !vd || !vd->vdev_path ) {
        return false;
    }
    
    allDisks = vdev_iokit_get_disks();
    
    if (!allDisks)
        return false;
    
    diskPath = vd->vdev_path;
    
    diskName = strrchr( diskPath, '/' );
    
    if (diskName) {
        diskName++;
    } else {
        diskName = diskPath;
    }
    
    while ( allDisks->getCount() > 0 ) {
        currentDisk = OSDynamicCast( IORegistryEntry, allDisks->getFirstObject() );
        
        if (!currentDisk)
            break;
        
        allDisks->removeObject(currentDisk);
        
        IOLog( "ZFS: vdev_iokit_find_by_path: Getting bsd name\n" );
        IOSleep( info_delay );
        
        OSObject * bsdnameosobj =    currentEntry->getProperty(kIOBSDNameKey,
                                                               gIOServicePlane,
                                                               kIORegistryIterateRecursively);
        OSString * bsdnameosstr =    OSDynamicCast(OSString, bsdnameosobj);
        IOLog("ZFS: vdev_iokit_find_by_path: bsd name is '%s'\n", bsdnameosstr->getCStringNoCopy());
        IOSleep( info_delay );
        
        if ( bsdnameosstr->isEqualTo(diskName) ) {
            matchedObject = currentDisk;
        }
        
        //        strlcpy( diskName, bsdnameosstr->getCStringNoCopy(), bsdnameosstr->getLength()-1 );
        
        
        IOLog("ZFS: vdev_iokit_find_by_path: strncpy\n");
        IOSleep( info_delay );
        /* Start with '/dev' */
        strncpy( diskPath, "/dev/\0", 6 );
        IOLog("ZFS: vdev_iokit_find_by_path: strncpy done '%s'\n", diskPath);
        IOSleep( info_delay );
        
        /*
         * Add "r" before the BSD node name from the I/O Registry
         * to specify the raw disk node. The raw disk node receives
         * I/O requests directly and does not go through the
         * buffer cache.
         */
        //        strlcat( diskPath, "r", 1 );
        //strlen(diskName)
        
        strncat( diskPath, bsdnameosstr->getCStringNoCopy(), bsdnameosstr->getLength());
        IOLog( "ZFS: vdev_iokit_find_by_path: Got bsd path %s\n", diskPath );
        IOSleep( info_delay );
        
        result = (strlen(diskPath) > 0);
        
        if(!result) {
            IOLog( "ZFS: vdev_iokit_find_by_path: Couldn't get BSD path for %s\n", diskName );
            IOSleep( error_delay );
            /* clean up */
        }
        
        IOLog( "ZFS: vdev_iokit_find_by_path: BSD path: %s\n", diskPath );
        IOSleep( info_delay );
    }
    
    
    
    return result;
    
    
    bool result = false;
    
    return result;
}

IOMedia * vdev_iokit_find_by_guid( vdev_t * vd, void * diskIOMedia )
{
    UInt64 labelSize;
    
    char diskName[MAXPATHLEN];
    char diskPath[MAXPATHLEN];
    
    bool result = false;
    
    return false;
}


/*
 *  ZFS internal
 */

#ifdef __cplusplus
extern "C" {
#endif
    
#include <sys/vdev_iokit.h>

/*
 * C language interfaces
 */

bool vdev_iokit_handle_open (vdev_t * vd, uint64_t *size, uint64_t *max_size, uint64_t *ashift)
{
    IOMedia * vdev_disk;
    bool result = false;
    
    void * matched_disk = 0;
    
    result = vdev_iokit_find_by_path( vd->vdev_path, matched_disk );
    
    if ( !result || !matched_disk )
        result = vdev_iokit_find_by_path( vd->vdev_phys_path, matched_disk );
    
    if ( !result || !matched_disk )
        result = vdev_iokit_find_by_guid( vd->vdev_guid, matched_disk );
    
    if ( result && matched_disk )
        vd->vdev_tpd = matched_disk;
    
    vdev_disk = OSDynamicCast( IOMedia, vd->vdev_tpd );
    
    if ( ! vdev_disk )
        return false;
    
    result = vdev_disk->open(this, 0, kIOStorageAccessReaderWriter);
    
    return result;
}

bool vdev_iokit_handle_close (vdev_t * vd )
{
    IOMedia * vdev_disk;
    
    if ( !vd || !vd->vdev_tpd )
        return false;
    
    vdev_disk = OSDynamicCast( IOMedia, vd->vdev_tpd );
    
    if ( ! vdev_disk )
        return false;
    
    vdev_disk->close(this, 0);
    
    return true;
}

bool vdev_iokit_strategy( vdev_t * vd, zio_t * zio )
{
    IOBufferMemoryDescriptor * io_buf = 0;
    bool result = false;
    
    /*
    typedef enum zio_type {
        ZIO_TYPE_NULL = 0,
        ZIO_TYPE_READ,
        ZIO_TYPE_WRITE,
        ZIO_TYPE_FREE,
        ZIO_TYPE_CLAIM,
        ZIO_TYPE_IOCTL,
        ZIO_TYPES
    } zio_type_t;
    */
    
//    io_buf =
    
    /*
     *IOBufferMemoryDescriptor::withAddress( zio->io_start, zio->io_size,
     *                                      (zio->io_type == ZIO_TYPE_WRITE ? kIODirectionOut : kIODirectionIn) );
     *
     * io_buf->write();
     * void *address, IOByteCount withLength, IODirection withDirection);
     */
    
    return result;
}

#ifdef __cplusplus
}   /* extern "C" */
#endif