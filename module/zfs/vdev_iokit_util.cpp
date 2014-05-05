
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

#define info_delay 1000
#define error_delay 3000

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

    registryIterator = IORegistryIterator::iterateOver( gIOServicePlane ),
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

/* Returned object will have a reference count and should be released */
bool vdev_iokit_find_by_path( vdev_t * vd, uintptr_t * diskIOMedia )
{
    OSOrderedSet * allDisks = 0;
    IORegistryEntry * currentDisk = 0;
    IORegistryEntry * matchedDisk = 0;
    OSObject * bsdnameosobj = 0;
    OSString * bsdnameosstr = 0;
    
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
        /* /dev/disk0s2 -> /disk0s2 */
        /* Start after the last path divider */
        diskName++;
        /* /disk0s2 -> disk0s2 */
    } else {
        /*
         * XXX To do - check that diskName
         * is in the form diskNsN
         */
        diskName = diskPath;
    }
    
    while ( allDisks->getCount() > 0 ) {
        currentDisk = OSDynamicCast( IORegistryEntry, allDisks->getFirstObject() );
        
        if (!currentDisk)
            break;
        
        IOLog( "ZFS: vdev_iokit_find_by_path: Getting bsd name\n" );
        IOSleep( info_delay );
        
        bsdnameosobj =    currentEntry->getProperty(kIOBSDNameKey,
                                                               gIOServicePlane,
                                                               kIORegistryIterateRecursively);
        if(bsdnameosobj)
            bsdnameosstr =    OSDynamicCast(OSString, bsdnameosobj);
        
        if(bsdnameosstr) {
            IOLog("ZFS: vdev_iokit_find_by_path: bsd name is '%s'\n", bsdnameosstr->getCStringNoCopy());
            IOSleep( info_delay );
            
            /* Check if the name matches */
            if ( bsdnameosstr->isEqualTo(diskName) ) {
                IOLog("ZFS: vdev_iokit_find_by_path: Found matching disk\n");
                IOSleep( info_delay );
                
                matchedDisk = currentDisk;
                matchedDisk->retain();
            }
            
        } else {
            IOLog("ZFS: vdev_iokit_find_by_path: Couldn't get bsd name\n");
            IOSleep( error_delay );
        }
        
        allDisks->removeObject(currentDisk);
        currentDisk = 0;
        
        if (matchedDisk)
            break;
    }
    
    if (allDisks) {
        allDisks->release();
        allDisks = 0;
    }
    
    diskIOMedia = <static_cast>(uintptr_t*)matchedDisk;
    matchedDisk = 0;

    return (diskIOMedia != NULL);
}

/* Returned object will have a reference count and should be released */
bool vdev_iokit_find_by_guid( vdev_t * vd, uintptr_t * diskIOMedia )
{
    
    OSOrderedSet * allDisks = 0;
    IORegistryEntry * currentDisk;
    IORegistryEntry * matchedDisk;
    UInt64 labelSize;
    int guid;
    IOBufferMemoryDescriptor* buffer = 0;
    nvlist_t * config = 0;
    
    char * diskName = 0;
    
    nvlist_t *nvtop, *nvroot, **child;
    uint64_t pgid, guid;
    uint_t children;
    spa_t * spa;
    
    char * pool_name = 0;
    char * tmpPath = 0;
    vdev_label_t * label;
    uint64_t s, size;
    int l;
    int error = -1;
    bool result = false;
    
    if ( !vd || !vd->vdev_path ) {
        return false;
    }
    
    allDisks = vdev_iokit_get_disks();
    
    if (!allDisks)
        return false;
    
    diskPath = vd->vdev_path;
    
    diskName = strrchr( diskPath, '/' );
    
    if (diskName) {
        /* /dev/disk0 -> /disk0 */
        /* Start after the last path divider */
        diskName++;
        /* /disk0 -> disk0 */
    } else {
        /*
         * XXX To do - check that diskName
         * is in the form diskNsN
         */
        diskName = diskPath;
    }
    
    if( allDisks->getCount() > 0 ) {
        /* Lazy allocate, and only if there will be work to do */
        buffer = IOBufferMemoryDescriptor::withCapacity(labelSize, kIODirectionIn);
        
        if (buffer == NULL) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't allocate a memory buffer\n");
            IOSleep( error_delay );
            return false;
        }
    }
    
    while ( allDisks->getCount() > 0 ) {
        currentDisk = OSDynamicCast( IORegistryEntry, allDisks->getFirstObject() );
        
        if (!currentDisk) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Invalid disk\n");
            IOSleep( error_delay );
            result = false;
            goto nextDisk;
        }
        
        IOLog( "ZFS: vdev_iokit_find_by_guid: Getting vdev guid\n" );
        IOSleep( info_delay );
        
        // Determine whether this media is formatted.
        if ( currentDisk->isFormatted() != true ) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Disk %s not formatted\n", diskPath);
            IOSleep( error_delay );
            result = false;
            goto nextDisk;
        }
        
        if ( currentDisk->isOpen(0) ) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Disk %s is already open!\n", diskPath);
            IOSleep( error_delay );
        }
        
        //error = ((IOMedia*)currentEntry)->open(this,0,kIOStorageAccessReader);
        result = currentDisk->open(currentDisk->getProvider(),0,kIOStorageAccessReader);
        
        /* If the disk could not be opened, skip to the next one */
        if (!result) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Disk %s couldn't be opened for reading\n", diskPath);
            IOSleep( error_delay );
            result = false;
            goto nextDisk;
        }
        
        //IOLog("zfs_mountroot: Getting size of disk %s\n", diskPath);
        //IOSleep( info_delay );
        
        /* Get size */
        s = currentDisk->getSize();
        
        //IOLog("zfs_mountroot: Got size %llu\n", s);
        //IOSleep( info_delay );
        
        if( s <= 0 ) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't get size of disk %s\n", diskPath);
            IOSleep( error_delay );
        }
        
        labelSize = VDEV_SKIP_SIZE + VDEV_PHYS_SIZE;
        // Allocate a vdev_label_t-sized buffer to hold data read from disk.

        size = P2ALIGN_TYPED(s, sizeof (vdev_label_t), uint64_t);
        label = (vdev_label_t*)kmem_alloc(sizeof (vdev_label_t), KM_SLEEP);
        
        config = NULL;
        for (l = 0; l < VDEV_LABELS; l++) {
            nvlist_t * bestconfig = 0;
            uint64_t besttxg = 0;
            uint64_t offset, state, txg = 0;
            
            /* read vdev label */
            offset = vdev_label_offset(size, l, 0);
            
            //                if (vdev_disk_iokit_physio(vd_lh, (caddr_t)label,
            //                                           VDEV_SKIP_SIZE + VDEV_PHYS_SIZE, offset, B_READ) != 0) {
            
            
            IOLog("ZFS: vdev_iokit_find_by_guid: Reading from disk %s, %llu, %p, %llu\n", diskPath, offset, buffer, labelSize);
            IOSleep( info_delay );
            
            if( currentDisk->read(this, offset, buffer, NULL,
                                  (UInt64 *) NULL ) != kIOReturnSuccess ) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't read from disk %s\n", diskPath);
                IOSleep( info_delay );
                (void) currentDisk->close(currentDisk->getProvider(),kIOStorageAccessReader);
                nvlist_free(config);
                config = NULL;
                result = false;
                goto nextDisk;
                //continue;
            }
            
            //IOLog("zfs_mountroot: Closing disk %s\n", diskPath);
            //IOSleep( info_delay );
            
            (void) currentDisk->close(currentDisk->getProvider(),kIOStorageAccessReader);
            
            //IOLog("zfs_mountroot: Closed disk %s\n", diskPath);
            //IOSleep( info_delay );
            
            if( buffer->readBytes(0,label,buffer->getLength()) == 0 ) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Failed to copy from memory buffer to label_t\n");
                IOSleep( info_delay );
                result = false;
                goto nextDisk;
            }
            
            IOLog("ZFS: vdev_iokit_find_by_guid: Copied buffer into label %p\n", label);
            IOSleep( info_delay );
            
            if (nvlist_unpack(label->vl_vdev_phys.vp_nvlist,
                              sizeof (label->vl_vdev_phys.vp_nvlist), &config, 0) != 0) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't unpack nvlist label %p\n", label);
                IOSleep( info_delay );
                config = NULL;
                continue;
            }
            IOLog("ZFS: vdev_iokit_find_by_guid: Unpacked nvlist label %p\n", label);
            IOSleep( info_delay );
            
            /* Check the pool_name to see if it matches zfs_boot */
            if ((nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
                                      &pool_name) != 0 || strncmp(pool_name,zfs_pool,strlen(zfs_pool)) ) ) {
                IOLog("zfs_mountroot: Found config for %s, but it didn't match %s\n", pool_name, zfs_pool);
                IOSleep( info_delay );
                nvlist_free(config);
                config = NULL;
                continue;
            }
            IOLog("ZFS: vdev_iokit_find_by_guid: Found config for %s at %s\n", pool_name, diskPath);
            IOSleep( info_delay );
            
            if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
                                     &state) != 0 || state >= POOL_STATE_DESTROYED) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't read pool %s state\n", pool_name);
                IOSleep( info_delay );
                nvlist_free(config);
                config = NULL;
                continue;
            }
            IOLog("ZFS: vdev_iokit_find_by_guid: Pool state %s: %llu\n", pool_name, state);
            IOSleep( info_delay );
            
            if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
                                     &txg) != 0 || txg == 0) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't read pool %s txg number\n", pool_name);
                IOSleep( info_delay );
                nvlist_free(config);
                config = NULL;
                continue;
            }
            
            IOLog("ZFS: vdev_iokit_find_by_guid: Pool txg %s: %llu\n", pool_name, txg);
            IOSleep( info_delay );
            
            if ( txg > besttxg ) {
                nvlist_free(bestconfig);
                besttxg = txg;
                bestconfig = config;
                
                /* Found a valid config, keep looping */
                break;
            }
        }
        
        IOLog("ZFS: vdev_iokit_find_by_guid: Freeing label %p\n", label);
        IOSleep( info_delay );
        
        kmem_free(label, sizeof (vdev_label_t));
        
        if (config == NULL) {
            error = SET_ERROR(EIDRM);
            IOLog("ZFS: vdev_iokit_find_by_guid: Invalid config? %p\n", label);
            IOSleep( error_delay );
        }
        
        if(guid > 0) {
            IOLog("ZFS: vdev_iokit_find_by_guid: guid is '%llu'\n", guid);
            IOSleep( info_delay );
            
            /* Check if the guid matches */
            if ( guid == vd.vdev_guid ) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Found matching disk\n");
                IOSleep( info_delay );
                
                matchedDisk = currentDisk;
                matchedDisk->retain();
            }
            
        } else {
            IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't get bsd name\n");
            IOSleep( error_delay );
        }
        
        allDisks->removeObject(currentDisk);
        currentDisk = 0;
        
        if (matchedDisk)
            break;
    }
    
    if (allDisks) {
        allDisks->release();
        allDisks = 0;
    }
    
    diskIOMedia = <static_cast>(uintptr_t*)matchedDisk;
    matchedDisk = 0;
    
    return (diskIOMedia != NULL);
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
    uintptr_t * matched_disk = 0;
    
    result = vdev_iokit_find_by_path( vd->vdev_path, matched_disk );
    
    if ( !result || !matched_disk )
        result = vdev_iokit_find_by_path( vd->vdev_phys_path, matched_disk );
    
    if ( !result || !matched_disk )
        result = vdev_iokit_find_by_guid( vd->vdev_guid, matched_disk );
    
    vdev_disk = OSDynamicCast( IOMedia, matched_disk );
    
    if ( ! vdev_disk )
        return false;
    
    result = vdev_disk->open(vdev_disk->getProvider(), 0, kIOStorageAccessReaderWriter);
    
    if (result)
        vd->vdev_tsd->vd_iokit_hl = (void *)matched_disk;
    
    return result;
}

bool vdev_iokit_handle_close (vdev_t * vd )
{
    IOMedia * vdev_disk = 0;
    
    if ( !vd || !vd->vdev_tsd )
        return false;
    
    vdev_disk = OSDynamicCast( IOMedia, vd->vdev_tsd->vd_iokit_hl );
    
    if ( ! vdev_disk )
        return false;
    
    vdev_disk->close(vdev_disk->getProvider(), 0);
    
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