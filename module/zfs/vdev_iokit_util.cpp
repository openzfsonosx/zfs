
/*
 * Apple IOKit (c++)
 */
#include <IOKit/IOLib.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#include <sys/vdev_iokit.h>
#include <sys/vdev_impl.h>

/*
 * IOKit C++ functions
 */

#define info_delay 50
#define error_delay 250

extern void vdev_iokit_log( char * logString ) {
    IOLog( "ZFS: vdev log: %s", logString );
}

extern void vdev_iokit_log_ptr( char * logString, void * logPtr ) {
    IOLog( "ZFS: vdev log: %s [%p]", logString, logPtr );
}

extern void vdev_iokit_log_num( char * logString, uint64_t logNum ) {
    IOLog( "ZFS: vdev log: %s %llu", logString, logNum );
}

extern IOService * vdevGetService()
{
    IORegistryIterator * registryIterator = 0;
    OSIterator * newIterator = 0;
    IORegistryEntry * currentEntry = 0;
    OSDictionary * matchDict = 0;
    OSOrderedSet * allServices = 0;
    OSString * entryName = 0;
    IOService * zfs_service = 0;
    
    currentEntry = IORegistryEntry::fromPath( "IOService:/IOResources/net_lundman_zfs_zvol", 0, 0, 0, 0 );
    
    if ( currentEntry ) {
        zfs_service = OSDynamicCast( IOService, currentEntry );
        
        if (zfs_service) {
            currentEntry = 0;
            return zfs_service;
        } else {
            currentEntry->release();
            currentEntry = 0;
        }
    }
    
    IOLog("vdevGetService: zfs_service1? [%p]\n", zfs_service);
    
    matchDict =     IOService::resourceMatching( "net_lundman_zfs_zvol", 0 );
    IOLog("vdevGetService: create resourceMatching matchingDict...\n");
    
    if ( matchDict ) {
//        IOLog("vdevGetService: matchingDict [%p]\n", matchDict);
        
        newIterator = IOService::getMatchingServices(matchDict);
        matchDict->release();
        matchDict = 0;
        
        IOLog("vdevGetService: iterator %p\n", newIterator);
        if( newIterator ) {
            registryIterator = OSDynamicCast(IORegistryIterator, newIterator);
            IOLog("vdevGetService: registryIterator [%p]\n", registryIterator);
            if (registryIterator) {

                zfs_service = OSDynamicCast( IOService, registryIterator->getCurrentEntry() );
                IOLog("vdevGetService: zfs_service-during? [%p]\n", zfs_service);
                
                if (zfs_service)
                    zfs_service->retain();
                
                registryIterator->release();
                registryIterator = 0;
            }
        }
    }
    IOLog("vdevGetService: zfs_service2? [%p]\n", zfs_service);
    
    /* Should be matched, go to plan B if not */
    if (!zfs_service) {
        registryIterator = IORegistryIterator::iterateOver(gIOServicePlane,kIORegistryIterateRecursively);
        IOLog("vdevGetService: registryIterator 2 %p\n", registryIterator);
        if (!registryIterator) {
            IOLog("vdevGetService: couldn't iterate over service plane %p\n", registryIterator);
        } else {
        
            do {
                if(allServices)
                    allServices->release();
                
                allServices = registryIterator->iterateAll();
            } while (! registryIterator->isValid() );
            
            IOLog("vdevGetService: allServices %p\n", allServices);
            registryIterator->release();
            registryIterator = 0;
        }
        
        if (!allServices) {
            IOLog("vdevGetService: couldn't get service list from iterator %p\n", registryIterator);
            return 0;
        }
        
        while( ( currentEntry = OSDynamicCast(IORegistryEntry,
                                              allServices->getFirstObject() ) ) ) {
/*
 if( strncmp("net_lundman_zfs_zvol\0",currentEntry->getName(),
 sizeof("net_lundman_zfs_zvol\0") ) ) {
*/
            if (currentEntry) {
                
                entryName = OSDynamicCast( OSString, currentEntry->copyName() );
                
                if (entryName) {
                    if(entryName->isEqualTo("net_lundman_zfs_zvol") ) {
                        zfs_service = OSDynamicCast( IOService, currentEntry );
                        IOLog("vdevGetService: match: [%p]\n", zfs_service);
                    }
                    entryName->release();
                    entryName = 0;
                }
                
                // Remove from the set
                allServices->removeObject(currentEntry);
                currentEntry = 0;
                
                if (zfs_service) {
                    /* Found service */
                    break;
                }
            }
        }
        
        allServices->release();
        allServices = 0;
    }
    IOLog("vdevGetService: zfs_service 3? [%p] \n", zfs_service);
    
    return zfs_service;

} /* vdevGetService */

/*
 * We want to match on all disks or volumes that
 * do not contain a partition map / raid / LVM
 * - Caller must release the returned object
 */
extern OSOrderedSet * vdev_iokit_get_disks()
{
    IORegistryIterator * registryIterator = 0;
    IORegistryEntry * currentEntry = 0;
    OSOrderedSet * allEntries = 0;
    OSOrderedSet * allDisks = 0;
    OSBoolean * matchBool = 0;
    boolean_t result = false;

    registryIterator = IORegistryIterator::iterateOver( gIOServicePlane,
                                                       kIORegistryIterateRecursively );
    
    if(!registryIterator) {
        IOLog( "ZFS: vdev_iokit_get_disks: could not get ioregistry iterator from IOKit\n");
        registryIterator = 0;
        return 0;
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
            break;
        }
        
        /*
         * XXX - TO DO
         *
         *  Also filter out CoreStorage PVs but not LVMs?
         */
        
        /* Check 'Leaf' property */
        matchBool = OSDynamicCast( OSBoolean, currentEntry->getProperty(kIOMediaLeafKey) );
        
        result =     ( matchBool && matchBool->getValue() == true );
        
        matchBool = 0;
        
        if( result ) {
            allDisks->setLastObject( currentEntry );
        }
        
        /* Remove current item from ordered set */
        allEntries->removeObject( currentEntry );
        
        currentEntry = 0;
    }
    
    if (allEntries)
        allEntries->release();
    allEntries = 0;
    
    return allDisks;
}

/* Returned object will have a reference count and should be released */
extern uintptr_t*
vdev_iokit_find_by_path( vdev_t * vd, char * diskPath )
{
    IOService * zfsProvider = 0;
    OSOrderedSet * allDisks = 0;
    IORegistryEntry * currentDisk = 0;
    IORegistryEntry * matchedDisk = 0;
    //IOBufferMemoryDescriptor* buffer = 0;
    OSObject * bsdnameosobj = 0;
    OSString * bsdnameosstr = 0;
    char * diskName = 0;
    uintptr_t * diskIOMedia = 0;
    
    if ( !vd || !vd->vdev_path ) {
        IOLog( "ZFS: vdev_iokit_find_by_path: called with invalid vd or vdev_path\n" );
        return 0;
    }
    
    zfsProvider = vdevGetService();
    if ( !zfsProvider ) {
        IOLog( "ZFS: vdev_iokit_find_by_path: couldn't locate ZFS IOProvider\n" );
        return 0;
    }
    
    allDisks = vdev_iokit_get_disks();
    
    if (!allDisks) {
        IOLog( "ZFS: vdev_iokit_find_by_path: failed to browse disks\n" );
        return 0;
    }
    
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

    /*
    if( allDisks->getCount() > 0 ) {
        // Lazy allocate, and only if there will be work to do
        buffer = IOBufferMemoryDescriptor::withCapacity(labelSize, kIODirectionIn);
        
        if (buffer == NULL) {
            IOLog("ZFS: vdev_iokit_find_by_path: Couldn't allocate a memory buffer\n");
            IOSleep( error_delay );
            return false;
        }
    }
    */

    while ( allDisks->getCount() > 0 ) {
        
        currentDisk = OSDynamicCast( IORegistryEntry, allDisks->getFirstObject() );
        
        if (!currentDisk)
            break;
        
//        IOLog( "ZFS: vdev_iokit_find_by_path: Getting bsd name\n" );
//        IOSleep( info_delay );
        
        bsdnameosobj =    currentDisk->getProperty(kIOBSDNameKey,
                                                               gIOServicePlane,
                                                               kIORegistryIterateRecursively);
        if(bsdnameosobj)
            bsdnameosstr =    OSDynamicCast(OSString, bsdnameosobj);
        
        if(bsdnameosstr) {
//            IOLog("ZFS: vdev_iokit_find_by_path: bsd name is '%s'\n", bsdnameosstr->getCStringNoCopy());
//            IOSleep( info_delay );
            
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
    
    if (matchedDisk) {
//        IOLog("ZFS: vdev_iokit_find_by_guid: casting matching disk %p\n", matchedDisk);
        diskIOMedia = (uintptr_t*)matchedDisk;
//        IOLog("ZFS: vdev_iokit_find_by_guid: cast matching disk %p\n", diskIOMedia);
        matchedDisk = 0;
    }
    
    if (allDisks) {
        allDisks->release();
        allDisks = 0;
    }
    
    IOLog("ZFS: vdev_iokit_find_by_guid: matched disk %p\n", diskIOMedia);
    return diskIOMedia;
}

/* Returned object will have a reference count and should be released */
extern uintptr_t*
vdev_iokit_find_by_guid( vdev_t * vd )
{
    IOService * zfsProvider = 0;
    OSOrderedSet * allDisks = 0;
    IOMedia * currentDisk = 0;
    IOMedia * matchedDisk = 0;
    uintptr_t * diskIOMedia = 0;
    UInt64 labelSize =  VDEV_SKIP_SIZE + VDEV_PHYS_SIZE;
    IOBufferMemoryDescriptor* buffer = 0;
    nvlist_t * config = 0;
    
    char * diskPath = 0;
    char * diskName = 0;

    uint64_t guid = 0;
    
    char * pool_name = 0;
    vdev_label_t * label = 0;
    uint64_t s = 0, size = 0;
    int l = 0;
    int error = -1;
    boolean_t result = false;
    
    if ( !vd || !vd->vdev_path ) {
        return 0;
    }
    
    zfsProvider = vdevGetService();
    if ( !zfsProvider )
        return 0;
    
    allDisks = vdev_iokit_get_disks();
    
    if (!allDisks)
        return 0;
    
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
            return 0;
        }
    }
    
    while ( allDisks->getCount() > 0 ) {
        currentDisk = OSDynamicCast( IOMedia, allDisks->getFirstObject() );
        
        if (!currentDisk) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Invalid disk\n");
            IOSleep( error_delay );
            result = false;
            goto nextDisk;
        }
        
        IOLog( "ZFS: vdev_iokit_find_by_guid: Getting vdev guid\n" );
//        IOSleep( info_delay );
        
        // Determine whether media device is formatted.
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

        //error = ((IOMedia*)currentDisk)->open(zfsProvider,0,kIOStorageAccessReader);
        result = currentDisk->open(zfsProvider,0,kIOStorageAccessReader);
        
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

        size = P2ALIGN_TYPED(s, sizeof (vdev_label_t), uint64_t);
        label = (vdev_label_t*)kmem_alloc(sizeof (vdev_label_t), KM_PUSHPAGE);
        
        VERIFY(nvlist_alloc(&config, NV_UNIQUE_NAME, KM_SLEEP) == 0);
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
            
            if( currentDisk->read(zfsProvider, offset, buffer, NULL,
                                  (UInt64 *) NULL ) != kIOReturnSuccess ) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't read from disk %s\n", diskPath);
                IOSleep( info_delay );
                (void) currentDisk->close(zfsProvider);
                nvlist_free(config);
                config = NULL;
                result = false;
                goto nextDisk;
                //continue;
            }
            
            //IOLog("zfs_mountroot: Closing disk %s\n", diskPath);
            //IOSleep( info_delay );
            
            (void) currentDisk->close(zfsProvider);
            
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
                                      &pool_name) != 0 )) {
                IOLog("zfs_mountroot: Pool config for %s not found\n", pool_name);
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
            if ( guid == vd->vdev_guid ) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Found matching disk\n");
                IOSleep( info_delay );
                
                matchedDisk = currentDisk;
                matchedDisk->retain();
            }
            
        } else {
            IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't get guid\n");
            IOSleep( error_delay );
        }
        
    nextDisk:
        IOLog("ZFS: vdev_iokit_find_by_guid: nextDisk / cleanup\n");
        IOSleep( info_delay );
        
        /* clean up */
        if(config) {
            nvlist_free(config);
            config = 0;
        }
        
        allDisks->removeObject(currentDisk);
        currentDisk = 0;
        
        if (matchedDisk)
            break;
    }

    if (matchedDisk) {
        IOLog("ZFS: vdev_iokit_find_by_guid: casting matching disk %p\n", matchedDisk);
        diskIOMedia = (uintptr_t*)matchedDisk;
        IOLog("ZFS: vdev_iokit_find_by_guid: casting matching disk %p\n", diskIOMedia);
        matchedDisk = 0;
    }
    
    if( buffer ) {
        buffer->release();
    }
    buffer = 0;
    
    if (allDisks) {
        allDisks->release();
        allDisks = 0;
    }
    
    IOLog("ZFS: vdev_iokit_find_by_guid: matched disk %p\n", diskIOMedia);
    return diskIOMedia;
}


/*
 *  ZFS internal
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C language interfaces
 */

int
vdev_iokit_handle_open (vdev_t * vd, uint64_t *size, uint64_t *max_size, uint64_t *ashift)
{
    IOService * zfsProvider = 0;
    IOMedia * vdev_disk = 0;
    uintptr_t * matched_disk = 0;
    boolean_t result = false;
    uint64_t blksize = 0;
    vdev_iokit_t *dvd = NULL;
IOLog( "vdev_iokit_handle_open: [%p]:(%llu,%llu,%llu)\n", vd, *size, *max_size, *ashift );
    zfsProvider = vdevGetService();
    if ( !zfsProvider )
        return EINVAL;
    
	dvd = (vdev_iokit_t*)kmem_zalloc(sizeof (vdev_iokit_t), KM_SLEEP);
    
    if (dvd == NULL)
        return EINVAL;
	
    vd->vdev_nowritecache = B_FALSE;
    
    IOLog("ZFS: vdev_iokit_handle_open: Trying by path\n");
    matched_disk = vdev_iokit_find_by_path( vd, vd->vdev_path );
    IOLog("ZFS: vdev_iokit_handle_open: found %p\n", matched_disk);
    if ( !matched_disk ) {
        IOLog("ZFS: vdev_iokit_handle_open: Trying by physpath\n");
        matched_disk = vdev_iokit_find_by_path( vd, vd->vdev_physpath );
        IOLog("ZFS: vdev_iokit_handle_open: found %p\n", matched_disk);
    }
    
    if ( !matched_disk ) {
        IOLog("ZFS: vdev_iokit_handle_open: Trying by guid\n");
        matched_disk = vdev_iokit_find_by_guid( vd );
        IOLog("ZFS: vdev_iokit_handle_open: found %p\n", matched_disk);
    }
    
    if( !matched_disk ) {
        IOLog("ZFS: vdev_iokit_handle_open: Did not find a matching disk\n");
        goto error;
    }
    
    vdev_disk = (IOMedia *)matched_disk;
    
    if ( ! vdev_disk ) {
        IOLog("ZFS: vdev_iokit_handle_open: Couldn't cast matched_disk to vdev_disk\n");
        goto error;
    }
    
    /* Check if the media is in use */
    result = vdev_disk->isOpen(0);
    
    if (result == true) {
        IOLog("ZFS: vdev_iokit_handle_open: Disk is already open\n");
        goto error;
    }
    
    blksize =           vdev_disk->getPreferredBlockSize();
    if (blksize <= 0) {
        IOLog("ZFS: vdev_iokit_handle_open: Couldn't get blocksize %u %p\n", result, matched_disk);
        blksize = SPA_MINBLOCKSIZE;
    }
    
    dvd->vd_ashift =    highbit(MAX(blksize, SPA_MINBLOCKSIZE)) - 1;
    IOLog("ZFS: vdev_iokit_handle_open: ashift %llu\n", dvd->vd_ashift);
    
    *size =             vdev_disk->getSize();
    IOLog("ZFS: vdev_iokit_handle_open: size %llu\n", *size);
    /*
     * XXX - TO DO
     *  Read-only vdev/pool access
     *      kIOStorageAccessReader
     */
    
    result = vdev_disk->open(zfsProvider, 0, kIOStorageAccessReaderWriter);
    IOLog("ZFS: vdev_iokit_handle_open: open: %u\n", result);
    
    if (result) {
        IOLog("ZFS: vdev_iokit_handle_open: success\n");
        dvd->vd_iokit_hl = (uintptr_t *)matched_disk;
        dvd->vd_client_hl = (uintptr_t *)zfsProvider;
        
        vd->vdev_tsd = dvd;
    } else {
        IOLog("ZFS: vdev_iokit_handle_open: fail\n");
        goto error;
    }

    if (result)
        return 0;
    else
        return EINVAL;
    
error:
    zfsProvider = 0;
    vdev_disk = 0;
    matched_disk = 0;
    
    if (dvd) {
        dvd->vd_iokit_hl = 0;
        dvd->vd_client_hl = 0;
        kmem_free(dvd, sizeof (vdev_iokit_t));
        dvd = 0;
    }
    
    return EINVAL;
}

int
vdev_iokit_handle_close (vdev_t * vd )
{
    IOService * zfsProvider = 0;
    IOMedia * vdev_disk = 0;
    vdev_iokit_t * dvd = 0;
IOLog( "vdev_iokit_handle_close: [%p]\n", vd );
    if ( !vd || !vd->vdev_tsd )
        return EINVAL;
    
    dvd =           (vdev_iokit_t *)(vd->vdev_tsd);

    vdev_disk =     (IOMedia *)(dvd->vd_iokit_hl);
    
    if ( ! vdev_disk )
        return EINVAL;

    zfsProvider =   (IOService *)(dvd->vd_client_hl);
    if ( !zfsProvider )
        return EINVAL;
    
    /* Close the user client handle */
    vdev_disk->close(zfsProvider, 0);
    
    /* clean up */
    zfsProvider = 0;
    vdev_disk = 0;
    
    if (dvd) {
        dvd->vd_iokit_hl = 0;
        dvd->vd_client_hl = 0;
        kmem_free(dvd, sizeof (vdev_iokit_t));
        dvd = 0;
    }
    
    return 0;
}

int
vdev_iokit_ioctl( vdev_t * vd, zio_t * zio )
{
    /*
     * XXX - TO DO
     *  multiple IOctls / passthrough
     *
     *  Flush cache
     *   IOMedia::synchronizeCache(IOService * client);
     */
    IOService * zfsProvider = 0;
    IOMedia * vdev_disk = 0;
    vdev_iokit_t * dvd = 0;
IOLog( "vdev_iokit_ioctl: [%p] [%p]\n", vd, zio );
    if ( !vd || !vd->vdev_tsd )
        return EINVAL;
    
    dvd =           (vdev_iokit_t *)(vd->vdev_tsd);
    
    vdev_disk =     (IOMedia *)(dvd->vd_iokit_hl);
    
    if ( ! vdev_disk )
        return EINVAL;

    zfsProvider =   (IOService *)(dvd->vd_client_hl);
    if ( !zfsProvider )
        return EINVAL;
    
    /*
     *  Handle ioctl
     */

    zfsProvider = 0;
    
    return 0;
}
    
int vdev_iokit_sync( vdev_t * vd, zio_t * zio )
{
    uint64_t timeout =     5000000000; // 5 * 10^3 nanoseconds
    int result = EINVAL;
    
IOLog( "vdev_iokit_sync: [%p] [%p]\n", vd, zio );
    
    if (vd && vd->vdev_tsd && vd->vdev_tsd) {
        
        vdev_iokit_t * dvd = static_cast<vdev_iokit_t *>(vd->vdev_tsd);
        
        if (dvd && dvd->vd_iokit_hl) {
            
            IOService * diskIOMedia = (IOService *)(dvd->vd_iokit_hl);
            
            if (diskIOMedia) {
IOLog( "vdev_iokit_sync: do sync\n" );
                result = diskIOMedia->waitQuiet( timeout );
IOLog( "vdev_iokit_sync: done [%d]\n", result );
                if ( result == kIOReturnTimeout ) {
                    result = ETIMEDOUT;
                } else {
                    result = 0;
                }
            }
        }
    }
    
    return result;
}

int
vdev_iokit_strategy( vdev_t * vd, zio_t * zio )
{
    IOService * zfsProvider = 0;
    vdev_io_context_t * io_context = 0;
    IOMedia * vdev_disk = 0;
	vdev_iokit_t *dvd = 0;
IOLog( "vdev_iokit_strategy: [%p] [%p]\n", vd, zio );
    if (!vd || !zio)
        return EINVAL;
    
    dvd =   (vdev_iokit_t *)(vd->vdev_tsd);
    
    if (!dvd)
        return EINVAL;
    
    vdev_disk = (IOMedia *)(dvd->vd_iokit_hl);
    
    if(!vdev_disk)
        return EINVAL;
    
	ASSERT(zio->io_data != NULL);
	ASSERT(zio->io_size != 0);
    
    zfsProvider =   (IOService *)(dvd->vd_client_hl);

    if ( !zfsProvider )
        return EINVAL;
    
    /* Lazy allocate, and only if there will be work to do.
        Allocate buffer on zio mapped range
        Also the StorageCompletion struct
     
     bp = buf_alloc(dvd->vd_devvp);
     
     ASSERT(bp != NULL);
     
     buf_setdataptr(bp, (uintptr_t)zio->io_data);
     
     buf_setsize(bp, zio->io_size);
     
     buf_setcount(bp, zio->io_size);
     
     flags = (zio->io_type == ZIO_TYPE_READ ? B_READ : B_WRITE);
        //flags |= B_NOCACHE;
     ( ( zio->io_type == ZIO_TYPE_READ ) ? kIOMemoryDirectionIn : kIOMemoryDirectionOut );
     
     */
    
    io_context =            (vdev_io_context_t*)kmem_alloc(sizeof(vdev_io_context_t), KM_PUSHPAGE);
    io_context->zio =       zio;
    
    io_context->buffer =    (IOBufferMemoryDescriptor*)IOBufferMemoryDescriptor::withAddress( zio->io_data, zio->io_size,
                                          (zio->io_type == ZIO_TYPE_WRITE ? kIODirectionOut : kIODirectionIn) );
    
    if (io_context->buffer == NULL) {
        IOLog("ZFS: vdev_iokit_strategy: Couldn't allocate a memory buffer\n");
        IOSleep( error_delay );
        return ENOMEM;
    }
    
    /*
     typedef struct vdev_io_context {
         IOMemoryDescriptor *    buffer;
         zio_t *                 zio;
         IOStorageCompletion     completion;
     } vdev_io_context_t;
     */
    
    io_context->completion.target = 0;
    io_context->completion.parameter = io_context;
    io_context->completion.action =  (IOStorageCompletionAction) &vdev_iokit_io_intr;
    
#if 0   /*  Disabled  */
    /*  Calculate physical / logical block number  */
    if (zfs_iokit_vdev_ashift && vd->vdev_ashift) {
        /*
         *  buf_setlblkno(bp, zio->io_offset>>vd->vdev_ashift);
         *  buf_setblkno(bp,  zio->io_offset>>vd->vdev_ashift);
         */
    } else {
        /*
         *  buf_setlblkno(bp, lbtodb(zio->io_offset));
         *  buf_setblkno(bp, lbtodb(zio->io_offset));
         */
    }
#endif
    
    /*  Set flags for the transfer  */
    /*
     
     if (zio->io_flags & ZIO_FLAG_FAILFAST)
     flags |= B_FAILFAST;
     
     buf_setflags(bp, flags);
     
     */

    /* Set async callback */
//    if (zio->io_flags & ZIO_FLAG_FAILFAST) {
        
        /*  callback -> async  */
        
        /*
         struct IOStorageCompletion {
             void *target;
             IOStorageCompletionAction action;
             void *parameter;
         };
         
         Fields
         
         target
             Opaque client-supplied pointer (or an instance pointer for a C++ callback).
         action
             Completion routine to call on completion of the data transfer.
         parameter
             Opaque client-supplied pointer.
         
         Discussion
             The IOStorageCompletion structure describes the C (or C++) completion routine that is called once an asynchronous storage operation completes. The values passed for the target and parameter fields will be passed to the routine when it is called.
         
         Availability
             Available in OS X v10.6 and later.
         Declared In
             IOStorage.h
         
         IOStorageCompletionAction
         typedef void ( *IOStorageCompletionAction ) (
             void *target,
             void *parameter,
             IOReturn status,
             UInt64 actualByteCount
         );
         
         Parameters
         
         target
             Opaque client-supplied pointer (or an instance pointer for a C++ callback).
         parameter
             Opaque client-supplied pointer.
         status
             Status of the data transfer.
         actualByteCount
             Actual number of bytes transferred in the data transfer.
         
         Discussion
             The IOStorageCompletionAction declaration describes the C (or C++) completion routine that is called once an asynchronous storage operation completes.
         
         Availability
             Available in OS X v10.6 and later.
         Declared In
             IOStorage.h
         */
        
//    } else {
        
        /*  callback -> sync  */
        /*
         if (buf_setcallback(bp, vdev_iokit_io_intr, zio) != 0)
         panic("vdev_iokit_io_start: buf_setcallback failed\n");
         */
//    }
    
    /* Start the transfer */
    /*
     if (zio->io_type == ZIO_TYPE_WRITE) {
     vnode_startwrite(dvd->vd_devvp);
     }
     error = VNOP_STRATEGY(bp);
     */

IOLog( "vdev_iokit_strategy: starting op [%p] [%p]\n", vd, zio );
    if (zio->io_type == ZIO_TYPE_WRITE) {
IOLog( "vdev_iokit_strategy: write (%llu,%llu)\n", zio->io_offset, zio->io_size );
        vdev_disk->IOMedia::write(zfsProvider, zio->io_offset, io_context->buffer, 0, &(io_context->completion) );
    } else {
IOLog( "vdev_iokit_strategy: read (%llu,%llu)\n", zio->io_offset, zio->io_size );
        vdev_disk->IOMedia::read(zfsProvider, zio->io_offset, io_context->buffer, 0, &(io_context->completion) );
    }
    /*
    read / write
     
    virtual void read(  IOService *client, UInt64 byteStart, IOMemoryDescriptor *buffer,
                        IOStorageAttributes *attributes, IOStorageCompletion *completion);
     
    virtual void write( IOService *client, UInt64 byteStart, IOMemoryDescriptor *buffer,
                        IOStorageAttributes *attributes, IOStorageCompletion *completion);
     
    Parameters
     
    client
        Client requesting the read / write.
    byteStart
        Starting byte offset for the data transfer.
    buffer
        Buffer for the data transfer. The size of the buffer implies the size of the data transfer.
    attributes
        Attributes of the data transfer. See IOStorageAttributes. It is the responsibility of the callee to maintain the information for the duration of the data transfer, as necessary.
    completion
        Completion routine to call once the data transfer is complete. It is the responsibility of the callee to maintain the information for the duration of the data transfer, as necessary.
     
    Discussion
        Read / write data from the storage object at the specified byte offset into / out of the specified buffer, asynchronously. When the operation completes, the caller will be notified via the specified completion action.
        The buffer will be retained for the duration of the read / write.
     */
    
    return 0;
}
    
extern void vdev_iokit_io_intr( void * target, void * parameter, kern_return_t status, UInt64 actualByteCount )
{
    vdev_io_context_t * io_context = 0;
    zio_t * zio = 0;
    
IOLog( "vdev_iokit_io_intr: [%p] [%p] (%d, %llu)\n", target, parameter, status, actualByteCount );
    
    io_context =        static_cast<vdev_io_context_t*>(parameter);
    
    if(!io_context) {
        zio_interrupt(NULL);
        return;
    }
    
    if(!io_context->zio) {
        zio_interrupt(NULL);
        return;
    }
    
    zio =   io_context->zio;
    
//    if (zio->io_flags & ZIO_FLAG_FAILFAST) {
//
//    }
    
    if (io_context) {
        if (io_context->buffer) {
            io_context->buffer->release();
            io_context->buffer = 0;
        }
        io_context->zio = 0;

        kmem_free(io_context,sizeof(io_context));
    }
    
    if( status != 0 )
        zio->io_error = EIO;
    
	//zio_next_stage_async(zio);
    zio_interrupt(zio);
    
    return;
}

#ifdef __cplusplus
}   /* extern "C" */
#endif