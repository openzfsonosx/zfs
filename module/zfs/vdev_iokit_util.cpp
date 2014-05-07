
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
    IOLog( "ZFS: vdev log: %s\n", logString );
}

extern void vdev_iokit_log_ptr( char * logString, void * logPtr ) {
    IOLog( "ZFS: vdev log: %s [%p]\n", logString, logPtr );
}

extern void vdev_iokit_log_num( char * logString, uint64_t logNum ) {
    IOLog( "ZFS: vdev log: %s (%llu)\n", logString, logNum );
}

void vdev_iokit_context_alloc( zio_t * zio )
{
    vdev_iokit_context_t * io_context = 0;
    
vdev_iokit_log_ptr( "vdev_iokit_context_alloc: zio", zio );
    
    if (!zio)
        return;
    
    io_context = zio->io_tsd =    kmem_alloc(sizeof(vdev_iokit_context_t), KM_PUSHPAGE);
    
    io_context->
}

void vdev_iokit_context_free( zio_t * zio )
{
    vdev_iokit_context_t * io_context = 0;
    
vdev_iokit_log_ptr( "vdev_iokit_context_free: zio", zio );
    
    if (!zio)
        return;
    
    io_context =        static_cast<vdev_iokit_context_t*>(zio->io_tsd);
    
    if(!io_context)
        return;
    
    //    if (zio->io_flags & ZIO_FLAG_FAILFAST) {
    //
    //    }
    
    if (io_context) {

        if (io_context->buffer) {
            io_context->buffer->release();
            io_context->buffer = 0;
        }
        
        kmem_free(io_context,sizeof(io_context));
    }
    
    io_context = 0;
    
    return;
}

extern IOService * vdev_iokit_get_service_hl()
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
    
    IOLog("vdev_iokit_get_service_hl: zfs_service1? [%p]\n", zfs_service);
    
    matchDict =     IOService::resourceMatching( "net_lundman_zfs_zvol", 0 );
    IOLog("vdev_iokit_get_service_hl: create resourceMatching matchingDict...\n");
    
    if ( matchDict ) {
//        IOLog("vdevGetService: matchingDict [%p]\n", matchDict);
        
        newIterator = IOService::getMatchingServices(matchDict);
        matchDict->release();
        matchDict = 0;
        
        IOLog("vdev_iokit_get_service_hl: iterator %p\n", newIterator);
        if( newIterator ) {
            registryIterator = OSDynamicCast(IORegistryIterator, newIterator);
            IOLog("vdev_iokit_get_service_hl: registryIterator [%p]\n", registryIterator);
            if (registryIterator) {

                zfs_service = OSDynamicCast( IOService, registryIterator->getCurrentEntry() );
                IOLog("vdev_iokit_get_service_hl: zfs_service-during? [%p]\n", zfs_service);
                
                if (zfs_service)
                    zfs_service->retain();
                
                registryIterator->release();
                registryIterator = 0;
            }
        }
    }
    IOLog("vdev_iokit_get_service_hl: zfs_service2? [%p]\n", zfs_service);
    
    /* Should be matched, go to plan B if not */
    if (!zfs_service) {
        registryIterator = IORegistryIterator::iterateOver(gIOServicePlane,kIORegistryIterateRecursively);
        IOLog("vdev_iokit_get_service_hl: registryIterator 2 %p\n", registryIterator);
        if (!registryIterator) {
            IOLog("vdev_iokit_get_service_hl: couldn't iterate over service plane %p\n", registryIterator);
        } else {
        
            do {
                if(allServices)
                    allServices->release();
                
                allServices = registryIterator->iterateAll();
            } while (! registryIterator->isValid() );
            
            IOLog("vdev_iokit_get_service_hl: allServices %p\n", allServices);
            registryIterator->release();
            registryIterator = 0;
        }
        
        if (!allServices) {
            IOLog("vdev_iokit_get_service_hl: couldn't get service list from iterator %p\n", registryIterator);
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
                        zfs_service->retain();
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
    IOLog("vdev_iokit_get_service_hl: zfs_service 3? [%p] \n", zfs_service);
    
    return zfs_service;

} /* vdev_iokit_get_service_hl */

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
int vdev_iokit_find_by_path(vdev_t * vd, char * diskPath)
{
    OSOrderedSet * allDisks = 0;
    IORegistryEntry * currentDisk = 0;
    IORegistryEntry * matchedDisk = 0;
    //IOBufferMemoryDescriptor* buffer = 0;
    OSObject * bsdnameosobj = 0;
    OSString * bsdnameosstr = 0;
    char * diskName = 0;
    uintptr_t * diskIOMedia = 0;
    vdev_iokit_t * dvd = 0;
    
    if ( !vd || !diskPath ) {
        IOLog( "ZFS: vdev_iokit_find_by_path: called with invalid vd or diskPath\n" );
        return EINVAL;
    }
    
    allDisks = vdev_iokit_get_disks();
    
    if (!allDisks) {
        IOLog( "ZFS: vdev_iokit_find_by_path: failed to browse disks\n" );
        return EINVAL;
    }
    
    dvd = vd->vdev_tsd;
    
    if (!dvd)
        return EINVAL;
    
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
//                IOSleep( info_delay );
                
                matchedDisk = currentDisk;
                matchedDisk->retain();
            }
            
        } else {
            IOLog("ZFS: vdev_iokit_find_by_path: Couldn't get bsd name\n");
//            IOSleep( error_delay );
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
    
    IOLog("ZFS: vdev_iokit_find_by_path: matched disk %p\n", diskIOMedia);
    
    dvd->vd_iokit_hl =      diskIOMedia;
    
    return (diskIOMedia != 0);
}

/* Returned object will have a reference count and should be released */
int vdev_iokit_find_by_guid( vdev_t * vd )
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
    
    vdev_iokit_t * dvd = 0;
    
    if ( !vd || !vd->vdev_path )
        return EINVAL;
    
    dvd = vd->vdev_tsd;
    
    if (!dvd)
        return EINVAL;
    
    zfsProvider = dvd->vd_zfs_hl;
    if ( !zfsProvider )
        return EINVAL;
    
    allDisks = vdev_iokit_get_disks();
    
    if (!allDisks)
        goto nextDisk;
    
    if( allDisks->getCount() > 0 ) {
        /* Lazy allocate, and only if there will be work to do */
        buffer = IOBufferMemoryDescriptor::withCapacity(labelSize, kIODirectionIn);
        
        if (buffer == NULL) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't allocate a memory buffer\n");
//            IOSleep( error_delay );
            goto nextDisk;
        }
    }
    
    while ( allDisks->getCount() > 0 ) {
        currentDisk = OSDynamicCast( IOMedia, allDisks->getFirstObject() );
        
        if (!currentDisk) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Invalid disk\n");
//            IOSleep( error_delay );
            result = false;
            goto nextDisk;
        }
        
        IOLog( "ZFS: vdev_iokit_find_by_guid: Getting vdev guid\n" );
//        IOSleep( info_delay );
        
        // Determine whether media device is formatted.
        if ( currentDisk->isFormatted() != true ) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Disk %s not formatted\n", diskPath);
//            IOSleep( error_delay );
            result = false;
            goto nextDisk;
        }
        
        if ( currentDisk->isOpen(zfsProvider) ) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Disk %s is already open!\n", diskPath);
        }
        
    IOLog("ZFS: vdev_iokit_find_by_guid: Issuing open...\n", diskPath);
        //error = ((IOMedia*)currentDisk)->open(zfsProvider,0,kIOStorageAccessReader);
        result = currentDisk->open(zfsProvider,0,kIOStorageAccessReader);
        
        /* If the disk could not be opened, skip to the next one */
        if (!result) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Disk %s couldn't be opened for reading\n", diskPath);
//            IOSleep( error_delay );
            result = false;
            goto nextDisk;
        }
        
        /* Get size */
        s = currentDisk->getSize();
        
        if( s <= 0 ) {
            IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't get size of disk %s\n", diskPath);
//            IOSleep( error_delay );
        }

        size = P2ALIGN_TYPED(s, sizeof (vdev_label_t), uint64_t);
        label = (vdev_label_t*)kmem_alloc(sizeof (vdev_label_t), KM_SLEEP);
        
        VERIFY(nvlist_alloc(&config, NV_UNIQUE_NAME, KM_SLEEP) == 0);
        for (l = 0; l < VDEV_LABELS; l++) {
            nvlist_t * bestconfig = 0;
            uint64_t besttxg = 0;
            uint64_t offset, state, txg = 0;
            
            /* read vdev label */
            offset = vdev_label_offset(size, l, 0);
            
            /* If label is outside disk boundaries, we're done */
            if (offset > s)
                break;
            
            IOLog("ZFS: vdev_iokit_find_by_guid: Reading from disk %s, %llu, %p, %llu\n", diskPath, offset, buffer, labelSize);
            
            if( currentDisk->read(zfsProvider, offset, buffer, NULL,
                                  (UInt64 *) NULL ) != kIOReturnSuccess ) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't read from disk %s\n", diskPath);
                (void) currentDisk->close(zfsProvider);
                if (config) {
                    nvlist_free(config);
                    config = NULL;
                }
                result = false;
                goto nextDisk;
                //continue;
            }
            
            (void) currentDisk->close(zfsProvider);
            
            /* Return Value - The number of bytes copied */
            if( buffer->readBytes(0,label,buffer->getLength()) == 0 ) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Failed to copy from memory buffer to label_t\n");
                result = false;
                continue;
            }
            
            IOLog("ZFS: vdev_iokit_find_by_guid: Copied buffer into label %p\n", label);
            
            if (nvlist_unpack(label->vl_vdev_phys.vp_nvlist,
                              sizeof (label->vl_vdev_phys.vp_nvlist), &config, 0) != 0) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't unpack nvlist label %p\n", label);
                config = NULL;
                continue;
            }
            IOLog("ZFS: vdev_iokit_find_by_guid: Unpacked nvlist label %p\n", label);
            
            /* Check the pool_name */
            if ((nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
                                      &pool_name) != 0 )) {
                IOLog("zfs_mountroot: Pool config for %s not found\n", pool_name);
                nvlist_free(config);
                config = NULL;
                continue;
            }
            IOLog("ZFS: vdev_iokit_find_by_guid: Found config for %s at %s\n", pool_name, diskPath);
            
            if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
                                     &state) != 0 || state >= POOL_STATE_DESTROYED) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't read pool %s state\n", pool_name);
                nvlist_free(config);
                config = NULL;
                continue;
            }
            IOLog("ZFS: vdev_iokit_find_by_guid: Pool state %s: %llu\n", pool_name, state);
            
            if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
                                     &txg) != 0 || txg == 0) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't read pool %s txg number\n", pool_name);
                nvlist_free(config);
                config = NULL;
                continue;
            }
            
            IOLog("ZFS: vdev_iokit_find_by_guid: Pool txg %s: %llu\n", pool_name, txg);
            
            if ( txg > besttxg ) {
                nvlist_free(bestconfig);
                besttxg = txg;
                bestconfig = config;
                
                /* Found a valid config */
                break;
            }
        }
        
        IOLog("ZFS: vdev_iokit_find_by_guid: Freeing label %p\n", label);
        
        kmem_free(label, sizeof (vdev_label_t));
        
        if (config == NULL) {
            error = SET_ERROR(EIDRM);
            IOLog("ZFS: vdev_iokit_find_by_guid: Invalid config? %p\n", label);
        }
        
        if(guid > 0) {
            IOLog("ZFS: vdev_iokit_find_by_guid: guid is '%llu'\n", guid);
            
            /* Check if the guid matches */
            if ( guid == vd->vdev_guid ) {
                IOLog("ZFS: vdev_iokit_find_by_guid: Found matching disk\n");
                
                matchedDisk = currentDisk;
                matchedDisk->retain();
            }
            
        } else {
            IOLog("ZFS: vdev_iokit_find_by_guid: Couldn't get guid\n");
        }
        
        IOLog("ZFS: vdev_iokit_find_by_guid: nextDisk / cleanup\n");
        
        /* clean up */
        if(config) {
            nvlist_free(config);
            config = 0;
        }
        
        allDisks->removeObject(currentDisk);
        currentDisk = 0;
        
        if (matchedDisk) {
            dvd->vd_iokit_hl = matchedDisk;
            return 0;
        }
        
        return EINVAL;
    }
    
    nextDisk:
    
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
    
    if (zfsProvider) {
        zfsProvider->release();
        zfsProvider = 0;
    }

    IOLog("ZFS: vdev_iokit_find_by_guid: matched disk %p\n", diskIOMedia);
    return diskIOMedia;
}

extern int vdev_iokit_physpath(vdev_t * vd, char * physpath)
{
    vdev_iokit_t * dvd = 0;
    IOMedia * diskIOMedia = 0;
    
    if (!vd !! !physpath)
        return EINVAL;
    
    dvd = static_cast<vdev_iokit_t *>(vd->vdev_tsd);
    
    if (!dvd || !dvd->vd_iokit_hl)
        return EINVAL;

    diskIOMedia = (IOMedia *)dvd->vd_iokit_hl;

    if (!diskIOMedia)
        return EINVAL;
    
    /* Get the 'Content' description from IOKit
     * Content Hint - set at creation time
     * Content - can be updated after creation,
     *   more accurate
     * In the case of GUID partitions, this is a
     *   GPT UUID
     * However APM and MBR, and a real whold-disk
     *   vdev, will not have Content filled.
     */
    physpath =  diskIOMedia->getContent();
    
    /* If there isn't a hint and it is not Apple_HFS */
    if (strlen(physpath) > 1 && strncmp("Apple_HFS", physpath,10) != 0 )
        return 0;
    
    /* Re-use the current path */
    physpath = sprintf( "%s", vd->vdev_path );
    return 0;
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
vdev_iokit_handle_open(vdev_t * vd, uint64_t *size, uint64_t *max_size, uint64_t *ashift)
{
    IOService * zfsProvider = 0;
    IOMedia * vdev_disk = 0;
    uintptr_t * matched_disk = 0;
    boolean_t result = false;
    uint64_t blksize = 0;
    vdev_iokit_t *dvd = 0;
    int error = 0;
    
IOLog( "vdev_iokit_handle_open: [%p]:(%llu,%llu,%llu)\n", vd, *size, *max_size, *ashift );
    
    if (!vd || !vd->vdev_tsd)
        return EINVAL;
    
    dvd = static_cast<vdev_iokit_t *>(vd->vdev_tsd);
    
    if (!dvd)
        return EINVAL;
    
    zfsProvider = dvd->vd_zfs_hl;
    
    if ( !zfsProvider )
        return EINVAL;
    
    if (vd && vd->vdev_tsd) {
        
    
        /* If re-opening a disk, skip the IOKit
         * open and just recheck disk size */
        if (!(dvd->vd_is_open) || !(dvd->vd_iokit_hl) ) {
			/*
			 * If we are opening a device in its offline notify
			 * context, the LDI handle was just closed. Clean
			 * up the LDI event callbacks and free vd->vdev_tsd.
			 */
			vdev_iokit_free(dvd);
		} else {
			ASSERT(vd->vdev_reopening);
			goto skipopen;
		}
        
        if( vd->vdev_reopening ) {
            goto skipopen;
        }
        
    }
    
    if (!dvd) {
        dvd = (vdev_iokit_t*)kmem_zalloc(sizeof (vdev_iokit_t), KM_SLEEP);
    }
    
    if (dvd == NULL) {
        error = EINVAL;
        goto error;
    }
    
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
        error = EINVAL;
        goto error;
    }
    
    vdev_disk = (IOMedia *)matched_disk;
    
    if ( ! vdev_disk ) {
        IOLog("ZFS: vdev_iokit_handle_open: Couldn't cast matched_disk to vdev_disk\n");
        error = EINVAL;
        goto error;
    }
    
    /* Specify that the iokit handle
     * should be kept open
     */
//    dvd->vd_keep_open = true;
    
    /* Check if the media is in use
     * update vd_is_open while here
     */
    result = dvd->vd_is_open = vdev_disk->isOpen(zfsProvider);
    
    if (result == true) {
        IOLog("ZFS: vdev_iokit_handle_open: Disk is already open\n");
        goto skipopen;
    }

    /*
     * XXX - TO DO
     *  Read-only vdev/pool access
     *      kIOStorageAccessReader
     */

    if (!dvd->vd_is_open) {
        result = vdev_disk->open(zfsProvider, 0, kIOStorageAccessReaderWriter);
        IOLog("ZFS: vdev_iokit_handle_open: open: %u\n", result);
        if (result == 1) {
            (void) vdev_disk->makeUsable();
            (void) vdev_disk->waitQuiet();
        }

        dvd->vd_is_open = true;
    } else {
        IOLog("ZFS: vdev_iokit_handle_open: vd_is_open was already true, didn't open: %u\n", result);
    }
    
skipopen:
    
    *size =             vdev_disk->getSize();
    IOLog("ZFS: vdev_iokit_handle_open: size %llu\n", *size);
    
    blksize =           vdev_disk->getPreferredBlockSize();
    if (blksize <= 0) {
        IOLog("ZFS: vdev_iokit_handle_open: Couldn't get blocksize %u %p\n", result, matched_disk);
        blksize = SPA_MINBLOCKSIZE;
    }
    
    *ashift = dvd->vd_ashift =    highbit(MAX(blksize, SPA_MINBLOCKSIZE)) - 1;
    IOLog("ZFS: vdev_iokit_handle_open: ashift %llu\n", dvd->vd_ashift);
    
    vd->vdev_nowritecache = B_FALSE;
    
    if (result == 1) {
        IOLog("ZFS: vdev_iokit_handle_open: success\n");
        dvd->vd_iokit_hl = (uintptr_t *)matched_disk;
        dvd->vd_client_hl = (uintptr_t *)zfsProvider;
        
        /* If there is a different iokit_t, clean it up */
        if ( vd->vdev_tsd && ( vd->vdev_tsd != (void*)dvd ) ) {
            vdev_iokit_free( static_cast<vdev_iokit_t*>(vd->vdev_tsd) );
        }
            
        vd->vdev_tsd = dvd;
    } else {
        IOLog("ZFS: vdev_iokit_handle_open: fail\n");
        error = EINVAL;
        goto error;
    }
    
error:
    if (error) {
        if (matched_disk)
            ((OSObject*)matched_disk)->release();
        
        if (zfsProvider)
            zfsProvider->release();
        
        vdev_iokit_free(dvd);
        
        return error;
    }

    zfsProvider = 0;
    vdev_disk = 0;
    matched_disk = 0;
    
    /* Success */
    return 0;
}

int
vdev_iokit_handle_close(vdev_t * vd )
{
    IOService * zfsProvider = 0;
    IOMedia * vdev_disk = 0;
    vdev_iokit_t * dvd = 0;
IOLog( "vdev_iokit_handle_close: [%p]\n", vd );
    if ( !vd || !vd->vdev_tsd ) {
IOLog( "vdev_iokit_handle_close: invalid vd or vdev_tsd [%p]\n", vd );
        return EINVAL;
    }
    
    dvd =           static_cast<vdev_iokit_t *>(vd->vdev_tsd);
    
    if (vd->vdev_reopening || dvd == NULL)
		return 0;
    
    zfsProvider =   (IOService *)(dvd->vd_client_hl);
    
    if ( !zfsProvider ) {
        IOLog( "vdev_iokit_handle_close: invalid zfsProvider [%p]\n", zfsProvider );
        return EINVAL;
    }

    vdev_disk =     (IOMedia *)(dvd->vd_iokit_hl);

    if ( vdev_disk ) {
        /* Close the user client handle */
        vdev_disk->close(zfsProvider, 0);
        (void) vdev_disk->waitQuiet();
        vdev_disk->release();
        vdev_disk = 0;
        
        dvd->vd_is_open = false;
        dvd->vd_iokit_hl = 0;
    }

    /* Reset keep_open flag */
//    dvd->vd_keep_open = false;
    
IOLog( "vdev_iokit_handle_close: finished\n" );
    /* clean up */
    if (zfsProvider) {
        zfsProvider->release();
        zfsProvider = 0;
    }
    vdev_disk = 0;
    
    vdev_iokit_free(dvd);
    
    return 0;
}
    
    
/*
 * Release an IOKit handle.  Call handle_close on last
 * reference or decrement reference count.
 *
 * To avoid race conditions, the v_count is left at 1 for
 * the call to handle_close. This prevents another thread
 * from reclaiming the handle *before* the handle_close
 * routine has a chance to destroy the handle.
 * We can't have more than 1 thread calling handle_close
 * on an IOKit handle.
 */
void
vdev_iokit_hl_rele(vdev_t * vd)
{
    vdev_iokit_t * dvd = 0;
    IOMedia * diskIOMedia = 0;
    
    if (!vd)
        return;
    
    dvd = vd->vdev_tsd;
    
    if (!dvd)
        return;
    
    diskIOMedia = (IOMedia *)dvd->vd_iokit_hl;
    
    VERIFY( dvd->vd_count > 1 );
    dvd->vd_count--;
    
    VERIFY( diskIOMedia->isOpen(dvd->vd_zfs_hl) != 0 );
    
    /*
     mutex_enter(&vp->v_lock);
     */
    
    if ( dvd->vd_count == 1 &&
         diskIOMedia->lockPhysicalExtents(dvd->vd_zfs_hl) ) {
        
        diskIOMedia->close(dvd->vd_zfs_hl, 0);
        
        diskIOMedia->unlockPhysicalExtents(dvd->vd_zfs_hl);
    }
}

int
iokit_hl_from_path(vdev_t * vd)
{
    vdev_iokit_t * dvd = 0;
    
    /* This should be called with no vdev_tsd */
    if (!vd || vd->vdev_tsd != 0)
        return EINVAL;
    
    vdev_iokit_alloc(vd);
    
    dvd = static_cast<vdev_iokit_t *>(vd->vdev_tsd);
    
    dvd->vd_client_hl =     vdevGetService();
    
    dvd->vd_iokit_hl =      vdev_iokit_find_by_path(vd, vd->vdev_path);
}
    
/* Return 0 on success,
 * EINVAL or EIO as needed */
extern int vdev_iokit_status( vdev_t * vd )
{
    vdev_iokit_t * dvd = 0;
    IOMedia * vdev_disk = 0;
    
    if (!vd)
        return EINVAL;

    dvd = static_cast<vdev_iokit_t*>(vd_vdev_tsd);
    
    if (!vd->vdev_tsd)
        return EINVAL;
    
    vdev_disk = (IOMedia *)dvd->vd_iokit_hl;
    
    if (!vdev_disk)
        return EINVAL;
    
    if (vdev_disk->isFormatted() == false)
        return EIO;
    
    return 0;
    
}

int vdev_iokit_ioctl( vdev_t * vd, zio_t * zio )
{
    /*
     * XXX - TO DO
     *  multiple IOctls / passthrough
     *
     *  Flush cache
     *   IOMedia::synchronizeCache(IOService * client);
     */
    
    /*
    IOService * zfsProvider = 0;
     */
    
    IOMedia * vdev_disk = 0;
    vdev_iokit_t * dvd = 0;
IOLog( "vdev_iokit_ioctl: [%p] [%p]\n", vd, zio );
    if ( !vd || !vd->vdev_tsd )
        return EINVAL;
    
    dvd =           (vdev_iokit_t *)(vd->vdev_tsd);
    
    vdev_disk =     (IOMedia *)(dvd->vd_iokit_hl);
    
    if ( ! vdev_disk )
        return EINVAL;

    /* 
     * Only if needed...
     *
     */
    /*
    zfsProvider =   (IOService *)(dvd->vd_client_hl);
    if ( !zfsProvider )
        return EINVAL;
    */
    
    
    /*
     *  Handle ioctl
     */

    /*
    if (zfsProvider) {
        zfsProvider->release();
        zfsProvider = 0;
    }
    */
    
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
    vdev_iokit_context_t * io_context = 0;
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
    
    if (!dvd->vd_is_open) {
        /* XXX - TO DO
         *  Check and open as kIOStorageAccessReader for reads
         *  Check and elevate to kIOStorageAccessReaderWriter for writes
         */
        if ( ! vdev_disk->open(zfsProvider, 0, kIOStorageAccessReaderWriter) ) {
            return EINVAL;
        }
        IOLog("ZFS: vdev_iokit_strategy: open: %p\n", vdev_disk);
        dvd->vd_is_open = true;
    }
    
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
    
    io_context =            (vdev_iokit_context_t*)kmem_alloc(sizeof(vdev_iokit_context_t), KM_PUSHPAGE);
    
    io_context->buffer =    (IOBufferMemoryDescriptor*)IOBufferMemoryDescriptor::withAddress( zio->io_data, zio->io_size,
                                          (zio->io_type == ZIO_TYPE_WRITE ? kIODirectionOut : kIODirectionIn) );
    
    if (io_context->buffer == NULL) {
        IOLog("ZFS: vdev_iokit_strategy: Couldn't allocate a memory buffer\n");
//        IOSleep( error_delay );
        return ENOMEM;
    }
    
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
    vdev_iokit_context_t * io_context = 0;
    zio_t * zio = 0;
    
IOLog( "vdev_iokit_io_intr: [%p] [%p] (%d, %llu)\n", target, parameter, status, actualByteCount );
    
    io_context =        static_cast<vdev_iokit_context_t*>(parameter);
    
    if(!io_context) {
        zio_interrupt(NULL);
        return;
    }
    
    if(!io_context->zio) {
        zio_interrupt(NULL);
        return;
    }
    
    vdev_iokit_context_free(zio);
    
    if( status != 0 )
        zio->io_error = EIO;
    
	//zio_next_stage_async(zio);
    zio_interrupt(zio);
    
    return;
}

#ifdef __cplusplus
}   /* extern "C" */
#endif