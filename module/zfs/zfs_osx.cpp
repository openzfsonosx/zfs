
/*
 * Apple IOKit (c++)
 */
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#include <libkern/version.h>

#include <libkern/sysctl.h>

/*
 *  zvol IOKit (c++ with extern c)
 */

#include <sys/zvolIO.h>

/*
 *  ZFS internal
 */

#ifdef __cplusplus
extern "C" {
#endif
    
#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

#include <sys/zfs_vnops.h>
#include <sys/taskq.h>

#include <sys/param.h>
#include <sys/nvpair.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/spa_impl.h>
//#include <sys/spa_config.h>
#include <sys/spa_boot.h>


  extern kern_return_t _start(kmod_info_t *ki, void *data);
  extern kern_return_t _stop(kmod_info_t *ki, void *data);

    
#ifdef __cplusplus
}   /* extern "C" */
#endif

  __attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(net.lundman.zfs, "1.0.0", _start, _stop)
  __private_extern__ kmod_start_func_t *_realmain = 0;
  __private_extern__ kmod_stop_func_t  *_antimain = 0;
  __private_extern__ int _kext_apple_cc = __APPLE_CC__ ;


/*
 * Can those with more C++ experience clean this up?
 */
static void *global_c_interface = NULL;


// Define the superclass.
#define super IOService

OSDefineMetaClassAndStructors(net_lundman_zfs_zvol, IOService)


/*
 * Some left over functions from zfs_osx.c, left as C until cleaned up
 */

#ifdef __cplusplus
extern "C" {
#endif



extern SInt32 zfs_active_fs_count;

/* Global system task queue for common use */
extern int system_taskq_size;
taskq_t	*system_taskq = NULL;




#ifdef __APPLE__
extern int
zfs_vfs_sysctl(int *name, __unused u_int namelen, user_addr_t oldp, size_t *oldlenp,
               user_addr_t newp, size_t newlen, __unused vfs_context_t context)
{
#if 0
	int error;
	switch(name[0]) {
	case ZFS_SYSCTL_FOOTPRINT: {
		zfs_footprint_stats_t *footprint;
		size_t copyinsize;
		size_t copyoutsize;
		int max_caches;
		int act_caches;

		if (newp) {
			return (EINVAL);
		}
		if (!oldp) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (0);
		}
		copyinsize = *oldlenp;
		if (copyinsize < sizeof (zfs_footprint_stats_t)) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (ENOMEM);
		}
		footprint = kmem_alloc(copyinsize, KM_SLEEP);

		max_caches = copyinsize - sizeof (zfs_footprint_stats_t);
		max_caches += sizeof (kmem_cache_stats_t);
		max_caches /= sizeof (kmem_cache_stats_t);

		footprint->version = ZFS_FOOTPRINT_VERSION;

		footprint->memory_stats.current = zfs_footprint.current;
		footprint->memory_stats.target = zfs_footprint.target;
		footprint->memory_stats.highest = zfs_footprint.highest;
		footprint->memory_stats.maximum = zfs_footprint.maximum;

		arc_get_stats(&footprint->arc_stats);

		kmem_cache_stats(&footprint->cache_stats[0], max_caches, &act_caches);
		footprint->caches_count = act_caches;
		footprint->thread_count = zfs_threads;

		copyoutsize = sizeof (zfs_footprint_stats_t) +
		              ((act_caches - 1) * sizeof (kmem_cache_stats_t));

		error = copyout(footprint, oldp, copyoutsize);

		kmem_free(footprint, copyinsize);

		return (error);
	    }

	case ZFS_SYSCTL_CONFIG_DEBUGMSG:
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_msg_buf_enabled);
		return error;

	case ZFS_SYSCTL_CONFIG_zdprintf:
#ifdef ZFS_DEBUG
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_zdprintf_enabled);
#else
		error = ENOTSUP;
#endif
		return error;
	}
#endif
	return (ENOTSUP);
}
#endif /* __APPLE__ */



void
system_taskq_fini(void)
{
    if (system_taskq)
        taskq_destroy(system_taskq);
}


#include <sys/utsname.h>
#include <string.h>

void
system_taskq_init(void)
{

    system_taskq = taskq_create("system_taskq",
                                system_taskq_size * max_ncpus,
                                minclsyspri, 4, 512,
                                TASKQ_DYNAMIC | TASKQ_PREPOPULATE);


}

/*
 * fnv_32a_str - perform a 32 bit Fowler/Noll/Vo FNV-1a hash on a string
 *
 * input:
 *	str	- string to hash
 *	hval	- previous hash value or 0 if first call
 *
 * returns:
 *	32 bit hash as a static hash type
 *
 * NOTE: To use the recommended 32 bit FNV-1a hash, use FNV1_32A_INIT as the
 *  	 hval arg on the first call to either fnv_32a_buf() or fnv_32a_str().
 */
#define FNV1_32A_INIT ((uint32_t)0x811c9dc5)
uint32_t
fnv_32a_str(const char *str, uint32_t hval)
{
    unsigned char *s = (unsigned char *)str;	/* unsigned string */

    /*
     * FNV-1a hash each octet in the buffer
     */
    while (*s) {

	/* xor the bottom with the current octet */
	hval ^= (uint32_t)*s++;

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif
    }

    /* return our new hash value */
    return hval;
}

#ifdef __cplusplus
} /* Extern "C" */
#endif



bool net_lundman_zfs_zvol::init (OSDictionary* dict)
{
    bool res = super::init(dict);
    //IOLog("ZFS::init\n");
    global_c_interface = (void *)this;
    return res;
}


void net_lundman_zfs_zvol::free (void)
{
  //IOLog("ZFS::free\n");
    global_c_interface = NULL;
    super::free();
}


IOService* net_lundman_zfs_zvol::probe (IOService* provider, SInt32* score)
{
    IOService *res = super::probe(provider, score);
    //IOLog("ZFS::probe\n");
    return res;
}

bool net_lundman_zfs_zvol::start (IOService *provider)
{
    bool res = super::start(provider);


    IOLog("ZFS: Loading module ... \n");
	/*
	 * Initialize znode cache, vnode ops, etc...
	 */
	zfs_znode_init();

	/*
	 * Initialize /dev/zfs, this calls spa_init->dmu_init->arc_init-> etc
	 */
	zfs_ioctl_init();

	///sysctl_register_oid(&sysctl__debug_maczfs);
	//sysctl_register_oid(&sysctl__debug_maczfs_stalk);

    zfs_vfsops_init();

    /*
     * When is the best time to start the system_taskq? It is strictly
     * speaking not used by SPL, but by ZFS. ZFS should really start it?
     */
    system_taskq_init();


    /*
     * hostid is left as 0 on OSX, and left to be set if developers wish to
     * use it. If it is 0, we will hash the hardware.uuid into a 32 bit
     * value and set the hostid.
     */
    if (!zone_get_hostid(NULL)) {
      uint32_t myhostid = 0;
      IORegistryEntry *ioregroot =  IORegistryEntry::getRegistryRoot();
      if(ioregroot) {
        //IOLog("ioregroot is '%s'\n", ioregroot->getName(gIOServicePlane));
        IORegistryEntry *macmodel = ioregroot->getChildEntry(gIOServicePlane);
        if(macmodel) {
          //IOLog("macmodel is '%s'\n", macmodel->getName(gIOServicePlane));
          OSObject *ioplatformuuidobj;
          //ioplatformuuidobj = ioregroot->getProperty("IOPlatformUUID", gIOServicePlane, kIORegistryIterateRecursively);
          ioplatformuuidobj = macmodel->getProperty(kIOPlatformUUIDKey);
          if(ioplatformuuidobj) {
            OSString *ioplatformuuidstr = OSDynamicCast(OSString, ioplatformuuidobj);
            //IOLog("IOPlatformUUID is '%s'\n", ioplatformuuidstr->getCStringNoCopy());

            myhostid = fnv_32a_str(ioplatformuuidstr->getCStringNoCopy(),
                                   FNV1_32A_INIT);

            sysctlbyname("kern.hostid", NULL, NULL, &myhostid, sizeof(myhostid));
            printf("ZFS: hostid set to %08x from UUID '%s'\n",
                   myhostid, ioplatformuuidstr->getCStringNoCopy());
          }
        }
      }
    }
    
    /* Check if ZFS should try to mount root */
    IOLog("Checking if root pool should be imported...");
    if( ( res && zfs_check_mountroot() ) == true ) {
        IOLog("Trying to import root pool...");
        /* Looks good, give it a go */
        res = zfs_mountroot();
    }

    return res;
}

void net_lundman_zfs_zvol::stop (IOService *provider)
{


#if 0
  // You can not stop unload :(
	if (zfs_active_fs_count != 0 ||
	    spa_busy() ||
	    zvol_busy()) {

      IOLog("ZFS: Can not unload as we have filesystems mounted.\n");
      return;
	}
#endif
    IOLog("ZFS: Attempting to unload ...\n");

    super::stop(provider);


    system_taskq_fini();

    zfs_ioctl_fini();
    zvol_fini();
    zfs_vfsops_fini();
    zfs_znode_fini();

	//sysctl_unregister_oid(&sysctl__debug_maczfs_stalk);
    //	sysctl_unregister_oid(&sysctl__debug_maczfs);

    IOLog("ZFS: Unloaded module\n");

}

bool net_lundman_zfs_zvol::zfs_check_mountroot()
{
    
    /*
     * Check if the kext is loading during early boot
     * and/or check if root is mounted (IORegistry?)
     * Use PE Boot Args to determine the root pool name.
     */
    const int arglen = 256;
    char zfs_boot[arglen];
    bool result = false;
    
    PE_parse_boot_argn( "zfs_boot", &zfs_boot, sizeof(zfs_boot) );
    //IOLog( "Raw zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    
    result =    ( strlen(zfs_boot) > 0 );
    
    if ( !result ) {
        PE_parse_boot_argn( "rd", &zfs_boot, sizeof(zfs_boot) );
        result =    (strlen(zfs_boot) > 0 && strncmp(zfs_boot,"zfs:",4));
        //IOLog( "Raw rd: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    }
    if ( !result ) {
        PE_parse_boot_argn( "rootdev", &zfs_boot, sizeof(zfs_boot) );
        result =    (strlen(zfs_boot) > 0 && strncmp(zfs_boot,"zfs:",4));
        //IOLog( "Raw rootdev: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    }
    
    //IOSleep( error_delay );
    
    if ( result ) {
        //        IOLog( "Got zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    } else {
        //        IOLog( "No zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    }
    
    return result;
    
}

#define error_delay 1000
#define info_delay 50
bool net_lundman_zfs_zvol::zfs_mountroot(   /*vfs_t *vfsp, enum whymountroot why*/ )
{
    
    /*              EDITORIAL / README
     *
     * The filesystem that we mount as root is defined in the
     * boot property "zfs_boot" with a format of
     * "poolname/root-dataset-name".
     * You may also use the options "rd=zfs:pool/dataset"
     *  or "rootdev=zfs:pool/dataset"
     *
     * Valid entries: "rpool", "tank/fish",
     *  "sys/ROOT/BootEnvironment", and so on.
     *
     *  see /Library/Preferences/SystemConfiguration/com.apple.Boot.plist
     *  and ${PREFIX}/share/zfs/com.apple.Boot.plist for examples
     *
     * Note that initial boot support uses ZVOLs formatted
     * as (Mac-native) Journaled HFS+
     * In this case the bootfs will be a ZVOL, which cannot
     * be set via "zpool set bootfs=pool/zvol"
     *
     * Using ZFS datasets as root will require an additional
     * hack to trick the xnu kernel.
     *
     * Candidate is creating a (blank) ramdisk in chosen/RamDisk,
     * then forcible root-mount, possibly using an overlay.
     * Other options may include grub2+zfs, Chameleon, Chimera, etc.
     *
     */
    
    
    /*
     *           TO DO -- TO DO -- TO DO
     *
     * - Use PE Boot Args to determine the root pool name.
     *  working basically, but needs to filter zfs: from
     *  start of argument string. Also testing multiple
     *  '/'s in the dataset/zvol name, though it doesn't
     *  use this right now. Of course, need to error check
     *  for invalid entries (and decide what to do then).
     *
     * - Use IORegistry to locate vdevs - DONE
     *
     * - Call functions in vdev_disk.c or spa_boot.c
     * to locate the pool, import it.
     *    Cloned these functions into this giant function.
     *    Needs to be abstracted.
     *
     *
     * Case 1: Present zvol for the Root volume
     *
     * Case 2: Similar to meklort's FSRoot method,
     * register vfs_fsadd, and mount root;
     * mount the bootfs dataset as a union mount on top
     * of a ramdisk if necessary.
     */
    
    IORegistryIterator * registryIterator = 0;
    IORegistryEntry * currentEntry = 0;
    OSOrderedSet * allDisks = 0;
    
    const int arglen = 256;
    int split = 0;
    UInt64 labelSize;
    char * strptr = NULL;
    
    char zfs_boot[arglen];
    char zfs_pool[arglen];
    char zfs_root[arglen];
    
    char diskName[arglen];
    char diskPath[arglen];
    
    bool result = false;
    
    PE_parse_boot_argn( "zfs_boot", &zfs_boot, sizeof(zfs_boot) );
    
    result =    ( strlen(zfs_boot) > 0 );
    
    if ( !result ) {
        PE_parse_boot_argn( "rd", &zfs_boot, sizeof(zfs_boot) );
        result =    (strlen(zfs_boot) > 0 && strncmp(zfs_boot,"zfs:",4));
        //        strptr = zfs_boot + 4;
    }
    if ( !result ) {
        PE_parse_boot_argn( "rootdev", &zfs_boot, sizeof(zfs_boot) );
        result =    (strlen(zfs_boot) > 0 && strncmp(zfs_boot,"zfs:",4));
        //        strptr = zfs_boot + 4;
    }
    
    if ( !result ) {
        IOLog( "Invalid zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( error_delay );
        return false;
    }
    
    /*
     char *slashp;
     uint64_t objnum;
     int error;
     
     if (*bpath == 0 || *bpath == '/')
     return (EINVAL);
     
     (void) strcpy(outpath, bpath);
     
     slashp = strchr(bpath, '/');
     
     // if no '/', just return the pool name
     if (slashp == NULL) {
     return (0);
     }
     
     // if not a number, just return the root dataset name
     if (str_to_uint64(slashp+1, &objnum)) {
     return (0);
     }
     
     *slashp = '\0';
     error = dsl_dsobj_to_dsname(bpath, objnum, outpath);
     *slashp = '/';
     
     return (error);
     
     //			(void) strlcat(name, "@", MAXPATHLEN);
     
     */
    
    // Error checking, should be longer than 1 character and null terminated
    strptr = strchr( zfs_boot, '\0' );
    if ( strptr == NULL ) {
        IOLog( "Invalid zfs_boot: Not null terminated : [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( error_delay );
    }
    
    // Error checking, should be longer than 1 character
    if ( strlen(strptr) == 1 ) {
        IOLog( "Invalid zfs_boot: Only null character : [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( error_delay );
    } else {
        IOLog( "Valid zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( info_delay );
    }
    
    // Find first '/' in the boot arg
    strptr = strchr( zfs_boot, '/' );
    
    // If leading '/', return error
    if ( strptr == (zfs_boot) ) {
        IOLog( "Invalid zfs_boot: starts with '/' : [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( error_delay );
        strptr = NULL;
        return false;
    }
    
    // If trailing '/', return error
    if ( strptr == ( zfs_boot + strlen(zfs_boot) - 1 )  ) {
        IOLog( "Invalid zfs_boot: ends with '/' : [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( error_delay );
        strptr = NULL;
        return false;
    }
    
    split = strlen(zfs_boot) - strlen(strptr);
    
    //    if ( split > 0 && split < strlen(zfs_boot) ) {
    if ( strptr > zfs_boot ) {
        //strpbrk(search.spa_name, "/@")
        strlcpy( zfs_pool, zfs_boot, split+1 );
        strlcpy( zfs_root, strptr+1, strlen(strptr) );
    } else {
        strlcpy( zfs_pool, zfs_boot, strlen(zfs_boot)+1 );
        strlcpy( zfs_root, "\0", 1 );
    }
    
    // Find last @ in zfs_root ds
    strptr = strrchr( zfs_root, '@' );
    
    //    split = strlen(zfs_root) - strlen(strptr);
    
    //    if ( split > 0 && split < strlen(zfs_boot) ) {
    if ( strptr > zfs_root ) {
        strptr += split;
        strlcpy( zfs_root, strptr, split );
    }
    
    IOLog( "Will attempt to import zfs_pool: [%llu] %s\n", (uint64_t)strlen(zfs_pool), zfs_pool );
    IOSleep( info_delay );
    
    result = ( strlen(zfs_pool) > 0 );
    
    /* Cleanup strptr */
    //bzero(strptr,strlen(strptr));
    
    IOLog( "Will attempt to mount zfs_root:  [%llu] %s\n", (uint64_t)strlen(zfs_root), zfs_root );
    IOSleep( info_delay );
    
    /*
     * We want to match on all disks or volumes that
     * do not contain a partition map / raid / LVM
     *
     */
    
    registryIterator = IORegistryIterator::iterateOver( IORegistryEntry::getPlane( kIODeviceTreePlane ),
                                                       kIORegistryIterateRecursively );
    
    //IOLog( "may have iterator\n");
    //IOSleep( info_delay );
    
    
    if(!registryIterator) {
        IOLog( "could not get ioregistry iterator from IOKit\n");
        IOSleep( error_delay );
        registryIterator = 0;
        return false;
    }
    
    if(allDisks) {
        /* clean up */
        allDisks->release();
        allDisks = 0;
    }
    
    //IOLog( "iterateAll\n");
    //IOSleep( info_delay );
    /* Grab all matching records */
    allDisks = registryIterator->iterateAll();
    
    //IOLog( "iterateAll done\n");
    //IOSleep( info_delay );
    
    if (registryIterator) {
        /* clean up */
        registryIterator->release();
        registryIterator = 0;
    }
    
    //IOLog( "while allDisks\n");
    //IOSleep( info_delay );
    
    /* Loop through all the items in allDisks */
    while ( allDisks->getCount() > 0 ) {
        
        /*
         * Grab the first object in the set.
         * (could just as well be the last object)
         */
        currentEntry = static_cast<IORegistryEntry*>(allDisks->getFirstObject());
        //IOLog( "Converted regEntry\n" );
        //IOSleep( info_delay );
        
        if(!currentEntry) {
            IOLog( "Error checking vdev disks\n" );
            IOSleep( error_delay );
            /* clean up */
            currentEntry = 0;
            allDisks->release();
            allDisks = 0;
            return false;
        }
        
        /* Remove current item from ordered set */
        allDisks->removeObject( currentEntry );
        //IOLog( "Removed current from allDisks\n" );
        //IOSleep( info_delay );
        
        if (!currentEntry) {
            IOLog( "removeObject destroyed currentEntry?\n" );
            IOSleep( error_delay );
            /* clean up */
            currentEntry = 0;
            allDisks->release();
            allDisks = 0;
            return false;
        }
        
        //IOLog("zfs_mountroot: Getting 'Leaf' property\n" );
        //IOSleep( info_delay );
        
        /* Check 'Leaf' property */
        OSObject * matchObject = currentEntry->getProperty(kIOMediaLeafKey);
        //IOLog("zfs_mountroot: Got 'Leaf' matchObject '%p'\n", matchObject );
        //IOSleep( info_delay );
        OSBoolean * matchBool = OSDynamicCast( OSBoolean, matchObject );
        //IOLog("zfs_mountroot: Got 'Leaf' matchBool '%p'\n", matchBool );
        //IOSleep( info_delay );
        
        result =     ( matchBool && matchBool->getValue() == true );
        
        matchObject = 0;
        matchBool = 0;
        
        if( matchBool ) {
            IOLog("zfs_mountroot: 'Leaf' property is '%d'\n", matchBool->getValue() );
            IOSleep( error_delay );
        } else {
            //IOLog("zfs_mountroot: matchBool is empty\n" );
            //IOSleep( info_delay );
        }
        
        if( result == false ) {
            //IOLog("zfs_mountroot: Disk %s is not a leaf\n", diskName );
            //IOSleep( info_delay );
            currentEntry = 0;
            continue;
        }
        
        IOLog( "zfs_mountroot: Getting bsd name\n" );
        IOSleep( info_delay );
        OSObject * bsdnameosobj =    currentEntry->getProperty(kIOBSDNameKey,
                                                               gIOServicePlane,
                                                               kIORegistryIterateRecursively);
        OSString * bsdnameosstr =    OSDynamicCast(OSString, bsdnameosobj);
        IOLog("zfs_mountroot: bsd name is '%s'\n", bsdnameosstr->getCStringNoCopy());
        IOSleep( info_delay );
        
        
        IOLog( "zfs_mountroot: Getting device major number\n" );
        IOSleep( info_delay );
        OSObject * bsdmajorobj =    currentEntry->getProperty(kIOBSDMajorKey,
                                                              gIOServicePlane,
                                                              kIORegistryIterateRecursively);
        OSNumber * bsdmajornumber =    OSDynamicCast(OSNumber, bsdmajorobj);
        IOLog("zfs_mountroot: bsd major is '%llu'\n", bsdmajornumber->unsigned64BitValue());
        IOSleep( info_delay );
        
        
        IOLog( "zfs_mountroot: Getting device minor number\n" );
        IOSleep( info_delay );
        OSObject * bsdminorobj =    currentEntry->getProperty(kIOBSDMinorKey,
                                                              gIOServicePlane,
                                                              kIORegistryIterateRecursively);
        OSNumber * bsdminornumber =    OSDynamicCast(OSNumber, bsdminorobj);
        IOLog("zfs_mountroot: bsd minor is '%llu'\n", bsdminornumber->unsigned64BitValue());
        IOSleep( info_delay );
        
        
        
        //        strlcpy( diskName, bsdnameosstr->getCStringNoCopy(), bsdnameosstr->getLength()-1 );
        
        
        IOLog("zfs_mountroot: strncpy\n");
        IOSleep( info_delay );
        /* Start with '/dev' */
        strncpy( diskPath, "/dev/\0", 6 );
        IOLog("zfs_mountroot: strncpy done '%s'\n", diskPath);
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
        IOLog( "Got bsd path %s\n", diskPath );
        IOSleep( info_delay );
        
        result = (strlen(diskPath) > 0);
        
        if(!result) {
            IOLog( "Couldn't get BSD path for %s\n", diskName );
            IOSleep( error_delay );
            /* clean up */
        }
        
        IOLog( "BSD path: %s\n", diskPath );
        IOSleep( info_delay );
        
        /*
         *
         * Finally, check the disk for bootpool nvlist
         *
         * get vdev nvlist from disk
         *
         * import
         *
         * break from loop (and clean up) on success
         *
         */
        
        IOMedia * currentDisk = static_cast<IOMedia*>(currentEntry);
        IOBufferMemoryDescriptor* buffer = 0;
        nvlist_t * config = 0;
        
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
        
        //IOLog("zfs_mountroot: Checking if disk %s is formatted...\n", diskPath);
        //IOSleep( info_delay );
        
        // Determine whether this media is formatted.
        if ( currentDisk->isFormatted() != true ) {
            IOLog("zfs_mountroot: Disk %s not formatted\n", diskPath);
            IOSleep( error_delay );
            result = false;
            goto nextDisk;
        }
        
        if ( currentDisk->isOpen(0) ) {
            IOLog("zfs_mountroot: Disk %s is already open!\n", diskPath);
            IOSleep( error_delay );
        }
        
        //IOLog("zfs_mountroot: Opening handle for disk %s\n", diskPath);
        //IOSleep( info_delay );
        
        //error = ((IOMedia*)currentEntry)->open(this,0,kIOStorageAccessReader);
        result = currentDisk->open(this,0,kIOStorageAccessReader);
        
        /* If the disk could not be opened, skip to the next one */
        if (!result) {
            IOLog("zfs_mountroot: Disk %s couldn't be opened for reading\n", diskPath);
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
            IOLog("zfs_mountroot: Couldn't get size of disk %s\n", diskPath);
            IOSleep( error_delay );
        }
        
        labelSize = VDEV_SKIP_SIZE + VDEV_PHYS_SIZE;
        // Allocate a vdev_label_t-sized buffer to hold data read from disk.
        //sizeof (vdev_label_t)
        buffer = IOBufferMemoryDescriptor::withCapacity(labelSize, kIODirectionIn);
        
        if (buffer == NULL) {
            IOLog("zfs_mountroot: Couldn't allocate a memory buffer\n");
            IOSleep( error_delay );
            result = false;
            goto nextDisk;
        }
        
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
            
            
            
            IOLog("zfs_mountroot: Reading from disk %s, %llu, %p, %llu\n", diskPath, offset, buffer, labelSize);
            IOSleep( info_delay );
            
            if( currentDisk->read(this, offset, buffer, NULL,
                                  (UInt64 *) NULL ) != kIOReturnSuccess ) {
                IOLog("zfs_mountroot: Couldn't read from disk %s\n", diskPath);
                IOSleep( info_delay );
                (void) currentDisk->close(this,kIOStorageAccessReader);
                nvlist_free(config);
                config = NULL;
                result = false;
                goto nextDisk;
                //continue;
            }
            
            //IOLog("zfs_mountroot: Closing disk %s\n", diskPath);
            //IOSleep( info_delay );
            
            (void) currentDisk->close(this,kIOStorageAccessReader);
            
            //IOLog("zfs_mountroot: Closed disk %s\n", diskPath);
            //IOSleep( info_delay );
            
            if( buffer->readBytes(0,label,buffer->getLength()) == 0 ) {
                IOLog("zfs_mountroot: Failed to copy from memory buffer to label_t\n");
                IOSleep( info_delay );
                result = false;
                goto nextDisk;
            }
            
            IOLog("zfs_mountroot: Copied buffer into label %p\n", label);
            IOSleep( info_delay );
            
            if (nvlist_unpack(label->vl_vdev_phys.vp_nvlist,
                              sizeof (label->vl_vdev_phys.vp_nvlist), &config, 0) != 0) {
                IOLog("zfs_mountroot: Couldn't unpack nvlist label %p\n", label);
                IOSleep( info_delay );
                config = NULL;
                continue;
            }
            IOLog("zfs_mountroot: Unpacked nvlist label %p\n", label);
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
            IOLog("zfs_mountroot: Found config for %s at %s\n", pool_name, diskPath);
            IOSleep( info_delay );
            
            if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
                                     &state) != 0 || state >= POOL_STATE_DESTROYED) {
                IOLog("zfs_mountroot: Couldn't read pool %s state\n", pool_name);
                IOSleep( info_delay );
                nvlist_free(config);
                config = NULL;
                continue;
            }
            IOLog("zfs_mountroot: Pool state %s: %llu\n", pool_name, state);
            IOSleep( info_delay );
            
            if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
                                     &txg) != 0 || txg == 0) {
                IOLog("zfs_mountroot: Couldn't read pool %s txg number\n", pool_name);
                IOSleep( info_delay );
                nvlist_free(config);
                config = NULL;
                continue;
            }
            
            IOLog("zfs_mountroot: Pool txg %s: %llu\n", pool_name, txg);
            IOSleep( info_delay );
            
            if ( txg > besttxg ) {
                nvlist_free(bestconfig);
                besttxg = txg;
                bestconfig = config;
                
                /* Found a valid config, keep looping */
                break;
            }
        }
        
        IOLog("zfs_mountroot: Freeing label %p\n", label);
        IOSleep( info_delay );
        
        kmem_free(label, sizeof (vdev_label_t));
        
        if (config == NULL) {
            error = SET_ERROR(EIDRM);
            IOLog("zfs_mountroot: Invalid config? %p\n", label);
            IOSleep( error_delay );
        }
        
        IOLog("zfs_mountroot: Adding root vdev to config %p\n", label);
        IOSleep( info_delay );
        
        /*
         * Add this top-level vdev to the child array.
         */
        VERIFY(nvlist_lookup_nvlist(config,
                                    ZPOOL_CONFIG_VDEV_TREE, &nvtop) == 0);
        VERIFY(nvlist_lookup_uint64(config,
                                    ZPOOL_CONFIG_POOL_GUID, &pgid) == 0);
        VERIFY(nvlist_lookup_uint64(config,
                                    ZPOOL_CONFIG_GUID, &guid) == 0);
        
        IOLog("zfs_mountroot: Pool guids %s, %llu, %llu\n", pool_name, pgid, guid);
        IOSleep( info_delay );
        IOLog("zfs_mountroot: Adding top-level vdevs to root vdev %p\n", label);
        IOSleep( info_delay );
        
        /*
         * Put this pool's top-level vdevs into a root vdev.
         */
        /*  KM_PUSHPAGE instead of KM_SLEEP? */
        
        VERIFY(nvlist_alloc(&nvroot,
                            NV_UNIQUE_NAME, KM_SLEEP) == 0);
        //VDEV_TYPE_DISK
        VERIFY(nvlist_add_string(nvroot,
                                 ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT) == 0);
        VERIFY(nvlist_add_uint64(nvroot,
                                 ZPOOL_CONFIG_ID, 0ULL) == 0);
        
        VERIFY(nvlist_add_uint64(nvroot,
                                 ZPOOL_CONFIG_GUID, pgid) == 0);
        /*
         * The last thing to do is add the vdev guid -> path
         * mappings so that we can fix up the configuration
         * as necessary before doing the import.
         */
        /*
         
         pool_list_t *pl;
         
         if ( pl == NULL ) {
         if( ( pl = kmem_alloc(sizeof(pool_list_t),KM_PUSHPAGE)) == NULL ) {
         IOLog( "Couldn't allocate a pool_list_t for pool list" );
         IOSleep(error_delay);
         return false;
         }
         
         pl.ne_guid = 0;
         pl.ne_order = 0;
         pl.ne_next = NULL;
         pl.names = NULL;
         }
         
         name_entry_t *ne;
         
         if ((ne = kmem_alloc(sizeof (name_entry_t),KM_PUSHPAGE)) == NULL) {
         IOLog( "Couldn't allocate a name_entry for current vdev" );
         IOSleep(error_delay);
         }
         
         if ((ne->ne_name = zfs_strdup(hdl, path)) == NULL) {
         free(ne);
         return (-1);
         }
         
         ne->ne_guid = guid;
         ne->ne_order = order;
         ne->ne_next = pl->names;
         pl->names = ne;
         */
        
        /*
         //        if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) != 0)
         //            path = NULL;
         //        if (nvlist_add_string(nv, ZPOOL_CONFIG_PATH, best->ne_name) != 0)
         //            return (-1);
         
         //        VERIFY(nvlist_add_nvlist_array(nvroot,
         //                                       ZPOOL_CONFIG_CHILDREN, &nvtop, 1) == 0);
         
         //      Adjust the vdev path accordingly
         //        fix_paths(config, pl);
         */
        
        if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
                                       &child, &children) == 0) {
            for (int c = 0; c < children; c++)
            {
                if (child[c] && nvlist_add_string(child[c],
                                                  ZPOOL_CONFIG_PATH, diskPath) == 0) {
                    if(nvlist_lookup_string(child[c], ZPOOL_CONFIG_PATH, &tmpPath) != 0) {
                        IOLog("zfs_mountroot: failed to fix path for child vdev %p", child[c]);
                        IOSleep(error_delay);
                    }
                }
            }
        } else {
            if(nvlist_lookup_string(nvtop, ZPOOL_CONFIG_PATH, &tmpPath) != 0) {
                IOLog("zfs_mountroot: tmpPath before is %s\n", tmpPath);
                IOSleep(info_delay);
            }
            if(nvlist_lookup_string(nvtop, ZPOOL_CONFIG_PHYS_PATH, &tmpPath) != 0) {
                IOLog("zfs_mountroot: physPath before is %s\n", tmpPath);
                IOSleep(info_delay);
            }
            if (nvlist_add_string(nvtop, ZPOOL_CONFIG_PATH, diskPath) == 0) {
                if(nvlist_lookup_string(nvtop, ZPOOL_CONFIG_PATH, &tmpPath) != 0) {
                    IOLog("zfs_mountroot: failed to fix path for root vdev %s", diskPath);
                    IOSleep(error_delay);
                } else {
                    IOLog("zfs_mountroot: tmpPath after is %s\n", tmpPath);
                    IOSleep(info_delay);
                }
                if(nvlist_lookup_string(nvtop, ZPOOL_CONFIG_PHYS_PATH, &tmpPath) != 0) {
                    IOLog("zfs_mountroot: physPath after is %s\n", tmpPath);
                    IOSleep(info_delay);
                }
            }
            
            
        }
        
        IOLog("zfs_mountroot: vdev guid %s, %llu, %llu\n", pool_name, pgid, guid);
        IOSleep( info_delay );
        
        
        VERIFY(nvlist_add_nvlist_array(nvroot,
                                       ZPOOL_CONFIG_CHILDREN, &nvtop, 1) == 0);
        
        /*
         * Replace the existing vdev_tree with the new root vdev in
         * this pool's configuration (remove the old, add the new).
         */
        IOLog("zfs_mountroot: nvlist shuffle %s\n", pool_name);
        IOSleep( info_delay );
        
        
        VERIFY(nvlist_add_nvlist(config,
                                 ZPOOL_CONFIG_VDEV_TREE, nvroot) == 0);
        nvlist_free(nvroot);
        
        IOLog("zfs_mountroot: Checking status...\n");
        IOSleep( info_delay );
        
        /* If the rootlabel has been found, try to import the pool */
        if ( error != 0 && config ) {
            
            
            /*
             IOLog("zfs_mountroot: entering mutex %s...\n", pool_name);
             IOSleep( info_delay );
             mutex_enter(&spa_namespace_lock);
             IOLog("zfs_mountroot: Opening pool config %s...\n", pool_name);
             IOSleep( info_delay );
             spa = spa_add(pool_name, config, NULL);
             spa->spa_is_root = B_TRUE;
             spa->spa_import_flags = ZFS_IMPORT_VERBATIM;
             
             IOLog("zfs_mountroot: exiting mutex %s...\n", pool_name);
             IOSleep( info_delay );
             mutex_exit(&spa_namespace_lock);
             
             IOLog("zfs_mountroot: Trying to importing pool %s...\n", pool_name);
             IOSleep( info_delay );
             
             config = spa_tryimport( config );
             
             if ( config ) {
             IOLog("zfs_mountroot: Tryimport succeeded %s\n", pool_name);
             IOSleep( info_delay );
             } else {
             IOLog("zfs_mountroot: Tryimport failed %s\n", pool_name);
             IOSleep( info_delay );
             }
             */
            
            /*
             #define	ZFS_IMPORT_NORMAL	0x0
             #define	ZFS_IMPORT_VERBATIM	0x1
             #define	ZFS_IMPORT_ANY_HOST	0x2
             #define	ZFS_IMPORT_MISSING_LOG	0x4
             #define	ZFS_IMPORT_ONLY		0x8
             #define	ZFS_IMPORT_TEMP_NAME	0x10
             */
            /*
             * (ZFS_IMPORT_VERBATIM | ZFS_IMPORT_ONLY |
             *  ZFS_IMPORT_ANY_HOST | ZFS_IMPORT_MISSING_LOG )
             */
            
            nvlist_t * newconfig = spa_tryimport(config);
            
            if ( newconfig ) {
                nvlist_free(config);
                config = newconfig;
                IOLog("zfs_mountroot: Using tryimport config %s\n", pool_name);
                IOSleep( info_delay );
                
                uint64_t importFlags =   ( ZFS_IMPORT_ONLY | ZFS_IMPORT_ANY_HOST |
                                          ZFS_IMPORT_MISSING_LOG );
                result = ( spa_import(pool_name, config,  NULL, importFlags  ) == 0 );
                
                IOLog("zfs_mountroot: May have imported pool %s: %d\n", pool_name, result);
                IOSleep( info_delay );
                
                if ( !result ) {
                    IOLog("zfs_mountroot: Failure importing pool %s!\n", pool_name);
                    IOSleep( error_delay );
                }
            }
            
            spa_t *list = spa_by_guid(pgid, guid);
            
            if( list ) {
                IOLog("zfs_mountroot: pool seems to be imported %p\n", list);
                IOSleep( error_delay );
                result = true;
            } else {
                IOLog("zfs_mountroot: Couldn't locate pool by guid / vdev_guid %s\n", pool_name);
                IOSleep( error_delay );
                result = false;
            }
            
            //            spa_t * spa = NULL;
            //            result = spa_open(pool_name, &spa, FTAG);
            
            //            if (!result) {
            //IOLog("zfs_mountroot: Failure opening pool %s!\n", pool_name);
            //IOSleep( error_delay );
            //            }
            
            goto nextDisk;
            
        }
        
    nextDisk:
        IOLog("zfs_mountroot: nextDisk / cleanup\n");
        IOSleep( info_delay );
        
        /* clean up */
        if( !result )
            nvlist_free(config);
        if( buffer )
            buffer->release();
        buffer = 0;
        
        currentDisk = 0;
        //if( currentEntry )
        //currentEntry->release();
        currentEntry = 0;
        
        if ( result )
            break;
        
    }
    IOLog("zfs_mountroot: Final cleanup\n");
    IOSleep( info_delay );
    
    /* Final clean up */
    if( allDisks ) {
        /* clean up */
        allDisks->release();
        allDisks = 0;
    }
    return result;
}

IOReturn net_lundman_zfs_zvol::doEjectMedia(void *arg1)
{
  zvol_state_t *nub = (zvol_state_t *)arg1;
  IOLog("block svc ejecting\n");
  if(nub) {

    // Only 10.6 needs special work to eject
    if ((version_major == 10) &&
	(version_minor == 8))
      destroyBlockStorageDevice(nub);

  }

  IOLog("block svc ejected\n");
  return kIOReturnSuccess;
}



bool net_lundman_zfs_zvol::createBlockStorageDevice (zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    bool            result = false;

    if (!zv) goto bail;

    //IOLog("createBlock size %llu\n", zv->zv_volsize);

    // Allocate a new IOBlockStorageDevice nub.
    nub = new net_lundman_zfs_zvol_device;
    if (nub == NULL)
        goto bail;

    // Call the custom init method (passing the overall disk size).
    if (nub->init(zv) == false)
        goto bail;

    // Attach the IOBlockStorageDevice to the this driver.
    // This call increments the reference count of the nub object,
    // so we can release our reference at function exit.
    if (nub->attach(this) == false)
        goto bail;

    // Allow the upper level drivers to match against the IOBlockStorageDevice.
    /*
     * We here use Synchronous, so that all services are attached now, then
     * we can go look for the BSDName. We need this to create the correct
     * symlinks.
     */
    nub->registerService( kIOServiceSynchronous);

    nub->getBSDName();

    if ((version_major != 10) &&
	(version_minor != 8))
      zvol_add_symlink(zv, &zv->zv_bsdname[1], zv->zv_bsdname);

    result = true;

 bail:
    // Unconditionally release the nub object.
    if (nub != NULL)
        nub->release();

   return result;
}

bool net_lundman_zfs_zvol::destroyBlockStorageDevice (zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    bool            result = true;

    if (zv->zv_iokitdev) {

      //IOLog("removeBlockdevice\n");

      nub = static_cast<net_lundman_zfs_zvol_device*>(zv->zv_iokitdev);
//      nub = OSDynamicCast(net_lundman_zfs_zvol_device, zv->zv_iokitdev);

      zv->zv_iokitdev = NULL;
      zv = NULL;
        
      if (nub)
          nub->terminate(kIOServiceSynchronous);
    }

    return result;
}

bool net_lundman_zfs_zvol::updateVolSize(zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    //bool            result = true;

    // Is it ok to keep a pointer reference to the nub like this?
    if (zv->zv_iokitdev) {
      nub = static_cast<net_lundman_zfs_zvol_device*>(zv->zv_iokitdev);
//      nub = OSDynamicCast(net_lundman_zfs_zvol_device, zv->zv_iokitdev);

      if (!nub)
          return false;
        
      //IOLog("Attempting to update volsize\n");
      nub->retain();
      nub->registerService(kIOServiceSynchronous);
      nub->release();
    }
    return true;
}

/*
 * Not used
 */
IOByteCount net_lundman_zfs_zvol::performRead (IOMemoryDescriptor* dstDesc,
                                               UInt64 byteOffset,
                                               UInt64 byteCount)
{
  IOLog("performRead offset %llu count %llu\n", byteOffset, byteCount);
    return dstDesc->writeBytes(0, (void*)((uintptr_t)m_buffer + byteOffset),
                               byteCount);
}

/*
 * Not used
 */
IOByteCount net_lundman_zfs_zvol::performWrite (IOMemoryDescriptor* srcDesc,
                                                UInt64 byteOffset,
                                                UInt64 byteCount)
{
  IOLog("performWrite offset %llu count %llu\n", byteOffset, byteCount);
    return srcDesc->readBytes(0, (void*)((uintptr_t)m_buffer + byteOffset), byteCount);
}


/*
 * C language interfaces
 */
#ifdef __cplusplus
extern "C" {
#endif

net_lundman_zfs_zvol * zfsGetService()
{
    IORegistryIterator * registryIterator = 0;
    OSIterator * newIterator;
    IORegistryEntry * currentEntry = 0;
    OSDictionary * matchDict = 0;
    OSOrderedSet * allServices = 0;
    net_lundman_zfs_zvol * zfs_service = 0;
    
    matchDict =     IOService::serviceMatching( "net_lundman_zfs_zvol", 0 );
    IOLog("zfsGetService: create matchingDict\n");
    
    if ( matchDict ) {
        IOLog("zfsGetService: matchingDict\n");
        
        newIterator = IOService::getMatchingServices(matchDict);
        matchDict->release();
        matchDict = 0;
        
        if( newIterator ) {
            IOLog("zfsGetService: iterator\n");
            registryIterator = OSDynamicCast(IORegistryIterator, newIterator);
            
            if (registryIterator) {
                IOLog("zfsGetService: registryIterator\n");
                zfs_service = OSDynamicCast( net_lundman_zfs_zvol, registryIterator->getCurrentEntry() );
                
                registryIterator->release();
                registryIterator = 0;
            }
        }
    }
    IOLog("zfsGetService: zfs_service? [%p]\n", zfs_service);
    
    /* Should be matched, go to plan B if not */
    if (zfs_service == 0) {
        registryIterator->iterateOver(gIOServicePlane,kIORegistryIterateRecursively);
        IOLog("zfsGetService: registryIterator 2\n");
        if (!registryIterator)
            return 0;
        
        do {
            if(allServices)
                allServices->release();
            
            allServices = registryIterator->iterateAll();
        } while (! registryIterator->isValid() );
        
        IOLog("zfsGetService: allServices\n");
        registryIterator->release();
        registryIterator = 0;
        
        if (!allServices)
            return 0;
        IOLog("zfsGetService: entering while loop\n");
        while( ( currentEntry = OSDynamicCast(IORegistryEntry,
                                              allServices->getFirstObject() ) ) ) {
            // Remove from the set immidiately
            allServices->removeObject(currentEntry);
            IOLog("zfsGetService: currentEntry: [%p]\n", currentEntry);
            
            if (currentEntry) {
                if( strncmp("net_lundman_zfs_zvol\0",currentEntry->getName(),
                            sizeof("net_lundman_zfs_zvol\0") ) ) {
                    zfs_service = OSDynamicCast( net_lundman_zfs_zvol, currentEntry );
                    IOLog("zfsGetService: match: [%p]\n", zfs_service);
                }
                
                currentEntry->release();
                currentEntry = 0;
                
                if (zfs_service) /* Found service */
                    break;
            }
            IOLog("zfsGetService: While looped [%p]\n", currentEntry);
        }
        
        allServices->release();
        allServices = 0;
    }
    IOLog("zfsGetService: zfs_service 2? [%p] \n", zfs_service);
    
    return zfs_service;
}
    
int zvolCreateNewDevice(zvol_state_t *zv)
{
    //static_cast<net_lundman_zfs_zvol*>(global_c_interface)->createBlockStorageDevice(zv);
    net_lundman_zfs_zvol * zfsProvider = 0;
    zfsProvider = zfsGetService();
    if(!zfsProvider)
        zfsProvider = static_cast<net_lundman_zfs_zvol *>(global_c_interface);
    
    if(zfsProvider) {
        zfsProvider->createBlockStorageDevice(zv);
        return 0;
    } else {
        IOLog( "ZFS: zvolCreateNewDevice: Failed to locate zfs IOProvider\n" );
        return 1;
    }
}

int zvolRemoveDevice(zvol_state_t *zv)
{
//    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->destroyBlockStorageDevice(zv);
    net_lundman_zfs_zvol * zfsProvider = 0;
    zfsProvider = zfsGetService();
    if(!zfsProvider)
        zfsProvider = static_cast<net_lundman_zfs_zvol *>(global_c_interface);
    
    if(zfsProvider) {
        zfsProvider->destroyBlockStorageDevice(zv);
        return 0;
    } else {
        IOLog( "ZFS: zvolRemoveDevice: Failed to locate zfs IOProvider\n" );
        return 1;
    }
}

int zvolSetVolsize(zvol_state_t *zv)
{
//    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->updateVolSize(zv);
    net_lundman_zfs_zvol * zfsProvider = 0;
    zfsProvider = zfsGetService();
    if(!zfsProvider)
        zfsProvider = static_cast<net_lundman_zfs_zvol *>(global_c_interface);
    
    if(zfsProvider) {
        zfsProvider->updateVolSize(zv);
        return 0;
    } else {
        IOLog( "ZFS: zvolSetVolsize: Failed to locate zfs IOProvider\n" );
        return 1;
    }
}


uint64_t zvolIO_kit_read(void *iomem, uint64_t offset, char *address, uint64_t len)
{
  IOByteCount done;
  //IOLog("zvolIO_kit_read offset %p count %llx to offset %llx\n",
  //    address, len, offset);
    
    /* 
     * XXX - Is is safer and/or slower to use OSDynamicCast here?
     *  would allow for an error check instead of a panic. Don't
     *  know if there would be a performance hit.
     */
  done=static_cast<IOMemoryDescriptor*>(iomem)->writeBytes(offset,
                                                           (void *)address,
                                                           len);
  return done;
}

uint64_t zvolIO_kit_write(void *iomem, uint64_t offset, char *address, uint64_t len)
{
  IOByteCount done;
  //IOLog("zvolIO_kit_write offset %p count %llx to offset %llx\n",
  //    address, len, offset);
  done=static_cast<IOMemoryDescriptor*>(iomem)->readBytes(offset,
                                                          (void *)address,
                                                          len);
  return done;
}

#ifdef __cplusplus
}   /* extern "C" */
#endif