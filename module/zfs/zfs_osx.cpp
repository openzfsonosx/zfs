
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOTimerEventSource.h>

#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

#include <sys/zvolIO.h>

#include <sys/zfs_vnops.h>
#include <sys/taskq.h>

#include <sys/param.h>
#include <sys/nvpair.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/vdev_iokit.h>
#include <sys/spa_impl.h>
#include <sys/spa_boot.h>

#include <libkern/version.h>

#include <libkern/sysctl.h>


extern "C" {
  extern kern_return_t _start(kmod_info_t *ki, void *data);
  extern kern_return_t _stop(kmod_info_t *ki, void *data);

};
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

extern "C" {

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


} // Extern "C"




bool net_lundman_zfs_zvol::init (OSDictionary* dict)
{
    bool res = super::init(dict);
    //IOLog("ZFS::init\n");
    global_c_interface = (void *)this;
    mountTimer = 0;
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
	 * Initialize /dev/zfs, this calls spa_init->dmu_init->arc_init-> etc
	 */
	zfs_ioctl_osx_init();

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

	if (res == false || zfs_check_mountroot() == false) {
		return (res);
	}

	/* Looks good, give it a go */
	mountTimer = IOTimerEventSource::timerEventSource(this,
	    mountTimerFired);

	if (!mountTimer) {
		IOLog("ZFS: Couldn't create mountTimer\n");
		return (false);
	}

	res = getWorkLoop()->addEventSource(mountTimer);

	mountedRootPool = false;

	if (res != kIOReturnSuccess) {
		IOLog("Couldn't add mountTimer event source\n");
		return (false);
	}

	IOLog("Setting mountTimer for 1 second...\n");
	mountTimer->setTimeoutMS(1000);

	/* At this point, always return true */
	return (true);
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

    clearMountTimer();

    system_taskq_fini();

    zfs_ioctl_osx_fini();
    zvol_fini();
    zfs_vfsops_fini();

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
	char zfs_boot[MAXPATHLEN];
	bool result = false;

	/* Ugly hack to determine if this is early boot */
	uint64_t uptime =   0;

	clock_get_uptime(&uptime); /* uptime since boot in nanoseconds */

	IOLog("ZFS: zfs_check_mountroot: uptime (%llu)\n", uptime);

	/* 3 billion nanoseconds ~= 3 seconds */
	if (uptime >= 3LLU<<30) {
		IOLog("ZFS: zfs_check_mountroot: Already booted\n");

		return (false);
	} else {
		IOLog("ZFS: zfs_check_mountroot: Boot time\n");
	}

	result = PE_parse_boot_argn("zfs_boot", &zfs_boot, sizeof (zfs_boot));
	// IOLog( "Raw zfs_boot: [%llu] {%s}\n",
	//    (uint64_t)strlen(zfs_boot), zfs_boot);

	result = (result && zfs_boot && strlen(zfs_boot) > 0);

	if (!result) {
		result = PE_parse_boot_argn("rd", &zfs_boot,
		    sizeof (zfs_boot));
		result = (result && zfs_boot &&
		    strlen(zfs_boot) > 0 &&
		    strncmp(zfs_boot, "zfs:", 4));
		// IOLog( "Raw rd: [%llu] {%s}\n",
		//    (uint64_t)strlen(zfs_boot), zfs_boot );
	}
	if (!result) {
		result = PE_parse_boot_argn("rootdev", &zfs_boot,
		    sizeof (zfs_boot));
		result = (result && zfs_boot &&
		    strlen(zfs_boot) > 0 &&
		    strncmp(zfs_boot, "zfs:", 4));
		// IOLog( "Raw rootdev: [%llu] {%s}\n",
		//    (uint64_t)strlen(zfs_boot), zfs_boot );
	}

	if (result) {
		IOLog("Got zfs_boot: [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
	} else {
		IOLog("No zfs_boot: [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
	}

	return (result);
}

bool net_lundman_zfs_zvol::zfs_mountroot()
{
	/* EDITORIAL / README
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
	 *
	 * TO DO -- TO DO -- TO DO
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
	 * to locate the pool, import it. - DONE
	 *	Cloned these functions into this giant function.
	 *	Needs to be abstracted. - DONE
	 *
	 * - Present single zvol as specified in zfs_boot?
	 *	Currently all zvols are made available on import.
	 *
	 * - Provide sample Boot.plist
	 *	${PREFIX}/share/zfs/com.apple.Boot.plist
	 *	Install to:
	 *	/Library/Preferences/SystemConfiguration/com.apple.Boot.plist
	 *
	 * Case 1: Present zvol for the Root volume - DONE
	 *
	 * Case 2: Similar to meklort's FSRoot method,
	 * register vfs_fsadd, and mount root;
	 * mount the bootfs dataset as a union mount on top
	 * of a ramdisk if necessary.
	 */

	char *strptr = 0;
	vdev_iokit_t *dvd = 0;

	char zfs_boot[MAXPATHLEN];
	char zfs_pool[MAXPATHLEN];
	char zfs_root[MAXPATHLEN];

	int split = 0;
	bool result = false;

	if (mountedRootPool == true)
		return (false);

	PE_parse_boot_argn("zfs_boot", zfs_boot, MAXPATHLEN);

	result =	(strlen(zfs_boot) > 0);

	if (!result) {
		PE_parse_boot_argn("rd", zfs_boot, sizeof (zfs_boot));
		result =	(strlen(zfs_boot) > 0 &&
		    strncmp(zfs_boot, "zfs:", 4));
		// strptr = zfs_boot + 4;
	}
	if (!result) {
		PE_parse_boot_argn("rootdev", zfs_boot, sizeof (zfs_boot));
		result =	(strlen(zfs_boot) > 0 &&
		    strncmp(zfs_boot, "zfs:", 4));
		// strptr = zfs_boot + 4;
	}

	if (!result) {
		IOLog("Invalid zfs_boot: [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
		return (false);
	}

	// Error checking, should be longer than 1 character and null terminated
	strptr = strchr(zfs_boot, '\0');
	if (strptr == NULL) {
		IOLog("Invalid zfs_boot: Not null terminated : [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
	}

	// Error checking, should be longer than 1 character
	if (strlen(strptr) == 1) {
		IOLog("Invalid zfs_boot: Only null character : [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
	} else {
		IOLog("Valid zfs_boot: [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
	}

	// Find first '/' in the boot arg
	strptr = strchr(zfs_boot, '/');

	// If leading '/', return error
	if (strptr == (zfs_boot)) {
		IOLog("Invalid zfs_boot: starts with '/' : [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
		strptr = NULL;
		return (false);
	}

	// If trailing '/', return error
	if (strptr == (zfs_boot + strlen(zfs_boot) - 1)) {
		IOLog("Invalid zfs_boot: ends with '/' : [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
		strptr = NULL;
		return (false);
	}

	//	if (split > 0 && split < strlen(zfs_boot)) {
	if (strptr && strptr > zfs_boot) {
		// strpbrk(search.spa_name, "/@")
		split = strlen(zfs_boot) - strlen(strptr);
		strlcpy(zfs_pool, zfs_boot, split+1);
		strlcpy(zfs_root, strptr+1, strlen(strptr));
	} else {
		strlcpy(zfs_pool, zfs_boot, strlen(zfs_boot)+1);
		strlcpy(zfs_root, "\0", 1);
	}

	// Find last @ in zfs_root ds
	strptr = strrchr(zfs_root, '@');

	//	if (split > 0 && split < strlen(zfs_boot)) {
	if (strptr && strptr > zfs_root) {
		split = strlen(zfs_root) - strlen(strptr);
		strptr += split;
		strlcpy(zfs_root, strptr, split);
	}

	IOLog("Will attempt to import zfs_pool: [%llu] %s\n",
	    (uint64_t)strlen(zfs_pool), zfs_pool);

	result = (zfs_pool && strlen(zfs_pool) > 0);

	IOLog("Will attempt to mount zfs_root:  [%llu] %s\n",
	    (uint64_t)strlen(zfs_root), zfs_root);

	/*
	 * We want to match on all disks or volumes that
	 * do not contain a partition map / raid / LVM
	 *
	 */

	if (vdev_iokit_alloc(&dvd) != 0) {
		IOLog("Couldn't allocate dvd [%p]\n", dvd);
		return (false);
	}

	IOLog("Searching for pool by name {%s}\n", zfs_pool);

	if (vdev_iokit_find_pool(dvd, zfs_pool) == 0 &&
	    dvd != 0 && dvd->vd_iokit_hl != 0) {

		IOLog("\nFound pool {%s}, importing handle: [%p]\n",
		    zfs_pool, dvd->vd_iokit_hl);
	}

	if (dvd->vd_iokit_hl == 0) {
		IOLog("Couldn't locate pool by name {%s}\n", zfs_pool);
		vdev_iokit_free(&dvd);
		return (false);
	}

	if (spa_import_rootpool(dvd) == 0) {
		IOLog("Imported pool {%s}\n", zfs_pool);
		mountedRootPool = true;
	} else {
		IOLog("Couldn't import pool by handle [%p]\n", dvd);
	}

	vdev_iokit_free(&dvd);

	return (true);
}

bool net_lundman_zfs_zvol::isRootMounted()
{
	return (mountedRootPool);
}

void net_lundman_zfs_zvol::mountTimerFired(OSObject* owner,
    IOTimerEventSource* sender)
{
	bool result = false;
	net_lundman_zfs_zvol *driver =	0;

	if (!owner) {
		IOLog("ZFS: mountTimerFired: Called without owner\n");
		return;
	}

	driver = OSDynamicCast(net_lundman_zfs_zvol, owner);

	if (!driver) {
		IOLog("ZFS: mountTimerFired: Couldn't cast driver object\n");
		return;
	}

	result = driver->isRootMounted();

	if (result == true) {
		IOLog("ZFS: mountTimerFired: Root pool already mounted\n");
		driver->clearMountTimer();
		return;
	}

	result = driver->zfs_mountroot();

	if (result == true) {
		IOLog("ZFS: mountTimerFired: Successfully mounted root pool\n");
		driver->clearMountTimer();
		return;
	}

	IOLog("ZFS: mountTimerFired: root pool not found, retrying...\n");
	sender->setTimeoutMS(100);
}

void net_lundman_zfs_zvol::clearMountTimer()
{
	if (!mountTimer)
		return;

	IOLog("ZFS: clearMountTimer: Resetting and removing timer\n");
	mountTimer->cancelTimeout();
	mountTimer->release();
	mountTimer =	0;
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
    nub->registerService(kIOServiceSynchronous);

    if (nub->getBSDName() == 0) {
        if ((version_major != 10) &&
            (version_minor != 8))
            zvol_add_symlink(zv, &zv->zv_bsdname[1], zv->zv_bsdname);
            result = true;
    } else
        result = false;

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

      zv->zv_iokitdev = NULL;
      zv = NULL;

		if (nub)
			nub->terminate(kIOServiceRequired|
			    kIOServiceSynchronous);
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
 * C language interfaces
 */

int zvolCreateNewDevice(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->createBlockStorageDevice(zv);
    return 0;
}

int zvolRemoveDevice(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->destroyBlockStorageDevice(zv);
    return 0;
}

int zvolSetVolsize(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->updateVolSize(zv);
    return 0;
}

uint64_t zvolIO_kit_read(void *iomem, uint64_t offset, char *address, uint64_t len)
{
  IOByteCount done;
  //IOLog("zvolIO_kit_read offset %p count %llx to offset %llx\n",
  //    address, len, offset);
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
