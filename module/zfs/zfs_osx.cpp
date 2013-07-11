
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>

#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

#include <sys/zvolIO.h>

#include <sys/zfs_vnops.h>
#include <sys/taskq.h>



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

void
system_taskq_init(void)
{
    system_taskq = taskq_create("system_taskq",
                                system_taskq_size * max_ncpus,
                                minclsyspri, 4, 512,
                                TASKQ_DYNAMIC | TASKQ_PREPOPULATE);
}

} // Extern "C"






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


    return res;
}

void net_lundman_zfs_zvol::stop (IOService *provider)
{

    super::stop(provider);

    IOLog("ZFS: Attempting to unload ...\n");

#if 0
	if (zfs_active_fs_count != 0 ||
	    spa_busy() ||
	    zvol_busy()) {

		return KERN_FAILURE;   /* ZFS Still busy! */
	}
#endif

    system_taskq_fini();

    zfs_ioctl_fini();
    zvol_fini();
    zfs_vfsops_fini();
	zfs_znode_fini();

	//sysctl_unregister_oid(&sysctl__debug_maczfs_stalk);
    //	sysctl_unregister_oid(&sysctl__debug_maczfs);

    IOLog("ZFS: Unloaded module\n");

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

      zv->zv_iokitdev = NULL;
      zv = NULL;


      zvol_remove_symlink(zv);

      nub->terminate();
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

      //IOLog("Attempting to update volsize\n");
      nub->retain();
      nub->registerService();
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
  //IOLog("zvolIO_kit_read offset %p count %llu to offset %llu\n",
  //    address, len, offset);
  done=static_cast<IOMemoryDescriptor*>(iomem)->writeBytes(offset,
                                                           (void *)address,
                                                           len);
  return done;
}

uint64_t zvolIO_kit_write(void *iomem, uint64_t offset, char *address, uint64_t len)
{
  IOByteCount done;
  //IOLog("zvolIO_kit_write offset %p count %llu to offset %llu\n",
  //    address, len, offset);
  done=static_cast<IOMemoryDescriptor*>(iomem)->readBytes(offset,
                                                          (void *)address,
                                                          len);
  return done;
}






