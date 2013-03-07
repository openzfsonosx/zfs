/*-
 *
 */

/*
 * OSX Port by Jorgen Lundman <lundman@lundman.net>
 */


#include <sys/debug.h>
#include <sys/kmem.h>

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>

#include <sys/mutex.h>
#include <sys/rwlock.h>

#include <sys/fs/zfs.h>
#include <sys/zfs_znode.h>

extern SInt32 zfs_active_fs_count;


#ifdef __APPLE__
extern int
zfs_vfs_sysctl(int *name, __unused u_int namelen, user_addr_t oldp, size_t *oldlenp,
               user_addr_t newp, size_t newlen, __unused vfs_context_t context)
{
	int error;
#if 0
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



kern_return_t zfs_start (kmod_info_t * ki, void * d)
{

    printf("ZFS: Loading module ...\n");

    //if ((error = zvol_init()) != 0)
    //   goto out1;

	/*
	 * Initialize our context globals
	 */
	//zfs_context_init();

	/*
	 * Initialize slab allocator and taskq layers
	 */
	//kmem_init(); // in spl?

	// .zfs not supported yet

	/*
	 * Initialize .zfs directory structures
	 */
	//zfsctl_init();

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

    return KERN_SUCCESS;
}


kern_return_t zfs_stop (kmod_info_t * ki, void * d)
{
    printf("ZFS: Attempting to unload ...\n");

#if 0
	if (zfs_active_fs_count != 0 ||
	    spa_busy() ||
	    zvol_busy()) {

		return KERN_FAILURE;   /* ZFS Still busy! */
	}
#endif

    zfs_ioctl_fini();
    zvol_fini();
    zfs_vfsops_fini();
	zfs_znode_fini();

	//kmem_fini();

	//zfs_context_fini();

	//sysctl_unregister_oid(&sysctl__debug_maczfs_stalk);
    //	sysctl_unregister_oid(&sysctl__debug_maczfs);

    printf("ZFS: Unloaded module\n");
    return KERN_SUCCESS;
}


extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t spl_start(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t spl_stop(kmod_info_t *ki, void *data);

__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(net.lundman.zfs, "1.0.0", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = zfs_start;
__private_extern__ kmod_stop_func_t *_antimain = zfs_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__ ;
