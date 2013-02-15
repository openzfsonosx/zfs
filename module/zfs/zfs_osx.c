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


kern_return_t zfs_start (kmod_info_t * ki, void * d)
{
    printf("ZFS: Loaded module v0.01. Pool version -1\n");
    return KERN_SUCCESS;
}


kern_return_t zfs_stop (kmod_info_t * ki, void * d)
{
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
