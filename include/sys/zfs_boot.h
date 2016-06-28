
#ifdef ZFS_BOOT
#ifndef	ZFS_BOOT_H_INCLUDED
#define	ZFS_BOOT_H_INCLUDED

#if 0
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOTimerEventSource.h>
#endif
#include <IOKit/IOService.h>

extern "C" {

//static uint16_t mount_attempts = 0;
#define ZFS_MOUNTROOT_RETRIES	50
#define ZFS_BOOTLOG_DELAY	100

//#ifdef ZFS_DEBUG
#define	zfs_boot_log(fmt, ...) {	\
	printf(fmt, __VA_ARGS__);	\
	IOSleep(ZFS_BOOTLOG_DELAY);	\
	}
//#else
//#define	zfs_boot_log(fmt, ...)
//#endif

#if 0
bool mountedRootPool;
IOTimerEventSource* mountTimer;
OSSet* disksInUse;

bool zfs_check_mountroot(char *, uint64_t *);
bool start_mount_timer(void);
bool registerDisk(IOService* newDisk);
bool unregisterDisk(IOService* oldDisk);
bool isDiskUsed(IOService* checkDisk);
bool zfs_mountroot(void);
bool isRootMounted(void);
void mountTimerFired(OSObject* owner, IOTimerEventSource* sender);
void clearMountTimer(void);
#endif

bool zfs_boot_init(IOService *);
void zfs_boot_fini();
//void zfs_boot_free(pool_list_t *pools);

} /* extern "C" */

#endif /* ZFS_BOOT_H_INCLUDED */
#endif /* ZFS_BOOT */
