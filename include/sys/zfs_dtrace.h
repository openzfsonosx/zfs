#include <sys/zfs_dtrace_gen.h>


#define ZFS_zfs__dbgmsg(v) ZFS_ZFS_DBGMSG(v)
#define ZFS_zfs__dbgmsg_ENABLED ZFS_ZFS_DBGMSG_ENABLED

#undef  DTRACE_PROBE1
#define DTRACE_PROBE1(name, type, variable) do { \
		if(ZFS_##name##_ENABLED()) ZFS_##name(variable); } while(0);
