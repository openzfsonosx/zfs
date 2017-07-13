/* Comment */
/*
 * dtrace -h -o zfs_dtrace.h -s zfs_dtrace.d
 * produces zfs_dtrace.h
 */

provider zfs { probe zfs__dbgmsg(char *); };
