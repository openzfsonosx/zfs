#ifndef _SYS_ZFS_MOUNT_H_
#define _SYS_ZFS_MOUNT_H_

struct zfs_mount_args {
	const char	*fspec;         /* block special device to mount */
	uint64_t	flags;
};

#endif	/* _SYS_ZFS_IOCTL_H */
