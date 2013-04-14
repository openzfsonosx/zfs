int
zfs_vnop_ioctl_fullfsync(struct vnode *vp, vfs_context_t ct, zfsvfs_t *zfsvfs)
{
	int error;
	struct vnop_fsync_args fsync_args = {
		.a_vp = vp,
		.a_waitfor = MNT_WAIT,
		.a_context = ct,
	};

	error = zfs_vnop_fsync(&fsync_args);
	if (error)
		return (error);

	if (zfsvfs->z_log != NULL)
		zil_commit(zfsvfs->z_log, 0);
	else
		txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
	return (0);
}
