
Very early work for ZFS on OSX.

Does not even compile yet, keep moving..


Current status:

```
# kextload -r /tmp/ -v /tmp/zfs.kext/

Requesting load of /tmp/zfs.kext.
/tmp/zfs.kext failed to load - (libkern/kext) link error; check the system/kernel logs for errors or try kextutil(8).
.apple.kextd[12]: Failed to load /tmp/zfs.kext - (libkern/kext) link error.
: kxld[net.lundman.zfs]: The following symbols are unresolved for this kext:
: kxld[net.lundman.zfs]:        _VOP_PUTPAGE
: kxld[net.lundman.zfs]:        _arc_referenced
: kxld[net.lundman.zfs]:        _chklock
: kxld[net.lundman.zfs]:        _crgetgroups
: kxld[net.lundman.zfs]:        _crgetngroups
: kxld[net.lundman.zfs]:        _deactivate_super
: kxld[net.lundman.zfs]:        _dmu_allocate_check
: kxld[net.lundman.zfs]:        _dmu_buf_add_ref
: kxld[net.lundman.zfs]:        _dmu_buf_fill_done
: kxld[net.lundman.zfs]:        _dmu_buf_refcount
: kxld[net.lundman.zfs]:        _dmu_buf_rele
: kxld[net.lundman.zfs]:        _dmu_buf_will_dirty
: kxld[net.lundman.zfs]:        _dmu_objset_close
: kxld[net.lundman.zfs]:        _dmu_objset_open
: kxld[net.lundman.zfs]:        _dmu_objset_rename
: kxld[net.lundman.zfs]:        _dmu_write_pages
: kxld[net.lundman.zfs]:        _getf
: kxld[net.lundman.zfs]:        _qsort
: kxld[net.lundman.zfs]:        _releasef
: kxld[net.lundman.zfs]:        _rootdir
: kxld[net.lundman.zfs]:        _schedule
: kxld[net.lundman.zfs]:        _secpolicy_vnode_remove
: kxld[net.lundman.zfs]:        _secpolicy_vnode_setid_retain
: kxld[net.lundman.zfs]:        _smp_processor_id
: kxld[net.lundman.zfs]:        _spa_busy
: kxld[net.lundman.zfs]:        _spa_history_internal_log
: kxld[net.lundman.zfs]:        _spl_kmem_availrmem
: kxld[net.lundman.zfs]:        _taskq_dispatch_ent
: kxld[net.lundman.zfs]:        _taskq_empty_ent
: kxld[net.lundman.zfs]:        _taskq_init_ent
: kxld[net.lundman.zfs]:        _thr_self
: kxld[net.lundman.zfs]:        _tsd_get
: kxld[net.lundman.zfs]:        _tsd_set
: kxld[net.lundman.zfs]:        _vdev_disk_ops
: kxld[net.lundman.zfs]:        _vdev_disk_read_rootlabel
: kxld[net.lundman.zfs]:        _vmem_zalloc
: kxld[net.lundman.zfs]:        _vn_has_cached_data
: kxld[net.lundman.zfs]:        _vn_ismntpt
: kxld[net.lundman.zfs]:        _xdrmem_create
: kxld[net.lundman.zfs]:        _zfs_ace_valid
: kxld[net.lundman.zfs]:        _zfs_acl_next_ace
: kxld[net.lundman.zfs]:        _zfs_fuid_overquota
: kxld[net.lundman.zfs]:        _zfs_get_zplprop
: kxld[net.lundman.zfs]:        _zfs_is_readonly
: kxld[net.lundman.zfs]:        _zfs_obj_to_stats
: kxld[net.lundman.zfs]:        _zfs_perm_init
: kxld[net.lundman.zfs]:        _zfs_prefault_write
: kxld[net.lundman.zfs]:        _zfs_resume_fs
: kxld[net.lundman.zfs]:        _zfs_sb_create
: kxld[net.lundman.zfs]:        _zfs_sb_free
: kxld[net.lundman.zfs]:        _zfs_set_userquota
: kxld[net.lundman.zfs]:        _zfs_suspend_fs
: kxld[net.lundman.zfs]:        _zfs_tstamp_update_setup
: kxld[net.lundman.zfs]:        _zfs_userspace_many
: kxld[net.lundman.zfs]:        _zfs_userspace_one
: kxld[net.lundman.zfs]:        _zfs_vfs_sysctl
: kxld[net.lundman.zfs]:        _zfs_vnop_readdirattr
: kxld[net.lundman.zfs]:        _zfs_zevent_fd_hold
: kxld[net.lundman.zfs]:        _zfsctl_root
: kxld[net.lundman.zfs]:        _zfsctl_root_lookup
: kxld[net.lundman.zfs]:        _zfsctl_unmount_snapshot
: kxld[net.lundman.zfs]:        _zil_add_vdev
: kxld[net.lundman.zfs]:        _zio_alloc_arena
: kxld[net.lundman.zfs]:        _zone_get_hostid
```