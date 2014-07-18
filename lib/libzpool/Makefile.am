include $(top_srcdir)/config/Rules.am

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libzpool.la

libzpool_la_SOURCES = \
	kernel.c \
	taskq.c \
	util.c \
	../../module/zcommon/zfs_comutil.c \
	../../module/zcommon/zfs_deleg.c \
	../../module/zcommon/zfs_fletcher.c \
	../../module/zcommon/zfs_namecheck.c \
	../../module/zcommon/zfs_prop.c \
	../../module/zcommon/zfs_uio.c \
	../../module/zcommon/zpool_prop.c \
	../../module/zcommon/zprop_common.c \
	../../module/zfs/arc.c \
	../../module/zfs/bplist.c \
	../../module/zfs/bpobj.c \
	../../module/zfs/bptree.c \
	../../module/zfs/dbuf.c \
	../../module/zfs/dbuf_stats.c \
	../../module/zfs/ddt.c \
	../../module/zfs/ddt_zap.c \
	../../module/zfs/dmu.c \
	../../module/zfs/dmu_diff.c \
	../../module/zfs/dmu_object.c \
	../../module/zfs/dmu_objset.c \
	../../module/zfs/dmu_send.c \
	../../module/zfs/dmu_traverse.c \
	../../module/zfs/dmu_tx.c \
	../../module/zfs/dmu_zfetch.c \
	../../module/zfs/dnode.c \
	../../module/zfs/dnode_sync.c \
	../../module/zfs/dsl_dataset.c \
	../../module/zfs/dsl_deadlist.c \
	../../module/zfs/dsl_deleg.c \
	../../module/zfs/dsl_destroy.c \
	../../module/zfs/dsl_dir.c \
	../../module/zfs/dsl_pool.c \
	../../module/zfs/dsl_prop.c \
	../../module/zfs/dsl_scan.c \
	../../module/zfs/dsl_synctask.c \
	../../module/zfs/dsl_userhold.c \
	../../module/zfs/fm.c \
	../../module/zfs/gzip.c \
	../../module/zfs/lzjb.c \
	../../module/zfs/lz4.c \
	../../module/zfs/metaslab.c \
	../../module/zfs/refcount.c \
	../../module/zfs/rrwlock.c \
	../../module/zfs/sa.c \
	../../module/zfs/sha256.c \
	../../module/zfs/spa.c \
	../../module/zfs/spa_boot.c \
	../../module/zfs/spa_config.c \
	../../module/zfs/spa_errlog.c \
	../../module/zfs/spa_history.c \
	../../module/zfs/spa_misc.c \
	../../module/zfs/spa_stats.c \
	../../module/zfs/space_map.c \
	../../module/zfs/txg.c \
	../../module/zfs/uberblock.c \
	../../module/zfs/unique.c \
	../../module/zfs/vdev.c \
	../../module/zfs/vdev_cache.c \
	../../module/zfs/vdev_file.c \
	../../module/zfs/vdev_label.c \
	../../module/zfs/vdev_mirror.c \
	../../module/zfs/vdev_missing.c \
	../../module/zfs/vdev_queue.c \
	../../module/zfs/vdev_raidz.c \
	../../module/zfs/vdev_root.c \
	../../module/zfs/zap.c \
	../../module/zfs/zap_leaf.c \
	../../module/zfs/zap_micro.c \
	../../module/zfs/zfeature.c \
	../../module/zfs/zfeature_common.c \
	../../module/zfs/zfs_byteswap.c \
	../../module/zfs/zfs_debug.c \
	../../module/zfs/zfs_fm.c \
	../../module/zfs/zfs_fuid.c \
	../../module/zfs/zfs_sa.c \
	../../module/zfs/zfs_znode.c \
	../../module/zfs/zil.c \
	../../module/zfs/zio.c \
	../../module/zfs/zio_checksum.c \
	../../module/zfs/zio_compress.c \
	../../module/zfs/zio_inject.c \
	../../module/zfs/zle.c \
	../../module/zfs/zrlock.c

libzpool_la_LIBADD = \
	$(top_builddir)/lib/libunicode/libunicode.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libnvpair/libnvpair.la

libzpool_la_LDFLAGS = -lz -pthread -version-info 1:1:0

EXTRA_DIST = \
	$(top_srcdir)/module/zfs/vdev_disk.c \
	$(top_srcdir)/module/zfs/zfs_acl.c \
	$(top_srcdir)/module/zfs/zfs_ctldir.c \
	$(top_srcdir)/module/zfs/zfs_dir.c \
	$(top_srcdir)/module/zfs/zfs_ioctl.c \
	$(top_srcdir)/module/zfs/zfs_log.c \
	$(top_srcdir)/module/zfs/zfs_onexit.c \
	$(top_srcdir)/module/zfs/zfs_replay.c \
	$(top_srcdir)/module/zfs/zfs_rlock.c \
	$(top_srcdir)/module/zfs/zfs_vfsops.c \
	$(top_srcdir)/module/zfs/zfs_vnops.c \
	$(top_srcdir)/module/zfs/zpl_ctldir.c \
	$(top_srcdir)/module/zfs/zpl_export.c \
	$(top_srcdir)/module/zfs/zpl_file.c \
	$(top_srcdir)/module/zfs/zpl_inode.c \
	$(top_srcdir)/module/zfs/zpl_super.c \
	$(top_srcdir)/module/zfs/zpl_xattr.c \
	$(top_srcdir)/module/zfs/zvol.c \
	$(top_srcdir)/module/zpios/pios.c
