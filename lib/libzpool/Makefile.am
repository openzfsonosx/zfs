include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

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
	../../module/zfs/abd.c \
	../../module/zfs/arc.c \
	../../module/zfs/blkptr.c \
	../../module/zfs/bplist.c \
	../../module/zfs/bpobj.c \
	../../module/zfs/bptree.c \
	../../module/zfs/bqueue.c \
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
	../../module/zfs/dsl_bookmark.c \
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
	../../module/zfs/edonr_zfs.c \
	../../module/zfs/fm.c \
	../../module/zfs/gzip.c \
	../../module/zfs/lzjb.c \
	../../module/zfs/lz4.c \
	../../module/zfs/metaslab.c \
	../../module/zfs/multilist.c \
	../../module/zfs/range_tree.c \
	../../module/zfs/refcount.c \
	../../module/zfs/rrwlock.c \
	../../module/zfs/sa.c \
	../../module/zfs/sha256.c \
	../../module/zfs/skein_zfs.c \
	../../module/zfs/spa.c \
	../../module/zfs/spa_boot.c \
	../../module/zfs/spa_config.c \
	../../module/zfs/spa_errlog.c \
	../../module/zfs/spa_history.c \
	../../module/zfs/spa_misc.c \
	../../module/zfs/spa_stats.c \
	../../module/zfs/space_map.c \
	../../module/zfs/space_reftree.c \
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
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libicp/libicp.la

libzpool_la_LDFLAGS = -lz -version-info 1:1:0

EXTRA_DIST = $(USER_C)
