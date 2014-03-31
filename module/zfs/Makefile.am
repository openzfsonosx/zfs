include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

INFO_PLIST = Info.plist
PLIST_STRING = InfoPlist.strings

ZFS_META_VERSION = @ZFS_META_VERSION@
ZFS_DEBUG_STR = @ZFS_DEBUG_STR@

# XXX Make this usable for the installed location too
SPL_KMODDIR=	@SPL@/module/spl/spl.kext

CFLAGS_KMOD = \
	$(AM_CFLAGS) \
	-Wall \
	-nostdinc \
	-mkernel \
	-D_KERNEL \
	-DKERNEL \
	-DKERNEL_PRIVATE \
	-DDRIVER_PRIVATE \
	-DAPPLE \
	-DNeXT \
	-DNAMEDSTREAMS=1 \
	-DHAVE_SPL=1 \
	-I$(top_srcdir)/include \
	-I@SPL_OBJ@ -I@SPL_OBJ@/include \
	-I@KERNELSRC@

LINKFLAGS_KMOD = \
	-Xlinker \
	-kext \
	-nostdlib \
	-lkmodc++ \
	-lkmod \
	-lcc_kext

bin_PROGRAMS = zfs.kext
noinst_PROGRAMS = zfs

zfs_kext_SOURCE =

zfs_SOURCES = \
	arc.c \
	bplist.c \
	bpobj.c \
	bptree.c \
	dbuf.c \
	dbuf_stats.c \
	ddt.c \
	ddt_zap.c \
	dmu.c \
	dmu_diff.c \
	dmu_object.c \
	dmu_objset.c \
	dmu_send.c \
	dmu_traverse.c \
	dmu_tx.c \
	dmu_zfetch.c \
	dnode.c \
	dnode_sync.c \
	dsl_dataset.c \
	dsl_deadlist.c \
	dsl_deleg.c \
	dsl_destroy.c \
	dsl_dir.c \
	dsl_pool.c \
	dsl_prop.c \
	dsl_scan.c \
	dsl_synctask.c \
	dsl_userhold.c \
	fm.c \
	gfs.c \
	gzip.c \
	lzjb.c \
	lz4.c \
	metaslab.c \
	refcount.c \
	rrwlock.c \
	sa.c \
	sha256.c \
	spa.c \
	spa_boot.c \
	spa_config.c \
	spa_errlog.c \
	spa_history.c \
	spa_misc.c \
	spa_stats.c \
	space_map.c \
	txg.c \
	uberblock.c \
	unique.c \
	vdev.c \
	vdev_cache.c \
	vdev_disk.c \
	vdev_file.c \
	vdev_label.c \
	vdev_mirror.c \
	vdev_missing.c \
	vdev_queue.c \
	vdev_raidz.c \
	vdev_root.c \
	zap.c \
	zap_leaf.c \
	zap_micro.c \
	zfeature.c \
	zfeature_common.c \
	zfs_acl.c \
	zfs_byteswap.c \
	zfs_ctldir.c \
	zfs_debug.c \
	zfs_dir.c \
	zfs_fm.c \
	zfs_fuid.c \
	zfs_ioctl.c \
	zfs_log.c \
	zfs_onexit.c \
	zfs_osx.cpp \
	zfs_replay.c \
	zfs_rlock.c \
	zfs_sa.c \
	zfs_vfsops.c \
	zfs_vnops.c \
	zfs_vnops_osx.c \
	zfs_vnops_osx_lib.c \
	zfs_znode.c \
	zil.c \
	zio.c \
	zio_checksum.c \
	zio_compress.c \
	zio_inject.c \
	zle.c \
	zrlock.c \
	zvol.c \
	zvolIO.cpp \
	../avl/avl.c \
	../nvpair/fnvpair.c \
	../nvpair/nvpair.c \
	../nvpair/nvpair_alloc_fixed.c \
	../nvpair/nvpair_alloc_spl.c \
	../unicode/u8_textprep.c \
	../unicode/uconv.c \
	../zcommon/zfs_comutil.c \
	../zcommon/zfs_deleg.c \
	../zcommon/zfs_fletcher.c \
	../zcommon/zfs_namecheck.c \
	../zcommon/zfs_prop.c \
	../zcommon/zpool_prop.c \
	../zcommon/zprop_common.c

zfs_CPPFLAGS=$(CFLAGS_KMOD)
zfs_CXXFLAGS=$(CFLAGS_KMOD)
zfs_LDFLAGS=$(LINKFLAGS_KMOD)

KERNEL_MODDIR = $(DESTDIR)@KERNEL_MODPREFIX@/zfs.kext

dist_noinst_DATA = $(PLIST_STRING) $(INFO_PLIST)

zfs.kext$(EXEEXT): zfs $(PLIST_STRING) $(INFO_PLIST)
	@echo
	rm -rf zfs.kext
	mkdir -p zfs.kext/Contents/Resources/English.lproj zfs.kext/Contents/MacOS
	cp -f $(INFO_PLIST) zfs.kext/Contents/
	cp -f $(PLIST_STRING) zfs.kext/Contents/Resources/English.lproj/
	cp -f $(top_srcdir)/VolumeIcon.icns zfs.kext/Contents/Resources/
	cp -f zfs zfs.kext/Contents/MacOS/
	kextlibs -undef-symbols -e -r $(SPL_KMODDIR) -xml zfs.kext/ || echo Ignoring errors

# Show more information if there are linking problems.
debug-kext-linking:
	kextlibs -all-symbols -e -r $(SPL_KMODDIR) -xml zfs.kext/

install-exec-local: zfs.kext
	rm -rf $(KERNEL_MODDIR)
	mkdir -p $(KERNEL_MODDIR)
	rsync -r zfs.kext/ $(KERNEL_MODDIR)
	chown -R root:wheel $(KERNEL_MODDIR)
	@echo
	@echo "To load module: kextload -v $(KERNEL_MODDIR)"
	@echo "To uninstall module: rm -rf $(KERNEL_MODDIR)"
	@echo

clean:
	rm -rf zfs.kext/
	rm -f *.o *.lo zfs
