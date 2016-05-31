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
	-I$(top_srcdir)/module/icp/include \
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
	abd.c \
	arc.c \
	blkptr.c \
	bplist.c \
	bpobj.c \
	bptree.c \
	bqueue.c \
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
	dsl_bookmark.c \
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
	edonr_zfs.c \
	fm.c \
	gfs.c \
	gzip.c \
	ldi_osx.c \
	ldi_vnode.c \
	ldi_iokit.cpp \
	lzjb.c \
	lz4.c \
	metaslab.c \
	multilist.c \
	range_tree.c \
	refcount.c \
	rrwlock.c \
	sa.c \
	sha256.c \
	skein_zfs.c \
	spa.c \
	spa_boot.c \
	spa_config.c \
	spa_errlog.c \
	spa_history.c \
	spa_misc.c \
	spa_stats.c \
	space_map.c \
	space_reftree.c \
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
	zfs_boot.cpp \
	zfs_byteswap.c \
	zfs_ctldir.c \
	zfs_debug.c \
	zfs_dir.c \
	zfs_fm.c \
	zfs_fuid.c \
	zfs_ioctl.c \
	zfs_kstat_osx.c \
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
	ZFSPool.cpp \
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
	../zcommon/zprop_common.c \
	../icp/illumos-crypto.c \
	../icp/api/kcf_cipher.c \
	../icp/api/kcf_digest.c \
	../icp/api/kcf_mac.c \
	../icp/api/kcf_miscapi.c \
	../icp/api/kcf_ctxops.c \
	../icp/core/kcf_callprov.c \
	../icp/core/kcf_prov_tabs.c \
	../icp/core/kcf_sched.c \
	../icp/core/kcf_mech_tabs.c \
	../icp/core/kcf_prov_lib.c \
	../icp/spi/kcf_spi.c \
	../icp/io/aes.c \
	../icp/io/sha2_mod.c \
	../icp/io/sha1_mod.c \
	../icp/os/modhash.c \
	../icp/os/bitmap_arch.c \
	../icp/os/modconf.c \
	../icp/algs/edonr/edonr.c \
	../icp/algs/modes/cbc.c \
	../icp/algs/modes/ccm.c \
	../icp/algs/modes/ctr.c \
	../icp/algs/modes/ecb.c \
	../icp/algs/modes/gcm.c \
	../icp/algs/modes/modes.c \
	../icp/algs/sha1/sha1.c \
	../icp/algs/sha2/sha2.c \
	../icp/algs/skein/skein.c \
	../icp/algs/skein/skein_block.c \
	../icp/algs/skein/skein_iv.c \
	../icp/algs/aes/aes_impl.c \
	../icp/algs/aes/aes_modes.c \
	../icp/asm-x86_64/aes/aeskey.c

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
	/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $(ZFS_META_VERSION)" zfs.kext/Contents/Info.plist
	/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $(ZFS_META_VERSION)" zfs.kext/Contents/Info.plist
	/usr/libexec/PlistBuddy -c "Set :OSBundleLibraries:net.lundman.spl $(ZFS_META_VERSION)" zfs.kext/Contents/Info.plist
	if [ "0$(ZFS_BOOT)" -eq 1 ]; then /usr/libexec/PlistBuddy -c "Add :OSBundleRequired string Root" zfs.kext/Contents/Info.plist && /usr/libexec/PlistBuddy -c "Set :IOKitPersonalities:net.lundman.zfs:IOResourceMatch IOBSD" zfs.kext/Contents/Info.plist; fi
	cp -f $(PLIST_STRING) zfs.kext/Contents/Resources/English.lproj/
	plutil -convert binary1 zfs.kext/Contents/Resources/English.lproj/InfoPlist.strings
	cp -f $(top_srcdir)/VolumeIcon.icns zfs.kext/Contents/Resources/
	cp -f zfs zfs.kext/Contents/MacOS/
	kextlibs -undef-symbols -e -r $(SPL_KMODDIR) -xml zfs.kext/ || echo Ignoring errors

# Show more information if there are linking problems.
debug-kext-linking:
	kextlibs -all-symbols -e -r $(SPL_KMODDIR) -xml zfs.kext/

install-exec-local:: zfs.kext
	rm -rf $(KERNEL_MODDIR)
	mkdir -p $(KERNEL_MODDIR)
	rsync -r zfs.kext/ $(KERNEL_MODDIR)
	chown -R root:wheel $(KERNEL_MODDIR) || echo "Unable to chown root:wheel $(KERNEL_MODDIR). KEXT will not load until it is"
	@echo
	@echo "To load module: kextload -v $(KERNEL_MODDIR)"
	@echo "To uninstall module: rm -rf $(KERNEL_MODDIR)"
	@echo

clean:
	rm -rf zfs.kext/
	rm -f *.o *.lo zfs

uninstall-hook:
	rm -rf "$(KERNEL_MODDIR)"
