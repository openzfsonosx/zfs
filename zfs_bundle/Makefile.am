include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

FS_BUNDLEPREFIX = @FILESYSTEMS_PREFIX@
FS_BUNDLEDIR = $(DESTDIR)$(FS_BUNDLEPREFIX)/zfs.fs

INFO_PLIST = Info.plist
EN_INFO_PLIST_STRINGS = en.lproj/InfoPlist.strings
PKGINFO = PkgInfo

bin_PROGRAMS = zfs.fs
noinst_PROGRAMS = zfs

zfs_fs_SOURCE =

zfs_SOURCES = \
	../cmd/zfs_util/zfs_util.c

zfs_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

zfs_LDFLAGS = -pthread -lm $(ZLIB) -ldl $(LIBUUID) $(LIBBLKID) -framework DiskArbitration -framework CoreServices -framework IOKit

ZFS_FS_DIR = $(DESTDIR)/Library/Filesystems/zfs.fs

dist_noinst_DATA = $(EN_INFO_PLIST_STRINGS) $(INFO_PLIST)

zfs.fs$(EXEEXT): zfs $(EN_INFO_PLIST_STRINGS) $(INFO_PLIST) $(PKGINFO)
	@echo
	rm -rf zfs.fs
	mkdir -p zfs.fs/Contents/Resources/en.lproj
	cp -f $(INFO_PLIST) zfs.fs/Contents/
	cp -f $(EN_INFO_PLIST_STRINGS) zfs.fs/Contents/Resources/$(EN_INFO_PLIST_STRINGS)
	cp -f $(PKGINFO) zfs.fs/Contents/

install-exec-local:: zfs.fs
	rm -f $(FS_BUNDLEDIR)/Contents/$(PKGINFO)
	rm -f $(FS_BUNDLEDIR)/Contents/$(INFO_PLIST)
	rm -f $(FS_BUNDLEDIR)/Contents/Resources/English.lproj/$(EN_INFO_PLIST_STRINGS)
	mkdir -p $(FS_BUNDLEDIR)
	rsync -aH zfs.fs/ $(FS_BUNDLEDIR)/
	chown -R root:wheel $(FS_BUNDLEDIR) || echo "Unable to chown root:wheel in $(FS_BUNDLEDIR)"

clean:
	rm -rf zfs.fs

uninstall-hook:
	rm -rf "$(FS_BUNDLEDIR)"
