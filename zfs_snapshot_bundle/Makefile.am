include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

INFO_PLIST = Info.plist
EN_INFO_PLIST_STRINGS = en.lproj/InfoPlist.strings
PKGINFO = PkgInfo

bin_PROGRAMS = zfssnapshot.fs
noinst_PROGRAMS = zfs

zfssnapshot_fs_SOURCE =

zfs_SOURCES = \
	../cmd/zfs_util/zfs_util.c

zfs_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

zfs_LDFLAGS = -pthread -lm $(ZLIB) -ldl $(LIBUUID) $(LIBBLKID) -framework DiskArbitration -framework CoreServices -framework IOKit

ZFS_FS_DIR = $(DESTDIR)/System/Library/Filesystems/zfssnapshot.fs

dist_noinst_DATA = $(EN_INFO_PLIST_STRINGS) $(INFO_PLIST)

zfssnapshot.fs$(EXEEXT): zfs $(EN_INFO_PLIST_STRINGS) $(INFO_PLIST) $(PKGINFO)
	@echo
	rm -rf zfssnapshot.fs
	mkdir -p zfssnapshot.fs/Contents/Resources/en.lproj
	cp -f $(INFO_PLIST) zfssnapshot.fs/Contents/
	cp -f $(EN_INFO_PLIST_STRINGS) zfssnapshot.fs/Contents/Resources/$(EN_INFO_PLIST_STRINGS)
	cp -f $(PKGINFO) zfssnapshot.fs/Contents/

install-exec-local:: zfssnapshot.fs
	rm -f /System/Library/Filesystems/zfssnapshot.fs/Resources/$(EN_INFO_PLIST_STRINGS)
	rm -f /System/Library/Filesystems/zfssnapshot.fs/$(INFO_PLIST)
	rm -f /System/Library/Filesystems/zfssnapshot.fs/Contents/$(PKGINFO)
	mkdir -p /System/Library/Filesystems/zfssnapshot.fs
	rsync -aH zfssnapshot.fs/ /System/Library/Filesystems/zfssnapshot.fs
	chown -R root:wheel /System/Library/Filesystems/zfssnapshot.fs

clean:
	rm -rf zfssnapshot.fs
