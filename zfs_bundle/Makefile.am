include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

INFO_PLIST = Info.plist
EN_INFO_PLIST_STRINGS = en.lproj/InfoPlist.strings
PKGINFO = PkgInfo

bin_PROGRAMS = zfs.fs
noinst_PROGRAMS = zfs

zfs_fs_SOURCE =

zfs_SOURCES = \
	../cmd/zfs_util/zfs_util.c

zfs_LDFLAGS = -pthread -lm $(ZLIB) -ldl $(LIBUUID) $(LIBBLKID) -framework DiskArbitration -framework CoreServices -framework IOKit

ZFS_FS_DIR = $(DESTDIR)/System/Library/Filesystems/zfs.fs

dist_noinst_DATA = $(EN_INFO_PLIST_STRINGS) $(INFO_PLIST)

zfs.fs$(EXEEXT): zfs $(EN_INFO_PLIST_STRINGS) $(INFO_PLIST) $(PKGINFO)
	@echo
	rm -rf zfs.fs
	mkdir -p zfs.fs/Contents/Resources/en.lproj
	cp -f $(INFO_PLIST) zfs.fs/Contents/
	cp -f $(EN_INFO_PLIST_STRINGS) zfs.fs/Contents/Resources/$(EN_INFO_PLIST_STRINGS)
	cp -f $(PKGINFO) zfs.fs/Contents/

install-exec-local:: zfs.fs
	rm -f /System/Library/Filesystems/zfs.fs/Resources/$(EN_INFO_PLIST_STRINGS)
	rm -f /System/Library/Filesystems/zfs.fs/$(INFO_PLIST)
	rm -f /System/Library/Filesystems/zfs.fs/Contents/$(PKGINFO)
	mkdir -p /System/Library/Filesystems/zfs.fs
	rsync -aH zfs.fs/ /System/Library/Filesystems/zfs.fs
	chown -R root:wheel /System/Library/Filesystems/zfs.fs

clean:
	rm -rf zfs.fs
