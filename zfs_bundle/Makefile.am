include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

FS_BUNDLEPREFIX = /System/Library/Filesystems
FS_BUNDLEDIR = $(DESTDIR)$(FS_BUNDLEPREFIX)/zfs.fs

PKGINFO = PkgInfo
INFO_PLIST = Info.plist
INFOPLIST_STRINGS = InfoPlist.strings

bin_PROGRAMS = zfs.fs

dist_noinst_DATA = $(INFO_PLIST) English.lproj/$(INFOPLIST_STRINGS) $(PKGINFO)

zfs.fs$(EXEEXT): $(INFO_PLIST) English.lproj/$(PLIST_STRINGS) $(PKGINFO)
	@echo
	rm -rf zfs.fs
	mkdir -p zfs.fs/Contents/Resources/English.lproj 
	cp -f $(PKGINFO) zfs.fs/Contents/
	cp -f $(INFO_PLIST) zfs.fs/Contents/
	cp -f English.lproj/$(INFOPLIST_STRINGS) zfs.fs/Contents/Resources/English.lproj/

install-exec-local:: zfs.fs
	rm -f $(FS_BUNDLEDIR)/Contents/$(PkgInfo)
	rm -f $(FS_BUNDLEDIR)/Contents/$(INFO_PLIST)
	rm -f $(FS_BUNDLEDIR)/Contents/Resources/English.lproj/$(INFOPLIST_STRINGS)
	mkdir -p $(FS_BUNDLEDIR)
	rsync -aH zfs.fs/ $(FS_BUNDLEDIR)
	chown -R root:wheel $(FS_BUNDLEDIR)

clean:
	rm -rf zfs.fs
