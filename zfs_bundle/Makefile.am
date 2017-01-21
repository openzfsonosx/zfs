include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

FS_BUNDLEPREFIX = @FILESYSTEMS_PREFIX@
FS_BUNDLEDIR = $(DESTDIR)$(FS_BUNDLEPREFIX)/zfs.fs

PKGINFO = PkgInfo
INFO_PLIST = Info.plist
INFOPLIST_STRINGS = InfoPlist.strings

bin_PROGRAMS = zfs.fs

dist_noinst_DATA = $(INFO_PLIST) English.lproj/$(INFOPLIST_STRINGS) $(PKGINFO)

zfs.fs/Contents/$(PKGINFO):

zfs.fs/Contents/$(INFO_PLIST):

zfs.fs/Contents/Resources/English.lproj/$(INFOPLIST_STRINGS):

zfs.fs$(EXEEXT): zfs.fs/Contents/$(PKGINFO) zfs.fs/Contents/$(INFO_PLIST) zfs.fs/Contents/Resources/English.lproj/$(INFOPLIST_STRINGS) $(INFO_PLIST) English.lproj/$(INFOPLIST_STRINGS) $(PKGINFO)
	rm -rf zfs.fs
	mkdir -p zfs.fs/Contents/Resources/English.lproj
	cp -f $(PKGINFO) zfs.fs/Contents/
	cp -f $(INFO_PLIST) zfs.fs/Contents/
	cp -f English.lproj/$(INFOPLIST_STRINGS) zfs.fs/Contents/Resources/English.lproj/
	plutil -convert binary1 zfs.fs/Contents/Resources/English.lproj/InfoPlist.strings

install-exec-local:: zfs.fs
	rm -f $(FS_BUNDLEDIR)/Contents/$(PKGINFO)
	rm -f $(FS_BUNDLEDIR)/Contents/$(INFO_PLIST)
	rm -f $(FS_BUNDLEDIR)/Contents/Resources/English.lproj/$(INFOPLIST_STRINGS)
	mkdir -p $(FS_BUNDLEDIR)
	rsync -aH zfs.fs/ $(FS_BUNDLEDIR)/
	cp -f $(DESTDIR)/$(MOUNTEXECDIR)/mount_zfs $(FS_BUNDLEDIR)/Contents/Resources/mount_zfs
	chown -R root:wheel $(FS_BUNDLEDIR) || echo "Unable to chown root:wheel in $(FS_BUNDLEDIR)"

clean:
	rm -rf zfs.fs

uninstall-hook:
	rm -rf "$(FS_BUNDLEDIR)"
