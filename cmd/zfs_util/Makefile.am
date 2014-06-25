include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

sbin_PROGRAMS = zfs.util

zfs_util_SOURCES = \
	zfs_util.c

zfs_util_LDFLAGS = -static

install-exec-hook:
	mkdir -p $(DESTDIR)/System/Library/Filesystems/zfs.fs/Contents/Resources
	/bin/ln -f $(DESTDIR)$(sbindir)/zfs.util $(DESTDIR)/System/Library/Filesystems/zfs.fs/Contents/Resources/zfs.util
	/bin/ln -fs Contents/Resources/zfs.util $(DESTDIR)/System/Library/Filesystems/zfs.fs/zfs.util
	sudo chown -R root:wheel ${DESTDIR}/System/Library/Filesystems/zfs.fs

uninstall-hook:
	-$(RM) $(DESTDIR)/System/Library/Filesystems/zfs.fs/Contents/Resources/zfs.util
	-$(RM) $(DESTDIR)/System/Library/Filesystems/zfs.fs/zfs.util
