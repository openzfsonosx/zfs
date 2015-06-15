include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = zfs.util

zfs_util_SOURCES = \
	zfs_util.c

zfs_util_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

zfs_util_LDFLAGS = -pthread -lm $(ZLIB) -ldl $(LIBUUID) $(LIBBLKID) -framework DiskArbitration -framework CoreServices -framework IOKit -static

install-exec-hook:
	mkdir -p $(DESTDIR)/Library/Filesystems/zfs.fs/Contents/Resources
	/bin/ln -f $(DESTDIR)$(sbindir)/zfs.util $(DESTDIR)/Library/Filesystems/zfs.fs/Contents/Resources/zfs.util
	/bin/ln -fs Contents/Resources/zfs.util $(DESTDIR)/Library/Filesystems/zfs.fs/zfs.util
	sudo chown -R root:wheel /Library/Filesystems/zfs.fs

uninstall-hook:
	-$(RM) $(DESTDIR)/Library/Filesystems/zfs.fs/Contents/Resources/zfs.util
	-$(RM) $(DESTDIR)/Library/Filesystems/zfs.fs/zfs.util
