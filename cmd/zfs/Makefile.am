include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = zfs

zfs_SOURCES = \
	zfs_iter.c \
	zfs_iter.h \
	zfs_main.c \
	zfs_util.h

zfs_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

zfs_LDFLAGS = -lm $(ZLIB) -ldl $(LIBUUID) $(LIBBLKID) -framework AppKit

install-exec-hook:
	echo "prefix $(PREFIX)"
	$(MKDIR_P) $(DESTDIR)/$(sbindir)
	/bin/ln -f $(DESTDIR)/$(sbindir)/zfs $(DESTDIR)/$(sbindir)/mount_zfs
	/bin/ln -f $(DESTDIR)/$(sbindir)/zfs $(DESTDIR)/$(sbindir)/umount_zfs

uninstall-hook:
	-$(RM) $(DESTDIR)/$(sbindir)/mount_zfs
	-$(RM) $(DESTDIR)/$(sbindir)/umount_zfs
