include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = mount.zfs

mount_zfs_SOURCES = \
	mount_zfs.c

mount_zfs_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la

mount_zfs_LDFLAGS = \
	-lm $(ZLIB) -ldl $(LIBUUID) $(LIBBLKID) $(LIBSELINUX)

install-exec-hook:

uninstall-hook:
