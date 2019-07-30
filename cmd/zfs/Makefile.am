include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = zfs mount_zfs

zfs_SOURCES = \
	zfs_iter.c \
	zfs_iter.h \
	zfs_main.c \
	zfs_osx.m  \
	zfs_util.h \
	zfs_project.c \
	zfs_projectutil.h

zfs_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

zfs_LDFLAGS = -lm $(ZLIB) -ldl $(LIBUUID) $(LIBBLKID) -framework AppKit


mount_zfs_SOURCES = $(zfs_SOURCES)

mount_zfs_LDADD = $(zfs_LDADD)

mount_zfs_LDFLAGS = $(zfs_LDFLAGS) -static


install-exec-hook:
	echo "prefix $(PREFIX)"
	$(MKDIR_P) $(DESTDIR)/$(MOUNTEXECDIR)
	/bin/ln -f $(DESTDIR)/$(sbindir)/mount_zfs $(DESTDIR)/$(MOUNTEXECDIR)/umount_zfs

uninstall-hook:
	-$(RM) $(DESTDIR)/$(MOUNTEXECDIR)/umount_zfs
