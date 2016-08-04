#dist_sbin_SCRIPTS = fsck.zfs

include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = fsck_zfs

fsck_zfs_SOURCES = \
	fsck_zfs.c

#fsck_zfs_LDADD = \
#        $(top_builddir)/lib/libzfs/libzfs.la

#fsck_zfs_LDFLAGS = -static -framework IOKit
fsck_zfs_LDFLAGS = -static

install-exec-hook:
	mkdir -p $(DESTDIR)/@FILESYSTEMS_PREFIX@/zfs.fs/Contents/Resources
	/bin/ln -f $(DESTDIR)$(sbindir)/$(sbin_PROGRAMS) $(DESTDIR)/@FILESYSTEMS_PREFIX@/zfs.fs/Contents/Resources/$(sbin_PROGRAMS)
	chown -R root:wheel ${DESTDIR}/@FILESYSTEMS_PREFIX@/$(sbin_PROGRAMS) || echo "Unable to chown root:wheel ${DESTDIR}/@FILESYSTEMS_PREFIX@/$(sbin_PROGRAMS)"

uninstall-hook:
	-$(RM) $(DESTDIR)/@FILESYSTEMS_PREFIX@/zfs.fs/Contents/Resources/$(sbin_PROGRAMS)
