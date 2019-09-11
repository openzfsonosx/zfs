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
