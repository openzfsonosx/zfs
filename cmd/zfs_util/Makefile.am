include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = zfs_util

zfs_util_SOURCES = \
	zfs_util.c

zfs_util_LDADD = \
        $(top_builddir)/lib/libzfs/libzfs.la

zfs_util_LDFLAGS = -static -framework IOKit
