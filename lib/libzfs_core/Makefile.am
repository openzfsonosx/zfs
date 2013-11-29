include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libzfs_core.la

libzfs_core_la_SOURCES = \
	libzfs_core.c

libzfs_core_la_LIBADD = \
	libnvpair.la

libzfs_core_la_LDFLAGS = -pthread -version-info 1:1:0
