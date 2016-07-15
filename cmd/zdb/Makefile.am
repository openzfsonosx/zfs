include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = zdb zdb_static

zdb_SOURCES = \
	zdb.c \
	zdb_il.c

zdb_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

zdb_LDFLAGS = -lm $(ZLIB) -ldl $(LIBUUID) $(LIBBLKID)


zdb_static_SOURCES = \
	zdb.c \
	zdb_il.c

zdb_static_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la

zdb_static_LDFLAGS = -static -lm $(ZLIB) -ldl $(LIBUUID) $(LIBBLKID) \
	-framework IOKit
