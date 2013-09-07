include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libnvpair.la

libnvpair_la_SOURCES = \
	libnvpair.c \
	nvpair_alloc_system.c \
	../../module/nvpair/nvpair_alloc_fixed.c \
	../../module/nvpair/nvpair.c \
	../../module/nvpair/fnvpair.c

libnvpair_la_LIBADD = \
        $(top_builddir)/lib/libuutil/libuutil.la

libnvpair_la_LDFLAGS = -version-info 1:1:0

EXTRA_DIST = \
	$(top_srcdir)/module/nvpair/nvpair_alloc_spl.c
