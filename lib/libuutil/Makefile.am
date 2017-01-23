include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libuutil.la

libuutil_la_SOURCES = \
	uu_alloc.c \
	uu_avl.c \
	uu_dprintf.c \
	uu_ident.c \
	uu_list.c \
	uu_misc.c \
	uu_open.c \
	uu_pname.c \
	uu_string.c \
	uu_strtoint.c

libuutil_la_LIBADD = \
	$(top_builddir)/lib/libavl/libavl.la \
	$(top_builddir)/lib/libspl/libspl.la \
	$(top_builddir)/lib/libefi/libefi.la

libuutil_la_LDFLAGS = -version-info 1:1:0

EXTRA_DIST = $(USER_C)
