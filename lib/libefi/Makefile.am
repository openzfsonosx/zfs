include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

noinst_LTLIBRARIES = libefi.la

libefi_la_LDFLAGS= -framework DiskArbitration -framework CoreServices

libefi_la_SOURCES = \
	rdwr_efi.c
