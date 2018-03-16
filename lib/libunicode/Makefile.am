include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

VPATH = $(top_srcdir)/module/unicode

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

noinst_LTLIBRARIES = libunicode.la

libunicode_la_SOURCES = \
	u8_textprep.c \
	uconv.c
