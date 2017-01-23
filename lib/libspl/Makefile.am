include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

SUBDIRS = include $(TARGET_ASM_DIR)
DIST_SUBDIRS = include asm-generic #asm-i386 asm-x86_64

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/include

AM_CCASFLAGS = \
	-I$(top_srcdir)/lib/libspl/include

noinst_LTLIBRARIES = libspl.la

libspl_la_SOURCES = \
	crypto/edonr/edonr.c \
	crypto/skein/skein.c \
	crypto/skein/skein_iv.c \
	crypto/skein/skein_block.c \
	crypto/sha2/sha2.c \
	fdatasync.c \
	gethrtime.c \
	gethrestime.c \
	getmntany.c \
	list.c \
	mkdirp.c \
	strnlen.c \
	timestamp.c \
	uio.c \
	zmount.c \
	zone.c \
	xdr.c \
	asm-generic/atomic.S \
	include/sys/list.h \
	include/sys/list_impl.h

#libspl_la_LDFLAGS = -lrt
