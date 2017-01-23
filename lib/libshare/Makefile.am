include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

noinst_LTLIBRARIES = libshare.la

libshare_la_SOURCES = \
	libshare_impl.h \
	libshare.c \
	nfs.c \
	nfs.h \
	smb.c \
	smb.h \
	afp.c \
	afp.h
