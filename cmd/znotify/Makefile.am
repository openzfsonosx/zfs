include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = znotify

znotify_SOURCES = \
	znotify.m

znotify_LDFLAGS = 	\
	-framework Cocoa -framework ScriptingBridge
