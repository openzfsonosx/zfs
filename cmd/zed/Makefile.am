include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

EXTRA_DIST = zed.d/README

sbin_PROGRAMS = zed

zed_SOURCES = \
	zed.c \
	zed.h \
	zed_conf.c \
	zed_conf.h \
	zed_event.c \
	zed_event.h \
	zed_exec.c \
	zed_exec.h \
	zed_file.c \
	zed_file.h \
	zed_log.c \
	zed_log.h \
	zed_strings.c \
	zed_strings.h

zed_LDADD = \
	$(top_builddir)/lib/libavl/libavl.la \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libspl/libspl.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

zedconfdir = $(sysconfdir)/zfs/zed.d

dist_zedconf_DATA = \
	zed.d/zed-functions.sh \
	zed.d/zed.rc

zedexecdir = $(libexecdir)/zfs/zed.d

dist_zedexec_SCRIPTS = \
	$(top_srcdir)/cmd/zed/zed.d/all-debug.sh \
	$(top_srcdir)/cmd/zed/zed.d/all-syslog.sh \
	$(top_srcdir)/cmd/zed/zed.d/config.sync.sh \
	$(top_srcdir)/cmd/zed/zed.d/config.remove.sh \
	$(top_srcdir)/cmd/zed/zed.d/checksum-notify.sh \
	$(top_srcdir)/cmd/zed/zed.d/checksum-spare.sh \
	$(top_srcdir)/cmd/zed/zed.d/data-notify.sh \
	$(top_srcdir)/cmd/zed/zed.d/generic-notify.sh \
	$(top_srcdir)/cmd/zed/zed.d/io-notify.sh \
	$(top_srcdir)/cmd/zed/zed.d/io-spare.sh \
	$(top_srcdir)/cmd/zed/zed.d/zpool.import.sh \
	$(top_srcdir)/cmd/zed/zed.d/zpool.destroy.sh \
	$(top_srcdir)/cmd/zed/zed.d/zvol.create.sh \
	$(top_srcdir)/cmd/zed/zed.d/zvol.remove.sh \
	$(top_srcdir)/cmd/zed/zed.d/snapshot.mount.sh \
	$(top_srcdir)/cmd/zed/zed.d/resilver.finish-notify.sh \
	$(top_srcdir)/cmd/zed/zed.d/scrub.finish-notify.sh

zedconfdefaults = \
	all-syslog.sh \
	config.sync.sh \
	config.remove.sh \
	checksum-notify.sh \
	checksum-spare.sh \
	data-notify.sh \
	io-notify.sh \
	io-spare.sh \
	zpool.import.sh \
	zpool.destroy.sh \
	zvol.create.sh \
	zvol.remove.sh \
	snapshot.mount.sh \
	resilver.finish-notify.sh \
	scrub.finish-notify.sh

install-data-hook:
	$(MKDIR_P) "$(DESTDIR)$(zedconfdir)"
	for f in $(zedconfdefaults); do \
	  test -f "$(DESTDIR)$(zedconfdir)/$${f}" -o \
	       -L "$(DESTDIR)$(zedconfdir)/$${f}" || \
	    ln -s "$(zedexecdir)/$${f}" "$(DESTDIR)$(zedconfdir)"; \
	done
	chmod 0600 "$(DESTDIR)$(zedconfdir)/zed.rc"
