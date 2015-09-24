ACLOCAL_AMFLAGS = -I config

include $(top_srcdir)/config/rpm.am
include $(top_srcdir)/config/deb.am
include $(top_srcdir)/config/tgz.am

if CONFIG_USER
include $(top_srcdir)/etc/launchd/daemons/launchd-daemons.am
endif

SUBDIRS = include
if CONFIG_KERNEL
SUBDIRS += module

extradir = @prefix@/src/zfs-$(VERSION)
extra_HEADERS = zfs.release.in zfs_config.h.in

kerneldir = /usr/src/zfs-$(VERSION)/$(LINUX_VERSION)
endif
if CONFIG_USER
# O3X - trim out linux stuff.
#SUBDIRS += udev etc man scripts lib cmd zfs_bundle
SUBDIRS += etc man scripts lib cmd zfs_bundle
endif


AUTOMAKE_OPTIONS = foreign
EXTRA_DIST  = autogen.sh copy-builtin
EXTRA_DIST += config/config.awk config/rpm.am config/deb.am config/tgz.am
EXTRA_DIST += META DISCLAIMER COPYRIGHT README.markdown OPENSOLARIS.LICENSE

distclean-local::
	-$(RM) -R autom4te*.cache
	-find . \( -name SCCS -o -name BitKeeper -o -name .svn -o -name CVS \
		-o -name .pc -o -name .hg -o -name .git \) -prune -o \
		\( -name '*.orig' -o -name '*.rej' -o -name '*~' \
		-o -name '*.bak' -o -name '#*#' -o -name '.*.orig' \
		-o -name '.*.rej' -o -name '.script-config' -o -size 0 \
		-o -name '*%' -o -name '.*.cmd' -o -name 'core' \
		-o -name 'Makefile' -o -name 'Module.symvers' \
		-o -name '*.order' -o -name '*.markers' \) \
		-type f -print | xargs $(RM)


checkstyle: cstyle shellcheck

cstyle:
	@find ${top_srcdir} -name '*.[hc]' ! -name 'zfs_config.*' \
		! -name '*.mod.c' -type f -exec scripts/cstyle.pl -cPp {} \+

shellcheck:
	@if type shellcheck > /dev/null 2>&1; then \
		(find ${top_srcdir} -type f -name '*.sh.in' -o -type f \
		 -name '*.sh'; find etc/init.d/zfs*.in -type f) | \
		 grep -v 'zfs-script-config' | \
		 while read file; do \
			shellcheck --format gcc "$$file"; \
		 done; \
	 fi

ctags:
	$(RM) tags
	find $(top_srcdir) -name .git -prune -o -name '*.[hc]' | xargs ctags

etags:
	$(RM) TAGS
	find $(top_srcdir) -name .pc -prune -o -name '*.[hc]' | xargs etags -a

tags: ctags etags

pkg: @DEFAULT_PACKAGE@
pkg-kmod: @DEFAULT_PACKAGE@-kmod
pkg-utils: @DEFAULT_PACKAGE@-utils

if CONFIG_USER
install-data-hook::
	@echo
	for plistfile in $(launchddaemon_DATA); do \
		bn=`basename "$$plistfile"`; \
		echo "Attempting to unload $$bn ..."; \
		$(DESTDIR)/bin/launchctl unload -F \
		$(DESTDIR)$(launchddaemondir)/"$$bn" \
		    || echo "Ignoring errors"; \
		echo "Attempting to load $$bn ..."; \
		$(DESTDIR)/bin/launchctl load -wF \
		$(DESTDIR)$(launchddaemondir)/"$$bn" \
		    || echo "Ignoring errors"; \
	done
	echo "Install done."

uninstall-hook::
	@echo
	for plistfile in $(launchddaemon_DATA); do \
		label=`defaults read "$$PWD"/"$$plistfile" Label`; \
		echo "Attempting to remove $$label ..."; \
		$(DESTDIR)/bin/launchctl remove "$$label" \
		    || echo "Ignoring errors"; \
	done
	$(RM) -r $(DESTDIR)@FILESYSTEMS_PREFIX@/zfs.fs
	$(RM) -r $(DESTDIR)@KERNEL_MODPREFIX@/zfs.kext
endif
