
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

extradir = /usr/src/zfs-$(VERSION)
extra_HEADERS = zfs.release.in zfs_config.h.in

kerneldir = /usr/src/zfs-$(VERSION)/$(LINUX_VERSION)
nodist_kernel_HEADERS = zfs.release zfs_config.h
endif
if CONFIG_USER
SUBDIRS += dracut udev etc man scripts lib cmd
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

if CONFIG_KERNEL
install-data-local:
	release=$(ZFS_META_VERSION)-$(ZFS_META_RELEASE); \
	instdest=$(DESTDIR)/usr/src/zfs-$$release/$(LINUX_VERSION); \
	for instfile in $(noinst_HEADERS); do \
		parentdir=`dirname $$instdest/$$instfile`; \
		mkdir -p $$parentdir; \
		$(INSTALL) $$instfile $$instdest/$$instfile; \
	done
endif


checkstyle:
	@find ${top_srcdir} -name '*.[hc]' ! -name 'zfs_config.*' \
		! -name '*.mod.c' -type f -exec scripts/cstyle.pl {} \+

ctags:
	$(RM) $(top_srcdir)/tags
	find $(top_srcdir) -name .git -prune -o -name '*.[hc]' | xargs ctags

etags:
	$(RM) $(top_srcdir)/TAGS
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
		echo "Attempting to load $$bn ..."; \
		$(DESTDIR)/bin/launchctl load -w \
		$(DESTDIR)$(launchddaemondir)/"$$bn" \
		    || echo "Ignoring errors"; \
	done

uninstall-hook::
	@echo
	for plistfile in $(launchddaemon_DATA); do \
		label=`defaults read "$$PWD"/"$$plistfile" Label`; \
		echo "Attempting to remove $$label ..."; \
		$(DESTDIR)/bin/launchctl remove "$$label" \
		    || echo "Ignoring errors"; \
	done
endif
