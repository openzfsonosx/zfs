AUTOMAKE_OPTIONS = subdir-objects

launchdscript_SCRIPTS = \
	$(top_srcdir)/etc/launchd/launchd.d/zed.service.sh \
	$(top_srcdir)/etc/launchd/launchd.d/zpool-autoimport.sh

EXTRA_DIST = \
	$(top_srcdir)/etc/launchd/launchd.d/zed.service.sh.in \
	$(top_srcdir)/etc/launchd/launchd.d/zpool-autoimport.sh.in

$(launchdscript_SCRIPTS):
	-$(SED) -e 's,@bindir\@,$(bindir),g' \
		-e 's,@runstatedir\@,$(runstatedir),g' \
		-e 's,@sbindir\@,$(sbindir),g' \
		-e 's,@sysconfdir\@,$(sysconfdir),g' \
		-e 's,@launchdscriptdir\@,$(launchdscriptdir),g' \
		-e 's,@reversedns\@,$(ZFS_INIT_LAUNCHD_REVERSE_DNS),g' \
		'$@.in' >'$@'

distclean-local::
	-$(RM) $(launchdscript_SCRIPTS)
