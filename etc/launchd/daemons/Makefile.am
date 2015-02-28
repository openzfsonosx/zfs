AUTOMAKE_OPTIONS = subdir-objects

include $(top_srcdir)/etc/launchd/daemons/launchd-daemons.am

EXTRA_DIST = \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zconfigd.plist.in \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zed.plist.in \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zpool-import-all.plist.in \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.InvariantDisks.plist.in

$(launchddaemon_DATA):
	-$(SED) -e 's,@bindir\@,$(bindir),g' \
		-e 's,@runstatedir\@,$(runstatedir),g' \
		-e 's,@sbindir\@,$(sbindir),g' \
		-e 's,@sysconfdir\@,$(sysconfdir),g' \
		-e 's,@launchddaemondir\@,$(launchddaemondir),g' \
		-e 's,@launchdscriptdir\@,$(launchdscriptdir),g' \
		'$@.in' >'$@'

distclean-local::
	-$(RM) $(launchddaemon_DATA)
