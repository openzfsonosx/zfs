AUTOMAKE_OPTIONS = subdir-objects

launchddaemon_DATA = \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zed.service.plist \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zpool-autoimport.plist

EXTRA_DIST = \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zed.service.plist.in \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zpool-autoimport.plist.in

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

install-exec-hook::
	@echo
	$(DESTDIR)/bin/launchctl load \
		$(DESTDIR)$(launchddaemondir)/org.openzfsonosx.zed.service.plist \
		|| echo "Ignoring errors loading org.openzfsonosx.zed.service.plist"
	$(DESTDIR)/bin/launchctl load \
		$(DESTDIR)/$(launchddaemondir)/org.openzfsonosx.zpool-autoimport.plist \
		|| echo "Ignoring errors loading org.openzfsonosx.zpool-autoimport.plist"

uninstall-local::
	@echo
	$(DESTDIR)/bin/launchctl remove org.openzfsonosx.zed.service \
		|| echo "Ignoring errors removing job org.openzfsonosx.zed.service"
	$(DESTDIR)/bin/launchctl remove org.openzfsonosx.zpool-autoimport \
		|| echo "Ignoring errors removing job org.openzfsonosx.zpool-autoimport"
