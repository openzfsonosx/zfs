AUTOMAKE_OPTIONS = subdir-objects

include $(top_srcdir)/etc/launchd/daemons/launchd-daemons.am

DAEMON_DIR = $(top_srcdir)/etc/launchd/daemons

$(DAEMON_DIR)/org.openzfsonosx.zconfigd.plist: $(DAEMON_DIR)/org.openzfsonosx.zconfigd.plist.in
$(DAEMON_DIR)/org.openzfsonosx.zed.plist: $(DAEMON_DIR)/org.openzfsonosx.zed.plist.in
$(DAEMON_DIR)/org.openzfsonosx.zpool-import-all.plist: $(DAEMON_DIR)/org.openzfsonosx.zpool-import-all.plist.in
$(DAEMON_DIR)/org.openzfsonosx.InvariantDisks.plist: $(DAEMON_DIR)/org.openzfsonosx.InvariantDisks.plist.in

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
