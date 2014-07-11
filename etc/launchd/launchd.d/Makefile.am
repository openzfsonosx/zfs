AUTOMAKE_OPTIONS = subdir-objects

launchdscript_SCRIPTS = \
	zed.service.sh \
	zpool-autoimport.sh \
	zpool-import-all.sh

CLEANFILES = $(launchdscript_SCRIPTS)

EXTRA_DIST = \
	$(top_srcdir)/etc/launchd/launchd.d/zed.service.sh.in \
	$(top_srcdir)/etc/launchd/launchd.d/zpool-autoimport.sh.in \
	$(top_srcdir)/etc/launchd/launchd.d/zpool-import-all.sh.in

do_subst = -$(SED) -e 's,@bindir\@,$(bindir),g' \
		-e 's,@runstatedir\@,$(runstatedir),g' \
		-e 's,@sbindir\@,$(sbindir),g' \
		-e 's,@sysconfdir\@,$(sysconfdir),g' \
		-e 's,@launchdscriptdir\@,$(launchdscriptdir),g'

zed.service.sh: zed.service.sh.in
	$(do_subst) < $(top_srcdir)/etc/launchd/launchd.d/zed.service.sh.in > zed.service.sh
	chmod +x zed.service.sh

zpool-autoimport.sh: zpool-autoimport.sh.in
	$(do_subst) < $(top_srcdir)/etc/launchd/launchd.d/zpool-autoimport.sh.in > zpool-autoimport.sh
	chmod +x zpool-autoimport.sh

zpool-import-all.sh: zpool-import-all.sh.in
	$(do_subst) < $(top_srcdir)/etc/launchd/launchd.d/zpool-import-all.sh.in > zpool-import-all.sh
	chmod +x zpool-import-all.sh
