SUBDIRS = zpool-config zpios-test zpios-profile

EXTRA_DIST = dkms.mkconf dkms.postinst kmodtool zfs2zol-patch.sed cstyle.pl

pkgdatadir = $(datadir)/@PACKAGE@
dist_pkgdata_SCRIPTS = \
	$(top_builddir)/scripts/common.sh \
	$(top_srcdir)/scripts/zconfig.sh \
	$(top_srcdir)/scripts/zfault.sh \
	$(top_srcdir)/scripts/zimport.sh \
	$(top_srcdir)/scripts/zfs.sh \
	$(top_srcdir)/scripts/zpool-create.sh \
	$(top_srcdir)/scripts/zpios.sh \
	$(top_srcdir)/scripts/zpios-sanity.sh \
	$(top_srcdir)/scripts/zpios-survey.sh \
	$(top_srcdir)/scripts/smb.sh

ZFS=$(top_builddir)/scripts/zfs.sh
ZCONFIG=$(top_builddir)/scripts/zconfig.sh
ZFAULT=$(top_builddir)/scripts/zfault.sh
ZIMPORT=$(top_builddir)/scripts/zimport.sh
ZTEST=$(top_builddir)/cmd/ztest/ztest
ZPIOS_SANITY=$(top_builddir)/scripts/zpios-sanity.sh

subst = $(SED) \
	-e 's:@sbindir[@]:$(sbindir):g' \
	-e 's:@sysconfdir[@]:$(sysconfdir):g'

%.plist: %.plist.in Makefile
	$(subst) $< > $@

%.sh: %.sh.in Makefile
	$(subst) $< > $@

zplists = org.openzfsonosx.zed.service.plist org.openzfsonosx.zpool-autoimport.plist
zscripts = zpool-autoimport.sh zed.service.sh

check:
	@$(ZFS) -u
	@echo
	@echo -n "===================================="
	@echo -n " ZTEST "
	@echo    "===================================="
	@echo
	@$(ZFS)
	@$(ZTEST) -V
	@$(ZFS) -u
	@echo
	@echo
	@echo -n "==================================="
	@echo -n " ZCONFIG "
	@echo    "==================================="
	@echo
	@$(ZCONFIG) -c
	@echo
	@echo -n "==================================="
	@echo -n " ZFAULT "
	@echo    "==================================="
	@echo
	@$(ZFAULT) -c
	@echo
	@echo -n "===================================="
	@echo -n " ZPIOS "
	@echo    "===================================="
	@echo
	@$(ZFS)
	@$(ZPIOS_SANITY)
	@$(ZFS) -u
	@echo

all-local: $(zplists) $(zscripts)

clean-local:
	-rm -f $(zplists) $(zscripts)

install-data-local: all-local
	@echo
	$(MKDIR_P) $(DESTDIR)/Library/LaunchDaemons
	$(INSTALL_DATA) org.openzfsonosx.zed.service.plist $(DESTDIR)/Library/LaunchDaemons/org.openzfsonosx.zed.service.plist
	$(INSTALL_DATA) org.openzfsonosx.zpool-autoimport.plist $(DESTDIR)/Library/LaunchDaemons/org.openzfsonosx.zpool-autoimport.plist
	$(MKDIR_P) $(DESTDIR)$(sbindir)
	$(INSTALL) zed.service.sh $(DESTDIR)$(sbindir)/zed.service.sh
	$(INSTALL) zpool-autoimport.sh $(DESTDIR)$(sbindir)/zpool-autoimport.sh
	$(DESTDIR)/bin/launchctl load -w $(DESTDIR)/Library/LaunchDaemons/org.openzfsonosx.zed.service.plist || echo "Ignoring errors"
	$(DESTDIR)/bin/launchctl load -w $(DESTDIR)/Library/LaunchDaemons/org.openzfsonosx.zpool-autoimport.plist || echo "Ignoring errors"

uninstall-local:
	@echo
	$(DESTDIR)/bin/launchctl unload -w $(DESTDIR)/Library/LaunchDaemons/org.openzfsonosx.zed.service.plist || echo "Ignoring errors"
	$(DESTDIR)/bin/launchctl unload -w $(DESTDIR)/Library/LaunchDaemons/org.openzfsonosx.zpool-autoimport.plist || echo "Ignoring errors"
	@rm -f $(DESTDIR)/Library/LaunchDaemons/org.openzfsonosx.zed.service.plist
	@rm -f $(DESTDIR)/Library/LaunchDaemons/org.openzfsonosx.zpool-autoimport.plist
	@rm -f $(DESTDIR)$(sbindir)/zed.service.sh
	@rm -f $(DESTDIR)$(sbindir)/zpool-autoimport.sh

