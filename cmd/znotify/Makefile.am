include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

INFO_PLIST = Info.plist
PLIST_STRING = InfoPlist.strings
MAINMENU = MainMenu

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

bin_PROGRAMS = bundle
noinst_PROGRAMS = znotify

bundle_SOURCES =

znotify_SOURCES = \
	znotify.m

znotify_LDFLAGS = 	\
	-framework Cocoa -framework ScriptingBridge

bundle$(EXEEXT): znotify $(PLIST_STRING) $(INFO_PLIST)
	@echo
	rm -rf znotify.app
	mkdir -p znotify.app/Contents/Resources/English.lproj znotify.app/Contents/MacOS
	cp -f $(INFO_PLIST) znotify.app/Contents/
	cp -f $(PLIST_STRING) znotify.app/Contents/Resources/English.lproj/
	ibtool --errors --warnings --notices --output-format human-readable-text \
	--compile znotify.app/Contents/Resources/${MAINMENU}.nib ${MAINMENU}.xib
	plutil -convert binary1 znotify.app/Contents/Resources/English.lproj/InfoPlist.strings
	cp -f $(top_srcdir)/VolumeIcon.icns znotify.app/Contents/Resources/
	cp -f znotify znotify.app/Contents/MacOS/

install-data-am:: bundle
	@echo "Installing znotify"
	rsync -ar znotify.app/ $(DESTDIR)$(bindir)/znotify.app/
