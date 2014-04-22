include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

INFO_PLIST = ZFSDriver-Info.plist
PLIST_STRING = en.lproj/InfoPlist.strings

ZFS_META_VERSION = @ZFS_META_VERSION@
ZFS_DEBUG_STR = @ZFS_DEBUG_STR@

# XXX Make this usable for the installed location too
SPL_KMODDIR=	@SPL@/module/spl/spl.kext

CFLAGS_KMOD = \
	$(AM_CFLAGS) \
	-Wall \
	-nostdinc \
	-mkernel \
	-D_KERNEL \
	-DKERNEL \
	-DKERNEL_PRIVATE \
	-DDRIVER_PRIVATE \
	-DAPPLE \
	-DNeXT \
	-DNAMEDSTREAMS=1 \
	-DHAVE_SPL=1 \
	-I$(top_srcdir)/include \
	-I@SPL_OBJ@ -I@SPL_OBJ@/include \
	-I@KERNELSRC@

LINKFLAGS_KMOD = \
	-Xlinker \
	-kext \
	-nostdlib \
	-lkmodc++ \
	-lkmod \
	-lcc_kext

bin_PROGRAMS = ZFSDriver.kext
noinst_PROGRAMS = ZFSDriver

ZFSDriver_kext_SOURCE =

ZFSDriver_SOURCES = ZFSLabelScheme.cpp ZFSProxyMediaScheme.cpp

ZFSDriver_CPPFLAGS=$(CFLAGS_KMOD)
ZFSDriver_CXXFLAGS=$(CFLAGS_KMOD)
ZFSDriver_LDFLAGS=$(LINKFLAGS_KMOD)

KERNEL_MODDIR = $(DESTDIR)@KERNEL_MODPREFIX@/ZFSDriver.kext

dist_noinst_DATA = $(PLIST_STRING) $(INFO_PLIST)

ZFSDriver.kext$(EXEEXT): ZFSDriver $(PLIST_STRING) $(INFO_PLIST)
	@echo
	rm -rf ZFSDriver.kext
	mkdir -p ZFSDriver.kext/Contents/Resources/English.lproj ZFSDriver.kext/Contents/MacOS
	cp -f $(INFO_PLIST) ZFSDriver.kext/Contents/Info.plist
	cp -f $(PLIST_STRING) ZFSDriver.kext/Contents/Resources/English.lproj/
	cp -f ZFSDriver ZFSDriver.kext/Contents/MacOS/
	kextlibs -undef-symbols -e -r $(SPL_KMODDIR) -xml ZFSDriver.kext/ || echo Ignoring errors

# Show more information if there are linking problems.
debug-kext-linking:
	kextlibs -all-symbols -e -r $(SPL_KMODDIR) -xml ZFSDriver.kext/

install-exec-local: ZFSDriver.kext
	rm -rf $(KERNEL_MODDIR)
	mkdir -p $(KERNEL_MODDIR)
	rsync -r ZFSDriver.kext/ $(KERNEL_MODDIR)
	chown -R root:wheel $(KERNEL_MODDIR)
	@echo
	@echo "To load module: kextload -v $(KERNEL_MODDIR)"
	@echo "To uninstall module: rm -rf $(KERNEL_MODDIR)"
	@echo

clean:
	rm -rf ZFSDriver.kext/
	rm -f *.o *.lo zfs
